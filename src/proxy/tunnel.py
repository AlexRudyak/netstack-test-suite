"""Proxy tunnel handshakes, encoded/decoded exactly per their RFCs.

Two explicit-proxy protocols are supported:

- **HTTP CONNECT** — RFC 9110 §9.3.6 (CONNECT semantics) with the
  authority-form request target of RFC 9112 §3.2.3. Any 2xx establishes the
  tunnel; everything after the header block is an opaque byte stream.
- **SOCKS5** — RFC 1928 (greeting, method selection, CONNECT request,
  reply), with optional username/password auth from RFC 1929.

Everything here is a pure function over bytes, or takes a `read(n)`
callable, so the wire formats can be verified against the RFCs in unit
tests without a socket or a live proxy.
"""
from __future__ import annotations

import ipaddress
from collections.abc import Callable
from dataclasses import dataclass, field

from src.errors import ConfigurationError, PeerClosedEarly, ProtocolViolation

Reader = Callable[[int], bytes]
"""Reads exactly n bytes (raising on short read) — a socket or a test stub."""

# --- HTTP CONNECT (RFC 9110 §9.3.6, RFC 9112) ------------------------------

CRLF = b"\r\n"
HEADER_TERMINATOR = b"\r\n\r\n"


@dataclass(frozen=True)
class HttpConnectResponse:
    status: int
    reason: str
    headers: dict[str, str] = field(default_factory=dict)

    @property
    def tunnel_established(self) -> bool:
        """RFC 9110 §9.3.6: *any* 2xx response establishes the tunnel."""
        return 200 <= self.status < 300


def format_authority(host: str, port: int) -> str:
    """authority-form target (RFC 9112 §3.2.3); IPv6 literals get brackets."""
    if ":" in host and not host.startswith("["):
        return f"[{host}]:{port}"
    return f"{host}:{port}"


def build_http_connect_request(
    host: str, port: int, *, extra_headers: dict[str, str] | None = None
) -> bytes:
    """`CONNECT authority HTTP/1.1` with the mandatory Host header.

    RFC 9112 §3.2.3 requires authority-form (host:port, no scheme or path)
    for CONNECT; RFC 9110 §7.2 requires a Host header matching the target.
    """
    authority = format_authority(host, port)
    lines = [f"CONNECT {authority} HTTP/1.1", f"Host: {authority}"]
    for name, value in (extra_headers or {}).items():
        lines.append(f"{name}: {value}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii")


def parse_http_connect_response(raw: bytes) -> HttpConnectResponse:
    """Parse a complete response header block (through CRLFCRLF)."""
    head = raw.split(HEADER_TERMINATOR, 1)[0]
    lines = head.split(CRLF)
    if not lines or not lines[0]:
        raise ProtocolViolation("empty HTTP response")

    # status-line: HTTP-version SP status-code SP [reason-phrase]
    parts = lines[0].decode("iso-8859-1").split(" ", 2)
    if len(parts) < 2 or not parts[0].upper().startswith("HTTP/"):
        raise ProtocolViolation(f"malformed HTTP status line: {lines[0]!r}")
    try:
        status = int(parts[1])
    except ValueError as exc:
        raise ProtocolViolation(f"non-numeric HTTP status code: {parts[1]!r}") from exc
    reason = parts[2] if len(parts) > 2 else ""

    headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line:
            continue
        name, _, value = line.decode("iso-8859-1").partition(":")
        headers[name.strip().lower()] = value.strip()
    return HttpConnectResponse(status=status, reason=reason, headers=headers)


def read_http_response_head(read: Reader) -> bytes:
    """Read byte-by-byte up to and including CRLFCRLF.

    A CONNECT tunnel becomes an opaque byte stream immediately after the
    header block, so we must not over-read into the relayed payload.
    """
    buffer = bytearray()
    while HEADER_TERMINATOR not in buffer:
        chunk = read(1)
        if not chunk:
            raise PeerClosedEarly("proxy closed the connection during the CONNECT response")
        buffer += chunk
        if len(buffer) > 64 * 1024:
            raise ProtocolViolation("HTTP response header block exceeded 64 KiB")
    return bytes(buffer)


# --- SOCKS5 (RFC 1928) ------------------------------------------------------

SOCKS5_VERSION = 0x05

AUTH_NONE = 0x00
AUTH_GSSAPI = 0x01
AUTH_USERNAME_PASSWORD = 0x02
AUTH_NO_ACCEPTABLE = 0xFF

CMD_CONNECT = 0x01
CMD_BIND = 0x02
CMD_UDP_ASSOCIATE = 0x03

ATYP_IPV4 = 0x01
ATYP_DOMAINNAME = 0x03
ATYP_IPV6 = 0x04

# RFC 1928 §6, field REP.
SOCKS5_REPLY_MESSAGES: dict[int, str] = {
    0x00: "succeeded",
    0x01: "general SOCKS server failure",
    0x02: "connection not allowed by ruleset",
    0x03: "network unreachable",
    0x04: "host unreachable",
    0x05: "connection refused",
    0x06: "TTL expired",
    0x07: "command not supported",
    0x08: "address type not supported",
}

# RFC 1929 username/password subnegotiation uses its own version byte.
AUTH_SUBNEGOTIATION_VERSION = 0x01


@dataclass(frozen=True)
class Socks5Reply:
    reply_code: int
    bound_host: str
    bound_port: int

    @property
    def succeeded(self) -> bool:
        return self.reply_code == 0x00

    @property
    def message(self) -> str:
        return SOCKS5_REPLY_MESSAGES.get(self.reply_code, f"unassigned reply code 0x{self.reply_code:02x}")


def build_socks5_greeting(methods: list[int]) -> bytes:
    """VER, NMETHODS, METHODS... (RFC 1928 §3)."""
    if not 1 <= len(methods) <= 255:
        raise ConfigurationError("SOCKS5 greeting needs between 1 and 255 methods")
    return bytes([SOCKS5_VERSION, len(methods), *methods])


def parse_socks5_method_selection(raw: bytes) -> int:
    """VER, METHOD (RFC 1928 §3). Returns the selected method."""
    if len(raw) != 2:
        raise ProtocolViolation(f"SOCKS5 method selection must be 2 bytes, got {len(raw)}")
    version, method = raw[0], raw[1]
    if version != SOCKS5_VERSION:
        raise ProtocolViolation(f"expected SOCKS version 0x05, got 0x{version:02x}")
    return method


def encode_socks5_address(host: str, port: int) -> bytes:
    """ATYP + DST.ADDR + DST.PORT (RFC 1928 §4).

    Port is 2 bytes in network byte order; a domain name is length-prefixed.
    """
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        encoded = host.encode("idna") if not host.isascii() else host.encode("ascii")
        if not 1 <= len(encoded) <= 255:
            raise ConfigurationError("SOCKS5 domain names must be 1-255 bytes") from None
        head = bytes([ATYP_DOMAINNAME, len(encoded)]) + encoded
    else:
        if address.version == 4:
            head = bytes([ATYP_IPV4]) + address.packed
        else:
            head = bytes([ATYP_IPV6]) + address.packed
    return head + port.to_bytes(2, "big")


def build_socks5_request(host: str, port: int, command: int = CMD_CONNECT) -> bytes:
    """VER, CMD, RSV(0x00), ATYP, DST.ADDR, DST.PORT (RFC 1928 §4)."""
    return bytes([SOCKS5_VERSION, command, 0x00]) + encode_socks5_address(host, port)


def build_socks5_userpass_auth(username: str, password: str) -> bytes:
    """VER(0x01), ULEN, UNAME, PLEN, PASSWD (RFC 1929 §2).

    Note the version byte is the subnegotiation version 0x01, not 0x05.
    """
    user = username.encode("utf-8")
    secret = password.encode("utf-8")
    if not 1 <= len(user) <= 255 or not 1 <= len(secret) <= 255:
        raise ConfigurationError("SOCKS5 username and password must each be 1-255 bytes")
    return (
        bytes([AUTH_SUBNEGOTIATION_VERSION, len(user)])
        + user
        + bytes([len(secret)])
        + secret
    )


def parse_socks5_userpass_result(raw: bytes) -> bool:
    """VER, STATUS — status 0x00 means success (RFC 1929 §2)."""
    if len(raw) != 2:
        raise ProtocolViolation(f"SOCKS5 auth result must be 2 bytes, got {len(raw)}")
    return raw[1] == 0x00


def read_socks5_reply(read: Reader) -> Socks5Reply:
    """Read VER, REP, RSV, ATYP, BND.ADDR, BND.PORT (RFC 1928 §6).

    The bound-address length depends on ATYP, so the reply is read
    incrementally rather than as a fixed-size block.
    """
    header = read(4)
    if len(header) != 4:
        raise PeerClosedEarly("short SOCKS5 reply header")
    version, reply_code, _reserved, atyp = header
    if version != SOCKS5_VERSION:
        raise ProtocolViolation(f"expected SOCKS version 0x05 in reply, got 0x{version:02x}")

    if atyp == ATYP_IPV4:
        host = str(ipaddress.IPv4Address(read(4)))
    elif atyp == ATYP_IPV6:
        host = str(ipaddress.IPv6Address(read(16)))
    elif atyp == ATYP_DOMAINNAME:
        # `read` is contracted to raise on a short read, but a reader that
        # returns b"" instead would make this an IndexError no caller expects.
        raw_length = read(1)
        if not raw_length:
            raise PeerClosedEarly("proxy closed before the SOCKS5 domain length byte")
        host = read(raw_length[0]).decode("ascii", errors="replace")
    else:
        raise ProtocolViolation(f"unknown SOCKS5 address type 0x{atyp:02x}")

    port = int.from_bytes(read(2), "big")
    return Socks5Reply(reply_code=reply_code, bound_host=host, bound_port=port)
