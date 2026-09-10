"""Tunnel-establishment strategies, one per proxy mode.

`ProxyClient.connect()` used to branch on `ProxyMode` and dispatch to two
private methods of 47 combined lines, and carried a `TunnelDetails` record
whose three fields each belonged to exactly one mode and were `None` for
the others — a union type pretending to be a record, with no type-level
hint that `socks_reply` is meaningful only under SOCKS5.

Each mode is now an object that establishes the tunnel and returns *its
own* result. A fourth mode (SOCKS4, a vendor CONNECT variant) is a new
class plus a HANDSHAKES entry, with no edit to ProxyClient.

The strategies stay thin because `tunnel.py` already did the hard part:
the wire formats are pure functions over bytes and a `read(n)` callable,
verifiable against the RFCs without a socket.
"""
from __future__ import annotations

import socket
from dataclasses import dataclass
from typing import Protocol

from src.proxy import tunnel
from src.proxy.config import ProxyConfig, ProxyMode


class ProxyTunnelError(RuntimeError):
    """The DUT refused or mishandled the tunnel-establishment handshake.

    `details` carries whatever the DUT managed to report before the
    failure (an HTTP error response, a non-zero SOCKS5 reply), or None
    when it said nothing. The conformance tests assert on it: "refused
    with a defined error code" is a pass, "reported success" is not.
    """

    def __init__(self, message: str, details: object = None) -> None:
        super().__init__(message)
        self.details = details


class TunnelHandshake(Protocol):
    """Establishes a tunnel over an already-connected socket.

    Returns whatever the DUT reported, so tests can assert on the
    RFC-specified fields rather than merely on success. Raises
    ProxyTunnelError when the DUT refuses or mishandles the exchange.
    """

    def establish(
        self, sock: socket.socket, read: tunnel.Reader, origin: tuple[str, int]
    ) -> object: ...


class TransparentHandshake:
    """No in-band negotiation — the DUT is inline and intercepts (RFC 9293
    only). There is nothing for the DUT to report, hence no result."""

    def establish(self, sock, read, origin) -> None:
        return None


class HttpConnectHandshake:
    """RFC 9110 §9.3.6 / RFC 9112 CONNECT tunnel."""

    def establish(self, sock, read, origin) -> tunnel.HttpConnectResponse:
        host, port = origin
        sock.sendall(tunnel.build_http_connect_request(host, port))
        response = tunnel.parse_http_connect_response(tunnel.read_http_response_head(read))
        if not response.tunnel_established:
            raise ProxyTunnelError(
                f"CONNECT {tunnel.format_authority(host, port)} was refused: "
                f"{response.status} {response.reason}".strip(),
                response,
            )
        return response


@dataclass(frozen=True)
class Socks5Result:
    """What the DUT reported across the whole SOCKS5 exchange."""

    method: int
    reply: tunnel.Socks5Reply


@dataclass
class Socks5Handshake:
    """RFC 1928 greeting → method selection → CONNECT → reply, with
    optional RFC 1929 username/password subnegotiation."""

    username: str | None = None
    password: str | None = None

    def establish(self, sock, read, origin) -> Socks5Result:
        method = self._negotiate(sock, read)

        host, port = origin
        sock.sendall(tunnel.build_socks5_request(host, port, tunnel.CMD_CONNECT))
        reply = tunnel.read_socks5_reply(read)
        if not reply.succeeded:
            raise ProxyTunnelError(
                f"SOCKS5 CONNECT to {host}:{port} failed: "
                f"0x{reply.reply_code:02x} ({reply.message})",
                Socks5Result(method, reply),
            )
        return Socks5Result(method, reply)

    def _negotiate(self, sock, read) -> int:
        """Greeting and method selection (RFC 1928 §3), plus RFC 1929 auth
        when the DUT selects it. Returns the selected method."""
        methods = [tunnel.AUTH_NONE]
        if self.username is not None:
            methods.append(tunnel.AUTH_USERNAME_PASSWORD)
        sock.sendall(tunnel.build_socks5_greeting(methods))

        method = tunnel.parse_socks5_method_selection(read(2))
        if method == tunnel.AUTH_NO_ACCEPTABLE:
            raise ProxyTunnelError(
                "SOCKS5 proxy rejected every offered authentication method (0xFF)"
            )
        if method == tunnel.AUTH_USERNAME_PASSWORD:
            if self.username is None or self.password is None:
                raise ProxyTunnelError(
                    "SOCKS5 proxy selected username/password auth but no "
                    "credentials were configured"
                )
            sock.sendall(tunnel.build_socks5_userpass_auth(self.username, self.password))
            if not tunnel.parse_socks5_userpass_result(read(2)):
                raise ProxyTunnelError(
                    "SOCKS5 username/password authentication failed (RFC 1929)"
                )
        elif method != tunnel.AUTH_NONE:
            raise ProxyTunnelError(f"SOCKS5 proxy selected unsupported method 0x{method:02x}")
        return method


def for_config(config: ProxyConfig) -> TunnelHandshake:
    """The handshake this run's mode requires."""
    return _BUILDERS[config.mode](config)


_BUILDERS = {
    ProxyMode.TRANSPARENT: lambda cfg: TransparentHandshake(),
    ProxyMode.HTTP_CONNECT: lambda cfg: HttpConnectHandshake(),
    ProxyMode.SOCKS5: lambda cfg: Socks5Handshake(cfg.username, cfg.password),
}
