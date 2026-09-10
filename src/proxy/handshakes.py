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

from src.errors import ProxyTunnelError
from src.proxy import tunnel
from src.proxy.config import ProxyConfig, ProxyMode

# Re-exported: raised by every handshake here and re-exported again by
# client.py, which is where callers reach for it. The class lives in
# src/errors.py so it shares the NetstackError base.
__all__ = [
    "ProxyTunnelError",
    "Socks5AuthFailure",
    "Socks5Result",
    "TunnelHandshake",
    "for_config",
]


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


# What a CONNECT refusal means, in the terms the operator has to act on.
# The SOCKS5 side already does this — tunnel.SOCKS5_REPLY_MESSAGES maps all
# nine RFC 1928 §6 reply codes — so a 407 read exactly like a 502 only
# because the HTTP side had no equivalent.
_CONNECT_HINTS = {
    403: "the proxy's ruleset forbids this origin",
    405: "the DUT does not implement the CONNECT method (RFC 9110 §9.3.6)",
    407: "the proxy requires authentication (RFC 9110 §11.7); no HTTP proxy "
         "credentials are configured",
    502: "the proxy could not reach the origin — is the backend instance running?",
    504: "the proxy timed out reaching the origin",
}


class HttpConnectHandshake:
    """RFC 9110 §9.3.6 / RFC 9112 CONNECT tunnel."""

    def establish(self, sock, read, origin) -> tunnel.HttpConnectResponse:
        host, port = origin
        sock.sendall(tunnel.build_http_connect_request(host, port))
        response = tunnel.parse_http_connect_response(tunnel.read_http_response_head(read))
        if not response.tunnel_established:
            hint = _CONNECT_HINTS.get(response.status)
            message = (
                f"CONNECT {tunnel.format_authority(host, port)} was refused: "
                f"{response.status} {response.reason}".strip()
            )
            raise ProxyTunnelError(f"{message} — {hint}" if hint else message, response)
        return response


@dataclass(frozen=True)
class Socks5Result:
    """What the DUT reported across the whole SOCKS5 exchange."""

    method: int
    reply: tunnel.Socks5Reply


@dataclass(frozen=True)
class Socks5AuthFailure:
    """What the DUT reported before the exchange got as far as a reply.

    The CONNECT-reply failures carry a Socks5Result, so `client.details`
    says what the DUT answered. The negotiation failures carried nothing,
    which left `details` as None — the same value TransparentHandshake
    produces on *success* — so an auth refusal could only be read out of the
    message string. `method` is the RFC 1928 §3 METHOD byte we actually saw.
    """

    method: int
    stage: str  # "method-selection" | "userpass"


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
                "SOCKS5 proxy rejected every offered authentication method (0xFF)",
                Socks5AuthFailure(method, "method-selection"),
            )
        if method == tunnel.AUTH_USERNAME_PASSWORD:
            if self.username is None or self.password is None:
                raise ProxyTunnelError(
                    "SOCKS5 proxy selected username/password auth but no "
                    "credentials were configured",
                    Socks5AuthFailure(method, "method-selection"),
                )
            sock.sendall(tunnel.build_socks5_userpass_auth(self.username, self.password))
            if not tunnel.parse_socks5_userpass_result(read(2)):
                raise ProxyTunnelError(
                    "SOCKS5 username/password authentication failed (RFC 1929)",
                    Socks5AuthFailure(method, "userpass"),
                )
        elif method != tunnel.AUTH_NONE:
            raise ProxyTunnelError(
                f"SOCKS5 proxy selected unsupported method 0x{method:02x}",
                Socks5AuthFailure(method, "method-selection"),
            )
        return method


def for_config(config: ProxyConfig) -> TunnelHandshake:
    """The handshake this run's mode requires."""
    return _BUILDERS[config.mode](config)


_BUILDERS = {
    ProxyMode.TRANSPARENT: lambda cfg: TransparentHandshake(),
    ProxyMode.HTTP_CONNECT: lambda cfg: HttpConnectHandshake(),
    ProxyMode.SOCKS5: lambda cfg: Socks5Handshake(cfg.username, cfg.password),
}
