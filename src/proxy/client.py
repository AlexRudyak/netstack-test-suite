"""Proxy client — the *client instance* in a proxy test.

Opens a connection through the DUT to the origin (the backend instance),
performing whichever in-band handshake the mode requires, then exposes the
relay operations the tests assert on: byte-fidelity round-trips and
half-close propagation.

Uses ordinary OS sockets for the same reason as `backend.py`: the DUT
terminates TCP on both legs, so what matters here is being a correct peer
and checking what comes back — not crafting packets.
"""
from __future__ import annotations

import socket
from dataclasses import dataclass

from src.proxy import tunnel
from src.proxy.backend import RECV_CHUNK
from src.proxy.config import ProxyConfig, ProxyMode


class ProxyTunnelError(RuntimeError):
    """The DUT refused or mishandled the tunnel-establishment handshake."""


@dataclass
class TunnelDetails:
    """What the DUT reported while establishing the tunnel — kept so tests
    can assert on the RFC-specified fields rather than just success."""

    http_response: tunnel.HttpConnectResponse | None = None
    socks_method: int | None = None
    socks_reply: tunnel.Socks5Reply | None = None


class ProxyClient:
    """A connection to the origin *through* the proxy DUT."""

    def __init__(self, config: ProxyConfig) -> None:
        self.config = config
        self.details = TunnelDetails()
        self._sock: socket.socket | None = None

    # --- connection lifecycle ----------------------------------------------

    def connect(self) -> "ProxyClient":
        host, port = self.config.dial_target
        self._sock = socket.create_connection((host, port), timeout=self.config.timeout)
        self._sock.settimeout(self.config.timeout)
        if self.config.mode is ProxyMode.HTTP_CONNECT:
            self._http_connect()
        elif self.config.mode is ProxyMode.SOCKS5:
            self._socks5_connect()
        return self

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            finally:
                self._sock = None

    def __enter__(self) -> "ProxyClient":
        return self.connect()

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    @property
    def socket(self) -> socket.socket:
        if self._sock is None:
            raise RuntimeError("ProxyClient is not connected; call connect() first")
        return self._sock

    # --- handshakes ---------------------------------------------------------

    def _http_connect(self) -> None:
        """RFC 9110 §9.3.6 / RFC 9112 CONNECT tunnel."""
        host, port = self.config.origin
        self.socket.sendall(tunnel.build_http_connect_request(host, port))
        raw = tunnel.read_http_response_head(self._recv_exact)
        response = tunnel.parse_http_connect_response(raw)
        self.details.http_response = response
        if not response.tunnel_established:
            raise ProxyTunnelError(
                f"CONNECT {tunnel.format_authority(host, port)} was refused: "
                f"{response.status} {response.reason}".strip()
            )

    def _socks5_connect(self) -> None:
        """RFC 1928 greeting → method selection → CONNECT → reply."""
        methods = [tunnel.AUTH_NONE]
        if self.config.username is not None:
            methods.append(tunnel.AUTH_USERNAME_PASSWORD)
        self.socket.sendall(tunnel.build_socks5_greeting(methods))

        method = tunnel.parse_socks5_method_selection(self._recv_exact(2))
        self.details.socks_method = method
        if method == tunnel.AUTH_NO_ACCEPTABLE:
            raise ProxyTunnelError(
                "SOCKS5 proxy rejected every offered authentication method (0xFF)"
            )
        if method == tunnel.AUTH_USERNAME_PASSWORD:
            if self.config.username is None or self.config.password is None:
                raise ProxyTunnelError(
                    "SOCKS5 proxy selected username/password auth but no credentials were configured"
                )
            self.socket.sendall(
                tunnel.build_socks5_userpass_auth(self.config.username, self.config.password)
            )
            if not tunnel.parse_socks5_userpass_result(self._recv_exact(2)):
                raise ProxyTunnelError("SOCKS5 username/password authentication failed (RFC 1929)")
        elif method != tunnel.AUTH_NONE:
            raise ProxyTunnelError(f"SOCKS5 proxy selected unsupported method 0x{method:02x}")

        host, port = self.config.origin
        self.socket.sendall(tunnel.build_socks5_request(host, port, tunnel.CMD_CONNECT))
        reply = tunnel.read_socks5_reply(self._recv_exact)
        self.details.socks_reply = reply
        if not reply.succeeded:
            raise ProxyTunnelError(
                f"SOCKS5 CONNECT to {host}:{port} failed: "
                f"0x{reply.reply_code:02x} ({reply.message})"
            )

    # --- relay operations ---------------------------------------------------

    def _recv_exact(self, count: int) -> bytes:
        buffer = bytearray()
        while len(buffer) < count:
            chunk = self.socket.recv(count - len(buffer))
            if not chunk:
                raise ConnectionError(
                    f"connection closed after {len(buffer)} of {count} expected bytes"
                )
            buffer += chunk
        return bytes(buffer)

    def send(self, payload: bytes) -> None:
        self.socket.sendall(payload)

    def recv_exact(self, count: int) -> bytes:
        return self._recv_exact(count)

    def roundtrip(self, payload: bytes) -> bytes:
        """Send `payload` through the proxy and read back the same number of
        bytes the backend echoes. Equality proves both relay directions."""
        self.send(payload)
        return self._recv_exact(len(payload))

    def half_close(self) -> None:
        """Shut down our write side (send FIN) but keep reading, so the
        proxy's propagation of the half-close can be observed (RFC 9293 §3.6)."""
        self.socket.shutdown(socket.SHUT_WR)

    def read_until_eof(self, limit: int = 1 << 20) -> bytes:
        """Read until the peer closes. Returns everything received; an empty
        result means EOF arrived immediately."""
        buffer = bytearray()
        while len(buffer) < limit:
            try:
                chunk = self.socket.recv(RECV_CHUNK)
            except socket.timeout:
                break
            if not chunk:
                break
            buffer += chunk
        return bytes(buffer)
