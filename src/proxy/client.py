"""Proxy client — the *client instance* in a proxy test.

Opens a connection through the DUT to the origin (the backend instance),
performing whichever in-band handshake the mode requires, then exposes the
relay operations the tests assert on: byte-fidelity round-trips and
half-close propagation.

The handshakes themselves live in `handshakes.py`, one strategy per mode,
so this class is only the socket lifecycle and the relay operations.

Uses ordinary OS sockets for the same reason as `backend.py`: the DUT
terminates TCP on both legs, so what matters here is being a correct peer
and checking what comes back — not crafting packets.
"""
from __future__ import annotations

import socket

from src.proxy import handshakes
from src.proxy.config import RECV_CHUNK, ProxyConfig

# Re-exported: every caller reaches for it as src.proxy.client.ProxyTunnelError,
# and it is raised by the handshakes this module drives.
ProxyTunnelError = handshakes.ProxyTunnelError


class ProxyClient:
    """A connection to the origin *through* the proxy DUT."""

    def __init__(self, config: ProxyConfig) -> None:
        self.config = config
        # What the DUT reported while establishing the tunnel, typed by the
        # mode's handshake: None (transparent), an HttpConnectResponse, or a
        # Socks5Result. Populated on failure too, from the raised error, so
        # the "refused correctly" assertions have something to read.
        self.details: object = None
        self._sock: socket.socket | None = None

    # --- connection lifecycle ----------------------------------------------

    def connect(self) -> "ProxyClient":
        host, port = self.config.dial_target
        self._sock = socket.create_connection((host, port), timeout=self.config.timeout)
        self._sock.settimeout(self.config.timeout)
        handshake = handshakes.for_config(self.config)
        try:
            self.details = handshake.establish(
                self._sock, self._recv_exact, self.config.origin
            )
        except BaseException as exc:
            # `connect()` IS `__enter__`, so raising here means `__exit__`
            # never runs and this is the only place the socket can be
            # released. A refused tunnel is the *expected* outcome for the
            # refusal-conformance tests, and TrafficInducer reconnects every
            # 250ms for a whole session — so leaking one socket per refusal
            # exhausted the fd limit on exactly the runs that need to work.
            #
            # Catching BaseException, not ProxyTunnelError: a ConnectionError
            # or a protocol ValueError from tunnel.py leaks the same socket,
            # and so does a KeyboardInterrupt mid-handshake.
            self.details = getattr(exc, "details", None)
            self.close()
            raise
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
