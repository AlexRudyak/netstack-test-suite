"""Echo backend — the *server instance* in a proxy test.

Stands in as the origin server the proxy DUT dials out to. Everything the
proxy relays is echoed straight back, which is what lets the client
instance verify end-to-end fidelity without any side channel between the
two instances.

This deliberately uses ordinary OS sockets rather than the suite's raw L2
engine: the DUT *terminates* TCP on this leg, so the backend's job is to be
a correct, well-behaved TCP peer (RFC 9293) for the proxy to connect to —
not to craft packets. Packet-level conformance of the proxy's front leg is
covered separately by the raw-scapy tests.

Closing semantics matter for the lifecycle tests: when the peer half-closes
(FIN), the backend drains, echoes what it has, and closes its own side, so
a conformant proxy propagates the shutdown to the other leg (RFC 9293 §3.6).
"""
from __future__ import annotations

import socket
import threading
from collections.abc import Callable
from dataclasses import dataclass, field

from src.proxy.config import DEFAULT_BACKEND_PORT

RECV_CHUNK = 65536


@dataclass
class BackendStats:
    """Observable proof that the DUT's *client* side did its job."""

    tcp_connections: int = 0
    tcp_bytes_received: int = 0
    tcp_bytes_echoed: int = 0
    udp_datagrams: int = 0
    udp_bytes_received: int = 0
    peers: list[str] = field(default_factory=list)

    def summary(self) -> str:
        return (
            f"TCP: {self.tcp_connections} conn, {self.tcp_bytes_received} B in / "
            f"{self.tcp_bytes_echoed} B echoed | UDP: {self.udp_datagrams} dgram, "
            f"{self.udp_bytes_received} B"
        )


class EchoBackend:
    """Threaded TCP (and optionally UDP) echo server.

    Usable as a context manager, and safe to bind on port 0 for an
    ephemeral port (the self-tests rely on that).
    """

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = DEFAULT_BACKEND_PORT,
        *,
        enable_udp: bool = False,
        on_event: Callable[[str], None] | None = None,
    ) -> None:
        self.host = host
        self.port = port
        self.enable_udp = enable_udp
        self._on_event = on_event
        self._stats = BackendStats()
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self._tcp_socket: socket.socket | None = None
        self._udp_socket: socket.socket | None = None
        self._bound_port: int | None = None

    # --- lifecycle ---------------------------------------------------------

    @property
    def stats(self) -> BackendStats:
        with self._lock:
            return BackendStats(
                tcp_connections=self._stats.tcp_connections,
                tcp_bytes_received=self._stats.tcp_bytes_received,
                tcp_bytes_echoed=self._stats.tcp_bytes_echoed,
                udp_datagrams=self._stats.udp_datagrams,
                udp_bytes_received=self._stats.udp_bytes_received,
                peers=list(self._stats.peers),
            )

    @property
    def bound_port(self) -> int:
        """The actual listening port (resolves port 0 to what the OS chose)."""
        return self._bound_port if self._bound_port is not None else self.port

    def _emit(self, message: str) -> None:
        if self._on_event is not None:
            self._on_event(message)

    def start(self) -> None:
        self._tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._tcp_socket.bind((self.host, self.port))
        self._bound_port = self._tcp_socket.getsockname()[1]
        self._tcp_socket.listen(64)
        self._tcp_socket.settimeout(0.5)  # so the accept loop can observe _stop
        self._spawn(self._accept_loop, "echo-backend-tcp")
        self._emit(f"TCP echo backend listening on {self.host}:{self.bound_port}")

        if self.enable_udp:
            self._udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._udp_socket.bind((self.host, self.bound_port))
            self._udp_socket.settimeout(0.5)
            self._spawn(self._udp_loop, "echo-backend-udp")
            self._emit(f"UDP echo backend listening on {self.host}:{self.bound_port}")

    def stop(self) -> None:
        self._stop.set()
        for sock in (self._tcp_socket, self._udp_socket):
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
        self._tcp_socket = self._udp_socket = None
        for thread in self._threads:
            thread.join(timeout=2.0)
        self._threads.clear()
        self._emit("echo backend stopped")

    def _spawn(self, target: Callable[[], None], name: str) -> None:
        thread = threading.Thread(target=target, name=name, daemon=True)
        thread.start()
        self._threads.append(thread)

    def __enter__(self) -> "EchoBackend":
        self.start()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.stop()

    # --- serving -----------------------------------------------------------

    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            sock = self._tcp_socket
            if sock is None:
                return
            try:
                conn, peer = sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return  # socket closed by stop()
            with self._lock:
                self._stats.tcp_connections += 1
                self._stats.peers.append(f"{peer[0]}:{peer[1]}")
            self._emit(f"TCP connection from {peer[0]}:{peer[1]} (the DUT's client side)")
            self._spawn(lambda c=conn: self._handle_tcp(c), "echo-backend-conn")

    def _handle_tcp(self, conn: socket.socket) -> None:
        with conn:
            conn.settimeout(0.5)
            while not self._stop.is_set():
                try:
                    data = conn.recv(RECV_CHUNK)
                except socket.timeout:
                    continue
                except OSError:
                    return
                if not data:
                    # Peer half-closed: mirror the shutdown so a conformant
                    # proxy propagates it to the other leg (RFC 9293 §3.6).
                    try:
                        conn.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
                    return
                with self._lock:
                    self._stats.tcp_bytes_received += len(data)
                try:
                    conn.sendall(data)
                except OSError:
                    return
                with self._lock:
                    self._stats.tcp_bytes_echoed += len(data)

    def _udp_loop(self) -> None:
        while not self._stop.is_set():
            sock = self._udp_socket
            if sock is None:
                return
            try:
                data, peer = sock.recvfrom(RECV_CHUNK)
            except socket.timeout:
                continue
            except OSError:
                return
            with self._lock:
                self._stats.udp_datagrams += 1
                self._stats.udp_bytes_received += len(data)
            try:
                sock.sendto(data, peer)
            except OSError:
                return
