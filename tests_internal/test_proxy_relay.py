"""End-to-end self-validation of the proxy testing machinery.

Runs the real `EchoBackend` (the server instance) and the real
`ProxyClient` (the client instance) against a minimal in-process **stub
proxy** that stands in for the DUT. That exercises the same code path the
DUT-facing tests use — tunnel handshake, byte relay, half-close
propagation — with no hardware, no privileges, and no real proxy.

The stub proxy is deliberately conformant (RFC 1928 / RFC 9110 §9.3.6), so
a failure here means the *harness* is wrong, not the DUT.
"""
from __future__ import annotations

import socket
import threading

import pytest

from src.errors import ProtocolViolation
from src.proxy import tunnel
from src.proxy.backend import EchoBackend
from src.proxy.client import ProxyClient, ProxyTunnelError
from src.proxy.config import RECV_CHUNK, ProxyConfig, ProxyMode

pytestmark = [pytest.mark.internal]

LOOPBACK = "127.0.0.1"


class StubProxy:
    """A minimal conformant proxy: negotiates, dials the origin, relays.

    `fail_mode` makes it refuse the tunnel so the client's error handling
    can be tested (SOCKS5 reply 0x05, HTTP 403).
    """

    def __init__(self, mode: ProxyMode, *, fail: bool = False) -> None:
        self.mode = mode
        self.fail = fail
        self._stop = threading.Event()
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((LOOPBACK, 0))
        self._sock.listen(8)
        self._sock.settimeout(0.5)
        self.port: int = self._sock.getsockname()[1]
        self._threads: list[threading.Thread] = []
        self._accept_thread = threading.Thread(target=self._accept_loop, daemon=True)

    def __enter__(self) -> "StubProxy":
        self._accept_thread.start()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass
        self._accept_thread.join(timeout=2)
        for thread in self._threads:
            thread.join(timeout=2)

    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except (socket.timeout, OSError):
                if self._stop.is_set():
                    return
                continue
            thread = threading.Thread(target=self._handle, args=(conn,), daemon=True)
            thread.start()
            self._threads.append(thread)

    def _handle(self, conn: socket.socket) -> None:
        try:
            target = (
                self._negotiate_http(conn)
                if self.mode is ProxyMode.HTTP_CONNECT
                else self._negotiate_socks5(conn)
            )
            if target is None:
                conn.close()
                return
            upstream = socket.create_connection(target, timeout=5)
        except OSError:
            conn.close()
            return
        # Relay both directions, propagating half-close each way.
        threads = [
            threading.Thread(target=self._pump, args=(conn, upstream), daemon=True),
            threading.Thread(target=self._pump, args=(upstream, conn), daemon=True),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        conn.close()
        upstream.close()

    @staticmethod
    def _pump(src: socket.socket, dst: socket.socket) -> None:
        try:
            while True:
                data = src.recv(65536)
                if not data:
                    try:
                        dst.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
                    return
                dst.sendall(data)
        except OSError:
            return

    def _negotiate_http(self, conn: socket.socket) -> tuple[str, int] | None:
        buffer = bytearray()
        while tunnel.HEADER_TERMINATOR not in buffer:
            chunk = conn.recv(1)
            if not chunk:
                return None
            buffer += chunk
        request_line = bytes(buffer).split(tunnel.CRLF, 1)[0].decode()
        method, authority, _version = request_line.split(" ", 2)
        assert method == "CONNECT", f"stub proxy expected CONNECT, got {method}"
        if self.fail:
            conn.sendall(b"HTTP/1.1 403 Forbidden\r\n\r\n")
            return None
        host, _, port = authority.rpartition(":")
        conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        return host.strip("[]"), int(port)

    def _negotiate_socks5(self, conn: socket.socket) -> tuple[str, int] | None:
        header = conn.recv(2)
        if len(header) < 2:
            return None
        conn.recv(header[1])  # the offered methods
        conn.sendall(bytes([tunnel.SOCKS5_VERSION, tunnel.AUTH_NONE]))

        request = conn.recv(4)
        if len(request) < 4:
            return None
        atyp = request[3]
        if atyp == tunnel.ATYP_IPV4:
            host = socket.inet_ntoa(conn.recv(4))
        elif atyp == tunnel.ATYP_DOMAINNAME:
            host = conn.recv(conn.recv(1)[0]).decode()
        else:
            host = socket.inet_ntop(socket.AF_INET6, conn.recv(16))
        port = int.from_bytes(conn.recv(2), "big")

        if self.fail:
            conn.sendall(b"\x05\x05\x00\x01" + b"\x00\x00\x00\x00" + b"\x00\x00")
            return None
        conn.sendall(b"\x05\x00\x00\x01" + b"\x00\x00\x00\x00" + b"\x00\x00")
        return host, port


@pytest.fixture
def backend():
    with EchoBackend(LOOPBACK, 0) as running:
        yield running


def _config(backend, mode: ProxyMode, proxy_port: int | None = None) -> ProxyConfig:
    return ProxyConfig(
        mode=mode,
        backend_host=LOOPBACK,
        backend_port=backend.bound_port,
        proxy_host=LOOPBACK if proxy_port else None,
        proxy_port=proxy_port,
        timeout=5.0,
    )


# --- backend + client, no proxy in between (validates the harness itself) ---


def test_transparent_roundtrip_echoes_payload(backend) -> None:
    with ProxyClient(_config(backend, ProxyMode.TRANSPARENT)) as client:
        assert client.roundtrip(b"netstack-probe") == b"netstack-probe"
    assert backend.stats.tcp_connections == 1
    assert backend.stats.tcp_bytes_echoed == len(b"netstack-probe")


def test_backend_records_the_peer_that_dialled_it(backend) -> None:
    with ProxyClient(_config(backend, ProxyMode.TRANSPARENT)) as client:
        client.roundtrip(b"x")
    assert backend.stats.peers and backend.stats.peers[0].startswith(LOOPBACK)


# --- through the stub proxy, per mode ---------------------------------------


@pytest.mark.parametrize("mode", [ProxyMode.HTTP_CONNECT, ProxyMode.SOCKS5])
def test_roundtrip_through_proxy(backend, mode: ProxyMode) -> None:
    """The headline flow: client → proxy → backend → proxy → client."""
    with StubProxy(mode) as proxy:
        with ProxyClient(_config(backend, mode, proxy.port)) as client:
            assert client.roundtrip(b"round-trip-payload") == b"round-trip-payload"
    assert backend.stats.tcp_connections == 1


@pytest.mark.parametrize("mode", [ProxyMode.HTTP_CONNECT, ProxyMode.SOCKS5])
def test_binary_payload_is_relayed_unchanged(backend, mode: ProxyMode) -> None:
    """8-bit clean: CR/LF, NULs and high bytes must survive the relay."""
    payload = bytes(range(256)) + b"\r\n\r\n\x00 CONNECT not-a-request"
    with StubProxy(mode) as proxy:
        with ProxyClient(_config(backend, mode, proxy.port)) as client:
            assert client.roundtrip(payload) == payload


@pytest.mark.parametrize("mode", [ProxyMode.HTTP_CONNECT, ProxyMode.SOCKS5])
def test_large_payload_spanning_many_segments(backend, mode: ProxyMode) -> None:
    payload = bytes(i % 251 for i in range(200_000))
    with StubProxy(mode) as proxy:
        with ProxyClient(_config(backend, mode, proxy.port)) as client:
            assert client.roundtrip(payload) == payload


@pytest.mark.parametrize("mode", [ProxyMode.HTTP_CONNECT, ProxyMode.SOCKS5])
def test_client_half_close_propagates_to_eof(backend, mode: ProxyMode) -> None:
    """RFC 9293 §3.6: our FIN must reach the backend, whose close comes back."""
    with StubProxy(mode) as proxy:
        with ProxyClient(_config(backend, mode, proxy.port)) as client:
            client.send(b"final")
            assert client.recv_exact(5) == b"final"
            client.half_close()
            assert client.read_until_eof() == b""  # clean EOF, no hang


class HangingOrigin:
    """Echoes once, then holds the connection open forever.

    The smallest form of the defect the half-close tests exist to find: a
    peer that never propagates the close. `read_until_eof` used to return
    b"" here — the same value a clean EOF produces — so the test asserting
    "we observed a clean EOF" passed on the hang.
    """

    def __init__(self) -> None:
        self._stop = threading.Event()
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((LOOPBACK, 0))
        self._sock.listen(1)
        self._sock.settimeout(0.5)
        self.port: int = self._sock.getsockname()[1]
        self._held: list[socket.socket] = []
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def __enter__(self) -> "HangingOrigin":
        self._thread.start()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self._stop.set()
        for conn in self._held:
            try:
                conn.close()
            except OSError:
                pass
        try:
            self._sock.close()
        except OSError:
            pass
        self._thread.join(timeout=2)

    def _serve(self) -> None:
        try:
            conn, _ = self._sock.accept()
        except OSError:
            return
        self._held.append(conn)
        try:
            data = conn.recv(RECV_CHUNK)
            if data:
                conn.sendall(data)
        except OSError:
            return
        self._stop.wait()  # never send FIN


def test_read_until_eof_raises_when_the_peer_never_closes() -> None:
    """A read timeout is the opposite verdict from EOF, so it must not
    return the same bytes: b"" means "the close was propagated"."""
    with HangingOrigin() as origin:
        config = ProxyConfig(
            mode=ProxyMode.TRANSPARENT,
            backend_host=LOOPBACK,
            backend_port=origin.port,
            timeout=0.5,
        )
        with ProxyClient(config) as client:
            assert client.roundtrip(b"last-write") == b"last-write"
            client.half_close()
            with pytest.raises(ProtocolViolation, match="did not propagate"):
                client.read_until_eof()


def test_tunnel_details_expose_rfc_fields(backend) -> None:
    with StubProxy(ProxyMode.SOCKS5) as proxy:
        with ProxyClient(_config(backend, ProxyMode.SOCKS5, proxy.port)) as client:
            assert client.details.method == tunnel.AUTH_NONE
            assert client.details.reply is not None
            assert client.details.reply.succeeded

    with StubProxy(ProxyMode.HTTP_CONNECT) as proxy:
        with ProxyClient(_config(backend, ProxyMode.HTTP_CONNECT, proxy.port)) as client:
            assert client.details is not None
            assert client.details.status == 200


# --- refusal paths ----------------------------------------------------------


def test_socks5_refusal_raises_with_rfc_reply_text(backend) -> None:
    with StubProxy(ProxyMode.SOCKS5, fail=True) as proxy:
        with pytest.raises(ProxyTunnelError, match="connection refused"):
            ProxyClient(_config(backend, ProxyMode.SOCKS5, proxy.port)).connect()


def test_http_connect_refusal_raises_with_status(backend) -> None:
    with StubProxy(ProxyMode.HTTP_CONNECT, fail=True) as proxy:
        with pytest.raises(ProxyTunnelError, match="403"):
            ProxyClient(_config(backend, ProxyMode.HTTP_CONNECT, proxy.port)).connect()


@pytest.mark.parametrize(
    ("mode", "match"),
    [(ProxyMode.SOCKS5, "connection refused"), (ProxyMode.HTTP_CONNECT, "403")],
)
def test_a_refused_tunnel_releases_the_socket(backend, mode, match) -> None:
    """A refusal is the expected outcome for the conformance tests, and
    TrafficInducer reconnects every 250ms for a whole session — so a socket
    leaked per refusal exhausted the fd limit on exactly the runs that have
    to work. `connect()` IS `__enter__`, so a raise there means `__exit__`
    never runs and connect() itself has to close.
    """
    with StubProxy(mode, fail=True) as proxy:
        client = ProxyClient(_config(backend, mode, proxy.port))
        with pytest.raises(ProxyTunnelError, match=match):
            client.connect()

        with pytest.raises(RuntimeError, match="not connected"):
            client.socket  # noqa: B018 - the property is the assertion


def test_a_refused_tunnel_still_records_what_the_dut_reported(backend) -> None:
    """Closing the socket must not cost the details the refusal-conformance
    assertions read."""
    with StubProxy(ProxyMode.HTTP_CONNECT, fail=True) as proxy:
        client = ProxyClient(_config(backend, ProxyMode.HTTP_CONNECT, proxy.port))
        with pytest.raises(ProxyTunnelError):
            client.connect()

        assert client.details is not None
        assert client.details.status == 403


def test_a_non_tunnel_error_also_releases_the_socket(backend, monkeypatch) -> None:
    """The old handler caught only ProxyTunnelError, so a ConnectionError or
    a protocol ValueError from tunnel.py leaked the socket identically."""
    from src.proxy import handshakes

    class _Exploding:
        def establish(self, sock, read, origin):
            raise ConnectionError("proxy closed mid-handshake")

    monkeypatch.setattr(handshakes, "for_config", lambda cfg: _Exploding())

    with StubProxy(ProxyMode.SOCKS5) as proxy:
        client = ProxyClient(_config(backend, ProxyMode.SOCKS5, proxy.port))
        with pytest.raises(ConnectionError):
            client.connect()

        assert client.details is None
        with pytest.raises(RuntimeError, match="not connected"):
            client.socket  # noqa: B018 - the property is the assertion


def test_explicit_mode_requires_a_front_address(backend) -> None:
    """A ConfigurationError, so any caller can render it through the
    boundary. It used to be a bare ValueError, which worked only because
    the one caller — the proxy_config fixture — knew to catch that type."""
    from src.errors import ConfigurationError, NetstackError

    with pytest.raises(ConfigurationError, match="explicit proxy mode") as caught:
        ProxyConfig(mode=ProxyMode.SOCKS5, backend_host=LOOPBACK, backend_port=1)

    assert isinstance(caught.value, NetstackError)


def test_a_handshake_exists_for_every_proxy_mode() -> None:
    """The strategy table must cover ProxyMode exactly.

    A mode added to the enum but not here raises KeyError at connect time —
    after the socket is open, against a real DUT.
    """
    from src.proxy import handshakes

    assert set(handshakes._BUILDERS) == set(ProxyMode)


def test_every_mode_builds_a_handshake_that_can_establish(backend) -> None:
    from src.proxy import handshakes

    for mode in ProxyMode:
        handshake = handshakes.for_config(_config(backend, mode, backend.bound_port))
        assert callable(getattr(handshake, "establish", None)), mode


def test_transparent_mode_reports_no_tunnel_details(backend) -> None:
    """There is no in-band negotiation to report, so `details` is None
    rather than a record of three empty optionals."""
    with ProxyClient(_config(backend, ProxyMode.TRANSPARENT, backend.bound_port)) as client:
        assert client.details is None
        assert client.roundtrip(b"inline") == b"inline"


# --- Backend start is all-or-nothing ----------------------------------------


def test_a_failed_udp_bind_leaves_no_tcp_listener_behind() -> None:
    """start() used to bind TCP, spawn its accept loop, and only then bind
    UDP — so a UDP bind failure left a live listener with a running thread
    that the caller never got a reference to. Only process exit could
    reclaim the port.
    """
    import socket as socket_module
    import threading

    # Hold the UDP side of an ephemeral port so the backend's UDP bind fails
    # after its TCP bind has already succeeded.
    squatter = socket_module.socket(socket_module.AF_INET, socket_module.SOCK_DGRAM)
    squatter.bind((LOOPBACK, 0))
    port = squatter.getsockname()[1]

    before = threading.active_count()
    backend = EchoBackend(LOOPBACK, port, enable_udp=True)
    try:
        with pytest.raises(OSError):
            backend.start()

        # The TCP port must be free: binding it again is the proof.
        probe = socket_module.socket(socket_module.AF_INET, socket_module.SOCK_STREAM)
        try:
            probe.bind((LOOPBACK, port))
        finally:
            probe.close()

        assert threading.active_count() == before, "an accept loop outlived the failed start"
    finally:
        backend.stop()
        squatter.close()


def test_a_backend_can_be_restarted_after_stop() -> None:
    """stop() latches the _stop event the serving loops read, so start()
    has to clear it or a restarted backend accepts nothing."""
    backend = EchoBackend(LOOPBACK, 0)
    backend.start()
    first_port = backend.bound_port
    backend.stop()

    backend.start()
    try:
        with socket.create_connection((LOOPBACK, backend.bound_port), timeout=2.0) as conn:
            conn.sendall(b"restarted")
            assert conn.recv(64) == b"restarted"
    finally:
        backend.stop()

    assert first_port  # the first bind really did happen
