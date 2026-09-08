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

from src.proxy import tunnel
from src.proxy.backend import EchoBackend
from src.proxy.client import ProxyClient, ProxyTunnelError
from src.proxy.config import ProxyConfig, ProxyMode

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


def test_tunnel_details_expose_rfc_fields(backend) -> None:
    with StubProxy(ProxyMode.SOCKS5) as proxy:
        with ProxyClient(_config(backend, ProxyMode.SOCKS5, proxy.port)) as client:
            assert client.details.socks_method == tunnel.AUTH_NONE
            assert client.details.socks_reply is not None
            assert client.details.socks_reply.succeeded

    with StubProxy(ProxyMode.HTTP_CONNECT) as proxy:
        with ProxyClient(_config(backend, ProxyMode.HTTP_CONNECT, proxy.port)) as client:
            assert client.details.http_response is not None
            assert client.details.http_response.status == 200


# --- refusal paths ----------------------------------------------------------


def test_socks5_refusal_raises_with_rfc_reply_text(backend) -> None:
    with StubProxy(ProxyMode.SOCKS5, fail=True) as proxy:
        with pytest.raises(ProxyTunnelError, match="connection refused"):
            ProxyClient(_config(backend, ProxyMode.SOCKS5, proxy.port)).connect()


def test_http_connect_refusal_raises_with_status(backend) -> None:
    with StubProxy(ProxyMode.HTTP_CONNECT, fail=True) as proxy:
        with pytest.raises(ProxyTunnelError, match="403"):
            ProxyClient(_config(backend, ProxyMode.HTTP_CONNECT, proxy.port)).connect()


def test_explicit_mode_requires_a_front_address(backend) -> None:
    with pytest.raises(ValueError, match="explicit proxy mode"):
        ProxyConfig(mode=ProxyMode.SOCKS5, backend_host=LOOPBACK, backend_port=1)
