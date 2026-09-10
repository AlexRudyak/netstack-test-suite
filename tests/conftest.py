"""Shared fixtures for the automated suite, built on top of the root
conftest.py fixtures (dut_config, target_profile, network_interface,
payload_settings, confirm_vuln_tests).
"""
from __future__ import annotations

import itertools
from collections.abc import Callable, Iterator
from dataclasses import dataclass

import pytest
from scapy.layers.inet import ICMP, IP
from scapy.packet import Packet, Raw

from src.config import DUTConfig, ProxyLeg, back_leg_requirement_error
from src.packet_engine.builders import build_tcp, build_udp, wrap_ethernet
from src.packet_engine.payloads import resolve_payload
from src.proxy.config import ProxyConfig, ProxyMode
from src.proxy.inducer import TrafficInducer


@pytest.fixture(scope="session", autouse=True)
def proxy_back_leg_traffic(pytestconfig: pytest.Config) -> Iterator[TrafficInducer | None]:
    """Keep a proxy DUT's back leg busy for the whole run.

    The server-role tests observe connections the DUT initiates. An endpoint
    DUT does that by itself; a proxy only dials its origin while a client is
    driving traffic through the front. So when the endpoint suites are aimed
    at a proxy's back leg, we run a background inducer for the session — the
    proxy then keeps opening outbound connections for those tests to observe.

    No-op for every other kind of run.
    """
    leg = pytestconfig.getoption("--proxy-leg")
    if leg != ProxyLeg.BACK.value:
        yield None
        return

    mode = pytestconfig.getoption("--proxy-mode")
    backend_host = pytestconfig.getoption("--backend-host")
    blocked = back_leg_requirement_error(ProxyLeg.BACK, proxy_mode=mode, backend_host=backend_host)
    if blocked:
        pytest.fail(blocked)

    config = ProxyConfig(
        mode=ProxyMode(mode),
        backend_host=backend_host,
        backend_port=pytestconfig.getoption("--backend-port"),
        proxy_host=pytestconfig.getoption("--proxy-host"),
        proxy_port=pytestconfig.getoption("--proxy-port"),
    )
    with TrafficInducer(config) as inducer:
        yield inducer
    # Reported once at teardown: if nothing was induced, every server-role
    # timeout in this run has the same root cause, and this line says so.
    print(f"\n[proxy-leg back] {inducer.summary()}")


# --- Local source ports -----------------------------------------------------
# One monotonic sequence for the whole session, so no two tests can ever
# share a 4-tuple with the DUT — which could still be holding the previous
# test's in TIME_WAIT, corrupting the next handshake. Starts in the IANA
# dynamic range, above the SYN-flood sweep in tests/tcp/syn/test_syn_flood.py,
# and wraps rather than running off the end of the 16-bit port space.
_SOURCE_PORT_BASE = 49152
_SOURCE_PORT_SPAN = 65535 - _SOURCE_PORT_BASE + 1
_source_port_counter = itertools.count()


def _next_source_port() -> int:
    return _SOURCE_PORT_BASE + next(_source_port_counter) % _SOURCE_PORT_SPAN


@pytest.fixture
def source_ports() -> Callable[[], int]:
    """Allocates a distinct local source port on each call.

    For tests that open several connections and need each to be its own
    4-tuple. A pinned --dut-source-port can only apply to one connection,
    so it is deliberately not honoured here — use `source_port` for the
    single-connection case.
    """
    return _next_source_port


@pytest.fixture
def source_port(dut_config: DUTConfig, source_ports: Callable[[], int]) -> int:
    """This test's local source port: the operator's --dut-source-port if
    one was pinned, otherwise a session-unique ephemeral port."""
    return dut_config.source_port or source_ports()


@pytest.fixture
def payload(payload_settings: dict) -> bytes:
    return resolve_payload(
        payload_settings["mode"], size=payload_settings["size"], custom=payload_settings["custom"]
    )


@pytest.fixture
def nodeid(request: pytest.FixtureRequest) -> str:
    """This test's real pytest node id, for packet attribution in the run's
    pcap and debug log.

    Always accurate under rename and parametrization — unlike the hand-typed
    literals it replaces, which nothing checked and which had already gone
    stale in places.
    """
    return request.node.nodeid


# --- Packet crafting --------------------------------------------------------


@dataclass(frozen=True)
class Craft:
    """This run's addressing, pre-bound.

    Every DUT-facing test builds packets from the same five values (our IP
    and MAC, the DUT's IP and MAC, the DUT's port). Binding them once here
    keeps `wrap_ethernet(build_*(...))` out of ~50 call sites and shrinks
    the fixture signature every test would otherwise have to repeat.
    """

    local_ip: str
    local_mac: str
    dut_ip: str
    dut_mac: str
    dut_port: int

    def tcp(self, sport: int, *, dport: int | None = None, **kwargs) -> Packet:
        """An Ethernet-wrapped TCP segment to the DUT. `dport` defaults to
        the run's target port; pass it to probe a different one."""
        l3 = build_tcp(self.local_ip, self.dut_ip, sport, self.dut_port if dport is None else dport, **kwargs)
        return self.l3(l3)

    def udp(self, sport: int, *, dport: int | None = None, **kwargs) -> Packet:
        """An Ethernet-wrapped UDP datagram to the DUT."""
        l3 = build_udp(self.local_ip, self.dut_ip, sport, self.dut_port if dport is None else dport, **kwargs)
        return self.l3(l3)

    def l3(self, layer: Packet) -> Packet:
        """Wrap an already-built L3 layer — for the tests that hand-craft
        IP options, malformed headers, or raw TCP option lists."""
        return wrap_ethernet(layer, self.local_mac, self.dut_mac)

    def icmp_echo(self, *, icmp_id: int = 0x1234, seq: int = 1, payload: bytes = b"") -> Packet:
        """A well-formed ICMP Echo Request to the DUT."""
        layer = IP(src=self.local_ip, dst=self.dut_ip) / ICMP(type=8, id=icmp_id, seq=seq)
        return self.l3(layer / Raw(payload) if payload else layer)


@pytest.fixture(scope="session")
def craft(local_ip: str, local_mac: str, dut_config: DUTConfig, dut_mac: str) -> Craft:
    return Craft(local_ip, local_mac, dut_config.target_ip, dut_mac, dut_config.target_port)


@pytest.fixture
def assert_dut_alive(network_interface, dut_config, craft, nodeid) -> Callable[[str], None]:
    """Prove the DUT survived whatever the test just sent it.

    The malformed/attack-pattern tests (bad checksums, invalid IHL,
    Teardrop, Ping of Death, truncated ICMP) all end the same way: send a
    plain echo and require a reply, because "still answering" is what
    distinguishes *discarded the bad packet* from *crashed on it*. Written
    once here rather than at the end of each such test.
    """

    def check(what: str) -> None:
        reply = network_interface.send_receive(
            craft.icmp_echo(icmp_id=0x7E57), timeout=dut_config.timeout, test_nodeid=nodeid
        )
        assert reply is not None, f"DUT stopped answering after {what} — possible crash/hang"

    return check


@pytest.fixture(scope="session")
def local_mac(dut_config: DUTConfig) -> str:
    from scapy.arch import get_if_hwaddr

    return get_if_hwaddr(dut_config.interface)


@pytest.fixture(scope="session")
def local_ip(dut_config: DUTConfig) -> str:
    from scapy.arch import get_if_addr

    return get_if_addr(dut_config.interface)


@pytest.fixture(scope="session")
def dut_mac(dut_config: DUTConfig) -> str:
    """Falls back to broadcast when not explicitly configured — fine for
    a DUT on the same L2 segment answering ARP, but tests that need a
    guaranteed unicast reply path should require --dut-mac explicitly."""
    return dut_config.target_mac or "ff:ff:ff:ff:ff:ff"
