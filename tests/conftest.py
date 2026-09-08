"""Shared fixtures for the automated suite, built on top of the root
conftest.py fixtures (dut_config, target_profile, network_interface,
payload_settings, confirm_vuln_tests).
"""
from __future__ import annotations

from collections.abc import Iterator

import pytest

from src.config import DUTConfig, ProxyLeg
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
    if not mode or not backend_host:
        pytest.fail(
            "--proxy-leg back needs --proxy-mode and --backend-host: the back leg only "
            "carries traffic while something drives the proxy's front, so the suite has "
            "to induce it. See docs/proxy_testing.md."
        )

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


@pytest.fixture
def payload(payload_settings: dict) -> bytes:
    return resolve_payload(
        payload_settings["mode"], size=payload_settings["size"], custom=payload_settings["custom"]
    )


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
