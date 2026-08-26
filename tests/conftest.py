"""Shared fixtures for the automated suite, built on top of the root
conftest.py fixtures (dut_config, target_profile, network_interface,
payload_settings, confirm_vuln_tests).
"""
from __future__ import annotations

import pytest

from src.config import DUTConfig
from src.packet_engine.payloads import resolve_payload


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
