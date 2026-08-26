"""Unit tests for src/packet_engine/preflight.py: config validation,
privilege handling, and the ARP probe outcomes (reply / no-reply /
send-error). Scapy send and the privilege check are monkeypatched — no
NIC, no elevation required."""
from __future__ import annotations

import pytest

import src.packet_engine.preflight as preflight
from src.config import DUTConfig
from src.packet_engine.preflight import run_preflight
from src.utils.permissions import InsufficientPrivilegesError

pytestmark = [pytest.mark.internal]


def _config(**overrides) -> DUTConfig:
    base = dict(interface="eth0", target_ip="10.0.0.5", target_stack="linux")
    base.update(overrides)
    return DUTConfig(**base)


def test_missing_target_ip_is_a_blocker() -> None:
    result = run_preflight(_config(target_ip=""))
    assert result.ok is False
    assert any("Missing required configuration" in e for e in result.errors)
    assert any("Target IP" in e for e in result.errors)


def test_insufficient_privileges_is_a_blocker(monkeypatch) -> None:
    def _raise() -> None:
        raise InsufficientPrivilegesError("run as admin")

    monkeypatch.setattr(preflight, "require_elevation", _raise)
    result = run_preflight(_config())
    assert result.ok is False
    assert any("privileges" in e.lower() for e in result.errors)


def test_arp_reply_confirms_reachability(monkeypatch) -> None:
    monkeypatch.setattr(preflight, "require_elevation", lambda: None)

    class _FakeARP:
        hwsrc = "de:ad:be:ef:00:01"

    class _Reply:
        def __getitem__(self, _):
            return _FakeARP()

    monkeypatch.setattr(
        "scapy.sendrecv.srp1", lambda pkt, iface, timeout, verbose: _Reply()
    )
    result = run_preflight(_config())
    assert result.ok is True
    assert result.dut_mac == "de:ad:be:ef:00:01"
    assert any("responded to ARP" in m for m in result.info)


def test_no_arp_reply_is_a_warning_not_a_blocker(monkeypatch) -> None:
    """A custom stack may not implement ARP — no reply must not block the run."""
    monkeypatch.setattr(preflight, "require_elevation", lambda: None)
    monkeypatch.setattr("scapy.sendrecv.srp1", lambda pkt, iface, timeout, verbose: None)
    result = run_preflight(_config())
    assert result.ok is True  # proceeds
    assert result.dut_mac is None
    assert any("No ARP reply" in w for w in result.warnings)


def test_send_failure_is_a_blocker(monkeypatch) -> None:
    monkeypatch.setattr(preflight, "require_elevation", lambda: None)

    def _boom(pkt, iface, timeout, verbose):
        raise OSError("no such device")

    monkeypatch.setattr("scapy.sendrecv.srp1", _boom)
    result = run_preflight(_config())
    assert result.ok is False
    assert any("Could not send" in e for e in result.errors)


def test_render_lines_prefixes_levels(monkeypatch) -> None:
    monkeypatch.setattr(preflight, "require_elevation", lambda: None)
    monkeypatch.setattr("scapy.sendrecv.srp1", lambda pkt, iface, timeout, verbose: None)
    lines = run_preflight(_config()).render_lines()
    assert any(line.startswith("[ok]") for line in lines)
    assert any(line.startswith("[warn]") for line in lines)
