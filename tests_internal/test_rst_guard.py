"""Unit tests for src/packet_engine/rst_guard.py — the Windows-only guard
that stops the host's own TCP/IP stack from RST-ing traffic that belongs
to this suite's raw L2 connections (see that module's docstring).

No real WinDivert driver is involved here: `start_for_host`'s host-OS
branch is exercised with a stub `pydivert` module, the same way
test_packet_builders.py exercises platform_backend.py's Windows/Linux
branches without a real Npcap install.
"""
from __future__ import annotations

import sys
import types

import pytest

pytestmark = [pytest.mark.internal]


def test_start_for_host_is_a_noop_off_windows(monkeypatch) -> None:
    from src.packet_engine import rst_guard

    monkeypatch.setattr(rst_guard.platform, "system", lambda: "Linux")
    assert rst_guard.start_for_host("192.168.1.1") is None


def test_guard_filter_scopes_to_the_host_ip_and_ephemeral_range() -> None:
    from src.config import EPHEMERAL_PORT_RANGE
    from src.packet_engine.rst_guard import HostRstGuard

    guard = HostRstGuard("192.168.1.1")
    port_low, port_high = EPHEMERAL_PORT_RANGE
    assert guard._filter == (
        f"tcp and ip.DstAddr == 192.168.1.1 "
        f"and tcp.DstPort >= {port_low} and tcp.DstPort <= {port_high}"
    )


def test_start_opens_a_windivert_handle_with_the_guard_s_filter(monkeypatch) -> None:
    from src.packet_engine.rst_guard import HostRstGuard

    opened: dict[str, object] = {}

    class FakeHandle:
        def __init__(self, packet_filter: str, layer=None) -> None:
            opened["filter"] = packet_filter
            opened["layer"] = layer

        def open(self) -> None:
            opened["open_called"] = True

        def recv(self):  # pragma: no cover - the guard thread's loop body
            raise OSError("closed")

        def close(self) -> None:
            opened["close_called"] = True

    fake_pydivert = types.SimpleNamespace(WinDivert=FakeHandle, Layer=types.SimpleNamespace(NETWORK="network"))
    monkeypatch.setitem(sys.modules, "pydivert", fake_pydivert)

    guard = HostRstGuard("192.168.1.1")
    guard.start()
    try:
        assert opened["filter"] == guard._filter
        assert opened["layer"] == "network"
        assert opened["open_called"] is True
    finally:
        guard.stop()

    assert opened["close_called"] is True
