"""Unit tests for src/packet_engine/interface.py using monkeypatched
Scapy send/sniff functions — no real NIC, no elevated privileges."""
from __future__ import annotations

import pytest
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether

from src.packet_engine.interface import NetworkInterface
from src.reporting.models import PacketDirection

pytestmark = [pytest.mark.internal]


class _StubBackend:
    host_name = "Stub"

    def configure(self) -> None:
        pass

    def l2_socket_class(self):
        return None


@pytest.fixture
def stub_packet():
    return Ether(src="aa:aa:aa:aa:aa:aa", dst="bb:bb:bb:bb:bb:bb") / IP(src="10.0.0.1", dst="10.0.0.2")


def test_send_calls_sendp_and_records_event(monkeypatch, stub_packet) -> None:
    calls = []
    monkeypatch.setattr(
        "src.packet_engine.interface.sendp",
        lambda pkt, iface, verbose: calls.append((pkt, iface)),
    )

    events = []
    iface = NetworkInterface("dummy0", on_packet=events.append, backend=_StubBackend())
    iface.send(stub_packet, test_nodeid="unit")

    assert calls == [(stub_packet, "dummy0")]
    assert len(events) == 1
    assert events[0].direction is PacketDirection.SENT
    assert events[0].test_nodeid == "unit"


def test_send_receive_records_sent_and_received(monkeypatch, stub_packet) -> None:
    reply = Ether() / IP(src="10.0.0.2", dst="10.0.0.1")
    monkeypatch.setattr(
        "src.packet_engine.interface.srp1", lambda pkt, iface, timeout, verbose: reply
    )

    events = []
    iface = NetworkInterface("dummy0", on_packet=events.append, backend=_StubBackend())
    result = iface.send_receive(stub_packet, timeout=1.0, test_nodeid="unit")

    assert result is reply
    assert [e.direction for e in events] == [PacketDirection.SENT, PacketDirection.RECEIVED]


def test_send_receive_handles_no_reply(monkeypatch, stub_packet) -> None:
    monkeypatch.setattr(
        "src.packet_engine.interface.srp1", lambda pkt, iface, timeout, verbose: None
    )

    events = []
    iface = NetworkInterface("dummy0", on_packet=events.append, backend=_StubBackend())
    result = iface.send_receive(stub_packet, timeout=1.0)

    assert result is None
    assert len(events) == 1  # only the SENT event, no RECEIVED


def test_capture_streams_to_pcap_writer(monkeypatch, tmp_path, stub_packet) -> None:
    """Frames are streamed to a PcapWriter as recorded (not buffered and
    written in one shot), the parent dir is created lazily on first
    packet, and the writer is closed on close()."""
    monkeypatch.setattr("src.packet_engine.interface.sendp", lambda pkt, iface, verbose: None)

    state: dict = {"written": [], "closed": False}

    class _FakeWriter:
        def __init__(self, path, append, sync):
            state["path"] = path

        def write(self, packet):
            state["written"].append(packet)

        def close(self):
            state["closed"] = True

    monkeypatch.setattr("src.packet_engine.interface.PcapWriter", _FakeWriter)

    capture_path = tmp_path / "run" / "capture.pcap"
    iface = NetworkInterface("dummy0", capture_path=capture_path, backend=_StubBackend())
    iface.send(stub_packet)
    iface.send(stub_packet)

    assert capture_path.parent.exists()  # created lazily on first packet
    assert state["path"] == str(capture_path)
    assert len(state["written"]) == 2
    assert iface.captured_count == 2

    iface.close()
    assert state["closed"] is True


def test_no_pcap_writer_when_no_packets(monkeypatch, tmp_path) -> None:
    """A capture path with zero packets leaves no file (writer never opened)."""
    opened = {"count": 0}

    class _FakeWriter:
        def __init__(self, path, append, sync):
            opened["count"] += 1

        def write(self, packet):
            pass

        def close(self):
            pass

    monkeypatch.setattr("src.packet_engine.interface.PcapWriter", _FakeWriter)

    iface = NetworkInterface("dummy0", capture_path=tmp_path / "capture.pcap", backend=_StubBackend())
    iface.close()

    assert opened["count"] == 0
