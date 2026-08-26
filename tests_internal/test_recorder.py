"""Unit tests for src/packet_engine/recorder.py: filter construction,
incremental writing, and start/stop lifecycle — via monkeypatched Scapy
AsyncSniffer/PcapWriter, no real NIC."""
from __future__ import annotations

import pytest
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether

from src.packet_engine.recorder import PacketRecorder, build_host_filter

pytestmark = [pytest.mark.internal]


class _StubBackend:
    host_name = "Stub"

    def configure(self) -> None:
        pass

    def l2_socket_class(self):
        return None


class _FakeWriter:
    def __init__(self, path, append, sync) -> None:
        self.path = path
        self.written: list = []
        self.closed = False

    def write(self, packet) -> None:
        self.written.append(packet)

    def close(self) -> None:
        self.closed = True


class _FakeSniffer:
    """Captures the prn callback so tests can feed packets synchronously,
    standing in for AsyncSniffer's background thread."""

    def __init__(self, iface, filter, prn, store, count, timeout) -> None:
        self.iface = iface
        self.filter = filter
        self.prn = prn
        self.count = count
        self.timeout = timeout
        self.running = False
        self.joined = False

    def start(self) -> None:
        self.running = True

    def stop(self) -> None:
        self.running = False

    def join(self) -> None:
        self.joined = True


def test_build_host_filter() -> None:
    assert build_host_filter("10.0.0.5") == "host 10.0.0.5"
    assert build_host_filter(None) is None
    assert build_host_filter("") is None


@pytest.fixture
def patched(monkeypatch):
    created = {}

    def make_writer(path, append, sync):
        writer = _FakeWriter(path, append, sync)
        created["writer"] = writer
        return writer

    def make_sniffer(iface, filter, prn, store, count, timeout):
        sniffer = _FakeSniffer(iface, filter, prn, store, count, timeout)
        created["sniffer"] = sniffer
        return sniffer

    monkeypatch.setattr("src.packet_engine.recorder.PcapWriter", make_writer)
    monkeypatch.setattr("src.packet_engine.recorder.AsyncSniffer", make_sniffer)
    return created


def _packet():
    return Ether() / IP(src="10.0.0.1", dst="10.0.0.5")


def test_recorder_writes_incrementally_and_counts(patched, tmp_path) -> None:
    out = tmp_path / "sub" / "capture.pcap"
    recorder = PacketRecorder(
        "dummy0", out, bpf_filter="host 10.0.0.5", backend=_StubBackend()
    )
    recorder.start()

    assert out.parent.exists()  # parent dir created up front
    sniffer = patched["sniffer"]
    assert sniffer.filter == "host 10.0.0.5"
    assert sniffer.running

    # Feed packets as the sniffer thread would.
    sniffer.prn(_packet())
    sniffer.prn(_packet())

    assert recorder.packet_count == 2
    assert len(patched["writer"].written) == 2

    written = recorder.stop()
    assert written == 2
    assert not sniffer.running
    assert patched["writer"].closed


def test_recorder_on_packet_callback_invoked(patched, tmp_path) -> None:
    seen = []
    recorder = PacketRecorder(
        "dummy0", tmp_path / "c.pcap", on_packet=seen.append, backend=_StubBackend()
    )
    recorder.start()
    patched["sniffer"].prn(_packet())

    assert len(seen) == 1
    recorder.stop()


def test_recorder_join_closes_writer_for_bounded_capture(patched, tmp_path) -> None:
    recorder = PacketRecorder("dummy0", tmp_path / "c.pcap", backend=_StubBackend())
    recorder.start(count=5, timeout=10)

    assert patched["sniffer"].count == 5
    assert patched["sniffer"].timeout == 10

    recorder.join()
    assert patched["sniffer"].joined
    assert patched["writer"].closed


def test_recorder_context_manager_stops_on_exit(patched, tmp_path) -> None:
    with PacketRecorder("dummy0", tmp_path / "c.pcap", backend=_StubBackend()) as recorder:
        recorder.start()
        patched["sniffer"].prn(_packet())
    assert patched["writer"].closed
    assert not patched["sniffer"].running
