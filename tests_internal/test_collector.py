"""Unit tests for src/reporting/collector.py.

PacketEventLogWriter is the sink whose lines the parent process tails to
drive the GUI's live plot, and it is fed from the sniffer thread as well as
the test thread. What matters here is that concurrent writes stay
line-oriented and that teardown ordering can't turn a late frame into an
unrelated test error.
"""
from __future__ import annotations

import json
import threading

import pytest

from src.reporting.collector import PacketEventLogWriter
from src.reporting.models import PacketDirection, PacketEvent

pytestmark = [pytest.mark.internal]


def _event(index: int) -> PacketEvent:
    return PacketEvent(
        timestamp=1000.0 + index,
        direction=PacketDirection.SENT,
        # Long and distinctive, so an interleaved write shows up as a broken
        # line rather than by luck.
        summary=f"Ether / IP / TCP {'x' * 200} #{index}",
        size_bytes=54,
        test_nodeid="tests/x.py::t",
    )


def test_every_line_is_valid_json_under_concurrent_writers(tmp_path) -> None:
    """Two threads writing unserialized produce a line the parent's drain
    cannot parse — which is the failure mode runner.py now has to skip."""
    path = tmp_path / "packet_events.jsonl"
    writer = PacketEventLogWriter(path)
    writer_count = 4
    # Sized to the writer threads only; the main thread releases them with
    # the event below rather than joining the barrier itself.
    ready = threading.Barrier(writer_count)
    go = threading.Event()

    def spam() -> None:
        ready.wait(timeout=5)
        go.wait(timeout=5)
        for i in range(200):
            writer(_event(i))

    threads = [threading.Thread(target=spam) for _ in range(writer_count)]
    for thread in threads:
        thread.start()
    go.set()
    for thread in threads:
        thread.join(timeout=30)
        assert not thread.is_alive()
    writer.close()

    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 800
    for line in lines:
        json.loads(line)  # raises if two writes interleaved


def test_a_write_after_close_is_dropped_not_raised(tmp_path) -> None:
    """Late frames arrive from a background thread during session teardown,
    where ValueError("I/O operation on closed file") surfaces as an
    unrelated test error."""
    path = tmp_path / "packet_events.jsonl"
    writer = PacketEventLogWriter(path)
    writer(_event(1))
    writer.close()

    writer(_event(2))  # must not raise

    assert len(path.read_text(encoding="utf-8").splitlines()) == 1


def test_close_is_idempotent(tmp_path) -> None:
    writer = PacketEventLogWriter(tmp_path / "packet_events.jsonl")
    writer.close()
    writer.close()


def test_written_lines_round_trip_through_the_model(tmp_path) -> None:
    path = tmp_path / "packet_events.jsonl"
    writer = PacketEventLogWriter(path)
    writer(_event(7))
    writer.close()

    restored = PacketEvent.from_dict(json.loads(path.read_text(encoding="utf-8")))

    assert restored.direction is PacketDirection.SENT
    assert restored.timestamp == 1007.0
    assert restored.test_nodeid == "tests/x.py::t"
