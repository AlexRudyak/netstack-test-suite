"""Unit tests for the plotting engine: MetricsBuffer accumulation and
static_charts.py rendering with the Agg backend (headless, no display)."""
from __future__ import annotations

import time
from datetime import datetime, timezone

import pytest

from src.plotting.metrics import MetricsBuffer
from src.plotting.static_charts import render_packet_timeline, render_pass_fail_summary
from src.reporting.models import PacketDirection, PacketEvent, TestEvent, TestOutcome, TestRunResult

pytestmark = [pytest.mark.internal]


def _event(direction: PacketDirection, offset: float, size: int = 64) -> PacketEvent:
    return PacketEvent(timestamp=time.time() + offset, direction=direction, summary="stub", size_bytes=size)


def test_metrics_buffer_snapshot_is_cumulative() -> None:
    buf = MetricsBuffer()
    buf.add(_event(PacketDirection.SENT, 0))
    buf.add(_event(PacketDirection.SENT, 0.01))
    buf.add(_event(PacketDirection.RECEIVED, 0.02))

    snap = buf.snapshot()

    assert snap.sent_cumulative == [1, 2, 2]
    assert snap.received_cumulative == [0, 0, 1]
    assert len(snap.elapsed_s) == 3


def test_metrics_buffer_clear_resets_state() -> None:
    buf = MetricsBuffer()
    buf.add(_event(PacketDirection.SENT, 0))
    buf.clear()

    assert buf.snapshot().sent_cumulative == []


def _sample_result() -> TestRunResult:
    now = datetime.now(timezone.utc)
    return TestRunResult(
        run_id="unit-test-run",
        started_at=now,
        finished_at=now,
        target_ip="10.0.0.5",
        target_stack="linux",
        host_platform="TestOS",
        tests=[
            TestEvent(nodeid="tests/ip/test_x.py::test_a", outcome=TestOutcome.PASSED, duration_s=0.1),
            TestEvent(
                nodeid="tests/ip/test_x.py::test_b", outcome=TestOutcome.FAILED, duration_s=0.2, message="boom"
            ),
        ],
        packet_events=[_event(PacketDirection.SENT, 0), _event(PacketDirection.RECEIVED, 0.1)],
    )


def test_render_packet_timeline_writes_png(tmp_path) -> None:
    output = render_packet_timeline(_sample_result(), tmp_path / "timeline.png")
    assert output.exists()
    assert output.stat().st_size > 0


def test_render_pass_fail_summary_writes_png(tmp_path) -> None:
    output = render_pass_fail_summary(_sample_result(), tmp_path / "summary.png")
    assert output.exists()
    assert output.stat().st_size > 0
