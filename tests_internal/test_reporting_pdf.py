"""Unit tests for PDF/HTML report generation and result serialization —
verifies valid output structure, no DUT/network required."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from src.reporting.html_report import generate_html_report
from src.reporting.models import PacketDirection, PacketEvent, TestEvent, TestOutcome, TestRunResult
from src.reporting.pdf_report import generate_pdf_report

pytestmark = [pytest.mark.internal]


def _sample_result() -> TestRunResult:
    now = datetime.now(timezone.utc)
    return TestRunResult(
        run_id="unit-test-run",
        started_at=now,
        finished_at=now,
        target_ip="10.0.0.5",
        target_stack="windows",
        host_platform="TestOS",
        payload_mode="random",
        tests=[
            TestEvent(nodeid="tests/tcp/syn/test_x.py::test_a", outcome=TestOutcome.PASSED, duration_s=0.05),
            TestEvent(
                nodeid="tests/tcp/syn/test_x.py::test_b",
                outcome=TestOutcome.FAILED,
                duration_s=0.07,
                message="assertion failed",
            ),
        ],
        packet_events=[
            PacketEvent(timestamp=now.timestamp(), direction=PacketDirection.SENT, summary="stub", size_bytes=54)
        ],
    )


def test_generate_pdf_report_produces_valid_pdf(tmp_path) -> None:
    output = generate_pdf_report(_sample_result(), tmp_path / "report.pdf")
    assert output.exists()
    data = output.read_bytes()
    assert data.startswith(b"%PDF")
    assert len(data) > 500


def test_generate_html_report_contains_test_rows(tmp_path) -> None:
    output = generate_html_report(_sample_result(), tmp_path / "report.html")
    html = output.read_text(encoding="utf-8")
    assert "test_a" in html
    assert "test_b" in html
    assert "assertion failed" in html


def test_results_json_round_trip() -> None:
    result = _sample_result()
    restored = TestRunResult.from_dict(result.to_dict())

    assert restored.run_id == result.run_id
    assert restored.passed == result.passed
    assert restored.failed == result.failed
    assert len(restored.tests) == len(result.tests)
    assert len(restored.packet_events) == len(result.packet_events)
