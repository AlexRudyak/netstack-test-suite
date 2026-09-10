"""Unit tests for PDF/HTML report generation and result serialization —
verifies valid output structure, no DUT/network required."""
from __future__ import annotations

from dataclasses import fields
from datetime import datetime, timezone

import pytest

from src.reporting.html_report import generate_html_report
from src.reporting.models import PacketDirection, PacketEvent, TestEvent, TestOutcome, TestRunResult
from src.reporting.pdf_report import generate_pdf_report

from .conftest import make_run_result

pytestmark = [pytest.mark.internal]


def _sample_result() -> TestRunResult:
    now = datetime.now(timezone.utc)
    return make_run_result(
        run_id="unit-test-run",
        target_stack="windows",
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


def _sample_result_with_every_field_set() -> TestRunResult:
    """Every field non-default, so a dropped one changes the serialized form.

    A field left at its default survives a broken round trip by accident —
    from_dict simply falls back to the same default.
    """
    return make_run_result(
        **{
            **_sample_result().__dict__,
            "payload_mode": "zeros",
            "role": "server",
            "proxy_leg": "back",
            "pytest_returncode": 1,
        }
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
    """Compare the serialized forms, not a handful of named fields.

    This test used to assert five things (run_id, two counts, two lengths),
    so a field present in to_dict but missing from from_dict — target_stack,
    payload_mode, role, proxy_leg, pytest_returncode, or a TestEvent's
    markers/message — was written to results.json and then silently
    discarded on reload. Naming fields here would always miss the new one.
    """
    result = _sample_result_with_every_field_set()
    assert TestRunResult.from_dict(result.to_dict()).to_dict() == result.to_dict()


def test_serialized_form_covers_every_field() -> None:
    """Catches the other half: a field missing from *both* directions.

    The round-trip above is symmetric, so a field neither serializer knows
    about round-trips perfectly by being absent from both sides.
    """
    serialized = _sample_result_with_every_field_set().to_dict()
    assert set(serialized) == {f.name for f in fields(TestRunResult)}

    event = TestEvent(nodeid="t", outcome=TestOutcome.PASSED, duration_s=0.0)
    assert set(event.to_dict()) == {f.name for f in fields(TestEvent)}

    packet = PacketEvent(timestamp=0.0, direction=PacketDirection.SENT, summary="s", size_bytes=1)
    assert set(packet.to_dict()) == {f.name for f in fields(PacketEvent)}
