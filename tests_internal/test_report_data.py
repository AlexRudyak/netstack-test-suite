"""Unit tests for the enhanced-report data layer and the developer-oriented
sections in the HTML/PDF reports."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from src import catalog
from src.reporting import report_data
from src.reporting.html_report import generate_html_report
from src.reporting.models import PacketDirection, PacketEvent, TestEvent, TestOutcome, TestRunResult
from src.reporting.pdf_report import generate_pdf_report

pytestmark = [pytest.mark.internal]


def _result() -> TestRunResult:
    now = datetime.now(timezone.utc)
    # Use a REAL cataloged nodeid so findings join to a catalog spec.
    real = catalog.CATALOG[0].nodeid
    return TestRunResult(
        run_id="r1",
        started_at=now,
        finished_at=now,
        target_ip="10.0.0.5",
        target_stack="linux",
        host_platform="TestOS",
        tests=[
            TestEvent("tests/x.py::t_pass", TestOutcome.PASSED, 0.01),
            TestEvent(real, TestOutcome.FAILED, 0.02, message="AssertionError: boom"),
            TestEvent("tests/y.py::t_err", TestOutcome.ERROR, 0.03, message="RuntimeError: setup failed"),
            TestEvent("tests/z.py::t_skip", TestOutcome.SKIPPED, 0.0, message="Skipped: role mismatch"),
        ],
        packet_events=[PacketEvent(now.timestamp(), PacketDirection.SENT, "s", 60)],
    )


def test_findings_are_failures_and_errors_errors_first() -> None:
    findings = report_data.build_findings(_result())
    assert [f.event.outcome for f in findings] == [TestOutcome.ERROR, TestOutcome.FAILED]


def test_finding_joins_catalog_spec() -> None:
    findings = report_data.build_findings(_result())
    failed = next(f for f in findings if f.event.outcome is TestOutcome.FAILED)
    assert failed.spec is not None  # real cataloged nodeid
    assert failed.rfc != "—"
    assert failed.description


def test_finding_without_catalog_entry_degrades_gracefully() -> None:
    findings = report_data.build_findings(_result())
    errored = next(f for f in findings if f.event.outcome is TestOutcome.ERROR)
    assert errored.spec is None
    assert errored.rfc == "—"
    assert "no catalog description" in errored.description


def test_catalog_grouping_covers_every_spec() -> None:
    grouped = report_data.catalog_by_group()
    total = sum(len(specs) for _, specs in grouped)
    assert total == len(catalog.CATALOG)


def test_referenced_rfcs_are_sorted_and_titled() -> None:
    rfcs = report_data.referenced_rfcs()
    numbers = [int(label.split()[1]) for label, _ in rfcs]
    assert numbers == sorted(numbers)
    assert ("RFC 9293", "Transmission Control Protocol (TCP)") in rfcs


def test_html_report_has_developer_sections(tmp_path: Path) -> None:
    html = generate_html_report(_result(), tmp_path / "r.html").read_text(encoding="utf-8")
    assert "Findings" in html
    assert "What it checks" in html
    assert "Appendix A" in html and "Appendix B" in html
    assert "AssertionError: boom" in html  # the failure message is shown
    assert "capture.pcap" in html  # artifacts pointer


def test_pdf_report_still_valid_with_appendices(tmp_path: Path) -> None:
    out = generate_pdf_report(_result(), tmp_path / "r.pdf")
    data = out.read_bytes()
    assert data.startswith(b"%PDF")
    assert len(data) > 2000
