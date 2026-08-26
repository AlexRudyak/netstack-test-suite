"""PDF report generation (reportlab), embedding static_charts.py PNGs."""
from __future__ import annotations

import html
import tempfile
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    Image,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from src.plotting.static_charts import render_packet_timeline, render_pass_fail_summary
from src.reporting import report_data
from src.reporting.models import TestOutcome, TestRunResult

# Outcome → (text colour, row background). Used to colour the detail table.
_OUTCOME_COLORS = {
    TestOutcome.PASSED: (colors.HexColor("#1a7f37"), colors.HexColor("#e8f5e9")),
    TestOutcome.FAILED: (colors.HexColor("#b71c1c"), colors.HexColor("#ffebee")),
    TestOutcome.ERROR: (colors.HexColor("#8a1a9b"), colors.HexColor("#f3e5f5")),
    TestOutcome.SKIPPED: (colors.HexColor("#616161"), colors.HexColor("#f5f5f5")),
}


def generate_pdf_report(result: TestRunResult, output_path: Path) -> Path:
    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(str(output_path), pagesize=letter)
    story: list = []

    story.append(Paragraph("Network Stack Test Suite — Run Report", styles["Title"]))
    story.append(Spacer(1, 0.2 * inch))

    meta_label = ParagraphStyle("metalabel", fontSize=9, leading=11)
    meta_value = ParagraphStyle("metavalue", fontSize=9, leading=11, wordWrap="CJK")
    meta_pairs = [
        ("Run ID", result.run_id),
        ("Target", f"{result.target_ip} (stack: {result.target_stack})"),
        ("Host platform", result.host_platform),
        ("Payload mode", result.payload_mode),
        ("Started", result.started_at.isoformat()),
        ("Finished", result.finished_at.isoformat() if result.finished_at else "—"),
        (
            "Results (passed / failed / errored / skipped / total)",
            f"{result.passed} / {result.failed} / {result.errors} / {result.skipped} / {result.total}",
        ),
    ]
    meta_rows = [
        [Paragraph(html.escape(label), meta_label), Paragraph(html.escape(str(value)), meta_value)]
        for label, value in meta_pairs
    ]
    meta_table = Table(meta_rows, colWidths=[2.6 * inch, 3.9 * inch])
    meta_table.setStyle(
        TableStyle(
            [
                ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                ("BACKGROUND", (0, 0), (0, -1), colors.whitesmoke),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]
        )
    )
    story.append(meta_table)
    story.append(
        Paragraph(
            "Purpose: findings for a developer to fix the DUT's network stack. "
            "Failures first, full results next, spec references in the appendix.",
            ParagraphStyle("purpose", fontSize=8, textColor=colors.HexColor("#555555"), leading=10, spaceBefore=6),
        )
    )
    story.append(Spacer(1, 0.25 * inch))

    # Findings first — the actionable part for the developer.
    story.append(Paragraph("Findings — what to fix", styles["Heading2"]))
    story += _findings_flowables(result, styles)
    story.append(Spacer(1, 0.2 * inch))

    story += _artifacts_flowables(result, styles)

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        summary_png = render_pass_fail_summary(result, tmp_path / "summary.png")
        timeline_png = render_packet_timeline(result, tmp_path / "timeline.png")

        story.append(Paragraph("Results summary", styles["Heading2"]))
        story.append(Image(str(summary_png), width=3 * inch, height=2.6 * inch))
        story.append(Spacer(1, 0.2 * inch))

        story.append(Paragraph("Packet timeline", styles["Heading2"]))
        story.append(Image(str(timeline_png), width=6 * inch, height=3 * inch))
        story.append(Spacer(1, 0.3 * inch))

        story.append(Paragraph("Full results", styles["Heading2"]))
        story.append(_build_detail_table(result))

        # Appendices.
        story.append(PageBreak())
        story.append(Paragraph("Appendix A — Test catalog", styles["Heading2"]))
        story += _catalog_flowables(styles)
        story.append(PageBreak())
        story.append(Paragraph("Appendix B — RFC reference index", styles["Heading2"]))
        story += _rfc_flowables(styles)

        doc.build(story)

    return output_path


def _findings_flowables(result: TestRunResult, styles) -> list:
    findings = report_data.build_findings(result)
    if not findings:
        return [
            Paragraph(
                "No failures or errors — every test that ran passed. See the full results below "
                "and the catalog in Appendix A.",
                ParagraphStyle("okmsg", parent=styles["BodyText"], textColor=colors.HexColor("#1a7f37")),
            )
        ]

    label = ParagraphStyle("flabel", fontSize=7.5, leading=9, textColor=colors.HexColor("#555555"))
    body = ParagraphStyle("fbody", fontSize=8, leading=10, wordWrap="CJK")
    flow = [
        Paragraph(
            f"{len(findings)} test(s) failed or errored, most-severe first — each with the RFC clause "
            "it exercises, what it checks, and what the DUT actually did.",
            ParagraphStyle("intro", parent=styles["BodyText"], fontSize=9),
        ),
        Spacer(1, 0.08 * inch),
    ]
    for f in findings:
        text_color, bg = _OUTCOME_COLORS.get(f.event.outcome, (colors.black, colors.white))
        rows = [
            [
                Paragraph(
                    f'<b><font color="{_css_hex(text_color)}">[{f.event.outcome.value.upper()}]</font> '
                    f"{html.escape(f.title)}</b>",
                    body,
                ),
                Paragraph(html.escape(f.rfc), label),
            ],
            [Paragraph(f"<font face='Courier'>{html.escape(f.event.nodeid)}</font>", label), ""],
            [Paragraph(f"<b>What it checks:</b> {html.escape(f.description)}", body), ""],
            [Paragraph(f"<b>Observed:</b> {html.escape(f.event.message or '(no message)')}", body), ""],
        ]
        t = Table(rows, colWidths=[5.0 * inch, 1.5 * inch])
        t.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), bg),
                    ("LINEBEFORE", (0, 0), (0, -1), 2, text_color),
                    ("SPAN", (0, 1), (1, 1)),
                    ("SPAN", (0, 2), (1, 2)),
                    ("SPAN", (0, 3), (1, 3)),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("ALIGN", (1, 0), (1, 0), "RIGHT"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 6),
                    ("TOPPADDING", (0, 0), (-1, -1), 2),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
                ]
            )
        )
        flow.append(t)
        flow.append(Spacer(1, 0.08 * inch))
    return flow


def _artifacts_flowables(result: TestRunResult, styles) -> list:
    body = ParagraphStyle("artbody", parent=styles["BodyText"], fontSize=8.5, leading=11)
    mono = ParagraphStyle("artmono", fontSize=8, leading=11, fontName="Courier")
    return [
        Paragraph("Artifacts &amp; reproduction", styles["Heading2"]),
        Paragraph(
            f"For wire-level analysis, open this run's capture (in <font face='Courier'>reports/"
            f"{html.escape(result.run_id)}/</font>) in Wireshark:",
            body,
        ),
        Paragraph("• <font face='Courier'>capture.pcap</font> — every frame sent/received.", body),
        Paragraph(
            "• <font face='Courier'>debug.log</font> — tshark-style per-packet trace (if Debug mode was on).",
            body,
        ),
        Paragraph("• <font face='Courier'>pytest_output.log</font> — raw runner output.", body),
        Spacer(1, 0.05 * inch),
        Paragraph("Reproduce this run:", body),
        Paragraph(html.escape(report_data.reproduction_command(result)), mono),
        Paragraph(
            f"Note: informational checks compare the DUT against the selected "
            f"<b>{html.escape(result.target_stack)}</b> stack profile — a mismatch flags a behavioural "
            "difference, not necessarily an RFC violation.",
            ParagraphStyle("artnote", parent=body, textColor=colors.HexColor("#555555"), fontSize=8),
        ),
        Spacer(1, 0.2 * inch),
    ]


def _catalog_flowables(styles) -> list:
    cell = ParagraphStyle("ccell", fontSize=7, leading=8.5, wordWrap="CJK")
    head = ParagraphStyle("chead", parent=cell, textColor=colors.white)
    intro = Paragraph(
        "Every test in the suite, what it checks, the RFC clause it maps to, and its role(s). "
        "Use this to map a finding to the spec and to see the full coverage.",
        ParagraphStyle("cintro", parent=styles["BodyText"], fontSize=9),
    )
    flow = [intro, Spacer(1, 0.1 * inch)]
    for group, specs in report_data.catalog_by_group():
        flow.append(Paragraph(group, styles["Heading3"]))
        rows = [
            [
                Paragraph("Test", head),
                Paragraph("What it checks", head),
                Paragraph("RFC", head),
                Paragraph("Roles", head),
            ]
        ]
        for s in specs:
            rows.append(
                [
                    Paragraph(html.escape(s.test), cell),
                    Paragraph(html.escape(s.description), cell),
                    Paragraph(html.escape(s.rfc), cell),
                    Paragraph(html.escape(s.role_labels), cell),
                ]
            )
        t = Table(rows, colWidths=[1.7 * inch, 3.0 * inch, 1.3 * inch, 0.5 * inch], repeatRows=1)
        t.setStyle(
            TableStyle(
                [
                    ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#333333")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 4),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                    ("TOPPADDING", (0, 0), (-1, -1), 2),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
                ]
            )
        )
        flow.append(t)
        flow.append(Spacer(1, 0.12 * inch))
    return flow


def _rfc_flowables(styles) -> list:
    body = ParagraphStyle("rfcbody", parent=styles["BodyText"], fontSize=9, leading=13)
    flow = [
        Paragraph(
            "Specifications exercised by this suite — the reading list for interpreting the findings.",
            ParagraphStyle("rintro", parent=styles["BodyText"], fontSize=9),
        ),
        Spacer(1, 0.08 * inch),
    ]
    for label, title in report_data.referenced_rfcs():
        suffix = f" — {html.escape(title)}" if title else ""
        flow.append(Paragraph(f"<b>{html.escape(label)}</b>{suffix}", body))
    return flow


def _css_hex(color) -> str:
    return "#%02x%02x%02x" % (round(color.red * 255), round(color.green * 255), round(color.blue * 255))


def _build_detail_table(result: TestRunResult) -> Table:
    """Per-test table with wrapping cells and outcome colouring.

    Cells are Paragraphs (not bare strings) so long node ids and messages
    wrap inside their columns instead of overflowing; wordWrap="CJK" lets
    long unbroken tokens (path segments, `a::b` node ids) break mid-token.
    Column widths sum to the 6.5-inch usable width of a letter page.
    """
    cell = ParagraphStyle("cell", fontSize=7, leading=8.5, wordWrap="CJK")
    header = ParagraphStyle("cellhead", parent=cell, textColor=colors.white)

    def p(text: str, style: ParagraphStyle = cell) -> Paragraph:
        return Paragraph(html.escape(text or ""), style)

    rows = [[p("Test", header), p("Outcome", header), p("Duration (s)", header), p("Message", header)]]
    for t in result.tests:
        text_color, _ = _OUTCOME_COLORS.get(t.outcome, (colors.black, colors.white))
        outcome = Paragraph(f'<font color="{_css_hex(text_color)}">{t.outcome.value}</font>', cell)
        rows.append([p(t.nodeid), outcome, p(f"{t.duration_s:.3f}"), p(t.message or "")])

    table = Table(
        rows,
        colWidths=[3.0 * inch, 0.75 * inch, 0.75 * inch, 2.0 * inch],
        repeatRows=1,
    )
    style = TableStyle(
        [
            ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#333333")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 2),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ]
    )
    for row_index, t in enumerate(result.tests, start=1):
        _, bg = _OUTCOME_COLORS.get(t.outcome, (None, None))
        if bg is not None:
            style.add("BACKGROUND", (0, row_index), (-1, row_index), bg)
    table.setStyle(style)
    return table
