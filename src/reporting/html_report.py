"""HTML report — a developer-oriented document for fixing the DUT stack.

Leads with the failures (each tied to its RFC clause and what it tests),
then the full per-test results, then appendices: the complete test catalog
and the RFC reading list. The PDF report (pdf_report.py) mirrors this.
"""
from __future__ import annotations

import html
from pathlib import Path

from src import design_tokens
from src.reporting import report_data
from src.reporting.models import TestOutcome, TestRunResult
from src.reporting.palette import OUTCOME_STYLE

# CSS class per outcome, from the shared presentation table in
# reporting/palette.py — the same table the PDF report and the charts read.
_OUTCOME_CLASS = {outcome: style["css"] for outcome, style in OUTCOME_STYLE.items()}


def _palette_css() -> str:
    """Every outcome-coloured rule, generated from the shared palette.

    Kept out of the static stylesheet below so the hex values are stated in
    exactly one place across the HTML report, the PDF report and the charts.
    """
    rules = []
    for outcome, st in OUTCOME_STYLE.items():
        cls, fg, bg = st["css"], st["fg"], st["bg"]
        # PASSED tints only its outcome cell (a descendant selector), not the
        # whole row — a mostly-passing report should not be a wall of green.
        # Every other outcome tints the row, so a problem is scannable.
        if outcome is TestOutcome.PASSED:
            rules.append(f"tr.{cls} td.{cls} {{ background: {bg}; }}")
        else:
            rules.append(f"tr.{cls}, td.{cls} {{ background: {bg}; }}")
        rules.append(f"td.{cls} {{ color: {fg}; }}")
        rules.append(f".pill.{cls} {{ background: {bg}; color: {fg}; }}")
        if outcome in (TestOutcome.FAILED, TestOutcome.ERROR):
            rules.append(f".badge.{cls} {{ background: {fg}; }}")
    failed = OUTCOME_STYLE[TestOutcome.FAILED]["fg"]
    error = OUTCOME_STYLE[TestOutcome.ERROR]["fg"]
    passed = OUTCOME_STYLE[TestOutcome.PASSED]["fg"]
    rules.append(f".finding {{ border-left-color: {failed}; }}")
    rules.append(f".finding.error {{ border-left-color: {error}; }}")
    rules.append(f".ok {{ color: {passed}; font-weight: 600; }}")
    return "\n".join(rules)


def _e(text: object) -> str:
    return html.escape(str(text if text is not None else ""))


def _findings_section(result: TestRunResult) -> str:
    findings = report_data.build_findings(result)
    if not findings:
        return (
            "<section><h2>Findings</h2>"
            f"<p class='ok'>{_e(report_data.NO_FINDINGS)}</p></section>"
        )
    cards = []
    for f in findings:
        cards.append(
            f"""
            <div class="finding {_OUTCOME_CLASS[f.event.outcome]}">
              <div class="finding-head">
                <span class="badge {_OUTCOME_CLASS[f.event.outcome]}">{_e(f.event.outcome.value)}</span>
                <span class="finding-title">{_e(f.title)}</span>
                <span class="finding-rfc">{_e(f.rfc)}</span>
              </div>
              <div class="finding-node"><code>{_e(f.event.nodeid)}</code></div>
              <div class="finding-desc"><strong>What it checks:</strong> {_e(f.description)}</div>
              <div class="finding-msg"><strong>Observed:</strong> <code>{_e(f.event.message or '(no message)')}</code></div>
            </div>"""
        )
    return (
        "<section><h2>Findings — what to fix</h2>"
        f"<p>{_e(report_data.findings_intro(len(findings)))}</p>"
        + "".join(cards)
        + "</section>"
    )


def _summary_section(result: TestRunResult) -> str:
    return f"""
    <section>
      <h2>Run summary</h2>
      <table class="meta">
        <tr><th>Run ID</th><td>{_e(result.run_id)}</td></tr>
        <tr><th>Target (DUT)</th><td>{_e(result.target_ip)} — expected stack profile: <strong>{_e(result.target_stack)}</strong></td></tr>
        <tr><th>Suite role</th><td>{_e(result.role_description)}</td></tr>
        <tr><th>Suite host</th><td>{_e(result.host_platform)}</td></tr>
        <tr><th>Payload mode</th><td>{_e(result.payload_mode)}</td></tr>
        <tr><th>Started</th><td>{_e(result.started_at.isoformat())}</td></tr>
        <tr><th>Finished</th><td>{_e(result.finished_at.isoformat() if result.finished_at else '—')}</td></tr>
        <tr><th>Results</th><td>
          <span class="pill passed">{result.passed} passed</span>
          <span class="pill failed">{result.failed} failed</span>
          <span class="pill error">{result.errors} errored</span>
          <span class="pill skipped">{result.skipped} skipped</span>
          <span class="pill">{result.total} total</span>
        </td></tr>
      </table>
    </section>"""


def _artifact_items() -> str:
    return "".join(
        f"<li><code>{_e(name)}</code> — {_e(what)}</li>" for name, what in report_data.ARTIFACTS
    )


def _artifacts_section(result: TestRunResult) -> str:
    return f"""
    <section>
      <h2>Artifacts &amp; reproduction</h2>
      <p>For wire-level analysis, open the packet capture from this run's folder
      (<code>reports/{_e(result.run_id)}/</code>) in Wireshark:</p>
      <ul>{_artifact_items()}</ul>
      <p>Reproduce this run:</p>
      <pre>{_e(report_data.reproduction_command(result))}</pre>
      <p class="note">{_e(report_data.informational_note(result.target_stack))}</p>
    </section>"""


def _detail_section(result: TestRunResult) -> str:
    rows = []
    for t in result.tests:
        cls = _OUTCOME_CLASS[t.outcome]
        rows.append(
            f"<tr class='{cls}'><td><code>{_e(t.nodeid)}</code></td>"
            f"<td class='{cls}'>{_e(t.outcome.value)}</td>"
            f"<td>{t.duration_s:.3f}</td>"
            f"<td>{_e(t.message or '')}</td></tr>"
        )
    return (
        "<section><h2>Full results</h2>"
        "<table class='detail'><thead><tr><th>Test</th><th>Outcome</th>"
        "<th>Duration (s)</th><th>Message</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table></section>"
    )


def _appendix_catalog() -> str:
    blocks = []
    for group, specs in report_data.catalog_by_group():
        rows = "".join(
            f"<tr><td>{_e(s.test)}</td><td>{_e(s.description)}</td>"
            f"<td>{_e(s.rfc)}</td><td>{_e(s.role_labels)}</td></tr>"
            for s in specs
        )
        blocks.append(
            f"<h3>{_e(group)}</h3>"
            "<table class='catalog'><thead><tr><th>Test</th><th>What it checks</th>"
            "<th>RFC</th><th>Roles</th></tr></thead><tbody>"
            f"{rows}</tbody></table>"
        )
    return (
        "<section><h2>Appendix A — Test catalog</h2>"
        f"<p>{_e(report_data.CATALOG_INTRO)}</p>"
        + "".join(blocks)
        + "</section>"
    )


def _appendix_rfcs() -> str:
    items = "".join(
        f"<li><strong>{_e(label)}</strong>{(' — ' + _e(title)) if title else ''}</li>"
        for label, title in report_data.referenced_rfcs()
    )
    return (
        "<section><h2>Appendix B — RFC reference index</h2>"
        f"<p>{_e(report_data.RFC_INTRO)}</p>"
        f"<ul class='rfcs'>{items}</ul></section>"
    )


def _root_css() -> str:
    """The report's custom properties: the shared tokens plus the paper
    palette that only a printed document needs.

    Written as a function for the same reason `_palette_css()` is — the
    values come from `src/design_tokens.py`, so the app and its report
    cannot drift apart on what the accent colour is.
    """
    return ":root {\n" + design_tokens.css_variables() + """
  --ink: #16202c;
  --ink-muted: #5b6b7d;
  --paper: #ffffff;
  --ground: #f6f8fa;
  --rule: #dfe5ec;
}"""


_STYLE = """
* { box-sizing: border-box; }
body {
  font-family: var(--font-ui);
  margin: 0;
  padding: 2.5rem max(1.25rem, calc(50% - 32rem));
  line-height: 1.55;
  color: var(--ink);
  background: var(--ground);
  font-size: 15px;
}
h1 { font-size: 1.9rem; letter-spacing: -0.02em; margin: 0 0 0.2rem; }
h2 {
  font-size: 1.15rem; letter-spacing: -0.01em; margin: 0 0 0.9rem;
  padding-bottom: 0.45rem; border-bottom: 1px solid var(--rule);
}
h3 { font-size: 0.98rem; margin: 1.4rem 0 0.4rem; color: var(--ink); }
section {
  background: var(--paper); border: 1px solid var(--rule);
  border-radius: var(--radius); padding: 1.4rem 1.5rem; margin: 1.25rem 0;
}
table { border-collapse: separate; border-spacing: 0; width: 100%; margin: 0.5rem 0; }
td, th { padding: 7px 10px; font-size: 0.84rem; text-align: left; vertical-align: top;
         border-bottom: 1px solid var(--rule); }
th { background: var(--ground); color: var(--ink-muted); font-weight: 600;
     text-transform: uppercase; letter-spacing: 0.04em; font-size: 0.72rem;
     border-bottom: 1px solid var(--rule); }
tbody tr:last-child td { border-bottom: none; }
table.meta th { width: 11rem; text-transform: none; letter-spacing: 0; font-size: 0.84rem; }
code { font-family: var(--font-mono); font-size: 0.82em; word-break: break-all; }
pre { background: #0f141b; color: #e3e9f2; padding: 0.8rem 1rem;
      border-radius: var(--radius-small); overflow-x: auto; font-size: 0.8rem;
      font-family: var(--font-mono); }
.finding {
  border: 1px solid var(--rule); border-left: 4px solid; border-radius: var(--radius);
  padding: 0.9rem 1.1rem; margin: 0.8rem 0; background: var(--ground);
}
.finding-head { display: flex; gap: 0.6rem; align-items: baseline; flex-wrap: wrap; }
.finding-title { font-weight: 650; font-size: 1rem; }
.finding-rfc { margin-left: auto; color: var(--ink-muted); font-size: 0.78rem;
               white-space: nowrap; }
.finding-node code { color: var(--ink-muted); }
.finding-desc, .finding-msg { margin-top: 0.45rem; font-size: 0.87rem; }
.badge { font-size: 0.68rem; font-weight: 700; text-transform: uppercase;
         letter-spacing: 0.05em; padding: 2px 8px; border-radius: 999px; color: #fff; }
.pill { display: inline-block; padding: 2px 10px; border-radius: 999px;
        font-size: 0.78rem; font-weight: 600; margin-right: 5px; background: var(--ground);
        border: 1px solid var(--rule); }
.note { color: var(--ink-muted); font-size: 0.87rem; }
.lede { color: var(--ink-muted); font-size: 0.95rem; margin: 0 0 1.6rem; max-width: 44rem; }
ul.rfcs li { margin: 0.25rem 0; }
@media print {
  body { background: #fff; padding: 0; font-size: 12px; }
  section { border: none; padding: 0; margin: 1rem 0; break-inside: avoid; }
  .finding { break-inside: avoid; }
}
"""


def generate_html_report(result: TestRunResult, output_path: Path) -> Path:
    html_doc = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>Netstack DUT Report — {_e(result.run_id)}</title>
<style>{_root_css()}
{_STYLE}
{_palette_css()}</style></head>
<body>
<h1>Network Stack Conformance Report</h1>
<p class="lede">{_e(report_data.PURPOSE)}</p>
{_summary_section(result)}
{_findings_section(result)}
{_artifacts_section(result)}
{_detail_section(result)}
{_appendix_catalog()}
{_appendix_rfcs()}
</body></html>
"""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html_doc, encoding="utf-8")
    return output_path
