"""HTML report — a developer-oriented document for fixing the DUT stack.

Leads with the failures (each tied to its RFC clause and what it tests),
then the full per-test results, then appendices: the complete test catalog
and the RFC reading list. The PDF report (pdf_report.py) mirrors this.
"""
from __future__ import annotations

import html
from pathlib import Path

from src.reporting import report_data
from src.reporting.models import TestOutcome, TestRunResult

_OUTCOME_CLASS = {
    TestOutcome.PASSED: "passed",
    TestOutcome.FAILED: "failed",
    TestOutcome.ERROR: "error",
    TestOutcome.SKIPPED: "skipped",
}


def _e(text: object) -> str:
    return html.escape(str(text if text is not None else ""))


def _findings_section(result: TestRunResult) -> str:
    findings = report_data.build_findings(result)
    if not findings:
        return (
            "<section><h2>Findings</h2>"
            "<p class='ok'>No failures or errors — every test that ran passed. "
            "See the full results and appendix below.</p></section>"
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
        f"<p>{len(findings)} test(s) failed or errored, listed most-severe first. "
        "Each names the RFC clause it exercises, what it checks, and what the DUT actually did.</p>"
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


def _artifacts_section(result: TestRunResult) -> str:
    return f"""
    <section>
      <h2>Artifacts &amp; reproduction</h2>
      <p>For wire-level analysis, open the packet capture from this run's folder
      (<code>reports/{_e(result.run_id)}/</code>) in Wireshark:</p>
      <ul>
        <li><code>capture.pcap</code> — every frame the suite sent and received.</li>
        <li><code>debug.log</code> — tshark-style per-packet trace (present only if Debug mode was on).</li>
        <li><code>pytest_output.log</code> — raw test-runner output.</li>
        <li><code>results.json</code> — this run in machine-readable form.</li>
      </ul>
      <p>Reproduce this run:</p>
      <pre>{_e(report_data.reproduction_command(result))}</pre>
      <p class="note">Note: <em>informational</em> checks (e.g. advertised window size) compare the DUT
      against the selected <strong>{_e(result.target_stack)}</strong> stack profile — a mismatch flags a
      behavioural difference, not necessarily an RFC violation.</p>
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
        "<p>Every test in the suite, what it checks, the RFC clause it maps to, and which "
        "role(s) it runs in. Use this to map a finding to the spec and to see what else is covered.</p>"
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
        "<p>Specifications exercised by this suite — the reading list for interpreting the findings.</p>"
        f"<ul class='rfcs'>{items}</ul></section>"
    )


_STYLE = """
:root { color-scheme: light dark; }
body { font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 2rem; line-height: 1.45; color: #1a1a1a; }
h1 { margin-bottom: 0.2rem; }
h2 { margin-top: 2rem; border-bottom: 2px solid #ddd; padding-bottom: 0.2rem; }
h3 { margin-top: 1.2rem; color: #333; }
table { border-collapse: collapse; width: 100%; margin: 0.5rem 0; }
td, th { border: 1px solid #ccc; padding: 5px 8px; font-size: 0.85rem; text-align: left; vertical-align: top; }
th { background: #333; color: #fff; }
table.meta th { width: 12rem; background: #f4f4f4; color: #222; }
code { font-family: ui-monospace, Consolas, monospace; font-size: 0.82rem; word-break: break-all; }
pre { background: #f4f4f4; padding: 0.6rem; border-radius: 4px; overflow-x: auto; font-size: 0.82rem; }
tr.failed, td.failed { background: #ffebee; }
tr.error, td.error { background: #f3e5f5; }
tr.passed td.passed { background: #e8f5e9; }
tr.skipped, td.skipped { background: #f5f5f5; }
td.passed { color: #1a7f37; } td.failed { color: #b71c1c; } td.error { color: #8a1a9b; } td.skipped { color: #616161; }
.finding { border: 1px solid #ddd; border-left: 5px solid #b71c1c; border-radius: 5px; padding: 0.7rem 0.9rem; margin: 0.7rem 0; background: #fff; }
.finding.error { border-left-color: #8a1a9b; }
.finding-head { display: flex; gap: 0.6rem; align-items: baseline; flex-wrap: wrap; }
.finding-title { font-weight: 700; font-size: 1.02rem; }
.finding-rfc { margin-left: auto; color: #555; font-size: 0.82rem; }
.finding-node code { color: #444; }
.finding-desc, .finding-msg { margin-top: 0.3rem; font-size: 0.88rem; }
.badge { font-size: 0.72rem; font-weight: 700; text-transform: uppercase; padding: 1px 7px; border-radius: 10px; color: #fff; }
.badge.failed { background: #b71c1c; } .badge.error { background: #8a1a9b; }
.pill { display: inline-block; padding: 1px 9px; border-radius: 10px; font-size: 0.8rem; margin-right: 4px; background: #eee; }
.pill.passed { background: #e8f5e9; color: #1a7f37; } .pill.failed { background: #ffebee; color: #b71c1c; }
.pill.error { background: #f3e5f5; color: #8a1a9b; } .pill.skipped { background: #f5f5f5; color: #616161; }
.note { color: #555; font-size: 0.85rem; }
.ok { color: #1a7f37; font-weight: 600; }
ul.rfcs li { margin: 0.2rem 0; }
@media (prefers-color-scheme: dark) {
  body { background: #1e1e1e; color: #e6e6e6; }
  h2 { border-color: #444; } h3 { color: #ccc; }
  td, th { border-color: #444; } table.meta th { background: #2a2a2a; color: #ddd; }
  .finding { background: #262626; border-color: #444; } pre, td.passed { }
}
"""


def generate_html_report(result: TestRunResult, output_path: Path) -> Path:
    html_doc = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>Netstack DUT Report — {_e(result.run_id)}</title>
<style>{_STYLE}</style></head>
<body>
<h1>Network Stack Conformance Report</h1>
<p class="note">Purpose: findings for a developer to fix the DUT's network stack. Failures first, full results next, spec references in the appendix.</p>
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
