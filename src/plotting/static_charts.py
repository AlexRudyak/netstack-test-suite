"""Static chart rendering for PDF report embedding (matplotlib, Agg backend).

Separate from realtime_plotter.py on purpose: live display needs
pyqtgraph's frame-rate performance inside the Qt event loop; report
generation just needs one PNG per run with no interactivity or threading
concerns, so matplotlib's Agg backend (works headless, no GUI deps) is
the simpler, standard tool for that job.
"""
from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

from src.plotting.metrics import MetricsBuffer  # noqa: E402
from src.reporting.models import OUTCOME_STYLE, TestOutcome, TestRunResult  # noqa: E402

CHART_DPI = 150


def _save(fig, output_path: Path) -> Path:
    """Write a figure out and release it.

    matplotlib figures are not garbage-collected promptly, and a report
    renders several per run, so every chart closes its own figure.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output_path, dpi=CHART_DPI)
    plt.close(fig)
    return output_path


def render_packet_timeline(result: TestRunResult, output_path: Path) -> Path:
    # Replay the events through the same accumulator the live plot uses, so
    # the report's timeline and the GUI's plot can't compute "cumulative"
    # differently.
    buffer = MetricsBuffer()
    for event in sorted(result.packet_events, key=lambda e: e.timestamp):
        buffer.add(event)
    snap = buffer.snapshot()

    fig, ax = plt.subplots(figsize=(7, 3.5))
    ax.plot(snap.elapsed_s, snap.sent_cumulative, label="Sent", color="tab:green")
    ax.plot(snap.elapsed_s, snap.received_cumulative, label="Received", color="tab:blue")
    ax.set_xlabel("Elapsed (s)")
    ax.set_ylabel("Cumulative packets")
    ax.set_title(f"Packet timeline — run {result.run_id}")
    ax.legend()
    fig.tight_layout()

    return _save(fig, output_path)


def render_pass_fail_summary(result: TestRunResult, output_path: Path) -> Path:
    fig, ax = plt.subplots(figsize=(4, 3.5))
    other = max(result.total - result.passed - result.failed, 0)
    ax.bar(
        ["Passed", "Failed", "Skipped/Error"],
        [result.passed, result.failed, other],
        # Same outcome palette the HTML and PDF reports use.
        color=[
            OUTCOME_STYLE[TestOutcome.PASSED]["mpl"],
            OUTCOME_STYLE[TestOutcome.FAILED]["mpl"],
            OUTCOME_STYLE[TestOutcome.SKIPPED]["mpl"],
        ],
    )
    ax.set_ylabel("Test count")
    ax.set_title(f"Results — run {result.run_id}")
    fig.tight_layout()

    return _save(fig, output_path)
