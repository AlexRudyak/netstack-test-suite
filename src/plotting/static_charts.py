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

from src.reporting.models import PacketDirection, TestRunResult  # noqa: E402


def render_packet_timeline(result: TestRunResult, output_path: Path) -> Path:
    events = sorted(result.packet_events, key=lambda e: e.timestamp)
    start = events[0].timestamp if events else 0.0

    elapsed: list[float] = []
    sent_cum: list[int] = []
    recv_cum: list[int] = []
    sent = recv = 0
    for event in events:
        if event.direction is PacketDirection.SENT:
            sent += 1
        else:
            recv += 1
        elapsed.append(event.timestamp - start)
        sent_cum.append(sent)
        recv_cum.append(recv)

    fig, ax = plt.subplots(figsize=(7, 3.5))
    ax.plot(elapsed, sent_cum, label="Sent", color="tab:green")
    ax.plot(elapsed, recv_cum, label="Received", color="tab:blue")
    ax.set_xlabel("Elapsed (s)")
    ax.set_ylabel("Cumulative packets")
    ax.set_title(f"Packet timeline — run {result.run_id}")
    ax.legend()
    fig.tight_layout()

    output_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output_path, dpi=150)
    plt.close(fig)
    return output_path


def render_pass_fail_summary(result: TestRunResult, output_path: Path) -> Path:
    fig, ax = plt.subplots(figsize=(4, 3.5))
    other = max(result.total - result.passed - result.failed, 0)
    ax.bar(
        ["Passed", "Failed", "Skipped/Error"],
        [result.passed, result.failed, other],
        color=["tab:green", "tab:red", "tab:gray"],
    )
    ax.set_ylabel("Test count")
    ax.set_title(f"Results — run {result.run_id}")
    fig.tight_layout()

    output_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output_path, dpi=150)
    plt.close(fig)
    return output_path
