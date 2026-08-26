"""Result collection helpers used inside the pytest subprocess, and for
regenerating reports from a past run without re-executing any tests.

PacketEventLogWriter is wired as NetworkInterface's on_packet callback
(see tests/conftest.py) — it appends one JSON line per packet event,
flushed immediately, which src/runner.py tails from the parent process to
drive the GUI's live plot.
"""
from __future__ import annotations

import json
from pathlib import Path

from src.reporting.models import PacketEvent, TestRunResult


class PacketEventLogWriter:
    """Appends PacketEvents as JSON lines, flushing immediately so a
    tailing reader (src/runner.py, in the parent process) sees them
    promptly rather than waiting on OS write buffering."""

    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._file = path.open("a", encoding="utf-8")

    def __call__(self, event: PacketEvent) -> None:
        self._file.write(json.dumps(event.to_dict()) + "\n")
        self._file.flush()

    def close(self) -> None:
        self._file.close()


def load_run_result(run_dir: Path) -> TestRunResult:
    """Re-open a past run's results.json — used to regenerate a PDF/HTML
    report without re-running the suite against the DUT."""
    data = json.loads((run_dir / "results.json").read_text(encoding="utf-8"))
    return TestRunResult.from_dict(data)
