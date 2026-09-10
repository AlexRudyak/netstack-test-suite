"""The one description of what a run directory contains.

A run produces eight files, and before this module every one of their
names was a string literal repeated across `runner.py`, `run_controller.py`,
`collector.py`, `cli/main.py` and `report_data.py` — including
`report_data.ARTIFACTS`, whose whole job is telling a report's reader what
a run produced, and which was therefore a fourth independent copy of the
same names.

The read/write split was the sharper edge: `results.json` was serialized in
`runner.finalize_run` and deserialized in `reporting.collector`, in
different packages, with no import between them and no shared constant.

Everything that produces or consumes a run's files addresses them through
here, so a rename is one edit and the report's artifact list cannot drift
from what was actually written.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar

from src.reporting.models import TestRunResult


@dataclass(frozen=True)
class RunArtifacts:
    """The files of one run directory, addressed by name rather than literal.

    Cheap to construct (it is a frozen wrapper around a `Path`), so callers
    build one where they need it rather than threading it through.
    """

    root: Path

    # Names are plain class attributes, not dataclass fields — they have no
    # annotation, so `root` stays the only field.
    RESULTS = "results.json"
    REPORT_LOG = "report_log.jsonl"
    PACKET_EVENTS = "packet_events.jsonl"
    CAPTURE = "capture.pcap"
    DEBUG_LOG = "debug.log"
    PYTEST_OUTPUT = "pytest_output.log"

    # (filename, what it holds) for the reports' artifacts section —
    # generated from the same names the runner actually writes.
    DESCRIPTIONS: ClassVar[tuple[tuple[str, str], ...]] = (
        (CAPTURE, "every frame the suite sent and received."),
        (DEBUG_LOG, "tshark-style per-packet trace (present only if Debug mode was on)."),
        (PYTEST_OUTPUT, "raw test-runner output."),
        (RESULTS, "this run in machine-readable form."),
    )

    @property
    def results(self) -> Path:
        """The run in machine-readable form; `load()` reads it back."""
        return self.root / self.RESULTS

    @property
    def report_log(self) -> Path:
        """pytest's --report-log stream, tailed for live test progress."""
        return self.root / self.REPORT_LOG

    @property
    def packet_events(self) -> Path:
        """Live PacketEvent JSON lines, tailed for the GUI's realtime plot."""
        return self.root / self.PACKET_EVENTS

    @property
    def capture(self) -> Path:
        """pcap of every frame the suite programmatically sent/received."""
        return self.root / self.CAPTURE

    @property
    def debug_log(self) -> Path:
        """tshark-style per-packet trace; written only in debug mode."""
        return self.root / self.DEBUG_LOG

    @property
    def pytest_output(self) -> Path:
        """The subprocess's raw stdout/stderr — where a collection or usage
        error explains itself when a run appears to do nothing."""
        return self.root / self.PYTEST_OUTPUT

    def report(self, suffix: str) -> Path:
        """The default destination for a generated report of this format."""
        return self.root / f"report.{suffix}"

    # --- results.json, written and read in one place -----------------------

    def save(self, result: TestRunResult) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        self.results.write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")

    def load(self) -> TestRunResult:
        return TestRunResult.from_dict(json.loads(self.results.read_text(encoding="utf-8")))
