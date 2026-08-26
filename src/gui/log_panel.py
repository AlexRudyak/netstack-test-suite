"""Live log/output viewer, fed by RunController's output_line and
test_event signals."""
from __future__ import annotations

from PySide6.QtWidgets import QPlainTextEdit

from src.reporting.models import TestEvent, TestOutcome

_OUTCOME_PREFIX = {
    TestOutcome.PASSED: "PASS",
    TestOutcome.FAILED: "FAIL",
    TestOutcome.SKIPPED: "SKIP",
    TestOutcome.ERROR: "ERR",
}


class LogPanel(QPlainTextEdit):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setReadOnly(True)
        self.setMaximumBlockCount(10_000)

    def append_line(self, text: str) -> None:
        self.appendPlainText(text)

    def append_test_event(self, event: TestEvent) -> None:
        prefix = _OUTCOME_PREFIX.get(event.outcome, "?")
        line = f"[{prefix:5}] {event.nodeid} ({event.duration_s:.3f}s)"
        if event.message:
            line += f" — {event.message}"
        self.appendPlainText(line)

    def clear_log(self) -> None:
        self.clear()
