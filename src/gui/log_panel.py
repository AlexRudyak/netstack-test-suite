"""Live log/output viewer, fed by RunController's output_line and
test_event signals."""
from __future__ import annotations

from PySide6.QtWidgets import QPlainTextEdit

from src.reporting.models import TestEvent


class LogPanel(QPlainTextEdit):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setReadOnly(True)
        self.setMaximumBlockCount(10_000)

    def append_line(self, text: str) -> None:
        self.appendPlainText(text)

    def append_test_event(self, event: TestEvent) -> None:
        self.appendPlainText(event.summary_line(label_width=5))

    def clear_log(self) -> None:
        self.clear()
