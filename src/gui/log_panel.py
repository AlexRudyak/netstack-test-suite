"""Live log/output viewer, fed by RunController's output_line and
test_event signals.

Outcome lines are inked by the shared run palette rather than left as one
undifferentiated wall of text: in a run of a hundred tests the four
failures are what the operator is scanning for, and a monospaced, coloured
line finds them without reading.
"""
from __future__ import annotations

from PySide6.QtGui import QColor, QTextCharFormat
from PySide6.QtWidgets import QPlainTextEdit

from src.design_tokens import OUTCOME_INK, TEXT_MUTED
from src.reporting.models import TestEvent


class LogPanel(QPlainTextEdit):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setReadOnly(True)
        self.setMaximumBlockCount(10_000)
        # Monospaced on a sunken well — see `gui/theme.py`. Wire-level
        # summaries and nodeids are column-aligned data, not prose.
        self.setProperty("role", "console")
        self.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.setPlaceholderText("Run output appears here.")

    def append_line(self, text: str) -> None:
        # Indented continuation lines are the preflight's own detail lines;
        # muting them keeps the top-level narrative readable.
        self._append(text, TEXT_MUTED if text.startswith("  ") else None)

    def append_test_event(self, event: TestEvent) -> None:
        self._append(event.summary_line(label_width=5), OUTCOME_INK.get(event.outcome.value))

    def clear_log(self) -> None:
        self.clear()

    def _append(self, text: str, colour: str | None) -> None:
        """Append one line, optionally inked.

        `appendPlainText` would apply the cursor's current format, so the
        format is set per line and the cursor is left at the end for the
        auto-scroll to follow.
        """
        cursor = self.textCursor()
        cursor.movePosition(cursor.MoveOperation.End)
        fmt = QTextCharFormat()
        if colour is not None:
            fmt.setForeground(QColor(colour))
        if self.document().blockCount() > 1 or self.document().firstBlock().length() > 1:
            cursor.insertBlock()
        cursor.insertText(text, fmt)
        self.setTextCursor(cursor)
        self.ensureCursorVisible()
