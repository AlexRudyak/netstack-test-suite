"""Report panel: triggers PDF/HTML export for the most recently completed
run and shows the resulting output path."""
from __future__ import annotations

from pathlib import Path

from PySide6.QtWidgets import QFileDialog, QHBoxLayout, QLabel, QPushButton, QVBoxLayout, QWidget

from src.reporting import formats
from src.reporting.formats import ReportFormat
from src.reporting.models import TestRunResult
from src.run_artifacts import RunArtifacts
from src.runner import reports_dir


class ReportPanel(QWidget):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._result: TestRunResult | None = None

        self._status_label = QLabel("No completed run yet.")

        # One button per declared format. `_checked` absorbs the bool Qt
        # passes first, and `fmt=fmt` binds this iteration's format rather
        # than closing over the loop variable.
        buttons = QHBoxLayout()
        for fmt in formats.FORMATS:
            button = QPushButton(f"Export {fmt.label}")
            button.clicked.connect(lambda _checked=False, fmt=fmt: self._export(fmt))
            buttons.addWidget(button)

        layout = QVBoxLayout(self)
        layout.addWidget(self._status_label)
        layout.addLayout(buttons)

    def set_result(self, result: TestRunResult) -> None:
        self._result = result
        if result.errored:
            summary = (
                f"pytest exited with code {result.pytest_returncode} "
                "(collection/usage error or no tests) — see the Log tab."
            )
        elif result.total == 0:
            summary = "no tests ran — check the test selection and configuration."
        else:
            summary = f"{result.counts_summary}."
        self._status_label.setText(f"Run {result.run_id}: {summary}")

    def _export(self, fmt: ReportFormat) -> None:
        """Ask for a destination, generate, and report where it landed.

        The formats differ only in extension, dialog wording and generator —
        all three of which the ReportFormat carries, so this is the whole
        export flow for every format there is.
        """
        if self._result is None:
            return
        default_path = RunArtifacts(reports_dir() / self._result.run_id).report(fmt.key)
        path_str, _ = QFileDialog.getSaveFileName(
            self,
            f"Export {fmt.label} report",
            str(default_path),
            f"{fmt.label} files (*.{fmt.key})",
        )
        if path_str:
            output = fmt.generate(self._result, Path(path_str))
            self._status_label.setText(f"{fmt.label} written to {output}")
