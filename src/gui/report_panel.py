"""Report panel: triggers PDF/HTML export for the most recently completed
run and shows the resulting output path."""
from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from PySide6.QtWidgets import QFileDialog, QHBoxLayout, QLabel, QPushButton, QVBoxLayout, QWidget

from src.reporting.html_report import generate_html_report
from src.reporting.models import TestRunResult
from src.reporting.pdf_report import generate_pdf_report
from src.run_artifacts import RunArtifacts
from src.runner import reports_dir


class ReportPanel(QWidget):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._result: TestRunResult | None = None

        self._status_label = QLabel("No completed run yet.")
        pdf_button = QPushButton("Export PDF")
        pdf_button.clicked.connect(self._export_pdf)
        html_button = QPushButton("Export HTML")
        html_button.clicked.connect(self._export_html)

        buttons = QHBoxLayout()
        buttons.addWidget(pdf_button)
        buttons.addWidget(html_button)

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

    def _export(self, *, suffix: str, label: str, generate: Callable[..., Path]) -> None:
        """Ask for a destination, generate, and report where it landed.

        The PDF and HTML exports differ only in extension, dialog wording,
        and which generator runs, so they share one flow.
        """
        if self._result is None:
            return
        default_path = RunArtifacts(reports_dir() / self._result.run_id).report(suffix)
        path_str, _ = QFileDialog.getSaveFileName(
            self, f"Export {label} report", str(default_path), f"{label} files (*.{suffix})"
        )
        if path_str:
            output = generate(self._result, Path(path_str))
            self._status_label.setText(f"{label} written to {output}")

    def _export_pdf(self) -> None:
        self._export(suffix="pdf", label="PDF", generate=generate_pdf_report)

    def _export_html(self) -> None:
        self._export(suffix="html", label="HTML", generate=generate_html_report)
