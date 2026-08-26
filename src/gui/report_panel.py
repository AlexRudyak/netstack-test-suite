"""Report panel: triggers PDF/HTML export for the most recently completed
run and shows the resulting output path."""
from __future__ import annotations

from pathlib import Path

from PySide6.QtWidgets import QFileDialog, QHBoxLayout, QLabel, QPushButton, QVBoxLayout, QWidget

from src.reporting.html_report import generate_html_report
from src.reporting.models import TestRunResult
from src.reporting.pdf_report import generate_pdf_report
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
            summary = (
                f"{result.passed} passed, {result.failed} failed, "
                f"{result.errors} errored, {result.skipped} skipped, {result.total} total."
            )
        self._status_label.setText(f"Run {result.run_id}: {summary}")

    def _export_pdf(self) -> None:
        if self._result is None:
            return
        default_path = reports_dir() / self._result.run_id / "report.pdf"
        path_str, _ = QFileDialog.getSaveFileName(
            self, "Export PDF report", str(default_path), "PDF files (*.pdf)"
        )
        if path_str:
            output = generate_pdf_report(self._result, Path(path_str))
            self._status_label.setText(f"PDF written to {output}")

    def _export_html(self) -> None:
        if self._result is None:
            return
        default_path = reports_dir() / self._result.run_id / "report.html"
        path_str, _ = QFileDialog.getSaveFileName(
            self, "Export HTML report", str(default_path), "HTML files (*.html)"
        )
        if path_str:
            output = generate_html_report(self._result, Path(path_str))
            self._status_label.setText(f"HTML written to {output}")
