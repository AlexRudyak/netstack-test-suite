"""Report panel: triggers PDF/HTML export for the most recently completed
run and shows the resulting output path."""
from __future__ import annotations

import logging
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QWidget,
)

from src.design_tokens import SPACE
from src.gui.theme import refresh_style
from src.reporting import formats
from src.reporting.formats import ReportFormat
from src.reporting.models import TestRunResult
from src.run_artifacts import RunArtifacts
from src.runner import reports_dir

log = logging.getLogger(__name__)


class ReportPanel(QWidget):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._result: TestRunResult | None = None
        self._buttons: list[QPushButton] = []

        # A footer bar rather than a stacked label-over-buttons block: the
        # run verdict and the two things you do with it belong on one line,
        # and a full-width row of export buttons read as the window's
        # primary action, which they are not.
        self.setObjectName("reportFooter")
        # A QWidget subclass that does not paint itself ignores a
        # stylesheet background unless it asks for one.
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self._status_label = QLabel("No completed run yet.")
        self._status_label.setProperty("state", "idle")
        self._status_label.setWordWrap(True)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(SPACE + 4, SPACE, SPACE + 4, SPACE)
        layout.setSpacing(SPACE)
        layout.addWidget(self._status_label, stretch=1)

        # One button per declared format. `_checked` absorbs the bool Qt
        # passes first, and `fmt=fmt` binds this iteration's format rather
        # than closing over the loop variable. The first format is the
        # accented one — the report is the deliverable a run exists for.
        for index, fmt in enumerate(formats.FORMATS):
            button = QPushButton(f"Export {fmt.label}")
            button.setProperty("accent", "true" if index == 0 else "false")
            # Nothing to export until a run completes, and a save dialog
            # that opens onto no data is a worse answer than a disabled
            # button.
            button.setEnabled(False)
            button.clicked.connect(lambda _checked=False, fmt=fmt: self._export(fmt))
            layout.addWidget(button)
            self._buttons.append(button)

    def set_result(self, result: TestRunResult) -> None:
        self._result = result
        for button in self._buttons:
            button.setEnabled(True)
        if result.errored:
            summary = (
                f"pytest exited with code {result.pytest_returncode} "
                "(collection/usage error or no tests) — see the Log tab."
            )
        elif result.total == 0:
            summary = "no tests ran — check the test selection and configuration."
        else:
            summary = f"{result.counts_summary}."
        self._set_status(
            f"Run {result.run_id}: {summary}",
            "bad" if result.errored or result.failed or result.errors or not result.total else "ok",
        )

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
        if not path_str:
            return
        try:
            output = fmt.generate(self._result, Path(path_str))
        except Exception as exc:
            # This is a `clicked` slot, and the save dialog lets the operator
            # pick any destination — including one they can't write to. An
            # exception leaving here reaches sys.excepthook and takes the
            # window with it, over a failed export of a run whose data is
            # already safely on disk.
            log.exception("Report export failed")
            self._set_status(f"Could not write the {fmt.label} report: {exc}", "bad")
            QMessageBox.warning(
                self,
                f"{fmt.label} export failed",
                f"{exc}\n\nThe run's data is unaffected — try a different location.",
            )
            return
        self._set_status(f"{fmt.label} written to {output}", "ok")

    def _set_status(self, text: str, state: str) -> None:
        """One place the footer's line and its ink are set together, so a
        red message can never be left wearing the previous green."""
        self._status_label.setText(text)
        self._status_label.setProperty("state", state)
        refresh_style(self._status_label)
