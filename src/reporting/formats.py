"""The report formats the app can produce, in one table.

Both front ends read this rather than each spelling out the format list.
Before it, four places knew that list: the CLI's `--report` choices, the
CLI's `if report == "pdf" … elif "html"` dispatch, and the GUI's two
near-identical `_export_pdf` / `_export_html` wrappers — even though
`ReportPanel._export` had already been parameterised over the generator
and just had no table to drive it.

Every generator has the same `(result, output_path) -> path` signature, so
adding a format is one entry here plus its generator module.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from src.reporting.html_report import generate_html_report
from src.reporting.models import TestRunResult
from src.reporting.pdf_report import generate_pdf_report

Generator = Callable[[TestRunResult, Path], Path]

# The CLI's opt-out. Not a format, so it is deliberately not an entry
# below — it is the absence of one.
NO_REPORT = "none"


@dataclass(frozen=True)
class ReportFormat:
    key: str  # the --report value, and the file extension
    label: str  # human name, for the GUI's button and save dialog
    generate: Generator


FORMATS: tuple[ReportFormat, ...] = (
    ReportFormat("pdf", "PDF", generate_pdf_report),
    ReportFormat("html", "HTML", generate_html_report),
)

BY_KEY: dict[str, ReportFormat] = {fmt.key: fmt for fmt in FORMATS}

# What `--report` accepts: every format, plus the opt-out.
CLI_CHOICES: list[str] = [*BY_KEY, NO_REPORT]
