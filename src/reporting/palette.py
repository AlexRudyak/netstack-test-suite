"""Outcome → presentation, in one table.

Every renderer reads its own column here rather than re-typing the palette:
the HTML report's CSS class and hex values, the PDF's text/background
colours, and the matplotlib bar colour.

Kept out of `models.py` so the result model stays free of presentation.
`models` is imported by the runner, the collector, the packet interface,
the metrics buffer and every GUI panel — none of which render a report, and
all of which used to carry the stylesheet transitively.
"""
from __future__ import annotations

from src.reporting.models import TestOutcome

# There is deliberately no short-label column. One existed ("PASS"/"FAIL"/
# "ERR"/"SKIP") and was read by nothing; wiring it into
# TestEvent.summary_line would have made models.py import this module,
# which is the dependency this split exists to remove.
OUTCOME_STYLE: dict[TestOutcome, dict[str, str]] = {
    TestOutcome.PASSED: {
        "css": "passed", "fg": "#1a7f37", "bg": "#e8f5e9", "mpl": "tab:green",
    },
    TestOutcome.FAILED: {
        "css": "failed", "fg": "#b71c1c", "bg": "#ffebee", "mpl": "tab:red",
    },
    TestOutcome.ERROR: {
        "css": "error", "fg": "#8a1a9b", "bg": "#f3e5f5", "mpl": "tab:purple",
    },
    TestOutcome.SKIPPED: {
        "css": "skipped", "fg": "#616161", "bg": "#f5f5f5", "mpl": "tab:gray",
    },
}
