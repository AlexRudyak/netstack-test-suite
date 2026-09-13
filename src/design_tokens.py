"""The one place the interface's colours, spacing and type are written down.

Every surface the operator looks at — the Qt widgets, the live plot, the
generated HTML report — reads its values from here, so a palette change
lands everywhere at once instead of in whichever file happened to be
edited. The GUI's Qt stylesheet is built from these in
`src/gui/theme.py`; the plot pens come from `PLOT`; the report's CSS
variables come from `css_variables()`.

Deliberately import-free (and Qt-free): this is the leaf of the import
graph, so the engine, the reporting layer and the front ends can all agree
on one palette without any of them depending on a GUI toolkit.

The scheme is a single, committed dark one rather than a pair that follows
the desktop theme. The suite is an instrument panel — a log, a live plot
and a wall of packet fields, usually read next to Wireshark — and one
tuned scheme keeps the plot, the widgets and the outcome colours in a
relationship we can actually verify.

Outcome colours are the dark-background counterparts of the light-document
hexes in `src/reporting/palette.py`: same semantics (green/red/purple/grey
for passed/failed/errored/skipped), lifted to stay legible on a dark
surface, where that module's document inks go muddy.
"""
from __future__ import annotations

from typing import Final

# --- Surfaces, in depth order ------------------------------------------
# canvas < surface < raised: each step is a lighter slate, so panels read
# as stacked without a single hard border doing all the work.
CANVAS: Final = "#10141b"       # the window behind everything
SURFACE: Final = "#171d26"      # panels, group boxes, tab pages
SURFACE_RAISED: Final = "#1e2632"  # inputs, hovered rows, headers
SURFACE_SUNKEN: Final = "#0c1016"  # log/console wells, the plot bed

BORDER: Final = "#2b3644"       # ordinary separators
BORDER_STRONG: Final = "#3a4756"  # hovered inputs, splitter grips

# --- Ink ----------------------------------------------------------------
TEXT: Final = "#e3e9f2"         # primary copy
TEXT_MUTED: Final = "#95a3b8"   # labels, secondary metadata
TEXT_FAINT: Final = "#6a798e"   # placeholders, disabled

# --- Accent -------------------------------------------------------------
ACCENT: Final = "#38bdf8"
ACCENT_HOVER: Final = "#62cdfb"
ACCENT_PRESSED: Final = "#0ea5e9"
ACCENT_SOFT: Final = "#16324a"   # tinted fill behind selections
ACCENT_INK: Final = "#04141f"    # text drawn *on* the accent

# --- Semantics ----------------------------------------------------------
SUCCESS: Final = "#4ade80"
DANGER: Final = "#f87171"
DANGER_HOVER: Final = "#fb8f8f"
WARNING: Final = "#fbbf24"
INFO: Final = "#c084fc"
NEUTRAL: Final = "#94a3b8"

#: Run outcome -> ink, by the outcome's lowercase name. Keyed by string so
#: this module stays free of `src.reporting.models`; the GUI maps its
#: `TestOutcome` through `OUTCOME_INK[outcome.value]`.
OUTCOME_INK: Final[dict[str, str]] = {
    "passed": SUCCESS,
    "failed": DANGER,
    "error": INFO,
    "skipped": NEUTRAL,
}

# --- Plot ---------------------------------------------------------------
#: Pens and bed for the live pyqtgraph plot. Sent/received are two hues
#: apart rather than two shades of one, so the curves stay separable on a
#: projector and in a printed report.
PLOT: Final[dict[str, str]] = {
    "background": SURFACE_SUNKEN,
    "foreground": TEXT_MUTED,
    "grid": BORDER,
    "sent": ACCENT,
    "received": "#f0a4d8",
}

# --- Metrics ------------------------------------------------------------
RADIUS: Final = 7       # cards, inputs, buttons
RADIUS_SMALL: Final = 4  # indicators, chips
SPACE: Final = 8        # the base spacing unit; layouts use 1x, 1.5x, 2x

# --- Type ---------------------------------------------------------------
# Every family here is one that actually ships somewhere we run. Qt's
# stylesheet parser takes the first *existing* family, and a lead name
# that exists nowhere (Windows 11's "Segoe UI Variable Text" is not a
# registered family) renders as tofu under some platform plugins rather
# than falling through to the next entry.
FONT_UI: Final = '"Segoe UI", Inter, Ubuntu, "Noto Sans", "DejaVu Sans", sans-serif'
FONT_MONO: Final = '"Cascadia Mono", "JetBrains Mono", "SF Mono", Consolas, "DejaVu Sans Mono", monospace'
FONT_SIZE_PT: Final = 10       # base UI size
FONT_SIZE_SMALL_PT: Final = 9  # metadata, chips, the status line


def css_variables() -> str:
    """The palette as CSS custom properties, for the HTML report.

    The report is a light document (it gets printed and pasted into
    tickets), so it takes the accent and the semantic hues from here and
    keeps its own paper-coloured surfaces — the tokens that must not drift
    between the app and its output are the ones that carry meaning.
    """
    return "\n".join(
        f"  --{name}: {value};"
        for name, value in (
            ("accent", ACCENT_PRESSED),
            ("accent-soft", "#e6f4fb"),
            ("radius", f"{RADIUS}px"),
            ("radius-small", f"{RADIUS_SMALL}px"),
            ("font-ui", FONT_UI),
            ("font-mono", FONT_MONO),
        )
    )
