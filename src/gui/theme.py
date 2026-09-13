"""The GUI's visual layer: one Qt stylesheet built from `design_tokens`.

`apply_theme(app)` is the single call that dresses the whole application —
every window, panel and dialog inherits it, so no widget carries a
stylesheet of its own beyond the semantic *properties* documented below.

Three things have to happen together for a Qt app to look deliberate
rather than like the host's default theme applied to a form:

1. **A known base style.** Fusion, always — a stylesheet tuned against
   Windows' native style falls apart under GNOME's and vice versa.
2. **A palette as well as a stylesheet.** QSS does not reach the widgets
   Qt paints itself (menus, tooltips, text selection, the file dialog), so
   those follow `QPalette`; the stylesheet only refines what QSS can style.
3. **Drawn indicators.** Styling a check box or a combo arrow in QSS
   replaces Qt's painted glyph with nothing, so the glyphs are rendered
   here into small pixmaps (with `@2x` companions, which Qt picks up on
   HiDPI screens) and referenced by path.

## Semantic properties

Widgets opt into a role instead of carrying colours:

| Property | Effect |
|---|---|
| `accent="true"` on a `QPushButton` | filled primary action (Run, Send, Export) |
| `danger="true"` on a `QPushButton` | destructive/stop action, red outline |
| `role="heading"` / `"subheading"` / `"caption"` on a `QLabel` | type scale |
| `role="chip"` on a `QLabel` | pill-shaped metadata badge |
| `state="ok"` / `"bad"` / `"idle"` on a `QLabel` | status ink |
| `role="console"` on a text view | monospaced, sunken well |

A property set after the widget is polished needs `refresh_style(widget)`
for the new rule to take effect — that is Qt's rule, not ours.
"""
from __future__ import annotations

import tempfile
from functools import lru_cache
from pathlib import Path

from PySide6.QtCore import QPointF, Qt
from PySide6.QtGui import QColor, QFont, QPainter, QPainterPath, QPalette, QPen, QPixmap
from PySide6.QtWidgets import QApplication, QFormLayout, QFrame, QWidget

from src import design_tokens as t


def apply_theme(app: QApplication) -> None:
    """Dress `app` — base style, palette, default font, stylesheet.

    Call once, before the first window is constructed. The screenshot
    generator calls it too, so the documentation images show the themed
    app rather than an unstyled one.
    """
    app.setStyle("Fusion")
    app.setPalette(_palette())
    app.setFont(_ui_font())
    app.setStyleSheet(stylesheet())


def refresh_style(widget: QWidget) -> None:
    """Re-evaluate the stylesheet for `widget` after a property changed.

    Qt resolves property selectors when a widget is polished, so setting
    `state` on a status label later leaves it drawn with the old rule
    until the style is asked again.
    """
    widget.style().unpolish(widget)
    widget.style().polish(widget)
    widget.update()


def form_layout() -> QFormLayout:
    """A form column with the theme's row rhythm and growing fields.

    Every form in the app is built through this — the DUT cards, the
    packet fields, the payload sub-forms, the backend settings — so label
    alignment and row spacing cannot drift from one card to the next.
    """
    form = QFormLayout()
    form.setContentsMargins(0, 0, 0, 0)
    form.setHorizontalSpacing(t.SPACE + 4)
    form.setVerticalSpacing(t.SPACE)
    form.setLabelAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
    form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.ExpandingFieldsGrow)
    return form


def divider() -> QFrame:
    """A hairline rule, for separating a card's fields from its switches."""
    line = QFrame()
    line.setFrameShape(QFrame.Shape.HLine)
    line.setFixedHeight(1)
    line.setStyleSheet(f"background: {t.BORDER}; border: none;")
    return line


def _ui_font() -> QFont:
    font = QFont()
    # The stylesheet names the same stack; QFont takes the first family
    # that exists, so the two agree on what "the UI font" means.
    font.setFamilies(["Segoe UI", "Inter", "Ubuntu", "Noto Sans", "DejaVu Sans", "Sans Serif"])
    font.setPointSize(t.FONT_SIZE_PT)
    return font


def _palette() -> QPalette:
    """The colours Qt paints without consulting the stylesheet.

    Menus, tooltips, text selection and the native file dialog all read
    the palette — a stylesheet-only theme leaves them light grey against a
    dark window, which is exactly how a half-themed app announces itself.
    """
    p = QPalette()
    window, base, raised = QColor(t.CANVAS), QColor(t.SURFACE_SUNKEN), QColor(t.SURFACE_RAISED)
    text, muted, faint = QColor(t.TEXT), QColor(t.TEXT_MUTED), QColor(t.TEXT_FAINT)

    p.setColor(QPalette.ColorRole.Window, window)
    p.setColor(QPalette.ColorRole.WindowText, text)
    p.setColor(QPalette.ColorRole.Base, base)
    p.setColor(QPalette.ColorRole.AlternateBase, QColor(t.SURFACE))
    p.setColor(QPalette.ColorRole.Text, text)
    p.setColor(QPalette.ColorRole.PlaceholderText, faint)
    p.setColor(QPalette.ColorRole.Button, raised)
    p.setColor(QPalette.ColorRole.ButtonText, text)
    p.setColor(QPalette.ColorRole.ToolTipBase, raised)
    p.setColor(QPalette.ColorRole.ToolTipText, text)
    p.setColor(QPalette.ColorRole.Highlight, QColor(t.ACCENT))
    p.setColor(QPalette.ColorRole.HighlightedText, QColor(t.ACCENT_INK))
    p.setColor(QPalette.ColorRole.Link, QColor(t.ACCENT))
    p.setColor(QPalette.ColorRole.LinkVisited, QColor(t.INFO))
    p.setColor(QPalette.ColorRole.Mid, muted)
    p.setColor(QPalette.ColorRole.Dark, QColor(t.BORDER))
    p.setColor(QPalette.ColorRole.Shadow, QColor("#05080c"))
    for role in (
        QPalette.ColorRole.WindowText,
        QPalette.ColorRole.Text,
        QPalette.ColorRole.ButtonText,
    ):
        p.setColor(QPalette.ColorGroup.Disabled, role, faint)
    return p


# --------------------------------------------------------------------------
# Drawn indicators
# --------------------------------------------------------------------------

@lru_cache(maxsize=1)
def _icon_dir() -> Path:
    return Path(tempfile.mkdtemp(prefix="netstack-ui-"))


def _icon(name: str, colour: str, size: int = 16) -> str:
    """Render `name` in `colour` and return the path for a QSS `url()`.

    Written once per process into a temp directory, at 1x and 2x, because
    a stylesheet can only point at files. Qt loads the `@2x` companion by
    itself on a HiDPI screen.
    """
    path = _icon_dir() / f"{name}-{colour.lstrip('#')}.png"
    if not path.exists():
        for scale, target in ((1, path), (2, path.with_name(f"{path.stem}@2x.png"))):
            _draw(name, QColor(colour), size * scale, scale).save(str(target))
    return path.as_posix()


def _draw(name: str, colour: QColor, size: int, scale: int) -> QPixmap:
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    pen = QPen(colour, 1.9 * scale)
    pen.setCapStyle(Qt.PenCapStyle.RoundCap)
    pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
    painter.setPen(pen)
    u = size / 16  # one unit of the 16x16 design grid

    path = QPainterPath()
    if name == "check":
        path.moveTo(QPointF(3.5 * u, 8.5 * u))
        path.lineTo(QPointF(6.75 * u, 11.75 * u))
        path.lineTo(QPointF(12.5 * u, 4.75 * u))
    elif name == "dot":
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(colour)
        painter.drawEllipse(QPointF(size / 2, size / 2), 3.1 * u * scale, 3.1 * u * scale)
    elif name == "dash":
        path.moveTo(QPointF(4 * u, 8 * u))
        path.lineTo(QPointF(12 * u, 8 * u))
    elif name in ("chevron-down", "chevron-up", "chevron-right"):
        # One chevron, rotated — so the three never drift apart.
        painter.translate(size / 2, size / 2)
        painter.rotate({"chevron-down": 0, "chevron-up": 180, "chevron-right": -90}[name])
        painter.translate(-size / 2, -size / 2)
        path.moveTo(QPointF(4.5 * u, 6.5 * u))
        path.lineTo(QPointF(8 * u, 10 * u))
        path.lineTo(QPointF(11.5 * u, 6.5 * u))
    else:  # pragma: no cover - a typo in a call below, not a runtime state
        raise ValueError(f"no such indicator: {name!r}")
    painter.drawPath(path)
    painter.end()
    return pixmap


def stylesheet() -> str:
    """The application stylesheet.

    Public so the screenshot generator — and any future preview tool —
    renders exactly what the app renders.
    """
    check = _icon("check", t.ACCENT_INK, size=14)
    dash = _icon("dash", t.ACCENT_INK, size=14)
    dot = _icon("dot", t.ACCENT, size=14)
    chevron = _icon("chevron-down", t.TEXT_MUTED)
    chevron_lit = _icon("chevron-down", t.TEXT)
    up = _icon("chevron-up", t.TEXT_MUTED)
    branch_closed = _icon("chevron-right", t.TEXT_FAINT)
    branch_open = _icon("chevron-down", t.TEXT_FAINT)
    return f"""
/* ---------- base ---------- */
QWidget {{
    background: transparent;
    color: {t.TEXT};
    font-family: {t.FONT_UI};
    font-size: {t.FONT_SIZE_PT}pt;
}}
QMainWindow, QDialog, QMessageBox, QFileDialog {{ background: {t.CANVAS}; }}
QWidget:disabled {{ color: {t.TEXT_FAINT}; }}
QToolTip {{
    background: {t.SURFACE_RAISED};
    color: {t.TEXT};
    border: 1px solid {t.BORDER_STRONG};
    border-radius: {t.RADIUS_SMALL}px;
    padding: 6px 8px;
}}

/* ---------- cards ---------- */
QGroupBox {{
    background: {t.SURFACE};
    border: 1px solid {t.BORDER};
    border-radius: {t.RADIUS}px;
    margin-top: {t.SPACE * 2 + 6}px;  /* room for the title, which is drawn in it */
    padding: {t.SPACE + 4}px {t.SPACE + 2}px {t.SPACE + 2}px {t.SPACE + 2}px;
}}
QGroupBox::title {{
    subcontrol-origin: margin;
    subcontrol-position: top left;
    left: {t.SPACE + 4}px;
    padding: 0 4px;
    color: {t.TEXT};
    font-size: {t.FONT_SIZE_PT}pt;
    font-weight: 600;
}}

/* ---------- type scale ---------- */
QLabel {{ background: transparent; }}
QLabel[role="heading"] {{ font-size: 15pt; font-weight: 600; color: {t.TEXT}; }}
QLabel[role="subheading"] {{ font-size: 11pt; font-weight: 600; color: {t.TEXT}; }}
QLabel[role="caption"] {{ font-size: {t.FONT_SIZE_SMALL_PT}pt; color: {t.TEXT_MUTED}; }}
QLabel[role="chip"] {{
    background: {t.SURFACE_RAISED};
    border: 1px solid {t.BORDER};
    border-radius: {t.RADIUS_SMALL}px;
    color: {t.TEXT_MUTED};
    font-size: {t.FONT_SIZE_SMALL_PT}pt;
    padding: 2px 8px;
}}
QLabel[state="ok"] {{ color: {t.SUCCESS}; }}
QLabel[state="bad"] {{ color: {t.DANGER}; }}
QLabel[state="idle"] {{ color: {t.TEXT_MUTED}; }}

/* ---------- inputs ---------- */
QLineEdit, QSpinBox, QComboBox, QAbstractSpinBox {{
    background: {t.SURFACE_RAISED};
    border: 1px solid {t.BORDER};
    border-radius: {t.RADIUS_SMALL}px;
    padding: 5px 8px;
    min-height: 20px;
    selection-background-color: {t.ACCENT};
    selection-color: {t.ACCENT_INK};
}}
QLineEdit:hover, QSpinBox:hover, QComboBox:hover {{ border-color: {t.BORDER_STRONG}; }}
QLineEdit:focus, QSpinBox:focus, QComboBox:focus {{
    border-color: {t.ACCENT};
    background: {t.SURFACE_SUNKEN};
}}
QLineEdit:disabled, QSpinBox:disabled, QComboBox:disabled {{ background: {t.SURFACE}; }}
QComboBox::drop-down {{ border: none; width: 22px; }}
QComboBox::down-arrow {{ image: url({chevron}); width: 16px; height: 16px; }}
QComboBox::down-arrow:on {{ image: url({chevron_lit}); }}
QComboBox QAbstractItemView {{
    background: {t.SURFACE_RAISED};
    border: 1px solid {t.BORDER_STRONG};
    border-radius: {t.RADIUS_SMALL}px;
    padding: 4px;
    outline: none;
    selection-background-color: {t.ACCENT_SOFT};
    selection-color: {t.TEXT};
}}
QAbstractSpinBox::up-button, QAbstractSpinBox::down-button {{
    background: transparent;
    border: none;
    width: 18px;
}}
QAbstractSpinBox::up-arrow {{ image: url({up}); width: 14px; height: 14px; }}
QAbstractSpinBox::down-arrow {{ image: url({chevron}); width: 14px; height: 14px; }}

/* ---------- buttons ---------- */
QPushButton {{
    background: {t.SURFACE_RAISED};
    border: 1px solid {t.BORDER_STRONG};
    border-radius: {t.RADIUS_SMALL}px;
    color: {t.TEXT};
    font-weight: 600;
    padding: 6px 16px;
    min-height: 20px;
}}
QPushButton:hover {{ background: #27313f; border-color: {t.TEXT_FAINT}; }}
QPushButton:pressed {{ background: {t.SURFACE}; }}
QPushButton:disabled {{ background: {t.SURFACE}; border-color: {t.BORDER}; color: {t.TEXT_FAINT}; }}
QPushButton[accent="true"] {{
    background: {t.ACCENT};
    border-color: {t.ACCENT};
    color: {t.ACCENT_INK};
}}
QPushButton[accent="true"]:hover {{ background: {t.ACCENT_HOVER}; border-color: {t.ACCENT_HOVER}; }}
QPushButton[accent="true"]:pressed {{ background: {t.ACCENT_PRESSED}; border-color: {t.ACCENT_PRESSED}; }}
QPushButton[accent="true"]:disabled {{
    background: {t.SURFACE}; border-color: {t.BORDER}; color: {t.TEXT_FAINT};
}}
QPushButton[danger="true"] {{ border-color: {t.DANGER}; color: {t.DANGER}; }}
QPushButton[danger="true"]:hover {{
    background: #2a1a1e; border-color: {t.DANGER_HOVER}; color: {t.DANGER_HOVER};
}}
QPushButton[danger="true"]:disabled {{ border-color: {t.BORDER}; color: {t.TEXT_FAINT}; }}

/* ---------- check boxes & radios ---------- */
QCheckBox, QRadioButton {{ spacing: 8px; padding: 2px 0; }}
QCheckBox::indicator, QRadioButton::indicator {{
    width: 16px;
    height: 16px;
    border: 1px solid {t.BORDER_STRONG};
    background: {t.SURFACE_RAISED};
}}
QCheckBox::indicator {{ border-radius: {t.RADIUS_SMALL}px; }}
QRadioButton::indicator {{ border-radius: 9px; }}
QCheckBox::indicator:hover, QRadioButton::indicator:hover {{ border-color: {t.ACCENT}; }}
QCheckBox::indicator:checked {{
    background: {t.ACCENT};
    border-color: {t.ACCENT};
    image: url({check});
}}
QCheckBox::indicator:indeterminate {{
    background: {t.ACCENT};
    border-color: {t.ACCENT};
    image: url({dash});
}}
QRadioButton::indicator:checked {{
    border-color: {t.ACCENT};
    image: url({dot});
}}
QCheckBox::indicator:disabled, QRadioButton::indicator:disabled {{
    background: {t.SURFACE}; border-color: {t.BORDER};
}}

/* ---------- tabs ---------- */
QTabWidget::pane {{
    background: {t.SURFACE};
    border: 1px solid {t.BORDER};
    border-radius: {t.RADIUS}px;
    top: -1px;
}}
QTabBar {{ qproperty-drawBase: 0; }}
QTabBar::tab {{
    background: transparent;
    border: none;
    border-bottom: 2px solid transparent;
    color: {t.TEXT_MUTED};
    font-weight: 600;
    padding: 7px 16px;
    margin-right: 2px;
}}
QTabBar::tab:hover {{ color: {t.TEXT}; }}
QTabBar::tab:selected {{ color: {t.ACCENT}; border-bottom-color: {t.ACCENT}; }}

/* ---------- trees & lists ---------- */
QTreeWidget, QTreeView, QListView {{
    background: {t.SURFACE_SUNKEN};
    border: 1px solid {t.BORDER};
    border-radius: {t.RADIUS_SMALL}px;
    outline: none;
    alternate-background-color: {t.SURFACE};
}}
QTreeView::item, QListView::item {{ border-radius: {t.RADIUS_SMALL}px; padding: 3px 2px; }}
QTreeView::item:hover, QListView::item:hover {{ background: {t.SURFACE_RAISED}; }}
QTreeView::item:selected, QListView::item:selected {{
    background: {t.ACCENT_SOFT}; color: {t.TEXT};
}}
QTreeView::branch:has-children:!has-siblings:closed,
QTreeView::branch:closed:has-children:has-siblings {{ image: url({branch_closed}); }}
QTreeView::branch:open:has-children:!has-siblings,
QTreeView::branch:open:has-children:has-siblings {{ image: url({branch_open}); }}
/* The tree's own check boxes are a different sub-control from a
   QCheckBox's, and go unstyled unless named separately — which is how a
   themed app ends up with two different check marks in one window. */
QTreeView::indicator, QListView::indicator {{
    width: 16px;
    height: 16px;
    border: 1px solid {t.BORDER_STRONG};
    border-radius: {t.RADIUS_SMALL}px;
    background: {t.SURFACE_RAISED};
}}
QTreeView::indicator:hover, QListView::indicator:hover {{ border-color: {t.ACCENT}; }}
QTreeView::indicator:checked, QListView::indicator:checked {{
    background: {t.ACCENT};
    border-color: {t.ACCENT};
    image: url({check});
}}
QTreeView::indicator:indeterminate, QListView::indicator:indeterminate {{
    background: {t.ACCENT};
    border-color: {t.ACCENT};
    image: url({dash});
}}
QHeaderView::section {{
    background: {t.SURFACE_RAISED};
    border: none;
    border-bottom: 1px solid {t.BORDER};
    color: {t.TEXT_MUTED};
    font-size: {t.FONT_SIZE_SMALL_PT}pt;
    font-weight: 600;
    padding: 6px 8px;
}}

/* ---------- text views ---------- */
QPlainTextEdit, QTextEdit {{
    background: {t.SURFACE_SUNKEN};
    border: 1px solid {t.BORDER};
    border-radius: {t.RADIUS_SMALL}px;
    padding: 6px 8px;
    selection-background-color: {t.ACCENT};
    selection-color: {t.ACCENT_INK};
}}
QPlainTextEdit[role="console"], QTextEdit[role="console"] {{
    font-family: {t.FONT_MONO};
    font-size: {t.FONT_SIZE_SMALL_PT}pt;
}}

/* ---------- scrollbars ---------- */
QScrollBar:vertical, QScrollBar:horizontal {{ background: transparent; margin: 0; }}
QScrollBar:vertical {{ width: 11px; }}
QScrollBar:horizontal {{ height: 11px; }}
QScrollBar::handle {{ background: {t.BORDER_STRONG}; border-radius: 5px; }}
QScrollBar::handle:hover {{ background: {t.TEXT_FAINT}; }}
QScrollBar::handle:vertical {{ min-height: 28px; }}
QScrollBar::handle:horizontal {{ min-width: 28px; }}
QScrollBar::add-line, QScrollBar::sub-line {{ height: 0; width: 0; }}
QScrollBar::add-page, QScrollBar::sub-page {{ background: transparent; }}
QScrollArea {{ border: none; }}

/* ---------- splitters, frames, menus ---------- */
QSplitter::handle {{ background: transparent; }}
QSplitter::handle:horizontal {{ width: {t.SPACE}px; }}
QSplitter::handle:vertical {{ height: {t.SPACE}px; }}
QSplitter::handle:hover {{ background: {t.ACCENT_SOFT}; }}
QMenu {{
    background: {t.SURFACE_RAISED};
    border: 1px solid {t.BORDER_STRONG};
    border-radius: {t.RADIUS_SMALL}px;
    padding: 4px;
}}
QMenu::item {{ border-radius: {t.RADIUS_SMALL}px; padding: 5px 20px 5px 12px; }}
QMenu::item:selected {{ background: {t.ACCENT_SOFT}; }}
QStatusBar {{ background: {t.SURFACE}; color: {t.TEXT_MUTED}; border-top: 1px solid {t.BORDER}; }}

/* ---------- named surfaces ---------- */
/* The run-verdict + export footer, and the send form's reply well: both
   are cards in their own right, not panels inside one. */
QWidget#reportFooter, QWidget#panelCard {{
    background: {t.SURFACE};
    border: 1px solid {t.BORDER};
    border-radius: {t.RADIUS}px;
}}
QStatusBar::item {{ border: none; }}
"""
