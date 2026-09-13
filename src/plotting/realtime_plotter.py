"""pyqtgraph-based live tx/rx plot, embedded in the GUI's main window.

Update cadence is decoupled from packet arrival rate via a QTimer
(~25Hz): the ingestion side only appends to a MetricsBuffer (cheap,
thread-safe); this widget pulls a decimated snapshot on each timer tick.
Emitting a Qt signal per packet during a flood test would stall the Qt
event loop, so this indirection is deliberate, not incidental.

Requires the optional `gui` extra (PySide6, pyqtgraph).
"""
from __future__ import annotations

import pyqtgraph as pg
from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QVBoxLayout, QWidget

from src.design_tokens import PLOT, SPACE
from src.plotting.metrics import MetricsBuffer

FLUSH_INTERVAL_MS = 40  # ~25Hz


class RealtimePlotWidget(QWidget):
    def __init__(self, metrics: MetricsBuffer, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._metrics = metrics

        # pyqtgraph draws with its own colours, not Qt's stylesheet, so the
        # plot is themed here from the same tokens the widgets use —
        # otherwise the one panel that is watched throughout a run is the
        # one panel that looks like a different application.
        pg.setConfigOptions(antialias=True, background=PLOT["background"], foreground=PLOT["foreground"])

        self._plot_widget = pg.PlotWidget(title="Packets over time")
        self._plot_widget.setLabel("bottom", "Elapsed", units="s")
        self._plot_widget.setLabel("left", "Cumulative packets")
        self._plot_widget.showGrid(x=True, y=True, alpha=0.18)
        self._plot_widget.setMenuEnabled(False)
        self._plot_widget.getPlotItem().getViewBox().setDefaultPadding(0.02)
        for axis in ("bottom", "left"):
            self._plot_widget.getAxis(axis).setPen(pg.mkPen(PLOT["grid"]))
            self._plot_widget.getAxis(axis).setTextPen(pg.mkPen(PLOT["foreground"]))
        legend = self._plot_widget.addLegend(offset=(-10, 10), labelTextColor=PLOT["foreground"])
        legend.setBrush(pg.mkBrush(PLOT["background"]))
        legend.setPen(pg.mkPen(PLOT["grid"]))

        # Filled under the curve: the gap between sent and received is the
        # thing being read, and two translucent bands show it at a glance
        # where two hairlines only show it where they diverge.
        self._sent_curve = self._plot_widget.plot(
            [], [], name="Sent", pen=pg.mkPen(PLOT["sent"], width=2),
            fillLevel=0, brush=pg.mkBrush(_tint(PLOT["sent"])),
        )
        self._recv_curve = self._plot_widget.plot(
            [], [], name="Received", pen=pg.mkPen(PLOT["received"], width=2),
            fillLevel=0, brush=pg.mkBrush(_tint(PLOT["received"])),
        )

        layout = QVBoxLayout(self)
        layout.setContentsMargins(SPACE, SPACE, SPACE, SPACE)
        layout.addWidget(self._plot_widget)

        self._timer = QTimer(self)
        self._timer.timeout.connect(self._refresh)
        self._timer.start(FLUSH_INTERVAL_MS)

    def _refresh(self) -> None:
        snap = self._metrics.snapshot()
        self._sent_curve.setData(snap.elapsed_s, snap.sent_cumulative)
        self._recv_curve.setData(snap.elapsed_s, snap.received_cumulative)

    def reset(self) -> None:
        self._metrics.clear()
        self._sent_curve.setData([], [])
        self._recv_curve.setData([], [])


def _tint(colour: str, alpha: int = 38) -> tuple[int, int, int, int]:
    """`#rrggbb` as an RGBA tuple at `alpha`, for the area under a curve.

    Translucent rather than a lighter opaque shade, so the two bands stay
    readable where they overlap — which, on a healthy run, is everywhere.
    """
    r, g, b = (int(colour[i:i + 2], 16) for i in (1, 3, 5))
    return r, g, b, alpha
