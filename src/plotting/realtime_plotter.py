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

from src.plotting.metrics import MetricsBuffer

FLUSH_INTERVAL_MS = 40  # ~25Hz


class RealtimePlotWidget(QWidget):
    def __init__(self, metrics: MetricsBuffer, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._metrics = metrics

        self._plot_widget = pg.PlotWidget(title="Packets over time")
        self._plot_widget.setLabel("bottom", "Elapsed", units="s")
        self._plot_widget.setLabel("left", "Cumulative packets")
        self._plot_widget.addLegend()
        self._sent_curve = self._plot_widget.plot([], [], pen=pg.mkPen("g", width=2), name="Sent")
        self._recv_curve = self._plot_widget.plot([], [], pen=pg.mkPen("c", width=2), name="Received")

        layout = QVBoxLayout(self)
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
