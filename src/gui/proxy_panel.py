"""Proxy Backend panel — run this GUI instance as the *server* side.

For proxy-DUT testing you run two instances: this one stands in as the
origin server the proxy dials out to, echoing whatever it relays; the other
instance runs the `proxy` test module and verifies the round-trip.

The live counters are the visible proof that the DUT's *client* leg works —
a connection appearing here means the proxy successfully dialled out.
"""
from __future__ import annotations

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import (
    QCheckBox,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from src.design_tokens import SPACE
from src.gui.theme import divider, form_layout, refresh_style
from src.proxy.backend import EchoBackend
from src.proxy.config import DEFAULT_BACKEND_PORT

_REFRESH_MS = 500


class ProxyBackendPanel(QWidget):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._backend: EchoBackend | None = None

        self._listen_host = QLineEdit("0.0.0.0")
        self._listen_port = QSpinBox()
        # 0 means "let the OS pick a free port" — handy when the DUT is
        # configured to discover the origin, and it avoids needing a
        # privileged (<1024) port. The bound port is shown once started.
        self._listen_port.setRange(0, 65535)
        self._listen_port.setSpecialValueText("auto (ephemeral)")
        self._listen_port.setValue(DEFAULT_BACKEND_PORT)
        self._enable_udp = QCheckBox("Also echo UDP on the same port")

        form = form_layout()
        form.addRow("Listen address", self._listen_host)
        form.addRow("Listen port", self._listen_port)
        form.addRow("", self._enable_udp)

        self._start_button = QPushButton("Start backend")
        self._start_button.setProperty("accent", "true")
        self._start_button.clicked.connect(self._start)
        self._stop_button = QPushButton("Stop")
        self._stop_button.setProperty("danger", "true")
        self._stop_button.clicked.connect(self._stop)
        self._stop_button.setEnabled(False)
        buttons = QHBoxLayout()
        buttons.setSpacing(SPACE)
        buttons.addStretch(1)
        buttons.addWidget(self._start_button)
        buttons.addWidget(self._stop_button)

        self._status = QLabel()
        self._stats = QLabel("—")
        self._stats.setProperty("role", "chip")
        self._set_status("Stopped.", state="idle")

        self._log = QPlainTextEdit()
        self._log.setReadOnly(True)
        self._log.setMaximumBlockCount(2000)
        self._log.setProperty("role", "console")
        self._log.setPlaceholderText(
            "Connections the proxy DUT makes to this backend are logged here."
        )

        # The counters sit beside the status line: together they are the
        # answer to "is the DUT's client leg working?", which is the only
        # question this panel exists to answer.
        status_row = QHBoxLayout()
        status_row.setSpacing(SPACE)
        status_row.addWidget(self._status, stretch=1)
        status_row.addWidget(self._stats)

        config_box = QGroupBox("Backend (origin the proxy DUT dials)")
        config_layout = QVBoxLayout(config_box)
        config_layout.setSpacing(SPACE + 4)
        config_layout.addLayout(form)
        config_layout.addLayout(buttons)
        config_layout.addWidget(divider())
        config_layout.addLayout(status_row)

        hint = QLabel(
            "Run this instance as the <b>server</b> side. On the other instance, run the "
            "<i>proxy</i> test module pointed at this address."
        )
        hint.setProperty("role", "caption")
        hint.setWordWrap(True)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(SPACE + 2, SPACE + 2, SPACE + 2, SPACE + 2)
        layout.setSpacing(SPACE + 4)
        layout.addWidget(config_box)
        layout.addWidget(hint)
        layout.addWidget(self._log, stretch=1)

        self._timer = QTimer(self)
        self._timer.setInterval(_REFRESH_MS)
        self._timer.timeout.connect(self._refresh_stats)

    # --- lifecycle ---------------------------------------------------------

    def _start(self) -> None:
        if self._backend is not None:
            return
        try:
            backend = EchoBackend(
                self._listen_host.text().strip() or "0.0.0.0",
                self._listen_port.value(),
                enable_udp=self._enable_udp.isChecked(),
                on_event=self._log.appendPlainText,
            )
            backend.start()
        except OSError as exc:
            self._log.appendPlainText(f"Failed to start: {exc}")
            self._set_status(f"Failed to start: {exc}", state="bad")
            return
        self._backend = backend
        self._set_status(
            f"Listening on {backend.host}:{backend.bound_port} — waiting for the proxy DUT.",
            state="ok",
        )
        self._start_button.setEnabled(False)
        self._stop_button.setEnabled(True)
        self._timer.start()

    def _stop(self) -> None:
        if self._backend is None:
            return
        self._backend.stop()
        self._log.appendPlainText(self._backend.stats.summary())
        self._backend = None
        self._timer.stop()
        self._set_status("Stopped.", state="idle")
        self._start_button.setEnabled(True)
        self._stop_button.setEnabled(False)

    def _refresh_stats(self) -> None:
        if self._backend is None:
            return
        self._stats.setText(self._backend.stats.summary())
        if not self._backend.is_serving:
            # Holding a reference is not the same as still accepting: the
            # serving threads can end on an OSError that stop() did not
            # cause, and this label was the operator's only indication.
            self._set_status(
                "Not accepting — the backend's serving thread ended. See the log below; "
                "restart it before running proxy tests.",
                state="bad",
            )

    def _set_status(self, text: str, *, state: str) -> None:
        """The status line and its ink, set together — a red failure must
        never be left wearing the green of the last successful start."""
        self._status.setText(text)
        self._status.setProperty("state", state)
        refresh_style(self._status)

    def shutdown(self) -> None:
        """Called when the window closes so the listener is released."""
        self._stop()
