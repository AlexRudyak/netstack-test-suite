"""Custom/raw packet panel: ad-hoc L3/L4 packet crafting with a
user-selectable L7 payload mode (Zeros / Ones / Random / Custom), sent
via src/custom_packet — the same send path and pcap capture mechanism
the automated suite uses.
"""
from __future__ import annotations

from PySide6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QRadioButton,
    QSpinBox,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from src.custom_packet.builder import CustomPacketSpec
from src.custom_packet.sender import send_custom_packet
from src.packet_engine.payloads import PayloadMode, from_file, from_hex, from_text


class CustomPacketPanel(QWidget):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)

        self._proto = QComboBox()
        self._proto.addItems(["tcp", "udp"])
        self._iface = QLineEdit()
        self._src_ip = QLineEdit()
        self._dst_ip = QLineEdit()
        self._src_port = QSpinBox()
        self._src_port.setRange(1, 65535)
        self._src_port.setValue(12345)
        self._dst_port = QSpinBox()
        self._dst_port.setRange(1, 65535)
        self._dst_port.setValue(80)
        self._src_mac = QLineEdit()
        self._dst_mac = QLineEdit()
        self._ttl = QSpinBox()
        self._ttl.setRange(1, 255)
        self._ttl.setValue(64)
        self._tcp_flags = QLineEdit("S")

        form = QFormLayout()
        form.addRow("Protocol", self._proto)
        form.addRow("Interface", self._iface)
        form.addRow("Source IP", self._src_ip)
        form.addRow("Destination IP", self._dst_ip)
        form.addRow("Source port", self._src_port)
        form.addRow("Destination port", self._dst_port)
        form.addRow("Source MAC", self._src_mac)
        form.addRow("Destination MAC", self._dst_mac)
        form.addRow("TTL", self._ttl)
        form.addRow("TCP flags", self._tcp_flags)

        self._mode_zeros = QRadioButton("Zeros")
        self._mode_ones = QRadioButton("Ones")
        self._mode_random = QRadioButton("Random")
        self._mode_random.setChecked(True)
        self._mode_custom = QRadioButton("Custom")
        for button in (self._mode_zeros, self._mode_ones, self._mode_random, self._mode_custom):
            button.toggled.connect(self._on_mode_changed)

        mode_row = QHBoxLayout()
        for button in (self._mode_zeros, self._mode_ones, self._mode_random, self._mode_custom):
            mode_row.addWidget(button)

        self._size_spin = QSpinBox()
        self._size_spin.setRange(0, 65507)
        self._size_spin.setValue(64)

        self._custom_text = QLineEdit()
        self._custom_hex = QLineEdit()
        self._custom_file_path = QLineEdit()
        browse_button = QPushButton("Browse…")
        browse_button.clicked.connect(self._browse_file)
        file_row = QHBoxLayout()
        file_row.addWidget(self._custom_file_path)
        file_row.addWidget(browse_button)
        file_row_container = QWidget()
        file_row_container.setLayout(file_row)

        self._payload_stack = QStackedWidget()
        size_widget = QWidget()
        QFormLayout(size_widget).addRow("Size (bytes)", self._size_spin)
        custom_widget = QWidget()
        custom_form = QFormLayout(custom_widget)
        custom_form.addRow("Text", self._custom_text)
        custom_form.addRow("Hex", self._custom_hex)
        custom_form.addRow("File", file_row_container)
        self._payload_stack.addWidget(size_widget)
        self._payload_stack.addWidget(custom_widget)

        payload_box = QGroupBox("L7 payload")
        payload_layout = QVBoxLayout(payload_box)
        payload_layout.addLayout(mode_row)
        payload_layout.addWidget(self._payload_stack)

        send_button = QPushButton("Send")
        send_button.clicked.connect(self._on_send)

        self._response_view = QPlainTextEdit()
        self._response_view.setReadOnly(True)

        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(payload_box)
        layout.addWidget(send_button)
        layout.addWidget(self._response_view)

    def _on_mode_changed(self) -> None:
        self._payload_stack.setCurrentIndex(1 if self._mode_custom.isChecked() else 0)

    def _browse_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Select payload file")
        if path:
            self._custom_file_path.setText(path)

    def _current_mode(self) -> PayloadMode:
        if self._mode_zeros.isChecked():
            return PayloadMode.ZEROS
        if self._mode_ones.isChecked():
            return PayloadMode.ONES
        if self._mode_custom.isChecked():
            return PayloadMode.CUSTOM
        return PayloadMode.RANDOM

    def _resolve_custom_payload(self) -> bytes:
        if self._custom_text.text():
            return from_text(self._custom_text.text())
        if self._custom_hex.text():
            return from_hex(self._custom_hex.text())
        if self._custom_file_path.text():
            return from_file(self._custom_file_path.text())
        raise ValueError("Custom payload mode requires text, hex, or a file.")

    def _on_send(self) -> None:
        try:
            mode = self._current_mode()
            custom = self._resolve_custom_payload() if mode is PayloadMode.CUSTOM else None

            spec = CustomPacketSpec(
                proto=self._proto.currentText(),
                src_ip=self._src_ip.text(),
                dst_ip=self._dst_ip.text(),
                src_port=self._src_port.value(),
                dst_port=self._dst_port.value(),
                src_mac=self._src_mac.text(),
                dst_mac=self._dst_mac.text(),
                ttl=self._ttl.value(),
                tcp_flags=self._tcp_flags.text(),
                payload_mode=mode,
                payload_size=self._size_spin.value(),
                custom_payload=custom,
            )
            reply = send_custom_packet(spec, self._iface.text())
            self._response_view.setPlainText(
                reply.summary() if reply is not None else "No reply received within timeout."
            )
        except Exception as exc:  # surfaced in the panel, not a GUI crash
            self._response_view.setPlainText(f"Error: {exc}")
