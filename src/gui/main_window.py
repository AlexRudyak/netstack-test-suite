"""Main GUI window: DUT configuration, test selection tree, live plot,
log panel, and report export — plus a Custom Packet tab for ad-hoc sends.
"""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLineEdit,
    QMainWindow,
    QPushButton,
    QSpinBox,
    QSplitter,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from src.config import DUTConfig, Role, random_ephemeral_port
from src.gui.custom_packet_panel import CustomPacketPanel
from src.gui.log_panel import LogPanel
from src.gui.report_panel import ReportPanel
from src.gui.run_controller import RunController
from src.gui.test_details_panel import TestDetailsPanel
from src.gui.test_tree_widget import TestTreeWidget
from src.packet_engine.preflight import run_preflight
from src.plotting.metrics import MetricsBuffer
from src.plotting.realtime_plotter import RealtimePlotWidget
from src.reporting.models import PacketEvent, TestEvent, TestRunResult
from src.runner import RunRequest


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Network Stack Test Suite")
        self.resize(1200, 800)

        self._metrics = MetricsBuffer()
        # Chosen once, the first time a run leaves the destination port unset,
        # then reused for the rest of the session.
        self._session_random_dst_port: int | None = None
        self._controller = RunController(self)
        self._controller.test_event.connect(self._on_test_event)
        self._controller.packet_event.connect(self._on_packet_event)
        self._controller.output_line.connect(self._on_output_line)
        self._controller.finished.connect(self._on_finished)

        self._build_ui()

    def _build_ui(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)
        root_layout = QVBoxLayout(central)

        root_layout.addWidget(self._build_config_group())

        tabs = QTabWidget()
        tabs.addTab(self._build_suite_tab(), "Automated Suite")
        tabs.addTab(CustomPacketPanel(), "Custom Packet")
        root_layout.addWidget(tabs, stretch=1)

        self._report_panel = ReportPanel()
        root_layout.addWidget(self._report_panel)

    def _build_config_group(self) -> QGroupBox:
        box = QGroupBox("DUT configuration")
        form = QFormLayout(box)

        self._iface_combo = QComboBox()
        self._iface_combo.addItems(_list_interface_names())
        self._target_ip = QLineEdit()
        self._target_mac = QLineEdit()
        self._src_port = QSpinBox()
        self._src_port.setRange(0, 65535)
        self._src_port.setSpecialValueText("auto")
        self._src_port.setValue(0)
        self._src_port.setToolTip("Optional fixed local source port. 'auto' lets each test pick its own.")
        self._dst_port = QSpinBox()
        self._dst_port.setRange(0, 65535)
        self._dst_port.setSpecialValueText("random")
        self._dst_port.setValue(0)
        self._dst_port.setToolTip(
            "DUT port that port-specific tests target. 'random' picks one ephemeral "
            "port and reuses it for the whole session."
        )
        self._target_stack = QComboBox()
        self._target_stack.addItems(["linux", "windows"])
        self._role = QComboBox()
        self._role.addItems([r.value for r in Role])
        self._role.setToolTip(
            "client: the suite initiates (validates the DUT's responder).\n"
            "server: the suite responds; the DUT initiates (validates the DUT's client)."
        )
        self._allowed_targets = QLineEdit()
        self._allowed_targets.setPlaceholderText("e.g. 10.0.0.0/24, 192.168.1.5/32")
        self._confirm_vuln = QCheckBox("I authorize vuln-marked tests against this target")
        self._debug = QCheckBox("Debug mode (write tshark-style per-packet debug.log)")

        form.addRow("Interface", self._iface_combo)
        form.addRow("Target IP", self._target_ip)
        form.addRow("Target MAC (optional)", self._target_mac)
        form.addRow("Source port (optional)", self._src_port)
        form.addRow("Destination port", self._dst_port)
        form.addRow("Target stack", self._target_stack)
        form.addRow("Role", self._role)
        form.addRow("Allowed targets (CIDR)", self._allowed_targets)
        form.addRow(self._confirm_vuln)
        form.addRow(self._debug)
        return box

    def _build_suite_tab(self) -> QWidget:
        widget = QWidget()
        layout = QHBoxLayout(widget)

        left_widget = QWidget()
        left = QVBoxLayout(left_widget)
        self._tree = TestTreeWidget()
        self._tree.currentItemChanged.connect(self._on_tree_selection)
        left.addWidget(self._tree, stretch=3)
        # Per-test description: what the selected test checks + its RFC.
        self._details = TestDetailsPanel()
        left.addWidget(self._details, stretch=1)
        buttons = QHBoxLayout()
        run_button = QPushButton("Run selected")
        run_button.clicked.connect(self._on_run_clicked)
        stop_button = QPushButton("Stop")
        stop_button.clicked.connect(self._controller.stop)
        buttons.addWidget(run_button)
        buttons.addWidget(stop_button)
        left.addLayout(buttons)

        self._right_tabs = QTabWidget()
        self._plot = RealtimePlotWidget(self._metrics)
        self._right_tabs.addTab(self._plot, "Live plot")
        self._log_panel = LogPanel()
        self._right_tabs.addTab(self._log_panel, "Log")

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(left_widget)
        splitter.addWidget(self._right_tabs)
        layout.addWidget(splitter)
        return widget

    def _resolved_dst_port(self) -> int:
        """The Destination port field, or a session-stable random ephemeral
        port when it's left on 'random' (spinbox value 0)."""
        if self._dst_port.value():
            return self._dst_port.value()
        if self._session_random_dst_port is None:
            self._session_random_dst_port = random_ephemeral_port()
        return self._session_random_dst_port

    def _current_dut_config(self) -> DUTConfig:
        allowed = tuple(x.strip() for x in self._allowed_targets.text().split(",") if x.strip())
        return DUTConfig(
            interface=self._iface_combo.currentText(),
            target_ip=self._target_ip.text(),
            target_stack=self._target_stack.currentText(),
            target_mac=self._target_mac.text() or None,
            target_port=self._resolved_dst_port(),
            source_port=self._src_port.value() or None,
            allowed_targets=allowed,
            role=Role(self._role.currentText()),
        )

    def _on_tree_selection(self, current, _previous) -> None:
        self._details.show_spec(self._tree.spec_of(current))

    def _on_run_clicked(self) -> None:
        self._metrics.clear()
        self._plot.reset()
        self._log_panel.clear_log()
        # Surface progress/errors as text — the Log tab is where the run
        # actually reports what happened (a blank Live plot was exactly why
        # a failed run looked like "nothing happened").
        self._right_tabs.setCurrentWidget(self._log_panel)

        config = self._current_dut_config()
        if not self._dst_port.value():
            self._log_panel.append_line(
                f"Destination port left on 'random' — using {config.target_port} for this session."
            )

        # Preflight first: validate config + privileges and probe the DUT,
        # reporting the outcome. Hard blockers abort before launching pytest;
        # a no-ARP-reply warning still proceeds (a custom stack may not
        # implement ARP).
        self._log_panel.append_line("Preflight connectivity check…")
        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
        try:
            pre = run_preflight(config)
        finally:
            QApplication.restoreOverrideCursor()
        for line in pre.render_lines():
            self._log_panel.append_line("  " + line)
        if not pre.ok:
            self._log_panel.append_line("Preflight failed — not starting the run.")
            return

        # Warn up front if a checked test won't run under the selected role
        # (otherwise it just silently skips — the confusing case).
        for spec in self._tree.checked_specs():
            if config.role not in spec.roles:
                self._log_panel.append_line(
                    f"Note: '{spec.test}' applies to role(s) [{spec.role_labels}] but the Role is "
                    f"'{config.role.value}' — it will be SKIPPED. Change the Role selector to run it."
                )

        targets = tuple(self._tree.checked_targets())
        selection = ", ".join(targets) if targets else "all tests"
        self._log_panel.append_line(f"Starting run (role={config.role.value}, selection: {selection})…")

        request = RunRequest(
            config=config,
            targets=targets,
            confirm_vuln_tests=self._confirm_vuln.isChecked(),
            debug=self._debug.isChecked(),
            role=config.role,
        )
        self._controller.start(request)

    def _on_test_event(self, event: TestEvent) -> None:
        self._log_panel.append_test_event(event)

    def _on_packet_event(self, event: PacketEvent) -> None:
        self._metrics.add(event)

    def _on_output_line(self, line: str) -> None:
        self._log_panel.append_line(line)

    def _on_finished(self, result: TestRunResult) -> None:
        self._report_panel.set_result(result)
        if result.errored:
            self._log_panel.append_line(
                f"pytest exited with code {result.pytest_returncode} "
                f"(collection/usage error or no tests) — see reports/{result.run_id}/pytest_output.log"
            )
        elif result.total == 0:
            self._log_panel.append_line(
                "Run finished but no tests ran — check the test selection and configuration."
            )
        else:
            self._log_panel.append_line(
                f"Run finished: {result.passed} passed, {result.failed} failed, "
                f"{result.errors} errored, {result.skipped} skipped, {result.total} total."
            )
            if result.skipped and result.passed == 0 and result.failed == 0 and result.errors == 0:
                self._log_panel.append_line(
                    "Everything selected was skipped — see the SKIP reason(s) above "
                    "(often a role mismatch: switch the Role selector)."
                )


def _list_interface_names() -> list[str]:
    try:
        from scapy.interfaces import get_working_ifaces

        return [iface.name for iface in get_working_ifaces()]
    except Exception:
        return []
