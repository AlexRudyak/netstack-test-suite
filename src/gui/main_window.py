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

from src.config import (
    DUTConfig,
    ProxyLeg,
    Role,
    back_leg_requirement_error,
    random_ephemeral_port,
    resolve_leg_target,
    resolve_role,
)
from src.gui.custom_packet_panel import CustomPacketPanel
from src.gui.log_panel import LogPanel
from src.gui.proxy_panel import ProxyBackendPanel
from src.gui.report_panel import ReportPanel
from src.gui.run_controller import RunController
from src.gui.test_details_panel import TestDetailsPanel
from src.gui.test_tree_widget import TestTreeWidget
from src.packet_engine.preflight import run_preflight
from src.proxy.config import ProxyMode
from src.plotting.metrics import MetricsBuffer
from src.plotting.realtime_plotter import RealtimePlotWidget
from src.reporting.models import PacketEvent, TestEvent, TestRunResult
from src.run_artifacts import RunArtifacts
from src.runner import RunRequest
from src.target_profiles import list_profiles


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Network Stack Test Suite")
        self.resize(1200, 800)

        self._metrics = MetricsBuffer()
        # Chosen once, the first time a run leaves the destination port unset,
        # then reused for the rest of the session.
        self._session_random_dst_port: int | None = None
        # Set when the runner process failed to launch, so the generic
        # "no tests ran" line doesn't follow the specific reason.
        self._launch_failed = False
        self._controller = RunController(self)
        self._controller.test_event.connect(self._on_test_event)
        self._controller.packet_event.connect(self._on_packet_event)
        self._controller.output_line.connect(self._on_output_line)
        self._controller.finished.connect(self._on_finished)
        self._controller.failed.connect(self._on_launch_failed)

        self._build_ui()

    def _build_ui(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)
        root_layout = QVBoxLayout(central)

        root_layout.addWidget(self._build_config_group())

        tabs = QTabWidget()
        tabs.addTab(self._build_suite_tab(), "Automated Suite")
        tabs.addTab(CustomPacketPanel(), "Custom Packet")
        # Run this instance as the backend/server side of a proxy-DUT test.
        self._proxy_panel = ProxyBackendPanel()
        tabs.addTab(self._proxy_panel, "Proxy Backend")
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
        self._target_stack.addItems(list_profiles())
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

        # Proxy-DUT topology (only used by the `proxy` test module; leave the
        # mode off for ordinary endpoint testing).
        self._proxy_mode = QComboBox()
        self._proxy_mode.addItem("(off)", userData=None)
        for mode in ProxyMode:
            self._proxy_mode.addItem(mode.value, userData=mode.value)
        self._proxy_mode.setToolTip(
            "Enable the proxy test module. Requires a second instance running the "
            "Proxy Backend tab (or `netstack-cli proxy-serve`)."
        )
        self._proxy_front = QLineEdit()
        self._proxy_front.setPlaceholderText("proxy front host:port — e.g. 10.0.0.5:1080")
        self._proxy_backend = QLineEdit()
        self._proxy_backend.setPlaceholderText("backend host:port — e.g. 10.0.0.9:9099")
        # Aims the ordinary ip/udp/icmp/tcp suites at one side of a proxy DUT.
        self._proxy_leg = QComboBox()
        self._proxy_leg.addItem("(endpoint — not a proxy)", userData=None)
        for leg in ProxyLeg:
            self._proxy_leg.addItem(leg.value, userData=leg.value)
        self._proxy_leg.setToolTip(
            "Run the ordinary IP/UDP/ICMP/TCP tests against a proxy DUT:\n"
            "front — probe its client-facing stack (runs as client, retargets to Proxy front).\n"
            "back — observe the stack it dials origins with (runs as server; needs a\n"
            "proxy mode and backend so traffic can be induced through the front)."
        )

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
        form.addRow("Proxy mode", self._proxy_mode)
        form.addRow("Proxy front", self._proxy_front)
        form.addRow("Proxy backend", self._proxy_backend)
        form.addRow("Proxy leg (all tests)", self._proxy_leg)
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

    def _selected_proxy_leg(self) -> ProxyLeg | None:
        value = self._proxy_leg.currentData()
        return ProxyLeg(value) if value else None

    def _current_dut_config(self) -> DUTConfig:
        allowed = tuple(x.strip() for x in self._allowed_targets.text().split(",") if x.strip())
        leg = self._selected_proxy_leg()
        role = resolve_role(leg, Role(self._role.currentText()))
        front_host, front_port = _split_host_port(self._proxy_front.text())
        # `None` for a Destination port left on 'random' (spinbox 0), so a
        # front leg can substitute the proxy's front port before we fall back
        # to a session-stable random one.
        target_ip, target_port = resolve_leg_target(
            leg,
            target_ip=self._target_ip.text(),
            target_port=self._dst_port.value() or None,
            proxy_host=front_host,
            proxy_port=front_port,
        )
        if target_port is None:
            target_port = self._resolved_dst_port()
        return DUTConfig(
            interface=self._iface_combo.currentText(),
            target_ip=target_ip,
            target_stack=self._target_stack.currentText(),
            target_mac=self._target_mac.text() or None,
            target_port=target_port,
            source_port=self._src_port.value() or None,
            allowed_targets=allowed,
            role=role,
            proxy_leg=leg,
        )

    def _on_tree_selection(self, current, _previous) -> None:
        self._details.show_spec(self._tree.spec_of(current))

    def closeEvent(self, event) -> None:  # noqa: N802 - Qt naming
        """Release the proxy backend's listening socket on exit."""
        self._proxy_panel.shutdown()
        super().closeEvent(event)

    def _on_run_clicked(self) -> None:
        self._metrics.clear()
        self._plot.reset()
        self._log_panel.clear_log()
        self._launch_failed = False
        # Surface progress/errors as text — the Log tab is where the run
        # actually reports what happened (a blank Live plot was exactly why
        # a failed run looked like "nothing happened").
        self._right_tabs.setCurrentWidget(self._log_panel)

        config = self._current_dut_config()
        if not self._report_topology(config):
            return

        if not self._preflight_and_report(config):
            return
        self._warn_role_mismatches(config)

        request = self._build_run_request(config)
        selection = ", ".join(request.targets) if request.targets else "all tests"
        self._log_panel.append_line(f"Starting run (role={config.role.value}, selection: {selection})…")
        if request.proxy_mode:
            self._log_panel.append_line(
                f"Proxy mode {request.proxy_mode}: "
                f"front={request.proxy_host or '-'}:{request.proxy_port or '-'}, "
                f"backend={request.backend_host or '-'}:{request.backend_port or '-'} "
                "(the backend instance must be running)."
            )
        self._controller.start(request)

    def _report_topology(self, config: DUTConfig) -> bool:
        """Echo what the leg/port selectors resolved to and validate them.

        Returns whether the run may proceed. The CLI's counterpart is
        cli.main._resolve_topology, which applies the same rules from
        src.config and raises click.UsageError instead of logging.
        """
        leg = config.proxy_leg
        if leg is not None:
            self._log_panel.append_line(
                f"Proxy leg '{leg.value}' — running the selected tests as {config.role.value} "
                f"against {config.target_ip}:{config.target_port}."
            )
        blocked = back_leg_requirement_error(
            leg,
            proxy_mode=self._proxy_mode.currentData(),
            backend_host=_split_host_port(self._proxy_backend.text())[0],
            mode_label="a Proxy mode",
            host_label="a Proxy backend address",
        )
        if blocked:
            self._log_panel.append_line(f"{blocked} Not starting the run.")
            return False
        if not self._dst_port.value() and leg is not ProxyLeg.FRONT:
            self._log_panel.append_line(
                f"Destination port left on 'random' — using {config.target_port} for this session."
            )
        return True

    def _preflight_and_report(self, config: DUTConfig) -> bool:
        """Validate config + privileges and probe the DUT, reporting the
        outcome into the Log tab. Returns whether the run may proceed.

        Hard blockers abort before launching pytest; a no-ARP-reply warning
        still proceeds (a custom stack may not implement ARP).
        """
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
        return pre.ok

    def _warn_role_mismatches(self, config: DUTConfig) -> None:
        """Warn up front if a checked test won't run under the selected role
        (otherwise it just silently skips — the confusing case)."""
        for spec in self._tree.checked_specs():
            if config.role not in spec.roles:
                self._log_panel.append_line(
                    f"Note: '{spec.test}' applies to role(s) [{spec.role_labels}] but the Role is "
                    f"'{config.role.value}' — it will be SKIPPED. Change the Role selector to run it."
                )

    def _build_run_request(self, config: DUTConfig) -> RunRequest:
        """Widget state → RunRequest. The GUI's counterpart to the request
        construction in cli.main.run, against the same shared RunRequest."""
        proxy_host, proxy_port = _split_host_port(self._proxy_front.text())
        backend_host, backend_port = _split_host_port(self._proxy_backend.text())
        return RunRequest(
            config=config,
            targets=tuple(self._tree.checked_targets()),
            confirm_vuln_tests=self._confirm_vuln.isChecked(),
            debug=self._debug.isChecked(),
            # role/proxy_leg come from `config` (resolved in
            # _current_dut_config) — RunRequest deliberately has no copies.
            proxy_mode=self._proxy_mode.currentData(),
            proxy_host=proxy_host,
            proxy_port=proxy_port,
            backend_host=backend_host,
            backend_port=backend_port,
        )

    def _on_test_event(self, event: TestEvent) -> None:
        self._log_panel.append_test_event(event)

    def _on_packet_event(self, event: PacketEvent) -> None:
        self._metrics.add(event)

    def _on_output_line(self, line: str) -> None:
        self._log_panel.append_line(line)

    def _on_launch_failed(self, message: str) -> None:
        """The runner process never started. Nothing else will report it —
        a QProcess that fails to start emits no `finished`."""
        self._launch_failed = True
        self._log_panel.append_line(message)
        self._log_panel.append_line(
            "No tests were run. Check that the Python interpreter and the test "
            "tree are reachable from the project directory."
        )

    def _on_finished(self, result: TestRunResult) -> None:
        self._report_panel.set_result(result)
        if self._launch_failed:
            return  # _on_launch_failed already said what went wrong
        if result.errored:
            self._log_panel.append_line(
                f"pytest exited with code {result.pytest_returncode} "
                f"(collection/usage error or no tests) — see "
                f"reports/{result.run_id}/{RunArtifacts.PYTEST_OUTPUT}"
            )
        elif result.total == 0:
            self._log_panel.append_line(
                "Run finished but no tests ran — check the test selection and configuration."
            )
        else:
            self._log_panel.append_line(f"Run finished: {result.counts_summary}.")
            if result.skipped and result.passed == 0 and result.failed == 0 and result.errors == 0:
                self._log_panel.append_line(
                    "Everything selected was skipped — see the SKIP reason(s) above "
                    "(often a role mismatch: switch the Role selector)."
                )


def _split_host_port(text: str) -> tuple[str | None, int | None]:
    """Parse a `host:port` field, tolerating IPv6 literals in brackets.

    Returns (None, None) for an empty field so the option is simply omitted.
    """
    value = text.strip()
    if not value:
        return None, None
    if value.startswith("["):  # [::1]:9099
        host, _, rest = value.partition("]")
        host = host.lstrip("[")
        port = rest.lstrip(":")
    else:
        host, _, port = value.rpartition(":")
        if not host:  # no colon at all — treat the whole field as the host
            return value, None
    try:
        return host, int(port)
    except ValueError:
        return host or None, None


def _list_interface_names() -> list[str]:
    try:
        from scapy.interfaces import get_working_ifaces

        return [iface.name for iface in get_working_ifaces()]
    except Exception:
        return []
