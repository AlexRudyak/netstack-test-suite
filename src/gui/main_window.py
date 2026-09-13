"""Main GUI window: DUT configuration, test selection tree, live plot,
log panel, and report export — plus a Custom Packet tab for ad-hoc sends.
"""
from __future__ import annotations

import logging

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QGroupBox,
    QHBoxLayout,
    QLabel,
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
from src.design_tokens import SPACE
from src.errors import ConfigurationError
from src.gui.custom_packet_panel import CustomPacketPanel
from src.gui.log_panel import LogPanel
from src.gui.proxy_panel import ProxyBackendPanel
from src.gui.report_panel import ReportPanel
from src.gui.run_controller import RunController
from src.gui.test_details_panel import TestDetailsPanel
from src.gui.test_tree_widget import TestTreeWidget
from src.gui.theme import divider, form_layout, refresh_style
from src.packet_engine.preflight import run_preflight
from src.proxy.config import ProxyMode
from src.plotting.metrics import MetricsBuffer
from src.plotting.realtime_plotter import RealtimePlotWidget
from src.reporting.models import PacketEvent, TestEvent, TestRunResult
from src.run_artifacts import RunArtifacts
from src.runner import RunRequest
from src.target_profiles import list_profiles
from src.utils.permissions import remediation_message


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
        # Set when the operator pressed Stop, so a partial run is reported as
        # stopped rather than as "no tests ran".
        self._stopped = False
        self._controller = RunController(self)
        self._controller.test_event.connect(self._on_test_event)
        self._controller.packet_event.connect(self._on_packet_event)
        self._controller.output_line.connect(self._on_output_line)
        self._controller.finished.connect(self._on_finished)
        self._controller.failed.connect(self._on_launch_failed)
        self._controller.save_failed.connect(self._on_save_failed)
        self._controller.stopped.connect(self._on_stopped)

        self._build_ui()

    def _build_ui(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)
        root_layout = QVBoxLayout(central)
        root_layout.setContentsMargins(SPACE * 2, SPACE * 2, SPACE * 2, SPACE * 2)
        root_layout.setSpacing(SPACE + 4)

        root_layout.addWidget(self._build_header())
        root_layout.addWidget(self._build_config_bar())

        tabs = QTabWidget()
        tabs.addTab(self._build_suite_tab(), "Automated Suite")
        tabs.addTab(CustomPacketPanel(), "Custom Packet")
        # Run this instance as the backend/server side of a proxy-DUT test.
        self._proxy_panel = ProxyBackendPanel()
        tabs.addTab(self._proxy_panel, "Proxy Backend")
        root_layout.addWidget(tabs, stretch=1)

        self._report_panel = ReportPanel()
        root_layout.addWidget(self._report_panel)

    def _build_header(self) -> QWidget:
        """Title block plus the run-state pill.

        The pill is the one place the window says what it is doing right
        now: the log scrolls, the plot is only meaningful mid-run, and the
        verdict used to be legible solely by reading the last log line.
        """
        bar = QWidget()
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(2, 0, 2, 0)

        titles = QVBoxLayout()
        titles.setSpacing(1)
        title = QLabel("Network Stack Test Suite")
        title.setProperty("role", "heading")
        subtitle = QLabel("RFC conformance and vulnerability probing against a live DUT")
        subtitle.setProperty("role", "caption")
        titles.addWidget(title)
        titles.addWidget(subtitle)

        self._status_pill = QLabel()
        self._status_pill.setProperty("role", "chip")
        self._set_status("Idle — configure the DUT, pick tests, run", state="idle")

        layout.addLayout(titles)
        layout.addStretch(1)
        layout.addWidget(self._status_pill, alignment=Qt.AlignmentFlag.AlignVCenter)
        return bar

    def _set_status(self, text: str, *, state: str) -> None:
        """Update the header pill. `state` is one of the theme's
        `idle`/`ok`/`bad` inks."""
        self._status_pill.setText(text)
        self._status_pill.setProperty("state", state)
        refresh_style(self._status_pill)

    def _build_config_bar(self) -> QWidget:
        """The two configuration cards, side by side.

        They were one 13-row column, which pushed the tabs — the tree, the
        plot, the log, everything a run is actually watched through — off
        the bottom of a laptop screen. Splitting endpoint configuration
        from proxy topology also states which fields belong together.
        """
        bar = QWidget()
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(SPACE + 4)
        layout.addWidget(self._build_config_group(), stretch=3)
        layout.addWidget(self._build_proxy_group(), stretch=2)
        self._config_bar = bar
        return bar

    def _build_config_group(self) -> QGroupBox:
        box = QGroupBox("DUT configuration")

        self._iface_combo = QComboBox()
        interface_names = _list_interface_names()
        self._iface_combo.addItems(interface_names)
        if not interface_names:
            # Say why the list is empty where the operator is looking, rather
            # than letting the preflight report a missing field later.
            self._iface_combo.setPlaceholderText("No interfaces found — see tooltip")
            self._iface_combo.setToolTip(remediation_message())
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

        left = form_layout()
        left.addRow("Interface", self._iface_combo)
        left.addRow("Target IP", self._target_ip)
        left.addRow("Target MAC", self._target_mac)
        left.addRow("Allowed targets (CIDR)", self._allowed_targets)

        right = form_layout()
        right.addRow("Target stack", self._target_stack)
        right.addRow("Role", self._role)
        right.addRow("Destination port", self._dst_port)
        right.addRow("Source port", self._src_port)

        columns = QHBoxLayout()
        columns.setSpacing(SPACE * 3)
        columns.addLayout(left, stretch=1)
        columns.addLayout(right, stretch=1)

        layout = QVBoxLayout(box)
        layout.setSpacing(SPACE + 2)
        layout.addLayout(columns)
        layout.addWidget(divider())
        layout.addWidget(self._debug)
        layout.addWidget(self._confirm_vuln)
        return box

    def _build_proxy_group(self) -> QGroupBox:
        """Proxy-DUT topology — its own card because it is a different
        subject: these fields describe a *relay* under test, and every one
        of them is inert for ordinary endpoint testing."""
        box = QGroupBox("Proxy topology (optional)")

        # Only used by the `proxy` test module; leave the mode off for
        # ordinary endpoint testing.
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

        form = form_layout()
        form.addRow("Proxy mode", self._proxy_mode)
        form.addRow("Proxy front", self._proxy_front)
        form.addRow("Proxy backend", self._proxy_backend)
        form.addRow("Proxy leg (all tests)", self._proxy_leg)

        hint = QLabel(
            "Leave the mode off unless the DUT is a relay. A back leg also needs "
            "the other instance running the Proxy Backend tab."
        )
        hint.setProperty("role", "caption")
        hint.setWordWrap(True)

        layout = QVBoxLayout(box)
        layout.setSpacing(SPACE + 2)
        layout.addLayout(form)
        layout.addStretch(1)
        layout.addWidget(hint)
        return box

    def _build_suite_tab(self) -> QWidget:
        widget = QWidget()
        layout = QHBoxLayout(widget)
        layout.setContentsMargins(SPACE + 2, SPACE + 2, SPACE + 2, SPACE + 2)

        left_widget = QWidget()
        left = QVBoxLayout(left_widget)
        left.setContentsMargins(0, 0, 0, 0)
        left.setSpacing(SPACE)
        self._tree = TestTreeWidget()
        self._tree.currentItemChanged.connect(self._on_tree_selection)
        self._tree.setMinimumHeight(140)
        left.addWidget(self._tree, stretch=3)
        # Per-test description: what the selected test checks + its RFC.
        # Capped, because a stretch factor alone lost to the description
        # box's size hint and left the tree two rows tall.
        self._details = TestDetailsPanel()
        self._details.setMaximumHeight(170)
        left.addWidget(self._details, stretch=1)

        buttons = QHBoxLayout()
        buttons.setSpacing(SPACE)
        self._run_button = QPushButton("Run selected")
        self._run_button.setProperty("accent", "true")
        self._run_button.clicked.connect(self._on_run_clicked)
        self._stop_button = QPushButton("Stop")
        self._stop_button.setProperty("danger", "true")
        # Enabled only while a run is in flight: a Stop that is always
        # available says nothing about whether anything is running.
        self._stop_button.setEnabled(False)
        self._stop_button.clicked.connect(self._controller.stop)
        buttons.addWidget(self._run_button, stretch=1)
        buttons.addWidget(self._stop_button)
        left.addLayout(buttons)

        self._right_tabs = QTabWidget()
        self._plot = RealtimePlotWidget(self._metrics)
        self._right_tabs.addTab(self._plot, "Live plot")
        self._log_panel = LogPanel()
        self._right_tabs.addTab(self._log_panel, "Log")

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setChildrenCollapsible(False)
        splitter.addWidget(left_widget)
        splitter.addWidget(self._right_tabs)
        # The picker needs about a third: enough for long nodeids, not so
        # much that the plot and log — the live half — get squeezed.
        splitter.setStretchFactor(0, 2)
        splitter.setStretchFactor(1, 3)
        splitter.setSizes([420, 630])
        layout.addWidget(splitter)
        return widget

    def _set_running(self, running: bool) -> None:
        """Swap Run/Stop availability for the run in flight."""
        self._run_button.setEnabled(not running)
        self._stop_button.setEnabled(running)

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
        self._stopped = False
        self._set_status("Preflight…", state="idle")
        # Surface progress/errors as text — the Log tab is where the run
        # actually reports what happened (a blank Live plot was exactly why
        # a failed run looked like "nothing happened").
        self._right_tabs.setCurrentWidget(self._log_panel)

        try:
            config = self._current_dut_config()
            if not self._report_and_validate_topology(config):
                return

            if not self._preflight_and_report(config):
                return
            self._warn_role_mismatches(config)

            request = self._build_run_request(config)
        except ConfigurationError as exc:
            # A malformed field, reported where the operator is looking
            # instead of silently becoming an unset value. This is also a
            # `clicked` slot, so an escape here would end the process.
            self._log_panel.append_line(f"{exc.render()} Not starting the run.")
            return

        selection = ", ".join(request.targets) if request.targets else "all tests"
        self._log_panel.append_line(f"Starting run (role={config.role.value}, selection: {selection})…")
        if request.proxy_mode:
            self._log_panel.append_line(
                f"Proxy mode {request.proxy_mode}: "
                f"front={request.proxy_host or '-'}:{request.proxy_port or '-'}, "
                f"backend={request.backend_host or '-'}:{request.backend_port or '-'} "
                "(the backend instance must be running)."
            )
        self._set_status(f"Running — {selection}", state="idle")
        self._set_running(True)
        self._controller.start(request)

    def _report_and_validate_topology(self, config: DUTConfig) -> bool:
        """Echo what the leg/port selectors resolved to and validate them.

        Returns whether the run may proceed. The CLI's counterpart is
        cli.main._resolve_topology, which applies the same rules from
        src.config and raises click.UsageError instead of logging.

        Renamed from `_report_topology` (was reporting-only in name but also
        gates whether `_on_run_clicked` proceeds) to match the
        `_preflight_and_report` naming shape already used alongside it.
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
        self._set_running(False)
        self._set_status("Could not start the run", state="bad")
        self._log_panel.append_line(message)
        self._log_panel.append_line("No tests were run.")

    def _on_save_failed(self, message: str) -> None:
        """The run finished but its results could not be written to disk.

        Distinct from a launch failure: the verdict below is real, and the
        panels still show it — what is gone is the saved copy this run could
        have been re-reported from without touching the DUT again.
        """
        self._log_panel.append_line(message)
        self._log_panel.append_line(
            "The results below are from this session only — export a report now "
            "if you need to keep them."
        )

    def _on_stopped(self) -> None:
        """The run ended because it was killed, not because pytest chose to."""
        self._stopped = True

    def _on_finished(self, result: TestRunResult) -> None:
        self._report_panel.set_result(result)
        self._set_running(False)
        text, state = _verdict(result, stopped=self._stopped, launch_failed=self._launch_failed)
        self._set_status(text, state=state)
        if self._launch_failed:
            return  # _on_launch_failed already said what went wrong
        if self._stopped:
            self._log_panel.append_line(
                f"Run stopped — {result.counts_summary} before the stop. "
                "The tests that did not run are not failures."
            )
        elif result.errored:
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


def _verdict(result: TestRunResult, *, stopped: bool, launch_failed: bool) -> tuple[str, str]:
    """The header pill's text and ink for a finished run.

    Kept next to the log lines it summarises: the pill is the glanceable
    form of exactly what `_on_finished` writes out, so the two are read
    together and cannot disagree about what happened.
    """
    if launch_failed:
        return "Could not start the run", "bad"
    if stopped:
        return f"Stopped — {result.counts_summary}", "idle"
    if result.errored:
        return f"pytest exited {result.pytest_returncode} — see the Log", "bad"
    if result.total == 0:
        return "No tests ran", "bad"
    if result.failed or result.errors:
        return f"{result.failed} failed, {result.errors} errored of {result.total}", "bad"
    return f"All {result.total} selected tests passed", "ok"


def _split_host_port(text: str) -> tuple[str | None, int | None]:
    """Parse a `host:port` field, tolerating IPv6 literals in brackets.

    Returns (None, None) for an empty field, and a port of None when the
    field carries no port at all, so the option is simply omitted.

    A port that is *present but unparseable* raises instead of degrading to
    None. None means "unset" everywhere else in this codebase — it is why
    runner._optional_flags omits the flag entirely, and why that function
    forwards a port of 0 rather than substitute a different one — so a typo
    here silently ran against the default backend port, or, on a front leg,
    against a random ephemeral port instead of the proxy. The only hint the
    operator got was a dash in one log line.
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
    if not port:  # "10.0.0.5:" or a bare "[::1]" — a host, no port
        return host or None, None
    try:
        return host or None, int(port)
    except ValueError as exc:
        raise ConfigurationError(
            f"{value!r} is not a valid host:port — {port!r} is not a port number."
        ) from exc


def _list_interface_names() -> list[str]:
    """Working interfaces, or an empty list with the reason recorded.

    An empty combo box here almost always means the packet driver is missing
    (Npcap on Windows). Discarding the exception made that read to the
    operator as "you forgot to pick an interface": the config check reports
    `Missing required configuration: Interface`, which names the field
    rather than the cause.
    """
    try:
        from scapy.interfaces import get_working_ifaces

        return [iface.name for iface in get_working_ifaces()]
    except Exception:
        logging.getLogger(__name__).exception("Could not enumerate network interfaces")
        return []
