"""GUI smoke tests via pytest-qt, forced onto the offscreen platform so
no real display is required (works in CI on both Windows and Linux).

Requires the optional `gui`/`dev` extras (PySide6, pyqtgraph, pytest-qt);
skipped automatically if they aren't installed.
"""
from __future__ import annotations

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PySide6")
pytest.importorskip("pyqtgraph")
pytest.importorskip("pytestqt")

pytestmark = [pytest.mark.internal]


def test_main_window_launches_and_populates_tree(qtbot, tmp_path, monkeypatch) -> None:
    # The tree reads the tests/ tree under paths.project_root(); point it at
    # a temp tree so the test is hermetic.
    import src.paths as paths_mod

    (tmp_path / "tests" / "ip").mkdir(parents=True)
    (tmp_path / "tests" / "ip" / "test_example.py").write_text("def test_example(): pass\n")
    monkeypatch.setattr(paths_mod, "project_root", lambda: tmp_path)

    from src.gui.main_window import MainWindow

    window = MainWindow()
    qtbot.addWidget(window)

    assert window._tree.topLevelItemCount() == 1
    assert window._tree.topLevelItem(0).text(0) == "ip"


def test_custom_packet_panel_mode_switch_shows_custom_fields(qtbot) -> None:
    from src.gui.custom_packet_panel import CustomPacketPanel

    panel = CustomPacketPanel()
    qtbot.addWidget(panel)

    panel._mode_custom.setChecked(True)
    assert panel._payload_stack.currentIndex() == 1

    panel._mode_random.setChecked(True)
    assert panel._payload_stack.currentIndex() == 0


def test_run_controller_can_be_constructed(qtbot) -> None:
    from src.gui.run_controller import RunController

    controller = RunController()
    assert controller is not None


def test_tree_shows_test_functions_and_details_panel_describes_them(qtbot) -> None:
    """The tree drills down to individual test functions, and selecting one
    shows its catalog description + RFC in the details panel."""
    from src.gui.test_details_panel import TestDetailsPanel
    from src.gui.test_tree_widget import TestTreeWidget

    tree = TestTreeWidget()
    qtbot.addWidget(tree)

    # Find a known test-function node carrying a catalog spec.
    found = None

    def walk(item):
        nonlocal found
        spec = TestTreeWidget.spec_of(item)
        if spec is not None and spec.test == "test_syn_elicits_syn_ack":
            found = item
        for i in range(item.childCount()):
            walk(item.child(i))

    for i in range(tree.topLevelItemCount()):
        walk(tree.topLevelItem(i))

    assert found is not None, "expected the tree to include individual test-function nodes"
    spec = TestTreeWidget.spec_of(found)

    panel = TestDetailsPanel()
    qtbot.addWidget(panel)
    panel.show_spec(spec)
    assert "SYN-ACK" in panel._description.toPlainText()
    assert "RFC 9293" in panel._meta.text()


def test_checking_module_cascades_and_yields_module_target(qtbot) -> None:
    """The reported bug: checking a module must check all its descendants
    and run the whole module (one covering target), not nothing."""
    from PySide6.QtCore import Qt

    from src.gui.test_tree_widget import TestTreeWidget

    tree = TestTreeWidget()
    qtbot.addWidget(tree)

    # Find the 'ip' module node and check it.
    ip_item = None
    for i in range(tree.topLevelItemCount()):
        if tree.topLevelItem(i).text(0) == "ip":
            ip_item = tree.topLevelItem(i)
    assert ip_item is not None
    ip_item.setCheckState(0, Qt.CheckState.Checked)

    # Cascade: every descendant is now checked.
    def all_checked(item):
        ok = item.checkState(0) == Qt.CheckState.Checked
        for i in range(item.childCount()):
            ok = ok and all_checked(item.child(i))
        return ok

    assert all_checked(ip_item)

    # Minimal covering target is just the module.
    assert tree.checked_targets() == ["tests/ip"]


def test_checking_single_test_yields_its_nodeid(qtbot) -> None:
    from PySide6.QtCore import Qt

    from src.gui.test_tree_widget import TestTreeWidget

    tree = TestTreeWidget()
    qtbot.addWidget(tree)

    # Use a test in a file with SIBLINGS, so checking it leaves the file
    # partially checked and the covering target is the test's nodeid.
    target_found = None

    def walk(item):
        nonlocal target_found
        spec = TestTreeWidget.spec_of(item)
        if spec is not None and spec.test == "test_ttl_expiry_generates_icmp_time_exceeded":
            item.setCheckState(0, Qt.CheckState.Checked)
            target_found = tree.checked_targets()
        for i in range(item.childCount()):
            walk(item.child(i))

    for i in range(tree.topLevelItemCount()):
        walk(tree.topLevelItem(i))

    assert target_found == [
        "tests/ip/test_ip_header_validation.py::test_ttl_expiry_generates_icmp_time_exceeded"
    ]


def test_role_selector_feeds_run_request(qtbot, monkeypatch) -> None:
    """The GUI role selector is threaded into the RunRequest."""
    import src.gui.main_window as main_window
    from src.config import Role
    from src.packet_engine.preflight import PreflightResult

    monkeypatch.setattr(main_window, "run_preflight", lambda config: PreflightResult(ok=True, info=["ok"]))

    window = main_window.MainWindow()
    qtbot.addWidget(window)
    window._target_ip.setText("10.0.0.5")
    window._role.setCurrentText("server")

    captured = {}
    monkeypatch.setattr(window._controller, "start", lambda request: captured.update(request=request))
    window._on_run_clicked()

    assert captured["request"].role is Role.SERVER


def test_blank_destination_port_yields_one_stable_random_port(qtbot) -> None:
    """Leaving the Destination port on 'random' picks a single ephemeral
    port and reuses it for every config read in the session."""
    from src.config import EPHEMERAL_PORT_RANGE
    from src.gui.main_window import MainWindow

    window = MainWindow()
    qtbot.addWidget(window)

    assert window._dst_port.value() == 0  # 'random'
    first = window._current_dut_config().target_port
    lo, hi = EPHEMERAL_PORT_RANGE
    assert lo <= first <= hi
    assert window._current_dut_config().target_port == first  # stable

    window._dst_port.setValue(4444)
    assert window._current_dut_config().target_port == 4444


def test_proxy_backend_panel_starts_and_stops(qtbot) -> None:
    """The GUI can act as the backend (server) instance of a proxy test."""
    from src.gui.proxy_panel import ProxyBackendPanel

    panel = ProxyBackendPanel()
    qtbot.addWidget(panel)

    panel._listen_host.setText("127.0.0.1")
    # 0 = ephemeral: avoids a privileged (<1024) port, which a non-root CI
    # user cannot bind on Linux, and avoids colliding with a busy fixed port.
    panel._listen_port.setValue(0)
    panel._start()
    try:
        assert panel._backend is not None, "backend did not start"
        assert panel._backend.bound_port > 0, "ephemeral port was not resolved"
    finally:
        panel._stop()
    assert panel._backend is None


def test_proxy_mode_selection_feeds_run_request(qtbot, monkeypatch) -> None:
    """Proxy topology entered in the GUI reaches the RunRequest."""
    import src.gui.main_window as main_window
    from src.packet_engine.preflight import PreflightResult

    monkeypatch.setattr(main_window, "run_preflight", lambda config: PreflightResult(ok=True, info=["ok"]))

    window = main_window.MainWindow()
    qtbot.addWidget(window)
    window._target_ip.setText("10.0.0.5")
    window._proxy_mode.setCurrentText("socks5")
    window._proxy_front.setText("10.0.0.5:1080")
    window._proxy_backend.setText("10.0.0.9:9099")

    captured = {}
    monkeypatch.setattr(window._controller, "start", lambda request: captured.update(request=request))
    window._on_run_clicked()

    request = captured["request"]
    assert request.proxy_mode == "socks5"
    assert (request.proxy_host, request.proxy_port) == ("10.0.0.5", 1080)
    assert (request.backend_host, request.backend_port) == ("10.0.0.9", 9099)


def test_proxy_front_leg_retargets_and_forces_client_role(qtbot, monkeypatch) -> None:
    """Choosing the front leg points the ORDINARY suites at the proxy's
    client-facing address and runs them as client — overriding the Role
    selector, which can only be wrong once a leg is chosen."""
    import src.gui.main_window as main_window
    from src.config import ProxyLeg, Role
    from src.packet_engine.preflight import PreflightResult

    monkeypatch.setattr(main_window, "run_preflight", lambda config: PreflightResult(ok=True, info=["ok"]))

    window = main_window.MainWindow()
    qtbot.addWidget(window)
    window._target_ip.setText("10.0.0.5")
    window._proxy_front.setText("192.0.2.7:1080")
    window._role.setCurrentText("server")  # deliberately contradictory
    window._proxy_leg.setCurrentText("front")

    captured = {}
    monkeypatch.setattr(window._controller, "start", lambda request: captured.update(request=request))
    window._on_run_clicked()

    request = captured["request"]
    assert request.proxy_leg == "front"
    assert request.config.target_ip == "192.0.2.7"
    assert request.config.target_port == 1080
    assert request.config.role is Role.CLIENT
    assert request.config.proxy_leg is ProxyLeg.FRONT


def test_proxy_back_leg_without_a_topology_is_refused(qtbot, monkeypatch) -> None:
    """The back leg is idle unless traffic is driven through the front, so
    a back-leg run with no proxy mode/backend must say so instead of
    producing a run where every server-role test times out."""
    import src.gui.main_window as main_window
    from src.packet_engine.preflight import PreflightResult

    monkeypatch.setattr(main_window, "run_preflight", lambda config: PreflightResult(ok=True, info=["ok"]))

    window = main_window.MainWindow()
    qtbot.addWidget(window)
    window._target_ip.setText("10.0.0.5")
    window._proxy_leg.setCurrentText("back")

    started = {"called": False}
    monkeypatch.setattr(window._controller, "start", lambda request: started.__setitem__("called", True))
    window._on_run_clicked()

    assert started["called"] is False
    assert "back" in window._log_panel.toPlainText()


def test_failed_preflight_blocks_run_and_reports(qtbot, monkeypatch) -> None:
    """The reported bug: a run that can't proceed must report to the user
    and not silently start. A failing preflight blocks controller.start
    and writes the reason to the log panel."""
    import src.gui.main_window as main_window
    from src.packet_engine.preflight import PreflightResult

    monkeypatch.setattr(
        main_window,
        "run_preflight",
        lambda config: PreflightResult(ok=False, errors=["Missing required configuration: Target IP."]),
    )

    window = main_window.MainWindow()
    qtbot.addWidget(window)

    started = {"called": False}
    monkeypatch.setattr(window._controller, "start", lambda request: started.__setitem__("called", True))

    window._on_run_clicked()

    assert started["called"] is False
    log_text = window._log_panel.toPlainText()
    assert "Preflight" in log_text
    assert "Target IP" in log_text
    # And the user is shown the Log tab, not the blank Live plot.
    assert window._right_tabs.currentWidget() is window._log_panel


# --- widget state -> RunRequest --------------------------------------------
# Extracted from _on_run_clicked by the complexity audit (F-03) precisely so
# it could be asserted without driving the whole click handler.


def test_build_run_request_maps_widget_state(qtbot) -> None:
    from src.config import Role
    from src.gui.main_window import MainWindow

    window = MainWindow()
    qtbot.addWidget(window)

    window._target_ip.setText("10.0.0.5")
    window._iface_combo.addItem("eth9")
    window._iface_combo.setCurrentText("eth9")
    window._dst_port.setValue(8080)
    window._confirm_vuln.setChecked(True)
    window._debug.setChecked(True)
    window._proxy_front.setText("10.0.0.7:1080")
    window._proxy_backend.setText("10.0.0.9:9099")

    config = window._current_dut_config()
    request = window._build_run_request(config)

    assert request.config is config
    assert request.confirm_vuln_tests is True
    assert request.debug is True
    assert request.role is config.role
    assert request.proxy_host == "10.0.0.7"
    assert request.proxy_port == 1080
    assert request.backend_host == "10.0.0.9"
    assert request.backend_port == 9099
    # No proxy leg selected ⇒ the ordinary endpoint form.
    assert request.proxy_leg is None
    assert config.role is Role.CLIENT


def test_build_run_request_carries_proxy_leg_when_selected(qtbot) -> None:
    """A front leg forces the client role and retargets to the proxy front —
    the rule src.config owns and both front ends must apply identically."""
    from src.config import ProxyLeg, Role
    from src.gui.main_window import MainWindow

    window = MainWindow()
    qtbot.addWidget(window)

    window._target_ip.setText("10.0.0.5")
    window._proxy_front.setText("10.0.0.7:1080")
    window._role.setCurrentText("server")  # overridden by the front leg
    index = window._proxy_leg.findData(ProxyLeg.FRONT.value)
    window._proxy_leg.setCurrentIndex(index)

    config = window._current_dut_config()
    request = window._build_run_request(config)

    assert request.proxy_leg == "front"
    assert config.role is Role.CLIENT
    assert config.target_ip == "10.0.0.7"
    assert config.target_port == 1080


def test_a_runner_that_cannot_start_reports_instead_of_hanging(qtbot, tmp_path, monkeypatch) -> None:
    """A QProcess that fails to start never emits `finished`.

    So without errorOccurred wired up, the poll timer tails a report log
    that will never be created, finalize_run is never called, and the Log
    tab shows "Starting run…" and then nothing, forever.
    """
    import src.gui.run_controller as run_controller_mod
    from src.config import DUTConfig
    from src.gui.run_controller import RunController
    from src.runner import RunRequest

    # A launcher that cannot possibly start.
    monkeypatch.setattr(
        run_controller_mod,
        "build_pytest_args",
        lambda request, run_dir: [str(tmp_path / "no-such-interpreter"), "tests"],
    )
    monkeypatch.setattr(run_controller_mod, "new_run_dir", lambda: ("run-x", tmp_path))

    controller = RunController()
    request = RunRequest(
        config=DUTConfig(interface="eth0", target_ip="10.0.0.5", target_stack="linux")
    )

    with qtbot.waitSignal(controller.failed, timeout=5000) as blocker:
        controller.start(request)

    assert "Could not start the test runner" in blocker.args[0]
    assert not controller._timer.isActive(), "the poll timer outlived the failed launch"


def test_a_failed_launch_still_finalizes_the_run(qtbot, tmp_path, monkeypatch) -> None:
    """results.json is what keeps a failed launch visible in reports/."""
    import src.gui.run_controller as run_controller_mod
    from src.config import DUTConfig
    from src.gui.run_controller import RunController
    from src.run_artifacts import RunArtifacts
    from src.runner import RunRequest

    monkeypatch.setattr(
        run_controller_mod,
        "build_pytest_args",
        lambda request, run_dir: [str(tmp_path / "no-such-interpreter"), "tests"],
    )
    monkeypatch.setattr(run_controller_mod, "new_run_dir", lambda: ("run-y", tmp_path))

    controller = RunController()
    request = RunRequest(
        config=DUTConfig(interface="eth0", target_ip="10.0.0.5", target_stack="linux")
    )

    with qtbot.waitSignal(controller.finished, timeout=5000) as blocker:
        controller.start(request)

    result = blocker.args[0]
    assert result.pytest_returncode is None  # the process never ran
    assert RunArtifacts(tmp_path).results.exists()


def test_a_failing_export_warns_instead_of_taking_the_window_down(
    qtbot, tmp_path, monkeypatch
) -> None:
    """_export is a `clicked` slot and the save dialog lets the operator pick
    a destination they can't write to. An exception leaving the slot reaches
    sys.excepthook and closes the window, over a failed export of a run whose
    data is already on disk.
    """
    from PySide6.QtWidgets import QFileDialog, QMessageBox

    from src.gui.report_panel import ReportPanel
    from src.reporting import formats

    from .conftest import make_run_result

    panel = ReportPanel()
    qtbot.addWidget(panel)
    panel.set_result(make_run_result(run_id="export-run"))

    destination = tmp_path / "report.pdf"
    monkeypatch.setattr(
        QFileDialog, "getSaveFileName", staticmethod(lambda *a, **k: (str(destination), ""))
    )
    warned: list = []
    monkeypatch.setattr(
        QMessageBox, "warning", staticmethod(lambda *a, **k: warned.append(a))
    )

    def explode(_result, _path):
        raise OSError("[Errno 13] Permission denied")

    panel._export(formats.ReportFormat("pdf", "PDF", explode))

    assert warned, "the operator was not told the export failed"
    assert "Could not write the PDF report" in panel._status_label.text()


def test_an_empty_interface_list_explains_itself(qtbot, monkeypatch, tmp_path) -> None:
    """An empty combo box almost always means the packet driver is missing.
    Silently empty, that reads as "you forgot to pick an interface" — the
    preflight then names the field rather than the cause.
    """
    import src.gui.main_window as main_window_mod
    import src.paths as paths_mod

    (tmp_path / "tests").mkdir()
    monkeypatch.setattr(paths_mod, "project_root", lambda: tmp_path)
    monkeypatch.setattr(main_window_mod, "_list_interface_names", lambda: [])

    window = main_window_mod.MainWindow()
    qtbot.addWidget(window)

    assert window._iface_combo.count() == 0
    assert window._iface_combo.toolTip(), "no explanation offered for the empty list"


def test_interface_enumeration_failure_is_logged_not_swallowed(monkeypatch, caplog) -> None:
    import logging as logging_mod

    import src.gui.main_window as main_window_mod

    def explode():
        raise OSError("Npcap is not installed")

    monkeypatch.setattr("scapy.interfaces.get_working_ifaces", explode)

    with caplog.at_level(logging_mod.ERROR):
        assert main_window_mod._list_interface_names() == []

    assert "Could not enumerate network interfaces" in caplog.text


def test_an_uncreatable_run_directory_reports_instead_of_crashing(
    qtbot, tmp_path, monkeypatch
) -> None:
    """`start` runs inside a `clicked` slot, where an escaping exception
    reaches sys.excepthook — which logs, shows a dialog, and ends the
    process. An unwritable reports/ must not cost the session."""
    import src.gui.run_controller as run_controller_mod
    from src.config import DUTConfig
    from src.errors import RunArtifactError
    from src.gui.run_controller import RunController
    from src.runner import RunRequest

    def _refuse() -> tuple[str, object]:
        raise RunArtifactError("Could not create the run directory /nope: denied")

    monkeypatch.setattr(run_controller_mod, "new_run_dir", _refuse)

    controller = RunController()
    request = RunRequest(
        config=DUTConfig(interface="eth0", target_ip="10.0.0.5", target_stack="linux")
    )

    with qtbot.waitSignal(controller.failed, timeout=5000) as blocker:
        controller.start(request)

    assert "Could not create the run directory" in blocker.args[0]
    assert not controller._timer.isActive()


def test_a_results_write_failure_still_delivers_the_run(qtbot, tmp_path, monkeypatch) -> None:
    """finalize_run is called from Qt slots. A full disk there used to take
    the window down; the run's result is complete in memory either way."""
    import src.gui.run_controller as run_controller_mod
    from src.config import DUTConfig
    from src.errors import RunArtifactError
    from src.gui.run_controller import RunController
    from src.runner import RunRequest

    monkeypatch.setattr(
        run_controller_mod,
        "build_pytest_args",
        lambda request, run_dir: [str(tmp_path / "no-such-interpreter"), "tests"],
    )
    monkeypatch.setattr(run_controller_mod, "new_run_dir", lambda: ("run-z", tmp_path))

    def _refuse(result, run_dir, returncode):
        raise RunArtifactError("Could not write results.json: no space left on device")

    monkeypatch.setattr(run_controller_mod, "finalize_run", _refuse)

    controller = RunController()
    reported: list[str] = []
    controller.save_failed.connect(reported.append)
    request = RunRequest(
        config=DUTConfig(interface="eth0", target_ip="10.0.0.5", target_stack="linux")
    )

    with qtbot.waitSignal(controller.finished, timeout=5000) as blocker:
        controller.start(request)

    assert blocker.args[0] is not None, "the completed run was not delivered"
    assert reported and "no space left" in reported[0]


def _idle_controller(tmp_path, run_id: str):
    """A RunController holding a started run, with no live QProcess."""
    from src.config import DUTConfig
    from src.gui.run_controller import RunController
    from src.runner import RunRequest, new_run_result

    controller = RunController()
    controller._run_dir = tmp_path
    controller._result = new_run_result(
        run_id,
        RunRequest(config=DUTConfig(interface="eth0", target_ip="10.0.0.5", target_stack="linux")),
    )
    return controller


def test_a_stopped_run_is_not_reported_as_a_collection_error(qtbot, tmp_path) -> None:
    """QProcess.kill() reports the OS crash code (62097 on Windows), and
    `errored` is `pytest_returncode >= 2` — so pressing Stop was recorded,
    in the log and in results.json, as "pytest exited with code 62097
    (collection/usage error or no tests)"."""
    from PySide6.QtCore import QProcess

    controller = _idle_controller(tmp_path, "run-stopped")
    controller._stopping = True

    with qtbot.waitSignal(controller.finished, timeout=5000) as blocker:
        controller._on_finished(62097, QProcess.ExitStatus.CrashExit)

    result = blocker.args[0]
    assert result.pytest_returncode is None
    assert not result.errored, "the operator's own Stop was reported as a suite malfunction"


def test_a_real_pytest_exit_code_is_still_recorded(qtbot, tmp_path) -> None:
    """The fix must not swallow the codes pytest actually chooses: 2 is a
    genuine collection/usage error and has to stay visible."""
    from PySide6.QtCore import QProcess

    controller = _idle_controller(tmp_path, "run-errored")

    with qtbot.waitSignal(controller.finished, timeout=5000) as blocker:
        controller._on_finished(2, QProcess.ExitStatus.NormalExit)

    result = blocker.args[0]
    assert result.pytest_returncode == 2
    assert result.errored


def test_a_malformed_port_is_reported_not_silently_dropped(qtbot) -> None:
    """None means "unset" everywhere in this codebase, so degrading a typo
    to None ran the suite against the default backend port — or, on a front
    leg, a random ephemeral one — instead of what was typed."""
    from src.errors import ConfigurationError
    from src.gui.main_window import _split_host_port

    with pytest.raises(ConfigurationError, match="not a port number"):
        _split_host_port("10.0.0.5:abc")


def test_host_only_fields_still_yield_an_unset_port(qtbot) -> None:
    """Only a port that is present and unparseable is an error; a field with
    no port at all is a host, and stays one."""
    from src.gui.main_window import _split_host_port

    assert _split_host_port("") == (None, None)
    assert _split_host_port("10.0.0.5") == ("10.0.0.5", None)
    assert _split_host_port("10.0.0.5:") == ("10.0.0.5", None)
    assert _split_host_port("[::1]") == ("::1", None)
    assert _split_host_port("[::1]:9099") == ("::1", 9099)
    assert _split_host_port("10.0.0.9:9099") == ("10.0.0.9", 9099)


def test_a_malformed_proxy_field_blocks_the_run(qtbot, monkeypatch) -> None:
    """_on_run_clicked is a `clicked` slot: the report has to reach the log
    panel, and the exception must not reach sys.excepthook."""
    from src.gui.main_window import MainWindow

    window = MainWindow()
    qtbot.addWidget(window)
    window._target_ip.setText("10.0.0.5")
    window._proxy_backend.setText("10.0.0.9:not-a-port")

    started: list[object] = []
    monkeypatch.setattr(window._controller, "start", started.append)

    window._on_run_clicked()

    assert not started, "the run started with a port the operator did not type"
    assert "not a port number" in window._log_panel.toPlainText()


def test_a_rejected_custom_packet_reports_the_reason(qtbot, monkeypatch) -> None:
    """The panel's catch-all rendered four quite different failures as one
    untyped line and logged none of them."""
    from src.gui.custom_packet_panel import CustomPacketPanel

    panel = CustomPacketPanel()
    qtbot.addWidget(panel)
    panel._mode_custom.setChecked(True)
    panel._custom_hex.setText("zz")  # not hex: a ConfigurationError

    panel._on_send()

    assert "Error:" in panel._response_view.toPlainText()
    assert "not valid hex" in panel._response_view.toPlainText()


def test_an_unexpected_custom_packet_failure_is_typed_and_logged(
    qtbot, monkeypatch, caplog
) -> None:
    """A bug or a Scapy refusal keeps the window (this is a `clicked` slot),
    but its traceback must reach gui.log rather than being discarded."""
    import src.gui.custom_packet_panel as panel_mod
    from src.gui.custom_packet_panel import CustomPacketPanel

    def _explode(*_args, **_kwargs):
        raise OSError("no such device: eth42")

    monkeypatch.setattr(panel_mod, "send_custom_packet", _explode)

    panel = CustomPacketPanel()
    qtbot.addWidget(panel)

    with caplog.at_level("ERROR"):
        panel._on_send()

    shown = panel._response_view.toPlainText()
    assert "OSError" in shown, "the operator cannot tell a bug from bad input"
    assert "no such device" in shown
    assert "Custom packet send failed" in caplog.text


def test_controller_callbacks_are_safe_before_a_run_starts(qtbot) -> None:
    """These were asserts, which `python -O` strips — leaving an
    AttributeError on None inside a Qt slot, which ends the process. They
    encode an ordering between separate callbacks, not a local invariant."""
    from src.gui.run_controller import RunController

    controller = RunController()

    controller._drain()  # a poll with no run behind it
    controller._on_output()  # output with no process

    assert controller._report_offset == 0
