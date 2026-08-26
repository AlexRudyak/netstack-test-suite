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
