"""Regenerate the documentation screenshots in docs/images/.

Screenshots in a README go stale the moment a widget changes, so they are
*generated*, not hand-captured: every image below is produced by building
the real widget, feeding it representative data, and calling
``QWidget.grab()``. Re-run this after any GUI change.

    python tools/generate_screenshots.py

No DUT, no Administrator and no live capture are required — the data is
synthetic, so the images are deterministic and no real target address
ever lands in the docs.
"""
from __future__ import annotations

import sys
from datetime import datetime, timedelta
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from PySide6.QtCore import Qt  # noqa: E402
from PySide6.QtWidgets import QApplication, QTreeWidgetItem, QWidget  # noqa: E402

from src.plotting.metrics import MetricsBuffer  # noqa: E402
from src.reporting.models import (  # noqa: E402
    PacketDirection,
    PacketEvent,
    TestEvent,
    TestOutcome,
    TestRunResult,
)

IMAGES_DIR = PROJECT_ROOT / "docs" / "images"

# A documentation-only target inside the RFC 5737 TEST-NET-1 range, so no
# screenshot ever advertises a real host.
DOC_TARGET_IP = "192.0.2.10"
DOC_SOURCE_IP = "192.0.2.1"
DOC_TARGET_MAC = "02:42:c0:00:02:0a"
DOC_ALLOWED_CIDR = "192.0.2.0/24"


# --------------------------------------------------------------------------
# Synthetic run data
# --------------------------------------------------------------------------

def sample_result() -> TestRunResult:
    """A finished run with a realistic outcome mix, including the failures
    the report is designed to lead with."""
    started = datetime(2026, 3, 14, 9, 30, 0)
    # Every nodeid below is a real catalog entry, so the report and the
    # details panel render the genuine description/RFC rather than the
    # "(no catalog description)" fallback.
    tests = [
        TestEvent(
            "tests/icmp/test_icmp_echo.py::test_echo_request_elicits_reply",
            TestOutcome.PASSED, 0.042, ["icmp"],
        ),
        TestEvent(
            "tests/ip/test_ip_header_validation.py::test_icmp_echo_round_trip_baseline",
            TestOutcome.PASSED, 0.038, ["ip"],
        ),
        TestEvent(
            "tests/ip/test_ip_checksum.py::test_bad_ip_checksum_is_discarded",
            TestOutcome.PASSED, 0.071, ["ip"],
        ),
        TestEvent(
            "tests/ip/test_ip_header_validation.py::test_ttl_expiry_generates_icmp_time_exceeded",
            TestOutcome.FAILED, 1.204, ["ip"],
            "Expected ICMP Time Exceeded (type 11) after the TTL=1 decrement; "
            "the DUT forwarded the datagram with TTL=0.",
        ),
        TestEvent(
            "tests/ip/test_ip_fragmentation.py::test_overlapping_fragments_teardrop_do_not_crash_dut",
            TestOutcome.FAILED, 2.008, ["ip", "vuln"],
            "The DUT stopped answering ICMP echo for 1.6s after the overlapping "
            "fragment set; reassembly appears to trust the second fragment's offset.",
        ),
        TestEvent(
            "tests/udp/test_udp_header_validation.py::test_zero_checksum_datagram_is_accepted",
            TestOutcome.PASSED, 0.061, ["udp"],
        ),
        TestEvent(
            "tests/udp/test_udp_edge_cases.py::test_udp_length_below_minimum_is_discarded",
            TestOutcome.PASSED, 0.055, ["udp"],
        ),
        TestEvent(
            "tests/tcp/syn/test_three_way_handshake.py::test_syn_elicits_syn_ack",
            TestOutcome.PASSED, 0.187, ["tcp", "syn"],
        ),
        TestEvent(
            "tests/tcp/syn/test_server_handshake.py::test_dut_completes_handshake_it_initiated",
            TestOutcome.SKIPPED, 0.0, ["tcp", "syn"],
            "applies to role(s) [server]; the run role is 'client'",
        ),
        TestEvent(
            "tests/tcp/congestion/test_zero_window.py::test_zero_window_advertisement_does_not_break_connection",
            TestOutcome.ERROR, 0.0, ["tcp", "congestion"],
            "fixture 'dut_session' failed: no ARP reply from the target",
        ),
    ]

    base = started.timestamp()
    summaries = [
        (f"Ether / IP / ICMP {DOC_SOURCE_IP} > {DOC_TARGET_IP} echo-request 0", 98),
        (f"Ether / IP / ICMP {DOC_TARGET_IP} > {DOC_SOURCE_IP} echo-reply 0", 98),
        (f"Ether / IP / TCP {DOC_SOURCE_IP}:52344 > {DOC_TARGET_IP}:80 S", 74),
        (f"Ether / IP / TCP {DOC_TARGET_IP}:80 > {DOC_SOURCE_IP}:52344 SA", 74),
        (f"Ether / IP / UDP {DOC_SOURCE_IP}:41233 > {DOC_TARGET_IP}:9 / Raw", 142),
    ]
    # Every probe is sent; roughly one in four draws no reply (a dropped or
    # ignored probe), so the Sent and Received curves visibly diverge the way
    # they do on a real run rather than overlapping into a single line.
    packets: list[PacketEvent] = []
    clock = base
    for i in range(160):
        summary, size = summaries[i % len(summaries)]
        packets.append(
            PacketEvent(
                timestamp=clock,
                direction=PacketDirection.SENT,
                summary=summary,
                size_bytes=size,
                test_nodeid=tests[i % len(tests)].nodeid,
            )
        )
        clock += 0.028
        if i % 4 != 3:
            reply_summary, reply_size = summaries[(i + 1) % len(summaries)]
            packets.append(
                PacketEvent(
                    timestamp=clock,
                    direction=PacketDirection.RECEIVED,
                    summary=reply_summary,
                    size_bytes=reply_size,
                    test_nodeid=tests[i % len(tests)].nodeid,
                )
            )
            clock += 0.019

    return TestRunResult(
        run_id="20260314-093000",
        started_at=started,
        finished_at=started + timedelta(seconds=11),
        target_ip=DOC_TARGET_IP,
        target_stack="linux",
        host_platform="Windows",
        payload_mode="random",
        tests=tests,
        packet_events=packets,
        pytest_returncode=1,
    )


def sample_metrics() -> MetricsBuffer:
    buffer = MetricsBuffer()
    for event in sample_result().packet_events:
        buffer.add(event)
    return buffer


def sample_log_lines() -> list[str]:
    return [
        "Preflight connectivity check...",
        "  interface: Ethernet 2 - up, MTU 1500",
        "  privileges: Administrator - raw sockets available",
        f"  target {DOC_TARGET_IP} inside allowed range {DOC_ALLOWED_CIDR}",
        f"  ARP reply from {DOC_TARGET_IP} ({DOC_TARGET_MAC})",
        "Starting run (role=client, selection: tests/icmp, "
        "tests/ip/test_ip_header_validation.py::test_ttl_expiry_generates_icmp_time_exceeded)...",
    ]


# --------------------------------------------------------------------------
# Capture helpers
# --------------------------------------------------------------------------

def settle() -> None:
    """Let layout, styling and pyqtgraph's redraw timer catch up."""
    app = QApplication.instance()
    assert app is not None
    for _ in range(12):
        app.processEvents()


def capture(widget: QWidget, name: str, size: tuple[int, int] | None = None) -> Path:
    """Show, settle, and grab a widget to docs/images/<name>.png."""
    if size:
        widget.resize(*size)
    widget.show()
    settle()
    path = IMAGES_DIR / f"{name}.png"
    widget.grab().save(str(path))
    widget.hide()
    print(f"  wrote docs/images/{name}.png")
    return path


def find_item(tree, *labels) -> QTreeWidgetItem | None:
    """Walk a QTreeWidget down successive child labels, expanding as it goes."""
    items = [tree.topLevelItem(i) for i in range(tree.topLevelItemCount())]
    current = None
    for label in labels:
        current = next((item for item in items if item.text(0) == label), None)
        if current is None:
            return None
        current.setExpanded(True)
        items = [current.child(i) for i in range(current.childCount())]
    return current


# --------------------------------------------------------------------------
# Individual shots
# --------------------------------------------------------------------------

def fill_config(window) -> None:
    window._target_ip.setText(DOC_TARGET_IP)
    window._target_mac.setText(DOC_TARGET_MAC)
    window._allowed_targets.setText(DOC_ALLOWED_CIDR)
    window._target_stack.setCurrentText("linux")
    window._role.setCurrentText("client")
    window._confirm_vuln.setChecked(True)
    window._debug.setChecked(True)


def shot_main_window() -> None:
    from src.gui.main_window import MainWindow

    window = MainWindow()
    window.resize(1280, 860)
    fill_config(window)

    icmp = find_item(window._tree, "icmp")
    if icmp is not None:
        icmp.setCheckState(0, Qt.CheckState.Checked)
    ip_file = find_item(window._tree, "ip", "test_ip_header_validation")
    if ip_file is not None and ip_file.childCount():
        target = ip_file.child(0)
        target.setCheckState(0, Qt.CheckState.Checked)
        window._tree.setCurrentItem(target)

    result = sample_result()
    for event in result.packet_events:
        window._metrics.add(event)
    for line in sample_log_lines():
        window._log_panel.append_line(line)
    for event in result.tests:
        window._log_panel.append_test_event(event)
    window._log_panel.append_line(
        f"Run finished: {result.passed} passed, {result.failed} failed, "
        f"{result.errors} errored, {result.skipped} skipped, {result.total} total."
    )
    window._report_panel.set_result(result)

    window._right_tabs.setCurrentIndex(0)  # Live plot
    window._plot._refresh()
    capture(window, "gui-main-window")

    window._right_tabs.setCurrentIndex(1)  # Log
    capture(window, "gui-main-window-log")
    window.close()


def shot_config_group() -> None:
    from src.gui.main_window import MainWindow

    window = MainWindow()
    fill_config(window)
    group = window.centralWidget().layout().itemAt(0).widget()
    capture(group, "gui-dut-configuration", (780, 330))
    window.close()


def shot_test_tree() -> None:
    from src.gui.test_tree_widget import TestTreeWidget

    tree = TestTreeWidget()
    icmp = find_item(tree, "icmp")
    if icmp is not None:
        icmp.setCheckState(0, Qt.CheckState.Checked)
    # Check a single test function so its ancestors show the tri-state box.
    tcp_syn = find_item(tree, "tcp", "syn")
    if tcp_syn is not None and tcp_syn.childCount():
        first_file = tcp_syn.child(0)
        first_file.setExpanded(True)
        if first_file.childCount():
            first_file.child(0).setCheckState(0, Qt.CheckState.Checked)
    capture(tree, "gui-test-tree", (540, 640))


def shot_test_details() -> None:
    from src import catalog
    from src.gui.test_details_panel import TestDetailsPanel

    panel = TestDetailsPanel()
    spec = next(
        (s for s in catalog.CATALOG if s.test == "test_ttl_expiry_generates_icmp_time_exceeded"),
        catalog.CATALOG[0],
    )
    panel.show_spec(spec)
    capture(panel, "gui-test-details", (580, 270))


def shot_log_panel() -> None:
    from src.gui.log_panel import LogPanel

    panel = LogPanel()
    for line in sample_log_lines():
        panel.append_line(line)
    for event in sample_result().tests:
        panel.append_test_event(event)
    capture(panel, "gui-log-panel", (900, 300))


def shot_live_plot() -> None:
    from src.plotting.realtime_plotter import RealtimePlotWidget

    widget = RealtimePlotWidget(sample_metrics())
    widget.resize(780, 470)
    widget.show()
    widget._refresh()
    settle()
    capture(widget, "gui-live-plot")


def shot_report_panel() -> None:
    from src.gui.report_panel import ReportPanel

    panel = ReportPanel()
    panel.set_result(sample_result())
    capture(panel, "gui-report-panel", (660, 96))


def shot_custom_packet() -> None:
    from src.gui.custom_packet_panel import CustomPacketPanel

    panel = CustomPacketPanel()
    panel._iface.setText("Ethernet 2")
    panel._src_ip.setText(DOC_SOURCE_IP)
    panel._dst_ip.setText(DOC_TARGET_IP)
    panel._dst_mac.setText(DOC_TARGET_MAC)
    panel._tcp_flags.setText("S")
    panel._mode_random.setChecked(True)
    # The reply pane is where a send reports back; show it answered.
    panel._response_view.setPlainText(
        f"Ether / IP / TCP {DOC_TARGET_IP}:80 > {DOC_SOURCE_IP}:12345 SA / Padding"
    )
    capture(panel, "gui-custom-packet", (740, 700))

    # Custom mode swaps the size field for the text/hex/file sub-form.
    panel._mode_custom.setChecked(True)
    panel._custom_text.setText("GET / HTTP/1.0")
    panel._custom_hex.setText("de ad be ef")
    capture(panel, "gui-custom-packet-custom-payload", (740, 700))


def shot_html_report() -> None:
    """Render the generated HTML report itself — the deliverable the suite
    exists to produce, so the docs should show what it looks like."""
    import tempfile

    from PySide6.QtCore import QEventLoop, QTimer, QUrl
    from PySide6.QtWebEngineWidgets import QWebEngineView

    from src.reporting.html_report import generate_html_report

    with tempfile.TemporaryDirectory() as tmp:
        report_path = generate_html_report(sample_result(), Path(tmp) / "report.html")

        view = QWebEngineView()
        view.resize(1120, 1500)
        view.show()

        loop = QEventLoop()
        view.loadFinished.connect(lambda _ok: loop.quit())
        QTimer.singleShot(20_000, loop.quit)  # never hang the generator
        view.load(QUrl.fromLocalFile(str(report_path)))
        loop.exec()

        # The compositor needs a beat after loadFinished before the frame
        # is actually painted; grabbing immediately yields a blank page.
        paint = QEventLoop()
        QTimer.singleShot(1500, paint.quit)
        paint.exec()
        settle()

        view.grab().save(str(IMAGES_DIR / "report-html.png"))
        print("  wrote docs/images/report-html.png")
        view.close()


def shot_static_charts() -> None:
    from src.plotting.static_charts import render_packet_timeline, render_pass_fail_summary

    result = sample_result()
    render_packet_timeline(result, IMAGES_DIR / "chart-packet-timeline.png")
    print("  wrote docs/images/chart-packet-timeline.png")
    render_pass_fail_summary(result, IMAGES_DIR / "chart-pass-fail-summary.png")
    print("  wrote docs/images/chart-pass-fail-summary.png")


def main() -> int:
    IMAGES_DIR.mkdir(parents=True, exist_ok=True)
    app = QApplication.instance() or QApplication(sys.argv)

    print("Generating GUI screenshots...")
    shot_main_window()
    shot_config_group()
    shot_test_tree()
    shot_test_details()
    shot_log_panel()
    shot_live_plot()
    shot_report_panel()
    shot_custom_packet()
    print("Generating report + chart images...")
    shot_html_report()
    shot_static_charts()
    print("Done - images in docs/images/")
    app.quit()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
