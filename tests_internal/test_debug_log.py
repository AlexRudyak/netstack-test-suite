"""Unit tests for src/utils/debug_log.py: tshark-style formatting,
frame numbering, caller resolution, and NetworkInterface integration.
No network access."""
from __future__ import annotations

import pytest
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from src.packet_engine.interface import NetworkInterface
from src.utils.debug_log import DebugLogger, format_packet_summary

pytestmark = [pytest.mark.internal]


def test_format_tcp_summary_includes_flags_seq_ack_win_len() -> None:
    pkt = IP(src="10.0.0.1", dst="10.0.0.5") / TCP(
        sport=41100, dport=80, flags="SA", seq=1000, ack=2000, window=8192
    ) / Raw(b"abcd")
    line = format_packet_summary(pkt)
    assert "TCP 10.0.0.1:41100 -> 10.0.0.5:80" in line
    assert "[SYN, ACK]" in line
    assert "Seq=1000" in line
    assert "Ack=2000" in line
    assert "Win=8192" in line
    assert "Len=4" in line


def test_format_udp_and_icmp_summaries() -> None:
    udp = IP(src="10.0.0.1", dst="10.0.0.5") / UDP(sport=40000, dport=53) / Raw(b"xy")
    assert "UDP 10.0.0.1:40000 -> 10.0.0.5:53 Len=2" in format_packet_summary(udp)

    icmp = IP(src="10.0.0.1", dst="10.0.0.5") / ICMP(type=8, code=0)
    assert "ICMP 10.0.0.1 -> 10.0.0.5 type=8 code=0" in format_packet_summary(icmp)


def test_debug_logger_writes_header_and_frames(tmp_path) -> None:
    path = tmp_path / "sub" / "debug.log"
    logger = DebugLogger(path)
    pkt = IP(src="10.0.0.1", dst="10.0.0.5") / TCP(sport=1, dport=2, flags="S")
    logger.log_packet(pkt, "TX", test_nodeid="tests/x.py::test_a")
    logger.log_packet(pkt, "RX", test_nodeid="tests/x.py::test_a")
    logger.log_event("note")
    logger.close()

    content = path.read_text(encoding="utf-8")
    assert "# netstack debug log" in content
    assert "#000001" in content and "#000002" in content
    assert "TX" in content and "RX" in content
    assert "test=tests/x.py::test_a" in content
    assert "called_by=" in content
    assert "-- note" in content


def test_debug_logger_caller_is_the_test_function_not_internal(tmp_path) -> None:
    """The recorded caller should be this test function, not the logger's
    own frames — proving stack resolution skips internal files."""
    path = tmp_path / "debug.log"
    logger = DebugLogger(path)
    pkt = IP(src="10.0.0.1", dst="10.0.0.5") / TCP(sport=1, dport=2, flags="S")
    logger.log_packet(pkt, "TX")
    logger.close()

    content = path.read_text(encoding="utf-8")
    assert "test_debug_logger_caller_is_the_test_function_not_internal" in content


class _StubBackend:
    host_name = "Stub"

    def configure(self) -> None:
        pass

    def l2_socket_class(self):
        return None


def test_network_interface_forwards_to_debug_logger(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr("src.packet_engine.interface.sendp", lambda pkt, iface, verbose: None)

    logger = DebugLogger(tmp_path / "debug.log")
    iface = NetworkInterface("dummy0", debug_logger=logger, backend=_StubBackend())
    pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.5") / TCP(sport=1, dport=2, flags="S")
    iface.send(pkt, test_nodeid="tests/x.py::test_send")
    logger.close()

    content = (tmp_path / "debug.log").read_text(encoding="utf-8")
    assert "TX" in content
    assert "test=tests/x.py::test_send" in content


# --- Logging configuration -------------------------------------------------
# Distinct from the debug log above: that is the per-packet trace a run
# writes when asked. This is the application logging both entry points
# configure, which was INFO-only, console-only, and used by exactly one
# module.


def test_configure_logging_writes_to_a_file_when_asked(tmp_path) -> None:
    """The GUI's log panel is cleared at the start of every run, so without
    a file the record of a failed run dies with the next one."""
    import logging

    from src.utils.logging_config import configure_logging

    log_file = tmp_path / "nested" / "gui.log"
    configure_logging(log_file=log_file)
    try:
        logging.getLogger("netstack.test").error("something went wrong")
        for handler in logging.getLogger().handlers:
            handler.flush()

        assert "something went wrong" in log_file.read_text(encoding="utf-8")
    finally:
        logging.basicConfig(force=True)


def test_configure_logging_survives_an_unwritable_destination(tmp_path) -> None:
    """An unwritable log path must not stop the app from starting."""
    import logging

    from src.utils.logging_config import configure_logging

    blocker = tmp_path / "not-a-dir"
    blocker.write_text("", encoding="utf-8")
    try:
        configure_logging(log_file=blocker / "sub" / "gui.log")  # must not raise
        logging.getLogger("netstack.test").info("still logging")
    finally:
        logging.basicConfig(force=True)


def test_configure_logging_can_raise_the_level_on_a_second_call() -> None:
    """basicConfig is a no-op once the root logger has handlers, which would
    make --verbose silently do nothing."""
    import logging

    from src.utils.logging_config import configure_logging

    try:
        configure_logging(logging.INFO)
        configure_logging(logging.DEBUG)

        assert logging.getLogger().level == logging.DEBUG
    finally:
        logging.basicConfig(force=True)
