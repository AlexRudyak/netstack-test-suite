"""Opt-in per-run debug log with tshark-style packet lines.

Enabled only when the user selects debug mode (`netstack-cli run --debug`,
or `--debug-log=<path>` passed directly to pytest). Writes one line per
packet each test sends/receives, in a format deliberately close to
`tshark`'s one-line-per-frame output:

    #000001 2026-08-25T13:00:00.123456 +0.000000s TX  TCP \
        10.0.0.1:41100 -> 10.0.0.5:80 [SYN] Seq=1000 Ack=0 Win=8192 Len=0 \
        {test=tests/tcp/syn/test_three_way_handshake.py::test_syn_elicits_syn_ack \
         called_by=test_syn_elicits_syn_ack@interface.py:send_receive}

Each line carries: a monotonic frame number, an absolute ISO timestamp
and a relative offset from the first frame, direction (TX/RX), the L3/L4
summary (ports, TCP flags, Seq/Ack/Win, payload Len), the owning test
node id, and the Python function that initiated the packet (resolved by
walking the call stack past the packet-engine frames). Test lifecycle
boundaries (setup/call/teardown) are logged too, so the packet lines sit
inside the test that produced them.
"""
from __future__ import annotations

import os
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.packet import Packet, Raw

# TCP flag bit -> tshark-style name, in header bit order.
_TCP_FLAG_NAMES = [
    (0x01, "FIN"),
    (0x02, "SYN"),
    (0x04, "RST"),
    (0x08, "PSH"),
    (0x10, "ACK"),
    (0x20, "URG"),
    (0x40, "ECE"),
    (0x80, "CWR"),
]

# Frames whose caller we skip when resolving "who initiated this packet",
# so the recorded function is the test/helper, not our own plumbing.
_INTERNAL_FILES = ("interface.py", "debug_log.py", "recorder.py")


def _tcp_flag_labels(flags: int) -> str:
    names = [name for bit, name in _TCP_FLAG_NAMES if flags & bit]
    return "[" + ", ".join(names) + "]" if names else "[]"


def _payload_len(packet: Packet) -> int:
    return len(packet[Raw].load) if packet.haslayer(Raw) else 0


def format_packet_summary(packet: Packet) -> str:
    """tshark-like L3/L4 summary (no timestamp/frame prefix)."""
    if not packet.haslayer(IP):
        return packet.summary()

    ip = packet[IP]
    if packet.haslayer(TCP):
        tcp = packet[TCP]
        return (
            f"TCP {ip.src}:{tcp.sport} -> {ip.dst}:{tcp.dport} "
            f"{_tcp_flag_labels(int(tcp.flags))} "
            f"Seq={tcp.seq} Ack={tcp.ack} Win={tcp.window} Len={_payload_len(packet)}"
        )
    if packet.haslayer(UDP):
        udp = packet[UDP]
        return f"UDP {ip.src}:{udp.sport} -> {ip.dst}:{udp.dport} Len={_payload_len(packet)}"
    if packet.haslayer(ICMP):
        icmp = packet[ICMP]
        return f"ICMP {ip.src} -> {ip.dst} type={icmp.type} code={icmp.code}"
    return f"IP {ip.src} -> {ip.dst} proto={ip.proto} Len={len(packet)}"


def resolve_caller() -> str:
    """Walk the stack to the first frame outside the packet-engine
    plumbing — the test or helper that actually initiated the packet.

    Uses raw frame objects (`sys._getframe`) rather than `inspect.stack()`:
    the latter materializes a FrameInfo for every frame *and reads source
    files off disk* on each call, which is far too costly to run per packet
    under a flood with debug enabled. This walks `f_back` and reads only
    the cheap code attributes, doing no I/O.
    """
    frame = sys._getframe(1)  # skip resolve_caller itself
    while frame is not None:
        filename = os.path.basename(frame.f_code.co_filename)
        if filename not in _INTERNAL_FILES:
            return f"{frame.f_code.co_name}@{filename}:{frame.f_lineno}"
        frame = frame.f_back
    return "<unknown>"


class DebugLogger:
    """Thread-safe writer for the per-run debug log. Packet lines may
    arrive from the sniffer thread as well as the main test thread, so
    every write is serialized."""

    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._path = path
        self._file = path.open("w", encoding="utf-8")
        self._lock = threading.Lock()
        self._frame = 0
        self._start_monotonic: float | None = None
        self._write_header()

    @property
    def path(self) -> Path:
        return self._path

    def _write_header(self) -> None:
        self._file.write(
            "# netstack debug log — tshark-style per-packet trace\n"
            "# columns: #frame  iso_timestamp  +relative  DIR  <L3/L4 summary>  {test= called_by=}\n"
        )
        self._file.flush()

    def _now(self) -> tuple[str, float]:
        wall = datetime.now(timezone.utc).isoformat()
        mono = time.monotonic()
        if self._start_monotonic is None:
            self._start_monotonic = mono
        return wall, mono - self._start_monotonic

    def log_packet(self, packet: Packet, direction: str, *, test_nodeid: str | None = None) -> None:
        caller = resolve_caller()
        with self._lock:
            self._frame += 1
            frame = self._frame
            wall, rel = self._now()
            self._file.write(
                f"#{frame:06d} {wall} +{rel:.6f}s {direction:<2} "
                f"{format_packet_summary(packet)} "
                f"{{test={test_nodeid or '-'} called_by={caller}}}\n"
            )
            self._file.flush()

    def log_event(self, message: str) -> None:
        """Free-form line — test boundaries, fixture actions, notes."""
        with self._lock:
            wall, rel = self._now()
            self._file.write(f"       {wall} +{rel:.6f}s -- {message}\n")
            self._file.flush()

    def close(self) -> None:
        with self._lock:
            if not self._file.closed:
                self._file.flush()
                self._file.close()
