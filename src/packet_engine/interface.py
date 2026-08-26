"""Ethernet interface wrapper: L2 send/receive/sniff with capture + live events.

Deliberately OS-agnostic at this layer — platform_backend.py handles the
Windows/Linux socket differences via `conf.use_pcap`, so this module just
calls Scapy's standard sendp/srp1/sniff, which pick the right socket class
once the backend has configured `conf`.

Opening a raw socket is expensive; this is meant to be constructed once
(a session-scoped pytest fixture) and reused across tests, with per-test
sniff filters layered on top rather than per-test socket open/close.
"""
from __future__ import annotations

import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING

from scapy.packet import Packet
from scapy.sendrecv import sendp, sniff as scapy_sniff, srp1
from scapy.utils import PcapWriter

from src.packet_engine.platform_backend import SocketBackend, get_backend
from src.reporting.models import PacketDirection, PacketEvent

if TYPE_CHECKING:
    from src.utils.debug_log import DebugLogger

PacketCallback = Callable[[PacketEvent], None]

# tshark-style direction labels for the debug log.
_DEBUG_DIRECTION = {PacketDirection.SENT: "TX", PacketDirection.RECEIVED: "RX"}


class NetworkInterface:
    """Session-scoped wrapper around one Ethernet interface."""

    def __init__(
        self,
        iface: str,
        capture_path: Path | None = None,
        on_packet: PacketCallback | None = None,
        backend: SocketBackend | None = None,
        debug_logger: "DebugLogger | None" = None,
    ) -> None:
        self.iface = iface
        self._backend = backend or get_backend()
        self._backend.configure()
        self._capture_path = capture_path
        # Streamed to disk as packets are recorded, rather than buffered in
        # RAM and written in one shot at close — bounds memory for long or
        # flood runs and keeps the pcap valid if the run is interrupted.
        # Opened lazily on the first packet so a run with a capture path but
        # zero packets leaves no empty file.
        self._pcap_writer: PcapWriter | None = None
        self._packet_count = 0
        self._on_packet = on_packet
        self._debug_logger = debug_logger
        self._lock = threading.Lock()

    def send(self, packet: Packet, *, test_nodeid: str | None = None) -> None:
        sendp(packet, iface=self.iface, verbose=False)
        self._record(packet, PacketDirection.SENT, test_nodeid)

    def send_receive(
        self,
        packet: Packet,
        *,
        timeout: float = 2.0,
        test_nodeid: str | None = None,
    ) -> Packet | None:
        """Send one packet and wait for a single matching reply (srp1)."""
        self._record(packet, PacketDirection.SENT, test_nodeid)
        reply = srp1(packet, iface=self.iface, timeout=timeout, verbose=False)
        if reply is not None:
            self._record(reply, PacketDirection.RECEIVED, test_nodeid)
        return reply

    def sniff(
        self,
        *,
        count: int = 0,
        timeout: float | None = None,
        lfilter: Callable[[Packet], bool] | None = None,
        test_nodeid: str | None = None,
    ) -> list[Packet]:
        packets = scapy_sniff(
            iface=self.iface, count=count, timeout=timeout, lfilter=lfilter
        )
        for pkt in packets:
            self._record(pkt, PacketDirection.RECEIVED, test_nodeid)
        return list(packets)

    def _record(
        self, packet: Packet, direction: PacketDirection, test_nodeid: str | None
    ) -> None:
        if self._capture_path is not None:
            with self._lock:
                if self._pcap_writer is None:
                    self._capture_path.parent.mkdir(parents=True, exist_ok=True)
                    self._pcap_writer = PcapWriter(str(self._capture_path), append=False, sync=True)
                self._pcap_writer.write(packet)
                self._packet_count += 1
        if self._debug_logger is not None:
            self._debug_logger.log_packet(
                packet, _DEBUG_DIRECTION[direction], test_nodeid=test_nodeid
            )
        if self._on_packet is not None:
            self._on_packet(
                PacketEvent(
                    timestamp=time.time(),
                    direction=direction,
                    summary=packet.summary(),
                    size_bytes=len(packet),
                    test_nodeid=test_nodeid,
                )
            )

    @property
    def captured_count(self) -> int:
        """Number of frames written to the pcap so far."""
        with self._lock:
            return self._packet_count

    def close(self) -> None:
        """Close the pcap writer (frames were already streamed to disk)."""
        with self._lock:
            if self._pcap_writer is not None:
                self._pcap_writer.close()
                self._pcap_writer = None

    def __enter__(self) -> "NetworkInterface":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()
