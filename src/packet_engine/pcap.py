"""Shared pcap writer construction.

Both capture paths — `NetworkInterface`'s per-run capture of the packets the
suite programmatically sent/received, and `PacketRecorder`'s passive on-wire
sniff — write a pcap the same way, and for the same reason. Their lifecycles
genuinely differ (lazy on the first packet vs eager on start), so only the
construction is shared, not the ownership.
"""
from __future__ import annotations

from pathlib import Path

from scapy.utils import PcapWriter


def open_pcap(path: Path) -> PcapWriter:
    """A pcap writer that flushes every frame as it is written.

    `sync=True` costs a write per packet but means a long capture, or one cut
    short by an abrupt exit, still lands on disk as a valid, complete file
    rather than being buffered and lost.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    return PcapWriter(str(path), append=False, sync=True)
