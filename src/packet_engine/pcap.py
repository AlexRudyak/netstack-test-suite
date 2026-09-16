"""Shared pcap writer construction.

Both capture paths — `NetworkInterface`'s per-run capture of the packets the
suite programmatically sent/received, and `PacketRecorder`'s passive on-wire
sniff — write a pcap the same way, and for the same reason. Their lifecycles
genuinely differ (lazy on the first packet vs eager on start), so only the
construction is shared, not the ownership.

pcapng rather than classic pcap: classic pcap has no per-packet option
fields, so a comment attached to a `Packet` (via its `.comments` attribute)
is silently dropped by `RawPcapWriter._write_packet`. `NetworkInterface`
tags each packet with the owning test's nodeid before writing so a capture
spanning a whole run can be split back apart per test in Wireshark, which
requires pcapng's Enhanced Packet Block options.
"""
from __future__ import annotations

from pathlib import Path

from scapy.utils import PcapNgWriter


def open_pcap(path: Path) -> PcapNgWriter:
    """A pcapng writer. Callers must call `.flush()` after each `.write()`
    (there is no `sync=True` for pcapng, unlike classic PcapWriter) so a
    long capture, or one cut short by an abrupt exit, still lands on disk as
    a valid, complete file rather than being buffered and lost.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    return PcapNgWriter(str(path))
