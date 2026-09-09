"""Helpers for the TCP state-machine edge-case tests.

`established_tcp_connection` (tests/tcp/conftest.py) advances a sequence
tracker every time its `build()` is called, which is exactly wrong for
tests that need to inject a segment with a *deliberately* bogus seq/ack
(old, future, or unsent) without disturbing the tracker the rest of the
test relies on. `segment()` builds such a probe straight from the
connection's addressing, defaulting seq/ack to the tracker's current
position but leaving the tracker untouched.
"""
from __future__ import annotations

from scapy.layers.inet import IP, TCP
from scapy.packet import Packet, Raw

from src.packet_engine.builders import wrap_ethernet

RST = 0x04
ACK = 0x10
SYN = 0x02
FIN = 0x01


def segment(
    conn,
    *,
    flags: str,
    seq: int | None = None,
    ack: int | None = None,
    window: int = 8192,
    payload: bytes = b"",
) -> Packet:
    """A hand-addressed TCP segment on `conn` that does NOT touch the
    sequence tracker. seq/ack default to the tracker's current values."""
    l3 = IP(src=conn.local_ip, dst=conn.dut_ip) / TCP(
        sport=conn.local_port,
        dport=conn.dut_port,
        flags=flags,
        seq=conn.tracker.seq if seq is None else (seq & 0xFFFFFFFF),
        ack=conn.tracker.ack if ack is None else (ack & 0xFFFFFFFF),
        window=window,
    )
    if payload:
        l3 = l3 / Raw(load=payload)
    return wrap_ethernet(l3, conn.local_mac, conn.dut_mac)


def connection_still_alive(conn, network_interface, *, timeout: float = 1.5, nodeid: str = "") -> bool:
    """Probe `conn` with an in-window bare ACK; return False only if the
    DUT answers with RST (an unsolicited RST means it dropped the TCB).
    No reply is treated as still-alive: a conformant ESTABLISHED peer is
    not obliged to answer a bare duplicate ACK."""
    reply = network_interface.send_receive(
        segment(conn, flags="A"), timeout=timeout, test_nodeid=nodeid or "connection_still_alive"
    )
    if reply is None or not reply.haslayer(TCP):
        return True
    return not (reply[TCP].flags & RST)
