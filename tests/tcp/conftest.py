"""Shared TCP fixtures: an established-connection helper for tests that
need one as their starting point (state_machine, congestion) rather than
re-testing the handshake itself — that's syn/test_three_way_handshake.py's
job.
"""
from __future__ import annotations

import itertools
from dataclasses import dataclass

import pytest
from scapy.layers.inet import TCP
from scapy.packet import Packet

from src.packet_engine.builders import build_tcp, wrap_ethernet
from src.packet_engine.sequence import TCPSequenceTracker

_SYN_ACK = 0x12

# Hand each established connection a distinct ephemeral source port, so two
# tests in one session never reuse the same 4-tuple (which the DUT could
# still hold in TIME_WAIT from the previous test, corrupting the handshake).
_source_ports = itertools.count(41000)


@dataclass
class TCPConnection:
    local_ip: str
    dut_ip: str
    local_port: int
    dut_port: int
    local_mac: str
    dut_mac: str
    tracker: TCPSequenceTracker

    def build(self, *, flags: str, payload: bytes = b"") -> Packet:
        seq = self.tracker.on_send(len(payload), syn="S" in flags, fin="F" in flags)
        l3 = build_tcp(
            self.local_ip,
            self.dut_ip,
            self.local_port,
            self.dut_port,
            flags=flags,
            seq=seq,
            ack=self.tracker.ack,
            payload=payload,
        )
        return wrap_ethernet(l3, self.local_mac, self.dut_mac)


@pytest.fixture
def established_tcp_connection(network_interface, dut_config, local_mac, dut_mac, local_ip) -> TCPConnection:
    """Performs a standard RFC 9293 three-way handshake and yields a
    TCPConnection positioned right after it.

    On teardown it sends a RST to abort the connection on the DUT, so a
    half-open/ESTABLISHED connection from one test can't leak into the
    next. Teardown is best-effort — a cleanup failure must not mask the
    test's own result.
    """
    tracker = TCPSequenceTracker.new()
    conn = TCPConnection(
        local_ip,
        dut_config.target_ip,
        next(_source_ports),
        dut_config.target_port,
        local_mac,
        dut_mac,
        tracker,
    )

    syn_ack = network_interface.send_receive(
        conn.build(flags="S"), timeout=dut_config.timeout, test_nodeid="established_tcp_connection"
    )
    assert syn_ack is not None and syn_ack.haslayer(TCP) and syn_ack[TCP].flags & _SYN_ACK == _SYN_ACK, (
        "Fixture setup failed: DUT did not complete the handshake with SYN-ACK"
    )
    tracker.on_receive(syn_ack[TCP].seq, 0, syn=True)

    network_interface.send(conn.build(flags="A"), test_nodeid="established_tcp_connection")

    try:
        yield conn
    finally:
        try:
            network_interface.send(conn.build(flags="R"), test_nodeid="established_tcp_connection[teardown]")
        except Exception:
            pass  # best-effort cleanup; never mask the test outcome
