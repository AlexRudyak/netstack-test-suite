"""RFC 6528: Initial Sequence Numbers must not be predictable.

Samples several SYN-ACKs and checks for the naive vulnerability class (a
fixed or linearly-incrementing ISN), rather than attempting a full
statistical randomness test suite — that level of analysis belongs in a
dedicated crypto/PRNG evaluation tool, not an RFC conformance sweep.
"""
from __future__ import annotations

import pytest
from scapy.layers.inet import TCP

from src.packet_engine.builders import build_tcp, wrap_ethernet
from src.packet_engine.sequence import TCPSequenceTracker

pytestmark = [pytest.mark.tcp, pytest.mark.syn]

SAMPLE_COUNT = 20


def test_isn_is_not_fixed_or_linearly_incrementing(
    network_interface, dut_config, local_mac, dut_mac, local_ip
) -> None:
    isns: list[int] = []
    for i in range(SAMPLE_COUNT):
        tracker = TCPSequenceTracker.new()
        syn = wrap_ethernet(
            build_tcp(
                local_ip, dut_config.target_ip, 43000 + i, dut_config.target_port, flags="S", seq=tracker.seq
            ),
            local_mac,
            dut_mac,
        )
        reply = network_interface.send_receive(
            syn, timeout=dut_config.timeout, test_nodeid="test_isn_is_not_fixed_or_linearly_incrementing"
        )
        assert reply is not None and reply.haslayer(TCP), f"No SYN-ACK on sample {i}"
        isns.append(reply[TCP].seq)

    assert len(set(isns)) > 1, (
        "DUT returned the same ISN for every connection — trivially predictable (RFC 6528 violation)"
    )

    deltas = [b - a for a, b in zip(isns, isns[1:])]
    assert len(set(deltas)) > 1, (
        "ISN increases by a constant delta between samples — linearly predictable (RFC 6528 violation)"
    )
