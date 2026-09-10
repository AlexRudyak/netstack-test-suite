"""RFC 6298 retransmission timer: an unacknowledged SYN-ACK must be
retransmitted rather than silently dropped after one attempt."""
from __future__ import annotations

import pytest
from scapy.layers.inet import TCP

from src.packet_engine.sequence import TCPSequenceTracker
from src.utils.tcp_flags import is_syn_ack

pytestmark = [pytest.mark.tcp, pytest.mark.congestion, pytest.mark.slow]


def test_unacked_syn_ack_is_retransmitted(
    network_interface, dut_config, target_profile, craft, source_port, nodeid
) -> None:
    """Completes the SYN half of the handshake, then deliberately never
    sends the final ACK, and waits for the DUT to retransmit its
    SYN-ACK per RFC 6298's retransmission timer."""
    tracker = TCPSequenceTracker.new()
    syn = craft.tcp(source_port, flags="S", seq=tracker.seq)
    first = network_interface.send_receive(syn, timeout=dut_config.timeout, test_nodeid=nodeid)
    assert is_syn_ack(first)

    retransmits = network_interface.sniff(
        count=1,
        timeout=10.0,
        lfilter=lambda p: (
            is_syn_ack(p)
            and p[TCP].sport == dut_config.target_port
            and p[TCP].seq == first[TCP].seq
        ),
        test_nodeid=nodeid,
    )
    assert retransmits, (
        f"DUT ({target_profile.name} profile) did not retransmit its SYN-ACK within 10s "
        "of receiving no final ACK"
    )
