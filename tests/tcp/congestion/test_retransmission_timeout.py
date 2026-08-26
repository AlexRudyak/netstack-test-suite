"""RFC 6298 retransmission timer: an unacknowledged SYN-ACK must be
retransmitted rather than silently dropped after one attempt."""
from __future__ import annotations

import pytest
from scapy.layers.inet import TCP

from src.packet_engine.builders import build_tcp, wrap_ethernet
from src.packet_engine.sequence import TCPSequenceTracker

pytestmark = [pytest.mark.tcp, pytest.mark.congestion, pytest.mark.slow]

SYN = 0x02
ACK = 0x10


def test_unacked_syn_ack_is_retransmitted(
    network_interface, dut_config, target_profile, local_mac, dut_mac, local_ip
) -> None:
    """Completes the SYN half of the handshake, then deliberately never
    sends the final ACK, and waits for the DUT to retransmit its
    SYN-ACK per RFC 6298's retransmission timer."""
    tracker = TCPSequenceTracker.new()
    syn = wrap_ethernet(
        build_tcp(local_ip, dut_config.target_ip, 46100, dut_config.target_port, flags="S", seq=tracker.seq),
        local_mac,
        dut_mac,
    )
    first = network_interface.send_receive(
        syn, timeout=dut_config.timeout, test_nodeid="test_unacked_syn_ack_is_retransmitted"
    )
    assert first is not None and first.haslayer(TCP)
    assert first[TCP].flags & (SYN | ACK) == (SYN | ACK)

    retransmits = network_interface.sniff(
        count=1,
        timeout=10.0,
        lfilter=lambda p: (
            p.haslayer(TCP)
            and p[TCP].sport == dut_config.target_port
            and p[TCP].flags & (SYN | ACK) == (SYN | ACK)
            and p[TCP].seq == first[TCP].seq
        ),
        test_nodeid="test_unacked_syn_ack_is_retransmitted",
    )
    assert retransmits, (
        f"DUT ({target_profile.name} profile) did not retransmit its SYN-ACK within 10s "
        "of receiving no final ACK"
    )
