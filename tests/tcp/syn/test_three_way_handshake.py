"""RFC 9293 §3.5 standard TCP three-way handshake (SYN, SYN-ACK, ACK)."""
from __future__ import annotations

import pytest
from scapy.layers.inet import TCP

from src.packet_engine.sequence import TCPSequenceTracker
from src.utils.tcp_flags import is_rst, is_syn_ack

pytestmark = [pytest.mark.tcp, pytest.mark.syn]


def test_syn_elicits_syn_ack(network_interface, dut_config, craft, source_port, nodeid) -> None:
    """RFC 9293 §3.5: a SYN to an open, listening port MUST be answered
    with SYN-ACK."""
    tracker = TCPSequenceTracker.new()
    packet = craft.tcp(source_port, flags="S", seq=tracker.seq)

    reply = network_interface.send_receive(packet, timeout=dut_config.timeout, test_nodeid=nodeid)

    assert reply is not None, "Expected SYN-ACK, got no response"
    assert is_syn_ack(reply)


def test_full_handshake_completes_and_ack_is_accepted(
    network_interface, dut_config, craft, source_port, nodeid
) -> None:
    """Completes SYN -> SYN-ACK -> ACK, then confirms the connection is
    ESTABLISHED by sending a zero-length ACK-only segment and observing
    no RST — an RST here would mean the DUT never accepted the
    handshake's final ACK."""
    tracker = TCPSequenceTracker.new()

    syn = craft.tcp(source_port, flags="S", seq=tracker.on_send(0, syn=True))
    syn_ack = network_interface.send_receive(syn, timeout=dut_config.timeout, test_nodeid=nodeid)
    assert is_syn_ack(syn_ack)
    tracker.on_receive(syn_ack[TCP].seq, 0, syn=True)

    ack = craft.tcp(source_port, flags="A", seq=tracker.seq, ack=tracker.ack)
    network_interface.send(ack, test_nodeid=nodeid)

    probe = craft.tcp(source_port, flags="A", seq=tracker.seq, ack=tracker.ack)
    network_interface.send(probe, test_nodeid=nodeid)
    stray_rst = network_interface.sniff(
        count=1, timeout=1.0, lfilter=is_rst, test_nodeid=nodeid
    )

    assert not stray_rst, "DUT sent RST after handshake completion — connection was not accepted as ESTABLISHED"
