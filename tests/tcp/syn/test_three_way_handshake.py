"""RFC 9293 §3.5 standard TCP three-way handshake (SYN, SYN-ACK, ACK)."""
from __future__ import annotations

import pytest
from scapy.layers.inet import TCP

from src.packet_engine.builders import build_tcp, wrap_ethernet
from src.packet_engine.sequence import TCPSequenceTracker

pytestmark = [pytest.mark.tcp, pytest.mark.syn]

SYN = 0x02
ACK = 0x10
RST = 0x04


def test_syn_elicits_syn_ack(network_interface, dut_config, local_mac, dut_mac, local_ip) -> None:
    """RFC 9293 §3.5: a SYN to an open, listening port MUST be answered
    with SYN-ACK."""
    tracker = TCPSequenceTracker.new()
    packet = wrap_ethernet(
        build_tcp(local_ip, dut_config.target_ip, 41100, dut_config.target_port, flags="S", seq=tracker.seq),
        local_mac,
        dut_mac,
    )

    reply = network_interface.send_receive(
        packet, timeout=dut_config.timeout, test_nodeid="test_syn_elicits_syn_ack"
    )

    assert reply is not None, "Expected SYN-ACK, got no response"
    assert reply.haslayer(TCP)
    assert reply[TCP].flags & (SYN | ACK) == (SYN | ACK)


def test_full_handshake_completes_and_ack_is_accepted(
    network_interface, dut_config, local_mac, dut_mac, local_ip
) -> None:
    """Completes SYN -> SYN-ACK -> ACK, then confirms the connection is
    ESTABLISHED by sending a zero-length ACK-only segment and observing
    no RST — an RST here would mean the DUT never accepted the
    handshake's final ACK."""
    tracker = TCPSequenceTracker.new()
    local_port = 41101

    syn = wrap_ethernet(
        build_tcp(
            local_ip,
            dut_config.target_ip,
            local_port,
            dut_config.target_port,
            flags="S",
            seq=tracker.on_send(0, syn=True),
        ),
        local_mac,
        dut_mac,
    )
    syn_ack = network_interface.send_receive(
        syn, timeout=dut_config.timeout, test_nodeid="test_full_handshake_completes_and_ack_is_accepted"
    )
    assert syn_ack is not None and syn_ack.haslayer(TCP)
    assert syn_ack[TCP].flags & (SYN | ACK) == (SYN | ACK)
    tracker.on_receive(syn_ack[TCP].seq, 0, syn=True)

    ack = wrap_ethernet(
        build_tcp(
            local_ip,
            dut_config.target_ip,
            local_port,
            dut_config.target_port,
            flags="A",
            seq=tracker.seq,
            ack=tracker.ack,
        ),
        local_mac,
        dut_mac,
    )
    network_interface.send(ack, test_nodeid="test_full_handshake_completes_and_ack_is_accepted")

    probe = wrap_ethernet(
        build_tcp(
            local_ip,
            dut_config.target_ip,
            local_port,
            dut_config.target_port,
            flags="A",
            seq=tracker.seq,
            ack=tracker.ack,
        ),
        local_mac,
        dut_mac,
    )
    network_interface.send(probe, test_nodeid="test_full_handshake_completes_and_ack_is_accepted")
    stray_rst = network_interface.sniff(
        count=1,
        timeout=1.0,
        lfilter=lambda p: p.haslayer(TCP) and bool(p[TCP].flags & RST),
        test_nodeid="test_full_handshake_completes_and_ack_is_accepted",
    )

    assert not stray_rst, "DUT sent RST after handshake completion — connection was not accepted as ESTABLISHED"
