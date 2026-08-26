"""RFC 9293 §3.5.2 / §3.10.7.1 RST generation and acceptance."""
from __future__ import annotations

import pytest
from scapy.layers.inet import TCP

from src.packet_engine.builders import build_tcp, wrap_ethernet

pytestmark = [pytest.mark.tcp, pytest.mark.state_machine]

RST = 0x04


def test_ack_to_closed_port_elicits_rst(network_interface, dut_config, local_mac, dut_mac, local_ip) -> None:
    """RFC 9293 §3.10.7.1: any segment (other than another RST) arriving
    for a CLOSED port MUST be answered with RST."""
    closed_port = 2
    packet = wrap_ethernet(
        build_tcp(local_ip, dut_config.target_ip, 45000, closed_port, flags="A", seq=1000, ack=1000),
        local_mac,
        dut_mac,
    )

    reply = network_interface.send_receive(
        packet, timeout=dut_config.timeout, test_nodeid="test_ack_to_closed_port_elicits_rst"
    )

    assert reply is not None, "Expected RST for a segment to a closed port, got no response"
    assert reply.haslayer(TCP)
    assert reply[TCP].flags & RST


def test_established_connection_accepts_valid_rst(established_tcp_connection, network_interface, dut_config) -> None:
    """A RST with an in-window sequence number on an ESTABLISHED
    connection MUST abort it — proven by a follow-up segment on the same
    connection no longer being acknowledged normally (getting RST or no
    response instead of a plain ACK)."""
    conn = established_tcp_connection
    network_interface.send(conn.build(flags="R"), test_nodeid="test_established_connection_accepts_valid_rst")

    reply = network_interface.send_receive(
        conn.build(flags="A"), timeout=1.5, test_nodeid="test_established_connection_accepts_valid_rst"
    )

    assert reply is None or (reply.haslayer(TCP) and reply[TCP].flags & RST), (
        "DUT still acknowledged traffic on a connection after accepting our RST — connection was not aborted"
    )
