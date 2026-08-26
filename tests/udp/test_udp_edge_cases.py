"""UDP edge cases (RFC 768): malformed length field and boundary source
ports."""
from __future__ import annotations

import pytest
from scapy.layers.inet import IP, UDP

from src.packet_engine.builders import build_udp, wrap_ethernet

pytestmark = [pytest.mark.udp, pytest.mark.client]


def test_udp_length_below_minimum_is_discarded(
    network_interface, dut_config, local_mac, dut_mac, local_ip
) -> None:
    """RFC 768: the UDP length field includes the 8-byte header, so a value
    below 8 is invalid. Sends a datagram whose length field claims 4 and
    verifies the DUT discards it without crashing (a follow-up datagram
    still gets a response)."""
    malformed = wrap_ethernet(
        IP(src=local_ip, dst=dut_config.target_ip) / UDP(sport=40200, dport=1, len=4),
        local_mac,
        dut_mac,
    )
    network_interface.send(malformed, test_nodeid="test_udp_length_below_minimum_is_discarded")

    followup = wrap_ethernet(
        build_udp(local_ip, dut_config.target_ip, 40201, 1),
        local_mac,
        dut_mac,
    )
    reply = network_interface.send_receive(
        followup, timeout=dut_config.timeout, test_nodeid="test_udp_length_below_minimum_is_discarded"
    )
    assert reply is not None, "DUT unresponsive after a UDP datagram with an invalid length field"


def test_udp_source_port_zero_is_handled(
    network_interface, dut_config, local_mac, dut_mac, local_ip
) -> None:
    """RFC 768: source port 0 is valid and means 'no reply port'. Sending
    to a closed port with source port 0 should still be processed (e.g. an
    ICMP port unreachable) rather than crashing the DUT — verified by a
    normal follow-up still succeeding."""
    packet = wrap_ethernet(
        IP(src=local_ip, dst=dut_config.target_ip) / UDP(sport=0, dport=1),
        local_mac,
        dut_mac,
    )
    network_interface.send(packet, test_nodeid="test_udp_source_port_zero_is_handled")

    followup = wrap_ethernet(
        build_udp(local_ip, dut_config.target_ip, 40202, 1),
        local_mac,
        dut_mac,
    )
    reply = network_interface.send_receive(
        followup, timeout=dut_config.timeout, test_nodeid="test_udp_source_port_zero_is_handled"
    )
    assert reply is not None, "DUT unresponsive after a UDP datagram with source port 0"
