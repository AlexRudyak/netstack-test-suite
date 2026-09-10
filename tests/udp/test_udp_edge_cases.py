"""UDP edge cases (RFC 768): malformed length field and boundary source
ports."""
from __future__ import annotations

import pytest
from scapy.layers.inet import IP, UDP

pytestmark = [pytest.mark.udp, pytest.mark.client]

CLOSED_PORT = 1  # not expected to have a listener on the DUT


def _followup_reaches_dut(network_interface, dut_config, craft, sport, nodeid):
    """A well-formed datagram after the malformed one: any response at all
    (including an ICMP port unreachable) proves the DUT is still parsing."""
    followup = craft.udp(sport, dport=CLOSED_PORT)
    return network_interface.send_receive(
        followup, timeout=dut_config.timeout, test_nodeid=nodeid
    )


def test_udp_length_below_minimum_is_discarded(
    network_interface, dut_config, craft, source_ports, nodeid
) -> None:
    """RFC 768: the UDP length field includes the 8-byte header, so a value
    below 8 is invalid. Sends a datagram whose length field claims 4 and
    verifies the DUT discards it without crashing (a follow-up datagram
    still gets a response)."""
    malformed = craft.l3(
        IP(src=craft.local_ip, dst=craft.dut_ip)
        / UDP(sport=source_ports(), dport=CLOSED_PORT, len=4)
    )
    network_interface.send(malformed, test_nodeid=nodeid)

    reply = _followup_reaches_dut(network_interface, dut_config, craft, source_ports(), nodeid)
    assert reply is not None, "DUT unresponsive after a UDP datagram with an invalid length field"


def test_udp_source_port_zero_is_handled(
    network_interface, dut_config, craft, source_ports, nodeid
) -> None:
    """RFC 768: source port 0 is valid and means 'no reply port'. Sending
    to a closed port with source port 0 should still be processed (e.g. an
    ICMP port unreachable) rather than crashing the DUT — verified by a
    normal follow-up still succeeding."""
    packet = craft.l3(
        IP(src=craft.local_ip, dst=craft.dut_ip) / UDP(sport=0, dport=CLOSED_PORT)
    )
    network_interface.send(packet, test_nodeid=nodeid)

    reply = _followup_reaches_dut(network_interface, dut_config, craft, source_ports(), nodeid)
    assert reply is not None, "DUT unresponsive after a UDP datagram with source port 0"
