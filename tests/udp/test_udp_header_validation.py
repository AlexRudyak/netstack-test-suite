"""RFC 768 UDP header field handling: length field correctness and
checksum acceptance."""
from __future__ import annotations

import pytest
from scapy.layers.inet import IP, UDP

pytestmark = [pytest.mark.udp]

UDP_HEADER_BYTES = 8
CLOSED_PORT = 1  # not expected to have a listener on the DUT


def test_udp_length_field_matches_payload(craft, source_port, payload) -> None:
    """RFC 768: the UDP length field covers the 8-byte header plus data.
    A local, DUT-independent check that the builder computes it
    correctly — the round-trip checksum check lives in the next test."""
    packet = craft.udp(source_port, payload=payload)

    # UDP.len is computed lazily by Scapy at serialization time, not when
    # the layer is constructed — round-trip through bytes() to force it.
    assert UDP(bytes(packet[UDP])).len == UDP_HEADER_BYTES + len(payload)


def test_udp_datagram_reaches_dut_with_correct_checksum(
    network_interface, dut_config, craft, source_port, payload, nodeid
) -> None:
    """RFC 768 checksum: verifies the DUT can parse a datagram with a
    correctly computed checksum — proven by receiving *any* response
    (e.g. an ICMP Port Unreachable if the port is closed) rather than
    silence, which would suggest the packet was dropped during checksum
    validation."""
    packet = craft.udp(source_port, payload=payload)

    reply = network_interface.send_receive(packet, timeout=dut_config.timeout, test_nodeid=nodeid)

    assert reply is not None, "No response to a well-formed UDP datagram — possible checksum/parsing rejection"


def test_zero_checksum_datagram_is_accepted(
    network_interface, dut_config, craft, source_port, nodeid
) -> None:
    """RFC 768: a transmitted checksum of all zeros means 'no checksum was
    computed' and MUST be accepted. Sends a datagram with checksum=0 to a
    closed port and expects the DUT to still process it (an ICMP port
    unreachable is an acceptable 'processed it' signal), rather than
    dropping it as a checksum failure."""
    packet = craft.l3(
        IP(src=craft.local_ip, dst=craft.dut_ip)
        / UDP(sport=source_port, dport=CLOSED_PORT, chksum=0)
    )
    reply = network_interface.send_receive(packet, timeout=dut_config.timeout, test_nodeid=nodeid)
    assert reply is not None, (
        "No response to a zero-checksum (checksum-disabled) datagram — the DUT may be wrongly "
        "rejecting it instead of treating checksum=0 as 'no checksum'."
    )
