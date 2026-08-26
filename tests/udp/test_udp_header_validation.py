"""RFC 768 UDP header field handling: length field correctness and
checksum acceptance."""
from __future__ import annotations

import pytest
from scapy.layers.inet import IP, UDP

from src.packet_engine.builders import build_udp, wrap_ethernet

pytestmark = [pytest.mark.udp]


def test_udp_length_field_matches_payload(local_mac, dut_mac, local_ip, dut_config, payload) -> None:
    """RFC 768: the UDP length field covers the 8-byte header plus data.
    A local, DUT-independent check that the builder computes it
    correctly — the round-trip checksum check lives in the next test."""
    l3 = build_udp(local_ip, dut_config.target_ip, 40000, dut_config.target_port, payload=payload)
    packet = wrap_ethernet(l3, local_mac, dut_mac)

    # UDP.len is computed lazily by Scapy at serialization time, not when
    # the layer is constructed — round-trip through bytes() to force it.
    assert UDP(bytes(packet[UDP])).len == 8 + len(payload)


def test_udp_datagram_reaches_dut_with_correct_checksum(
    network_interface, dut_config, local_mac, dut_mac, local_ip, payload
) -> None:
    """RFC 768 checksum: verifies the DUT can parse a datagram with a
    correctly computed checksum — proven by receiving *any* response
    (e.g. an ICMP Port Unreachable if the port is closed) rather than
    silence, which would suggest the packet was dropped during checksum
    validation."""
    l3 = build_udp(local_ip, dut_config.target_ip, 40000, dut_config.target_port, payload=payload)
    packet = wrap_ethernet(l3, local_mac, dut_mac)

    reply = network_interface.send_receive(
        packet, timeout=dut_config.timeout, test_nodeid="test_udp_datagram_reaches_dut_with_correct_checksum"
    )

    assert reply is not None, "No response to a well-formed UDP datagram — possible checksum/parsing rejection"


def test_zero_checksum_datagram_is_accepted(
    network_interface, dut_config, local_mac, dut_mac, local_ip
) -> None:
    """RFC 768: a transmitted checksum of all zeros means 'no checksum was
    computed' and MUST be accepted. Sends a datagram with checksum=0 to a
    closed port and expects the DUT to still process it (an ICMP port
    unreachable is an acceptable 'processed it' signal), rather than
    dropping it as a checksum failure."""
    closed_port = 1
    packet = wrap_ethernet(
        IP(src=local_ip, dst=dut_config.target_ip) / UDP(sport=40100, dport=closed_port, chksum=0),
        local_mac,
        dut_mac,
    )
    reply = network_interface.send_receive(
        packet, timeout=dut_config.timeout, test_nodeid="test_zero_checksum_datagram_is_accepted"
    )
    assert reply is not None, (
        "No response to a zero-checksum (checksum-disabled) datagram — the DUT may be wrongly "
        "rejecting it instead of treating checksum=0 as 'no checksum'."
    )
