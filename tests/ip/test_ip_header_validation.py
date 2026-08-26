"""RFC 791 §3.1 IP header field handling: TTL expiry and basic
send/receive round-trip correctness."""
from __future__ import annotations

import pytest
from scapy.layers.inet import ICMP, IP

from src.packet_engine.builders import build_ip, wrap_ethernet
from src.packet_engine.interface import NetworkInterface

pytestmark = [pytest.mark.ip]


def test_ttl_expiry_generates_icmp_time_exceeded(
    network_interface: NetworkInterface, dut_config, local_mac, dut_mac, local_ip
) -> None:
    """RFC 791 §3.2 / RFC 792: a datagram whose TTL is decremented to
    zero in transit MUST NOT be forwarded, and SHOULD elicit an ICMP
    Time Exceeded (type 11) from the hop that discarded it."""
    l3 = build_ip(local_ip, dut_config.target_ip, ttl=1)
    packet = wrap_ethernet(l3, local_mac, dut_mac)

    reply = network_interface.send_receive(
        packet, timeout=dut_config.timeout, test_nodeid="test_ttl_expiry_generates_icmp_time_exceeded"
    )

    assert reply is not None, "Expected an ICMP Time Exceeded reply, got no response"
    assert reply.haslayer(ICMP)
    assert reply[ICMP].type == 11


def test_icmp_echo_round_trip_baseline(
    network_interface: NetworkInterface, dut_config, local_mac, dut_mac, local_ip
) -> None:
    """Baseline sanity check (not itself an RFC assertion beyond RFC 792
    echo/reply): establishes that a normally-formed packet with a
    correctly computed checksum round-trips against the DUT, before
    test_ip_malformed.py exercises intentionally corrupted headers."""
    packet = wrap_ethernet(IP(src=local_ip, dst=dut_config.target_ip) / ICMP(), local_mac, dut_mac)

    reply = network_interface.send_receive(
        packet, timeout=dut_config.timeout, test_nodeid="test_icmp_echo_round_trip_baseline"
    )

    assert reply is not None
    assert reply.haslayer(ICMP)
    assert reply[ICMP].type == 0  # Echo Reply
