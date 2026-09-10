"""RFC 791 §3.1 IP header field handling: TTL expiry and basic
send/receive round-trip correctness."""
from __future__ import annotations

import pytest
from scapy.layers.inet import ICMP

from src.packet_engine.builders import build_ip

pytestmark = [pytest.mark.ip]

ICMP_ECHO_REPLY = 0
ICMP_TIME_EXCEEDED = 11


def test_ttl_expiry_generates_icmp_time_exceeded(
    network_interface, dut_config, craft, nodeid
) -> None:
    """RFC 791 §3.2 / RFC 792: a datagram whose TTL is decremented to
    zero in transit MUST NOT be forwarded, and SHOULD elicit an ICMP
    Time Exceeded (type 11) from the hop that discarded it."""
    packet = craft.l3(build_ip(craft.local_ip, craft.dut_ip, ttl=1))

    reply = network_interface.send_receive(packet, timeout=dut_config.timeout, test_nodeid=nodeid)

    assert reply is not None, "Expected an ICMP Time Exceeded reply, got no response"
    assert reply.haslayer(ICMP)
    assert reply[ICMP].type == ICMP_TIME_EXCEEDED


def test_icmp_echo_round_trip_baseline(network_interface, dut_config, craft, nodeid) -> None:
    """Baseline sanity check (not itself an RFC assertion beyond RFC 792
    echo/reply): establishes that a normally-formed packet with a
    correctly computed checksum round-trips against the DUT, before
    test_ip_malformed.py exercises intentionally corrupted headers."""
    reply = network_interface.send_receive(
        craft.icmp_echo(), timeout=dut_config.timeout, test_nodeid=nodeid
    )

    assert reply is not None
    assert reply.haslayer(ICMP)
    assert reply[ICMP].type == ICMP_ECHO_REPLY
