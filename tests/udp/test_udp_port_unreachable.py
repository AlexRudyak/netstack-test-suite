"""RFC 792 ICMP Destination Unreachable (Port Unreachable) generation
when a UDP datagram targets a closed port."""
from __future__ import annotations

import pytest
from scapy.layers.inet import ICMP

from src.packet_engine.builders import build_udp, wrap_ethernet

pytestmark = [pytest.mark.udp]


def test_closed_port_elicits_icmp_port_unreachable(
    network_interface, dut_config, local_mac, dut_mac, local_ip
) -> None:
    """RFC 792: a UDP datagram to a port with no listener SHOULD elicit
    an ICMP Destination Unreachable, code 3 (Port Unreachable)."""
    closed_port = 1  # not expected to have a listener on the DUT
    l3 = build_udp(local_ip, dut_config.target_ip, 40000, closed_port)
    packet = wrap_ethernet(l3, local_mac, dut_mac)

    reply = network_interface.send_receive(
        packet, timeout=dut_config.timeout, test_nodeid="test_closed_port_elicits_icmp_port_unreachable"
    )

    assert reply is not None, "Expected ICMP Port Unreachable, got no response"
    assert reply.haslayer(ICMP)
    assert reply[ICMP].type == 3
    assert reply[ICMP].code == 3
