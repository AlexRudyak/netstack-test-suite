"""RFC 792 ICMP Destination Unreachable (Port Unreachable) generation
when a UDP datagram targets a closed port."""
from __future__ import annotations

import pytest
from scapy.layers.inet import ICMP

pytestmark = [pytest.mark.udp]

CLOSED_PORT = 1  # not expected to have a listener on the DUT
ICMP_DEST_UNREACHABLE = 3
ICMP_CODE_PORT_UNREACHABLE = 3


def test_closed_port_elicits_icmp_port_unreachable(
    network_interface, dut_config, craft, source_port, nodeid
) -> None:
    """RFC 792: a UDP datagram to a port with no listener SHOULD elicit
    an ICMP Destination Unreachable, code 3 (Port Unreachable)."""
    packet = craft.udp(source_port, dport=CLOSED_PORT)

    reply = network_interface.send_receive(packet, timeout=dut_config.timeout, test_nodeid=nodeid)

    assert reply is not None, "Expected ICMP Port Unreachable, got no response"
    assert reply.haslayer(ICMP)
    assert reply[ICMP].type == ICMP_DEST_UNREACHABLE
    assert reply[ICMP].code == ICMP_CODE_PORT_UNREACHABLE
