"""RFC 791 §3.1 mandatory IP header checksum: a datagram with a wrong
header checksum must be silently discarded."""
from __future__ import annotations

import pytest
from scapy.layers.inet import ICMP, IP

pytestmark = [pytest.mark.ip, pytest.mark.client]


def test_bad_ip_checksum_is_discarded(
    network_interface, dut_config, craft, assert_dut_alive, nodeid
) -> None:
    """RFC 791: the header checksum is mandatory; a datagram whose checksum
    doesn't verify MUST be discarded. Sends an echo request with a
    deliberately corrupted IP checksum and expects no reply, then confirms
    the DUT still answers a correctly-checksummed echo (so it discarded the
    bad one rather than crashing)."""
    # chksum is fixed to a wrong value; Scapy won't recompute it when set.
    bad = craft.l3(
        IP(src=craft.local_ip, dst=craft.dut_ip, chksum=0x0001) / ICMP(type=8, id=0x3333, seq=1)
    )
    reply = network_interface.send_receive(bad, timeout=dut_config.timeout, test_nodeid=nodeid)
    assert reply is None, "DUT replied to a packet with an invalid IP header checksum (should discard)"

    assert_dut_alive("a bad-checksum packet")

