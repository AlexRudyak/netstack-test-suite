"""Ping of Death (oversized reassembled datagram) and malformed IP
header handling."""
from __future__ import annotations

import pytest
from scapy.layers.inet import ICMP, IP, fragment
from scapy.packet import Raw

from src.packet_engine.payloads import zeros
from src.utils.safety import enforce_vuln_test_authorization

pytestmark = [pytest.mark.ip]

# RFC 791's maximum IP datagram size is 65535 bytes; reassembling more than
# that into an unchecked buffer is the Ping of Death.
OVERSIZED_PAYLOAD_BYTES = 65500


@pytest.mark.vuln
@pytest.mark.slow
def test_oversized_reassembled_datagram_ping_of_death(
    network_interface, craft, dut_config, confirm_vuln_tests, assert_dut_alive, nodeid
) -> None:
    """RFC 791's max IP datagram size is 65535 bytes. A stack that
    reassembles fragments into a buffer without checking this bound is
    vulnerable to Ping of Death. This sends fragments whose combined
    size exceeds 65535 and verifies the DUT rejects/discards them rather
    than crashing (proven via a liveness ping immediately after).
    """
    enforce_vuln_test_authorization(dut_config, confirmed=confirm_vuln_tests)

    full = IP(src=craft.local_ip, dst=craft.dut_ip) / ICMP() / zeros(OVERSIZED_PAYLOAD_BYTES)
    for frag in fragment(full, fragsize=1024):
        network_interface.send(craft.l3(frag), test_nodeid=nodeid)

    assert_dut_alive("an oversized reassembled datagram (Ping of Death)")


def test_invalid_ihl_is_discarded(network_interface, craft, assert_dut_alive, nodeid) -> None:
    """RFC 791 §3.1: IHL must be >= 5 (20-byte minimum header). A packet
    claiming an IHL below the minimum is invalid and MUST be discarded
    without processing — proven by a normal follow-up ping still
    succeeding (i.e. the malformed packet didn't wedge the DUT)."""
    malformed = craft.l3(
        IP(src=craft.local_ip, dst=craft.dut_ip, ihl=2) / ICMP() / Raw(b"x" * 4)
    )
    network_interface.send(malformed, test_nodeid=nodeid)

    assert_dut_alive("a malformed-IHL packet")
