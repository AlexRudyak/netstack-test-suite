"""ICMP robustness: a malformed/truncated ICMP message must not crash the
DUT (RFC 792 processing robustness)."""
from __future__ import annotations

import pytest
from scapy.layers.inet import ICMP, IP
from scapy.packet import Raw

pytestmark = [pytest.mark.icmp]


@pytest.mark.client
@pytest.mark.vuln
def test_truncated_icmp_does_not_crash_dut(
    network_interface, craft, assert_dut_alive, nodeid
) -> None:
    """Sends an ICMP message with a truncated body (a header claiming a
    type/code but no valid trailing structure) and verifies the DUT
    discards it without faulting — proven by a normal echo succeeding
    immediately afterward."""
    # An ICMP Timestamp (type 13) header with the body chopped to a single
    # byte — structurally invalid.
    malformed = craft.l3(IP(src=craft.local_ip, dst=craft.dut_ip) / ICMP(type=13) / Raw(b"\x00"))
    network_interface.send(malformed, test_nodeid=nodeid)

    assert_dut_alive("a truncated ICMP message")
