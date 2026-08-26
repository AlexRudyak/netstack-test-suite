"""ICMP robustness: a malformed/truncated ICMP message must not crash the
DUT (RFC 792 processing robustness)."""
from __future__ import annotations

import pytest
from scapy.layers.inet import ICMP, IP
from scapy.packet import Raw

from src.packet_engine.builders import wrap_ethernet

pytestmark = [pytest.mark.icmp]


@pytest.mark.client
@pytest.mark.vuln
def test_truncated_icmp_does_not_crash_dut(
    network_interface, dut_config, local_mac, dut_mac, local_ip
) -> None:
    """Sends an ICMP message with a truncated body (a header claiming a
    type/code but no valid trailing structure) and verifies the DUT
    discards it without faulting — proven by a normal echo succeeding
    immediately afterward."""
    # An ICMP Timestamp (type 13) header with the body chopped to a single
    # byte — structurally invalid.
    malformed = wrap_ethernet(
        IP(src=local_ip, dst=dut_config.target_ip) / ICMP(type=13) / Raw(b"\x00"),
        local_mac,
        dut_mac,
    )
    network_interface.send(malformed, test_nodeid="test_truncated_icmp_does_not_crash_dut")

    ping = wrap_ethernet(
        IP(src=local_ip, dst=dut_config.target_ip) / ICMP(type=8, id=0x2222, seq=1),
        local_mac,
        dut_mac,
    )
    reply = network_interface.send_receive(
        ping, timeout=dut_config.timeout, test_nodeid="test_truncated_icmp_does_not_crash_dut"
    )
    assert reply is not None, "DUT did not respond after a truncated ICMP message — possible crash/hang"
    assert reply.haslayer(ICMP) and reply[ICMP].type == 0
