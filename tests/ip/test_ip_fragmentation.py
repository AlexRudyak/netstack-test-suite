"""RFC 791 §3.2 fragmentation/reassembly, and the Teardrop
(overlapping-fragment) vulnerability class."""
from __future__ import annotations

import pytest
from scapy.layers.inet import ICMP, IP, fragment

from src.packet_engine.payloads import ones

pytestmark = [pytest.mark.ip]

# Big enough that fragment() must split it at the MTU-ish fragsize below.
FRAGMENTED_PAYLOAD_BYTES = 1400


def test_fragmented_icmp_echo_reassembles_correctly(
    network_interface, dut_config, craft, payload, nodeid
) -> None:
    """A payload too large for one MTU-sized fragment, split into
    multiple IP fragments, must be reassembled by the DUT before ICMP
    processes it — proven by receiving a valid Echo Reply."""
    icmp_payload = (
        payload if len(payload) >= FRAGMENTED_PAYLOAD_BYTES else ones(FRAGMENTED_PAYLOAD_BYTES)
    )

    full = IP(src=craft.local_ip, dst=craft.dut_ip) / ICMP() / icmp_payload
    fragments = fragment(full, fragsize=576)
    assert len(fragments) > 1, "Test payload too small to actually fragment"

    for frag in fragments:
        network_interface.send(craft.l3(frag), test_nodeid=nodeid)

    replies = network_interface.sniff(
        count=1,
        timeout=dut_config.timeout,
        lfilter=lambda p: p.haslayer(ICMP) and p[ICMP].type == 0,
        test_nodeid=nodeid,
    )
    assert replies, "DUT did not reassemble the fragments and reply to the Echo Request"


@pytest.mark.vuln
def test_overlapping_fragments_teardrop_do_not_crash_dut(
    network_interface, craft, assert_dut_alive, nodeid
) -> None:
    """Teardrop-class attack: two IP fragments with overlapping offsets
    that, on a vulnerable reassembly implementation, cause a
    negative-length calculation and crash the target. A conformant or
    hardened stack must discard the malformed pair rather than fault —
    proven here by the DUT still answering a plain ICMP echo immediately
    afterward.
    """
    base = IP(src=craft.local_ip, dst=craft.dut_ip, id=1234)
    frag1 = base / ICMP() / (b"A" * 32)
    frag1.flags = "MF"
    frag1.frag = 0

    frag2 = base.copy()
    frag2.frag = 1  # overlaps into frag1's payload instead of continuing past it
    frag2 = frag2 / (b"B" * 24)

    for frag in (frag1, frag2):
        network_interface.send(craft.l3(frag), test_nodeid=nodeid)

    assert_dut_alive("a Teardrop-style overlapping fragment pair")
