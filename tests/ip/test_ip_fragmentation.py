"""RFC 791 §3.2 fragmentation/reassembly, and the Teardrop
(overlapping-fragment) vulnerability class."""
from __future__ import annotations

import pytest
from scapy.layers.inet import ICMP, IP, fragment

from src.packet_engine.builders import wrap_ethernet
from src.packet_engine.payloads import ones
from src.utils.safety import enforce_vuln_test_authorization

pytestmark = [pytest.mark.ip]


def test_fragmented_icmp_echo_reassembles_correctly(
    network_interface, dut_config, local_mac, dut_mac, local_ip, payload
) -> None:
    """A payload too large for one MTU-sized fragment, split into
    multiple IP fragments, must be reassembled by the DUT before ICMP
    processes it — proven by receiving a valid Echo Reply."""
    icmp_payload = payload if len(payload) >= 1400 else ones(1400)

    full = IP(src=local_ip, dst=dut_config.target_ip) / ICMP() / icmp_payload
    fragments = fragment(full, fragsize=576)
    assert len(fragments) > 1, "Test payload too small to actually fragment"

    for frag in fragments:
        network_interface.send(
            wrap_ethernet(frag, local_mac, dut_mac),
            test_nodeid="test_fragmented_icmp_echo_reassembles_correctly",
        )

    replies = network_interface.sniff(
        count=1,
        timeout=dut_config.timeout,
        lfilter=lambda p: p.haslayer(ICMP) and p[ICMP].type == 0,
        test_nodeid="test_fragmented_icmp_echo_reassembles_correctly",
    )
    assert replies, "DUT did not reassemble the fragments and reply to the Echo Request"


@pytest.mark.vuln
def test_overlapping_fragments_teardrop_do_not_crash_dut(
    network_interface, dut_config, local_mac, dut_mac, local_ip, confirm_vuln_tests
) -> None:
    """Teardrop-class attack: two IP fragments with overlapping offsets
    that, on a vulnerable reassembly implementation, cause a
    negative-length calculation and crash the target. A conformant or
    hardened stack must discard the malformed pair rather than fault —
    proven here by the DUT still answering a plain ICMP echo immediately
    afterward.
    """
    enforce_vuln_test_authorization(dut_config, confirmed=confirm_vuln_tests)

    base = IP(src=local_ip, dst=dut_config.target_ip, id=1234)
    frag1 = base / ICMP() / (b"A" * 32)
    frag1.flags = "MF"
    frag1.frag = 0

    frag2 = base.copy()
    frag2.frag = 1  # overlaps into frag1's payload instead of continuing past it
    frag2 = frag2 / (b"B" * 24)

    for frag in (frag1, frag2):
        network_interface.send(
            wrap_ethernet(frag, local_mac, dut_mac),
            test_nodeid="test_overlapping_fragments_teardrop_do_not_crash_dut",
        )

    ping = wrap_ethernet(IP(src=local_ip, dst=dut_config.target_ip) / ICMP(), local_mac, dut_mac)
    reply = network_interface.send_receive(
        ping, timeout=dut_config.timeout, test_nodeid="test_overlapping_fragments_teardrop_do_not_crash_dut"
    )
    assert reply is not None, (
        "DUT did not respond after a Teardrop-style overlapping fragment pair "
        "— possible crash/hang"
    )
