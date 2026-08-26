"""Ping of Death (oversized reassembled datagram) and malformed IP
header handling."""
from __future__ import annotations

import pytest
from scapy.layers.inet import ICMP, IP, fragment
from scapy.packet import Raw

from src.packet_engine.builders import wrap_ethernet
from src.utils.safety import enforce_vuln_test_authorization

pytestmark = [pytest.mark.ip]


@pytest.mark.vuln
@pytest.mark.slow
def test_oversized_reassembled_datagram_ping_of_death(
    network_interface, dut_config, local_mac, dut_mac, local_ip, confirm_vuln_tests
) -> None:
    """RFC 791's max IP datagram size is 65535 bytes. A stack that
    reassembles fragments into a buffer without checking this bound is
    vulnerable to Ping of Death. This sends fragments whose combined
    size exceeds 65535 and verifies the DUT rejects/discards them rather
    than crashing (proven via a liveness ping immediately after).
    """
    enforce_vuln_test_authorization(dut_config, confirmed=confirm_vuln_tests)

    oversized_payload = b"\x00" * 65500
    full = IP(src=local_ip, dst=dut_config.target_ip) / ICMP() / oversized_payload
    fragments = fragment(full, fragsize=1024)

    for frag in fragments:
        network_interface.send(
            wrap_ethernet(frag, local_mac, dut_mac),
            test_nodeid="test_oversized_reassembled_datagram_ping_of_death",
        )

    ping = wrap_ethernet(IP(src=local_ip, dst=dut_config.target_ip) / ICMP(), local_mac, dut_mac)
    reply = network_interface.send_receive(
        ping, timeout=dut_config.timeout, test_nodeid="test_oversized_reassembled_datagram_ping_of_death"
    )
    assert reply is not None, (
        "DUT did not respond after an oversized reassembled datagram "
        "— possible Ping of Death crash"
    )


def test_invalid_ihl_is_discarded(network_interface, dut_config, local_mac, dut_mac, local_ip) -> None:
    """RFC 791 §3.1: IHL must be >= 5 (20-byte minimum header). A packet
    claiming an IHL below the minimum is invalid and MUST be discarded
    without processing — proven by a normal follow-up ping still
    succeeding (i.e. the malformed packet didn't wedge the DUT)."""
    malformed = IP(src=local_ip, dst=dut_config.target_ip, ihl=2) / ICMP() / Raw(b"x" * 4)
    network_interface.send(
        wrap_ethernet(malformed, local_mac, dut_mac), test_nodeid="test_invalid_ihl_is_discarded"
    )

    ping = wrap_ethernet(IP(src=local_ip, dst=dut_config.target_ip) / ICMP(), local_mac, dut_mac)
    reply = network_interface.send_receive(
        ping, timeout=dut_config.timeout, test_nodeid="test_invalid_ihl_is_discarded"
    )
    assert reply is not None, "DUT did not respond after a malformed-IHL packet — possible crash/hang"
