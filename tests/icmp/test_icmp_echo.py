"""RFC 792 ICMP Echo / Echo Reply, in both roles.

- CLIENT: the suite sends an Echo Request and validates the DUT's reply.
- SERVER: the DUT sends us an Echo Request and we reply, validating the
  DUT's ping-*client* path.
"""
from __future__ import annotations

import pytest
from scapy.layers.inet import ICMP, IP
from scapy.packet import Raw

from src.packet_engine.builders import wrap_ethernet
from src.packet_engine.responder import serve_icmp_echo

pytestmark = [pytest.mark.icmp]


@pytest.mark.client
def test_echo_request_elicits_reply(
    network_interface, dut_config, local_mac, dut_mac, local_ip
) -> None:
    """RFC 792: an Echo Request (type 8) MUST elicit an Echo Reply (type 0)
    echoing the same identifier, sequence, and data."""
    marker = b"netstack-echo"
    request = wrap_ethernet(
        IP(src=local_ip, dst=dut_config.target_ip) / ICMP(type=8, id=0x1234, seq=1) / Raw(marker),
        local_mac,
        dut_mac,
    )
    reply = network_interface.send_receive(
        request, timeout=dut_config.timeout, test_nodeid="test_echo_request_elicits_reply"
    )

    assert reply is not None, "Expected an ICMP Echo Reply, got no response"
    assert reply.haslayer(ICMP) and reply[ICMP].type == 0
    assert reply[ICMP].id == 0x1234 and reply[ICMP].seq == 1
    assert reply.haslayer(Raw) and bytes(reply[Raw].load) == marker


@pytest.mark.server
def test_server_responds_to_dut_echo(
    network_interface, dut_config, local_mac, local_ip
) -> None:
    """SERVER role: wait for the DUT to ping *us*, answer with an Echo
    Reply, and confirm the DUT initiated the request — exercising the
    DUT's ping-client behavior."""
    request = serve_icmp_echo(
        network_interface,
        local_ip,
        local_mac,
        timeout=dut_config.timeout * 3,
        test_nodeid="test_server_responds_to_dut_echo",
    )
    assert request is not None, (
        "No ICMP Echo Request received from the DUT within the timeout — the DUT did not "
        "initiate a ping (or isn't configured to ping this host)."
    )
    assert request[ICMP].type == 8
    assert request[IP].src == dut_config.target_ip
