"""SERVER role: the suite acts as a UDP echo server for the DUT.

Validates the DUT's UDP-*client* path — it sends a datagram to us, we
echo it back. The mirror of the client-role UDP tests.
"""
from __future__ import annotations

import pytest
from scapy.layers.inet import IP, UDP

from src.packet_engine.responder import serve_udp_echo

pytestmark = [pytest.mark.udp, pytest.mark.server]


def test_dut_sends_udp_and_receives_echo(
    network_interface, dut_config, local_mac, local_ip
) -> None:
    """RFC 768: wait for the DUT to send a UDP datagram to us, echo the
    payload back, and confirm the DUT initiated the exchange."""
    received = serve_udp_echo(
        network_interface,
        local_ip,
        local_mac,
        dut_config.target_port,
        timeout=dut_config.timeout * 3,
        test_nodeid="test_dut_sends_udp_and_receives_echo",
    )
    assert received is not None, (
        f"No UDP datagram received on {local_ip}:{dut_config.target_port} from the DUT — "
        "it did not initiate a UDP send to this host."
    )
    assert received.haslayer(UDP)
    assert received[IP].src == dut_config.target_ip
