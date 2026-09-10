"""SERVER role: the suite listens; the DUT initiates the connection.

Validates the DUT's active-open (connect) path — the mirror image of the
client-role handshake tests, where the suite initiates.
"""
from __future__ import annotations

import pytest
from scapy.layers.inet import IP

from src.packet_engine.responder import serve_tcp_handshake
from src.utils.tcp_flags import SYN, has_flags, is_ack

pytestmark = [pytest.mark.tcp, pytest.mark.syn, pytest.mark.server]


def test_dut_completes_handshake_it_initiated(
    network_interface, dut_config, local_mac, local_ip, nodeid
) -> None:
    """RFC 9293 §3.5: the suite acts as a TCP server. It waits for the DUT
    to send a SYN, replies SYN-ACK, and requires the DUT to complete the
    handshake with a valid ACK — i.e. the DUT's connect() path reaches
    ESTABLISHED against a conformant server."""
    listen_port = dut_config.target_port
    final_ack = serve_tcp_handshake(
        network_interface,
        local_ip,
        local_mac,
        listen_port,
        timeout=dut_config.timeout * 3,
        test_nodeid=nodeid,
    )

    assert final_ack is not None, (
        f"DUT did not complete a handshake to {local_ip}:{listen_port}. Either it never sent a "
        "SYN (not configured to connect here) or it didn't ACK our SYN-ACK."
    )
    assert is_ack(final_ack) and not has_flags(final_ack, SYN)
    assert final_ack[IP].src == dut_config.target_ip
