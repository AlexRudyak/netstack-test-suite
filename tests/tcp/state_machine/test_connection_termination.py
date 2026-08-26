"""RFC 9293 §3.6 connection termination via FIN."""
from __future__ import annotations

import pytest
from scapy.layers.inet import TCP

pytestmark = [pytest.mark.tcp, pytest.mark.state_machine]

ACK = 0x10


def test_fin_is_acknowledged(established_tcp_connection, network_interface, dut_config) -> None:
    """RFC 9293 §3.6: a FIN on an ESTABLISHED connection MUST be
    acknowledged, transitioning the DUT toward CLOSE-WAIT."""
    conn = established_tcp_connection
    fin = conn.build(flags="FA")

    reply = network_interface.send_receive(fin, timeout=dut_config.timeout, test_nodeid="test_fin_is_acknowledged")

    assert reply is not None, "Expected an ACK of our FIN, got no response"
    assert reply.haslayer(TCP)
    assert reply[TCP].flags & ACK
