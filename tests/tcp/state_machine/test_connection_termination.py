"""RFC 9293 §3.6 connection termination via FIN."""
from __future__ import annotations

import pytest

from src.utils.tcp_flags import is_ack

pytestmark = [pytest.mark.tcp, pytest.mark.state_machine]


def test_fin_is_acknowledged(
    established_tcp_connection, network_interface, dut_config, nodeid
) -> None:
    """RFC 9293 §3.6: a FIN on an ESTABLISHED connection MUST be
    acknowledged, transitioning the DUT toward CLOSE-WAIT."""
    conn = established_tcp_connection
    fin = conn.build(flags="FA")

    reply = network_interface.send_receive(fin, timeout=dut_config.timeout, test_nodeid=nodeid)

    assert reply is not None, "Expected an ACK of our FIN, got no response"
    assert is_ack(reply)
