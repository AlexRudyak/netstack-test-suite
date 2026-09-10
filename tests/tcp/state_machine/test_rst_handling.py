"""RFC 9293 §3.5.2 / §3.10.7.1 RST generation and acceptance."""
from __future__ import annotations

import pytest

from .conftest import is_rst

pytestmark = [pytest.mark.tcp, pytest.mark.state_machine]

# A port the DUT is not expected to have a listener on.
CLOSED_PORT = 2


def test_ack_to_closed_port_elicits_rst(
    network_interface, dut_config, craft, source_port, nodeid
) -> None:
    """RFC 9293 §3.10.7.1: any segment (other than another RST) arriving
    for a CLOSED port MUST be answered with RST."""
    packet = craft.tcp(source_port, dport=CLOSED_PORT, flags="A", seq=1000, ack=1000)

    reply = network_interface.send_receive(packet, timeout=dut_config.timeout, test_nodeid=nodeid)

    assert reply is not None, "Expected RST for a segment to a closed port, got no response"
    assert is_rst(reply)


def test_established_connection_accepts_valid_rst(
    established_tcp_connection, network_interface, nodeid
) -> None:
    """A RST with an in-window sequence number on an ESTABLISHED
    connection MUST abort it — proven by a follow-up segment on the same
    connection no longer being acknowledged normally (getting RST or no
    response instead of a plain ACK)."""
    conn = established_tcp_connection
    network_interface.send(conn.build(flags="R"), test_nodeid=nodeid)

    reply = network_interface.send_receive(conn.build(flags="A"), timeout=1.5, test_nodeid=nodeid)

    assert reply is None or is_rst(reply), (
        "DUT still acknowledged traffic on a connection after accepting our RST — connection was not aborted"
    )
