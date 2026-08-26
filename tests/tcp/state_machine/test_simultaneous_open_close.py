"""RFC 9293 §3.5.3 simultaneous close — sending our FIN without having
first received the DUT's FIN.

This is a representative scaffold test, not exhaustive coverage of
RFC 9293's simultaneous-open/simultaneous-close state diagram: a fuller
implementation would also drive true simultaneous OPEN (both sides
sending SYN before either sees the peer's SYN) and verify the exact
CLOSING-state ACK sequencing, which needs two independently-tracked
sequence spaces racing each other — worth its own follow-up module
rather than folding into this scaffold's single representative case.
"""
from __future__ import annotations

import pytest
from scapy.layers.inet import TCP

pytestmark = [pytest.mark.tcp, pytest.mark.state_machine]

ACK = 0x10


def test_fin_before_peer_fin_is_still_acknowledged(established_tcp_connection, network_interface, dut_config) -> None:
    """Confirms the DUT ACKs our FIN even though we haven't seen the
    DUT's own FIN first — i.e. it doesn't require a specific close
    ordering to accept a valid FIN on an ESTABLISHED connection."""
    conn = established_tcp_connection
    fin = conn.build(flags="FA")

    reply = network_interface.send_receive(
        fin, timeout=dut_config.timeout, test_nodeid="test_fin_before_peer_fin_is_still_acknowledged"
    )

    assert reply is not None, "Expected an ACK of our FIN even under simultaneous-close ordering"
    assert reply.haslayer(TCP) and reply[TCP].flags & ACK
