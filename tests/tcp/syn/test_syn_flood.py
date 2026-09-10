"""SYN flood: resource-exhaustion vulnerability class, and (implicitly)
SYN cookie / backlog-sizing behavior verification."""
from __future__ import annotations

import pytest

from src.packet_engine.sequence import TCPSequenceTracker
from src.utils.tcp_flags import is_syn_ack

pytestmark = [pytest.mark.tcp, pytest.mark.syn, pytest.mark.vuln, pytest.mark.slow]

FLOOD_SYN_COUNT = 500


def test_syn_flood_does_not_exhaust_connection_table(
    network_interface, dut_config, craft, source_ports, nodeid
) -> None:
    """Sends a burst of SYNs from many source ports, never ACKed
    (half-open connections), then verifies the DUT can still complete a
    legitimate handshake afterward — proving it didn't exhaust its
    backlog/connection table. A DUT implementing SYN cookies (or an
    adequately sized/pruned backlog) should pass; one with a small fixed
    backlog and no cookie fallback will start dropping legitimate SYNs
    under the flood.
    """
    for _ in range(FLOOD_SYN_COUNT):
        tracker = TCPSequenceTracker.new()
        network_interface.send(
            craft.tcp(source_ports(), flags="S", seq=tracker.seq), test_nodeid=nodeid
        )

    legit_tracker = TCPSequenceTracker.new()
    legit_syn = craft.tcp(source_ports(), flags="S", seq=legit_tracker.seq)
    reply = network_interface.send_receive(legit_syn, timeout=dut_config.timeout, test_nodeid=nodeid)

    assert reply is not None, "DUT stopped answering SYNs after a flood — connection table likely exhausted"
    assert is_syn_ack(reply)
