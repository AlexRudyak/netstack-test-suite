"""SYN flood: resource-exhaustion vulnerability class, and (implicitly)
SYN cookie / backlog-sizing behavior verification."""
from __future__ import annotations

import pytest
from scapy.layers.inet import TCP

from src.packet_engine.builders import build_tcp, wrap_ethernet
from src.packet_engine.sequence import TCPSequenceTracker
from src.utils.safety import enforce_vuln_test_authorization

pytestmark = [pytest.mark.tcp, pytest.mark.syn, pytest.mark.vuln, pytest.mark.slow]

SYN = 0x02
ACK = 0x10
FLOOD_SYN_COUNT = 500


def test_syn_flood_does_not_exhaust_connection_table(
    network_interface, dut_config, local_mac, dut_mac, local_ip, confirm_vuln_tests
) -> None:
    """Sends a burst of SYNs from many source ports, never ACKed
    (half-open connections), then verifies the DUT can still complete a
    legitimate handshake afterward — proving it didn't exhaust its
    backlog/connection table. A DUT implementing SYN cookies (or an
    adequately sized/pruned backlog) should pass; one with a small fixed
    backlog and no cookie fallback will start dropping legitimate SYNs
    under the flood.
    """
    enforce_vuln_test_authorization(dut_config, confirmed=confirm_vuln_tests)

    for i in range(FLOOD_SYN_COUNT):
        port = 42000 + (i % 5000)
        tracker = TCPSequenceTracker.new()
        syn = wrap_ethernet(
            build_tcp(local_ip, dut_config.target_ip, port, dut_config.target_port, flags="S", seq=tracker.seq),
            local_mac,
            dut_mac,
        )
        network_interface.send(syn, test_nodeid="test_syn_flood_does_not_exhaust_connection_table")

    legit_tracker = TCPSequenceTracker.new()
    legit_syn = wrap_ethernet(
        build_tcp(
            local_ip, dut_config.target_ip, 41200, dut_config.target_port, flags="S", seq=legit_tracker.seq
        ),
        local_mac,
        dut_mac,
    )
    reply = network_interface.send_receive(
        legit_syn, timeout=dut_config.timeout, test_nodeid="test_syn_flood_does_not_exhaust_connection_table"
    )

    assert reply is not None, "DUT stopped answering SYNs after a flood — connection table likely exhausted"
    assert reply.haslayer(TCP) and reply[TCP].flags & (SYN | ACK) == (SYN | ACK)
