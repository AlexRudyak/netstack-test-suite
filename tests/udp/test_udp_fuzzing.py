"""Payload fuzzing: verifies the DUT survives arbitrary/edge-case L7
content without crashing, using the same pluggable payload modes
(zeros/ones/random/custom) available across the suite."""
from __future__ import annotations

import pytest

from src.packet_engine.payloads import zeros

pytestmark = [pytest.mark.udp, pytest.mark.slow]

# Empty, single byte, common MTU-adjacent sizes, and the largest payload a
# single unfragmented IPv4 UDP datagram can carry.
EDGE_CASE_SIZES = [0, 1, 512, 1472, 65507]


@pytest.mark.parametrize("size", EDGE_CASE_SIZES)
def test_udp_survives_edge_case_payload_sizes(
    network_interface, dut_config, craft, source_ports, nodeid, size
) -> None:
    """Sends a zero-fill payload at RFC-legal boundary sizes (empty,
    single byte, common MTU-adjacent sizes, and the maximum UDP payload
    a single unfragmented IPv4 datagram can carry) and verifies the DUT
    remains responsive afterward."""
    network_interface.send(
        craft.udp(source_ports(), payload=zeros(size)), test_nodeid=nodeid
    )

    followup = craft.udp(source_ports(), payload=b"ping")
    reply = network_interface.send_receive(
        followup, timeout=dut_config.timeout, test_nodeid=nodeid
    )
    assert reply is not None, f"DUT unresponsive after a {size}-byte UDP payload"
