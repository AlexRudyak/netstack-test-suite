"""Payload fuzzing: verifies the DUT survives arbitrary/edge-case L7
content without crashing, using the same pluggable payload modes
(zeros/ones/random/custom) available across the suite."""
from __future__ import annotations

import pytest

from src.packet_engine.builders import build_udp, wrap_ethernet
from src.packet_engine.payloads import zeros

pytestmark = [pytest.mark.udp, pytest.mark.slow]


@pytest.mark.parametrize("size", [0, 1, 512, 1472, 65507])
def test_udp_survives_edge_case_payload_sizes(
    network_interface, dut_config, local_mac, dut_mac, local_ip, size
) -> None:
    """Sends a zero-fill payload at RFC-legal boundary sizes (empty,
    single byte, common MTU-adjacent sizes, and the maximum UDP payload
    a single unfragmented IPv4 datagram can carry) and verifies the DUT
    remains responsive afterward."""
    l3 = build_udp(local_ip, dut_config.target_ip, 40000, dut_config.target_port, payload=zeros(size))
    packet = wrap_ethernet(l3, local_mac, dut_mac)
    network_interface.send(packet, test_nodeid="test_udp_survives_edge_case_payload_sizes")

    followup = wrap_ethernet(
        build_udp(local_ip, dut_config.target_ip, 40001, dut_config.target_port, payload=b"ping"),
        local_mac,
        dut_mac,
    )
    reply = network_interface.send_receive(
        followup, timeout=dut_config.timeout, test_nodeid="test_udp_survives_edge_case_payload_sizes"
    )
    assert reply is not None, f"DUT unresponsive after a {size}-byte UDP payload"
