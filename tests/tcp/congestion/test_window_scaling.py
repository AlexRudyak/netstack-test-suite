"""RFC 9293 §3.7.1 flow control window advertisement, compared against
the selected target-stack profile's reference range.

This is a stack-characteristic (INFORMATIONAL) check, not an RFC mandate
— RFC 9293 leaves the initial window value implementation-defined. See
src/target_profiles/base.py for the strict/informational distinction: a
mismatch here flags "doesn't look like the claimed target stack," not
"violates the RFC."
"""
from __future__ import annotations

import pytest
from scapy.layers.inet import TCP

from src.packet_engine.builders import build_tcp, wrap_ethernet
from src.packet_engine.sequence import TCPSequenceTracker

pytestmark = [pytest.mark.tcp, pytest.mark.congestion]


def test_syn_ack_window_matches_target_stack_profile(
    network_interface, dut_config, target_profile, local_mac, dut_mac, local_ip
) -> None:
    tracker = TCPSequenceTracker.new()
    syn = wrap_ethernet(
        build_tcp(local_ip, dut_config.target_ip, 46000, dut_config.target_port, flags="S", seq=tracker.seq),
        local_mac,
        dut_mac,
    )
    reply = network_interface.send_receive(
        syn, timeout=dut_config.timeout, test_nodeid="test_syn_ack_window_matches_target_stack_profile"
    )

    assert reply is not None and reply.haslayer(TCP)
    window = reply[TCP].window
    expected = target_profile.tcp_initial_window
    assert expected.contains(window), (
        f"Advertised window {window} is outside the {target_profile.name} reference range "
        f"{expected} — informational: flags a stack-characteristic mismatch, not an RFC violation."
    )
