"""Invalid/contradictory TCP flag combinations: SYN+FIN, SYN+RST, and
the NULL/Xmas scan patterns.

RFC 9293 doesn't explicitly enumerate every combination a scanner might
send, but SYN+FIN/SYN+RST are semantically contradictory (simultaneously
requesting and terminating a connection), and NULL/Xmas are classic
scan-evasion patterns — a hardened stack should never treat any of these
as a valid connection request.
"""
from __future__ import annotations

import pytest

from src.utils.tcp_flags import is_bare_syn_ack

pytestmark = [pytest.mark.tcp, pytest.mark.syn]


@pytest.mark.parametrize(
    "flags,label",
    [
        ("SF", "syn_fin"),
        ("SR", "syn_rst"),
        ("", "null_scan"),
        ("FPU", "xmas_scan"),
    ],
)
def test_contradictory_flag_combination_does_not_establish_connection(
    network_interface, craft, source_port, nodeid, flags, label
) -> None:
    """None of these patterns should transition the DUT to ESTABLISHED —
    proven by never observing a bare SYN-ACK (SYN|ACK with no FIN/RST
    also set) in response."""
    packet = craft.tcp(source_port, flags=flags, seq=1000)
    network_interface.send(packet, test_nodeid=nodeid)

    replies = network_interface.sniff(
        count=1, timeout=1.5, lfilter=is_bare_syn_ack, test_nodeid=nodeid
    )
    assert not replies, (
        f"DUT answered a {label} probe with a bare SYN-ACK, treating a contradictory "
        "flag set as a valid connection request"
    )
