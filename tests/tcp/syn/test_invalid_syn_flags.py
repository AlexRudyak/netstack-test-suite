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
from scapy.layers.inet import TCP

from src.packet_engine.builders import build_tcp, wrap_ethernet

pytestmark = [pytest.mark.tcp, pytest.mark.syn]

SYN = 0x02
FIN = 0x01
RST = 0x04
ACK = 0x10


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
    network_interface, dut_config, local_mac, dut_mac, local_ip, flags, label
) -> None:
    """None of these patterns should transition the DUT to ESTABLISHED —
    proven by never observing a bare SYN-ACK (SYN|ACK with no FIN/RST
    also set) in response."""
    node_id = f"test_contradictory_flag_combination_does_not_establish_connection[{label}]"
    packet = wrap_ethernet(
        build_tcp(local_ip, dut_config.target_ip, 44000, dut_config.target_port, flags=flags, seq=1000),
        local_mac,
        dut_mac,
    )
    network_interface.send(packet, test_nodeid=node_id)

    replies = network_interface.sniff(
        count=1,
        timeout=1.5,
        lfilter=lambda p: (
            p.haslayer(TCP)
            and p[TCP].flags & (SYN | ACK) == (SYN | ACK)
            and not (p[TCP].flags & (FIN | RST))
        ),
        test_nodeid=node_id,
    )
    assert not replies, (
        f"DUT answered a {label} probe with a bare SYN-ACK, treating a contradictory "
        "flag set as a valid connection request"
    )
