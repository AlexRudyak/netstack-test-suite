"""IP options and flag edge cases (RFC 791 §3.1).

A conformant stack must parse IP options (using IHL to find the payload)
and ignore reserved header bits, rather than choking on them.
"""
from __future__ import annotations

import pytest
from scapy.layers.inet import ICMP, IP, IPOption_NOP, IPOption_RR

from src.packet_engine.builders import wrap_ethernet

pytestmark = [pytest.mark.ip, pytest.mark.client]


def _echo_with(network_interface, dut_config, local_mac, dut_mac, local_ip, ip_layer, nodeid):
    packet = wrap_ethernet(ip_layer / ICMP(type=8, id=0x4444, seq=1), local_mac, dut_mac)
    return network_interface.send_receive(packet, timeout=dut_config.timeout, test_nodeid=nodeid)


def test_ip_record_route_option_is_handled(
    network_interface, dut_config, local_mac, dut_mac, local_ip
) -> None:
    """RFC 791 §3.1: a datagram carrying a Record Route option (and thus a
    larger IHL) must still be processed — the DUT must use IHL to locate
    the ICMP payload, not assume a 20-byte header. Proven by an echo
    reply."""
    ip_layer = IP(src=local_ip, dst=dut_config.target_ip, options=[IPOption_RR(pointer=4, length=39)])
    reply = _echo_with(
        network_interface, dut_config, local_mac, dut_mac, local_ip, ip_layer,
        "test_ip_record_route_option_is_handled",
    )
    assert reply is not None, "DUT did not reply to an echo carrying an IP Record Route option"
    assert reply.haslayer(ICMP) and reply[ICMP].type == 0


def test_ip_nop_option_padding_is_handled(
    network_interface, dut_config, local_mac, dut_mac, local_ip
) -> None:
    """RFC 791: No-Operation options are pure padding; a datagram padded
    with several NOPs must still be processed normally."""
    ip_layer = IP(src=local_ip, dst=dut_config.target_ip, options=[IPOption_NOP()] * 3)
    reply = _echo_with(
        network_interface, dut_config, local_mac, dut_mac, local_ip, ip_layer,
        "test_ip_nop_option_padding_is_handled",
    )
    assert reply is not None, "DUT did not reply to an echo padded with IP NOP options"
    assert reply.haslayer(ICMP) and reply[ICMP].type == 0


def test_ip_reserved_flag_bit_is_ignored(
    network_interface, dut_config, local_mac, dut_mac, local_ip
) -> None:
    """RFC 791: the high-order IP flag bit is reserved and must be zero on
    send, but a receiver should ignore it rather than drop the datagram.
    Sends an echo with the reserved bit set and expects a normal reply
    (i.e. the bit was ignored, not treated as an error)."""
    ip_layer = IP(src=local_ip, dst=dut_config.target_ip, flags="evil")
    reply = _echo_with(
        network_interface, dut_config, local_mac, dut_mac, local_ip, ip_layer,
        "test_ip_reserved_flag_bit_is_ignored",
    )
    assert reply is not None, "DUT dropped an echo with the reserved IP flag bit set (should ignore it)"
    assert reply.haslayer(ICMP) and reply[ICMP].type == 0
