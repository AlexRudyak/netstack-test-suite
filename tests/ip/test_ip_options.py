"""IP options and flag edge cases (RFC 791 §3.1).

A conformant stack must parse IP options (using IHL to find the payload)
and ignore reserved header bits, rather than choking on them.
"""
from __future__ import annotations

import pytest
from scapy.layers.inet import ICMP, IP, IPOption_NOP, IPOption_RR

pytestmark = [pytest.mark.ip, pytest.mark.client]

ICMP_ECHO_REPLY = 0


def _echo_with(network_interface, dut_config, craft, ip_layer, nodeid):
    packet = craft.l3(ip_layer / ICMP(type=8, id=0x4444, seq=1))
    return network_interface.send_receive(packet, timeout=dut_config.timeout, test_nodeid=nodeid)


def _assert_echo_reply(reply, complaint: str) -> None:
    assert reply is not None, complaint
    assert reply.haslayer(ICMP) and reply[ICMP].type == ICMP_ECHO_REPLY


def test_ip_record_route_option_is_handled(network_interface, dut_config, craft, nodeid) -> None:
    """RFC 791 §3.1: a datagram carrying a Record Route option (and thus a
    larger IHL) must still be processed — the DUT must use IHL to locate
    the ICMP payload, not assume a 20-byte header. Proven by an echo
    reply."""
    ip_layer = IP(
        src=craft.local_ip, dst=craft.dut_ip, options=[IPOption_RR(pointer=4, length=39)]
    )
    reply = _echo_with(network_interface, dut_config, craft, ip_layer, nodeid)
    _assert_echo_reply(reply, "DUT did not reply to an echo carrying an IP Record Route option")


def test_ip_nop_option_padding_is_handled(network_interface, dut_config, craft, nodeid) -> None:
    """RFC 791: No-Operation options are pure padding; a datagram padded
    with several NOPs must still be processed normally."""
    ip_layer = IP(src=craft.local_ip, dst=craft.dut_ip, options=[IPOption_NOP()] * 3)
    reply = _echo_with(network_interface, dut_config, craft, ip_layer, nodeid)
    _assert_echo_reply(reply, "DUT did not reply to an echo padded with IP NOP options")


def test_ip_reserved_flag_bit_is_ignored(network_interface, dut_config, craft, nodeid) -> None:
    """RFC 791: the high-order IP flag bit is reserved and must be zero on
    send, but a receiver should ignore it rather than drop the datagram.
    Sends an echo with the reserved bit set and expects a normal reply
    (i.e. the bit was ignored, not treated as an error)."""
    ip_layer = IP(src=craft.local_ip, dst=craft.dut_ip, flags="evil")
    reply = _echo_with(network_interface, dut_config, craft, ip_layer, nodeid)
    _assert_echo_reply(
        reply, "DUT dropped an echo with the reserved IP flag bit set (should ignore it)"
    )
