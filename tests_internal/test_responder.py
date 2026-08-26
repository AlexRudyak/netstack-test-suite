"""Unit tests for src/packet_engine/responder.py — the server-role
primitives. The pure reply builders are tested directly; the serve_*
orchestration is tested with a fake interface (no NIC)."""
from __future__ import annotations

import pytest
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from src.packet_engine import responder

pytestmark = [pytest.mark.internal]

LOCAL_MAC = "aa:aa:aa:aa:aa:aa"
DUT_MAC = "bb:bb:bb:bb:bb:bb"


def _syn_from_dut() -> "Ether":
    return (
        Ether(src=DUT_MAC, dst=LOCAL_MAC)
        / IP(src="10.0.0.9", dst="10.0.0.1")
        / TCP(sport=50000, dport=80, flags="S", seq=42, window=8192)
    )


def test_build_syn_ack_reply_swaps_and_acknowledges() -> None:
    reply = responder.build_syn_ack_reply(_syn_from_dut(), LOCAL_MAC, server_isn=1000)
    assert reply[Ether].src == LOCAL_MAC and reply[Ether].dst == DUT_MAC
    assert reply[IP].src == "10.0.0.1" and reply[IP].dst == "10.0.0.9"
    assert reply[TCP].sport == 80 and reply[TCP].dport == 50000
    assert reply[TCP].flags == "SA"
    assert reply[TCP].seq == 1000
    assert reply[TCP].ack == 43  # dut seq + 1


def test_build_udp_echo_reply_preserves_payload() -> None:
    datagram = (
        Ether(src=DUT_MAC, dst=LOCAL_MAC)
        / IP(src="10.0.0.9", dst="10.0.0.1")
        / UDP(sport=5000, dport=9999)
        / Raw(b"ping-data")
    )
    reply = responder.build_udp_echo_reply(datagram, LOCAL_MAC)
    assert reply[IP].src == "10.0.0.1" and reply[IP].dst == "10.0.0.9"
    assert reply[UDP].sport == 9999 and reply[UDP].dport == 5000
    assert bytes(reply[Raw].load) == b"ping-data"


def test_build_icmp_echo_reply_mirrors_id_seq_payload() -> None:
    request = (
        Ether(src=DUT_MAC, dst=LOCAL_MAC)
        / IP(src="10.0.0.9", dst="10.0.0.1")
        / ICMP(type=8, id=7, seq=3)
        / Raw(b"abc")
    )
    reply = responder.build_icmp_echo_reply(request, LOCAL_MAC)
    assert reply[ICMP].type == 0
    assert reply[ICMP].id == 7 and reply[ICMP].seq == 3
    assert bytes(reply[Raw].load) == b"abc"


class _FakeInterface:
    """Returns queued sniff results in order; records sent packets."""

    def __init__(self, sniff_results: list[list]) -> None:
        self._sniff_results = list(sniff_results)
        self.sent: list = []

    def sniff(self, *, count, timeout, lfilter, test_nodeid=None):
        return self._sniff_results.pop(0) if self._sniff_results else []

    def send(self, packet, *, test_nodeid=None):
        self.sent.append(packet)


def test_serve_tcp_handshake_replies_and_returns_final_ack() -> None:
    syn = _syn_from_dut()
    final_ack = (
        Ether(src=DUT_MAC, dst=LOCAL_MAC)
        / IP(src="10.0.0.9", dst="10.0.0.1")
        / TCP(sport=50000, dport=80, flags="A")
    )
    iface = _FakeInterface([[syn], [final_ack]])

    result = responder.serve_tcp_handshake(iface, "10.0.0.1", LOCAL_MAC, 80, timeout=1.0)

    assert result is final_ack
    assert len(iface.sent) == 1  # our SYN-ACK
    assert iface.sent[0][TCP].flags == "SA"


def test_serve_tcp_handshake_times_out_without_syn() -> None:
    iface = _FakeInterface([[]])
    assert responder.serve_tcp_handshake(iface, "10.0.0.1", LOCAL_MAC, 80, timeout=0.1) is None
    assert iface.sent == []


def test_serve_udp_echo_echoes_and_returns_datagram() -> None:
    datagram = (
        Ether(src=DUT_MAC, dst=LOCAL_MAC)
        / IP(src="10.0.0.9", dst="10.0.0.1")
        / UDP(sport=5000, dport=7)
        / Raw(b"x")
    )
    iface = _FakeInterface([[datagram]])
    result = responder.serve_udp_echo(iface, "10.0.0.1", LOCAL_MAC, 7, timeout=1.0)
    assert result is datagram
    assert len(iface.sent) == 1 and iface.sent[0].haslayer(UDP)
