"""Unit tests for src/packet_engine/builders.py: correct layer
composition and field values. No network access."""
from __future__ import annotations

import pytest
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from src.packet_engine.builders import build_ip, build_tcp, build_udp, wrap_ethernet

pytestmark = [pytest.mark.internal]


def test_build_ip_sets_core_fields() -> None:
    pkt = build_ip("10.0.0.1", "10.0.0.2", ttl=32, flags="DF")
    assert pkt[IP].src == "10.0.0.1"
    assert pkt[IP].dst == "10.0.0.2"
    assert pkt[IP].ttl == 32
    assert pkt[IP].flags == "DF"


def test_build_ip_attaches_payload() -> None:
    pkt = build_ip("10.0.0.1", "10.0.0.2", payload=b"hello")
    assert pkt.haslayer(Raw)
    assert bytes(pkt[Raw]) == b"hello"


def test_build_ip_without_payload_has_no_raw_layer() -> None:
    pkt = build_ip("10.0.0.1", "10.0.0.2")
    assert not pkt.haslayer(Raw)


def test_build_udp_sets_ports_and_payload() -> None:
    pkt = build_udp("10.0.0.1", "10.0.0.2", 1111, 2222, payload=b"abc")
    assert pkt[UDP].sport == 1111
    assert pkt[UDP].dport == 2222
    assert bytes(pkt[Raw]) == b"abc"
    # UDP.len is computed lazily by Scapy at serialization time, not when
    # the layer is constructed — round-trip through bytes() to force it.
    assert UDP(bytes(pkt[UDP])).len == 8 + 3


def test_build_tcp_sets_flags_seq_ack_window() -> None:
    pkt = build_tcp("10.0.0.1", "10.0.0.2", 1111, 2222, flags="SA", seq=1000, ack=2000, window=4096)
    assert pkt[TCP].flags == "SA"
    assert pkt[TCP].seq == 1000
    assert pkt[TCP].ack == 2000
    assert pkt[TCP].window == 4096


def test_wrap_ethernet_prefixes_ether_header() -> None:
    l3 = build_ip("10.0.0.1", "10.0.0.2")
    pkt = wrap_ethernet(l3, "aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66")
    assert pkt.haslayer(Ether)
    assert pkt[Ether].src == "aa:bb:cc:dd:ee:ff"
    assert pkt[Ether].dst == "11:22:33:44:55:66"
    assert pkt.haslayer(IP)
