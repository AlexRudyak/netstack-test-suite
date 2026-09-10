"""Unit tests for src/packet_engine/builders.py: correct layer
composition and field values. No network access."""
from __future__ import annotations

import pytest
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from src.errors import UnsupportedHostError
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


# --- custom packet protocol selection --------------------------------------


def test_custom_packet_proto_is_an_enum_not_a_string() -> None:
    """`proto` was a bare `str` with a `# "tcp" | "udp"` comment, and the
    valid pair was retyped as a literal list in three places. A typo
    reached the builder and raised at send time, not at parse time."""
    from src.custom_packet.builder import Proto

    assert {p.value for p in Proto} == {"tcp", "udp"}
    with pytest.raises(ValueError):
        Proto("TCP")


def test_both_protocols_build_an_ethernet_framed_packet() -> None:
    from src.custom_packet.builder import CustomPacketSpec, Proto, build_custom_packet

    for proto, layer in ((Proto.TCP, TCP), (Proto.UDP, UDP)):
        packet = build_custom_packet(
            CustomPacketSpec(
                proto=proto,
                src_ip="10.0.0.1",
                dst_ip="10.0.0.5",
                src_port=41000,
                dst_port=80,
                src_mac="aa:aa:aa:aa:aa:aa",
                dst_mac="bb:bb:bb:bb:bb:bb",
            )
        )
        assert packet.haslayer(Ether) and packet.haslayer(IP) and packet.haslayer(layer)


def test_cli_and_gui_offer_exactly_the_declared_protocols() -> None:
    """Both front ends derive their choice list from the enum."""
    import src.cli.main as cli_main
    from src.custom_packet.builder import Proto

    option = next(p for p in cli_main.send.params if p.name == "proto")
    assert set(option.type.choices) == {p.value for p in Proto}


# --- host socket backend ----------------------------------------------------


def test_supported_hosts_each_have_a_backend() -> None:
    """SUPPORTED_HOSTS is what the error message promises; _BACKENDS is what
    get_backend can actually deliver. They must agree."""
    from src.packet_engine.platform_backend import SUPPORTED_HOSTS, _BACKENDS

    assert set(_BACKENDS) == set(SUPPORTED_HOSTS)


def test_each_backend_sets_the_socket_path_its_host_needs(monkeypatch) -> None:
    """Windows forces Npcap-backed L2 sockets; Linux uses native AF_PACKET.
    Standardising on L2 for both is the point of this module."""
    from scapy.config import conf

    from src.packet_engine import platform_backend

    for system, expected in (("Windows", True), ("Linux", False)):
        monkeypatch.setattr(platform_backend.platform, "system", lambda s=system: s)
        backend = platform_backend.get_backend()
        assert backend.host_name == system
        backend.configure()
        assert conf.use_pcap is expected


def test_unsupported_host_is_refused_with_the_shared_message(monkeypatch) -> None:
    from src.packet_engine import platform_backend

    monkeypatch.setattr(platform_backend.platform, "system", lambda: "Darwin")
    with pytest.raises(UnsupportedHostError, match="Unsupported host platform"):
        platform_backend.get_backend()
