"""Packet factories: RFC-sane defaults, arbitrary L7 payload attach.

Scope is deliberately L3 (IP)/L4 (TCP/UDP) — these builders have no
application-protocol awareness. `payload` is opaque bytes, produced by
`payloads.resolve_payload()`, riding in a Raw() layer.
"""
from __future__ import annotations

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Packet, Raw

DEFAULT_TTL = 64
DEFAULT_WINDOW = 8192


def build_ip(
    src_ip: str,
    dst_ip: str,
    *,
    ttl: int = DEFAULT_TTL,
    flags: str = "",
    frag: int = 0,
    proto: int | None = None,
    payload: bytes = b"",
) -> Packet:
    """A bare IP packet — used directly by IP-layer conformance tests."""
    kwargs: dict = {"src": src_ip, "dst": dst_ip, "ttl": ttl, "flags": flags, "frag": frag}
    if proto is not None:
        kwargs["proto"] = proto
    pkt: Packet = IP(**kwargs)
    if payload:
        pkt = pkt / Raw(load=payload)
    return pkt


def build_udp(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    *,
    ttl: int = DEFAULT_TTL,
    payload: bytes = b"",
) -> Packet:
    pkt: Packet = IP(src=src_ip, dst=dst_ip, ttl=ttl) / UDP(sport=src_port, dport=dst_port)
    if payload:
        pkt = pkt / Raw(load=payload)
    return pkt


def build_tcp(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    *,
    flags: str = "S",
    seq: int | None = None,
    ack: int = 0,
    window: int = DEFAULT_WINDOW,
    ttl: int = DEFAULT_TTL,
    payload: bytes = b"",
) -> Packet:
    tcp_kwargs: dict = {"sport": src_port, "dport": dst_port, "flags": flags, "ack": ack, "window": window}
    if seq is not None:
        tcp_kwargs["seq"] = seq
    pkt: Packet = IP(src=src_ip, dst=dst_ip, ttl=ttl) / TCP(**tcp_kwargs)
    if payload:
        pkt = pkt / Raw(load=payload)
    return pkt


def wrap_ethernet(l3_packet: Packet, src_mac: str, dst_mac: str) -> Packet:
    """Prefix an Ethernet header — required before sendp()/srp1()."""
    return Ether(src=src_mac, dst=dst_mac) / l3_packet
