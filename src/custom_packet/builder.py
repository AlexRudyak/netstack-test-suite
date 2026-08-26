"""Ad-hoc packet construction for the manual Custom Packet feature (CLI
`send` subcommand, GUI custom packet panel) — outside the pytest-driven
RFC assertion suite. Composes packet_engine.builders + payloads; adds no
new packet-crafting logic of its own.
"""
from __future__ import annotations

from dataclasses import dataclass

from scapy.packet import Packet

from src.packet_engine.builders import build_tcp, build_udp, wrap_ethernet
from src.packet_engine.payloads import PayloadMode, resolve_payload


@dataclass
class CustomPacketSpec:
    proto: str  # "tcp" | "udp"
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    src_mac: str
    dst_mac: str
    ttl: int = 64
    tcp_flags: str = "S"
    payload_mode: PayloadMode = PayloadMode.RANDOM
    payload_size: int = 64
    custom_payload: bytes | None = None  # required when payload_mode is CUSTOM


def build_custom_packet(spec: CustomPacketSpec) -> Packet:
    payload = resolve_payload(
        spec.payload_mode, size=spec.payload_size, custom=spec.custom_payload
    )

    if spec.proto == "tcp":
        l3 = build_tcp(
            spec.src_ip,
            spec.dst_ip,
            spec.src_port,
            spec.dst_port,
            flags=spec.tcp_flags,
            ttl=spec.ttl,
            payload=payload,
        )
    elif spec.proto == "udp":
        l3 = build_udp(
            spec.src_ip, spec.dst_ip, spec.src_port, spec.dst_port, ttl=spec.ttl, payload=payload
        )
    else:
        raise ValueError(f"Unsupported proto {spec.proto!r}; expected 'tcp' or 'udp'")

    return wrap_ethernet(l3, spec.src_mac, spec.dst_mac)
