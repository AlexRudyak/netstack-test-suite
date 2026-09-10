"""Ad-hoc packet construction for the manual Custom Packet feature (CLI
`send` subcommand, GUI custom packet panel) — outside the pytest-driven
RFC assertion suite. Composes packet_engine.builders + payloads; adds no
new packet-crafting logic of its own.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from scapy.packet import Packet

from src.packet_engine.builders import build_tcp, build_udp, wrap_ethernet
from src.packet_engine.payloads import PayloadMode, resolve_payload


class Proto(Enum):
    """The transport a custom packet is built over.

    An enum, like every other discriminator in this codebase, rather than
    the bare `str` this was: the valid pair was previously retyped as a
    literal list in three places (here, the CLI's click.Choice, the GUI's
    combo box), so an unexpected value reached the builder and raised at
    send time instead of being rejected at parse time.
    """

    TCP = "tcp"
    UDP = "udp"


@dataclass
class CustomPacketSpec:
    proto: Proto
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

    if spec.proto is Proto.TCP:
        l3 = build_tcp(
            spec.src_ip,
            spec.dst_ip,
            spec.src_port,
            spec.dst_port,
            flags=spec.tcp_flags,
            ttl=spec.ttl,
            payload=payload,
        )
    elif spec.proto is Proto.UDP:
        l3 = build_udp(
            spec.src_ip, spec.dst_ip, spec.src_port, spec.dst_port, ttl=spec.ttl, payload=payload
        )
    else:
        raise ValueError(f"Unhandled Proto: {spec.proto!r}")

    return wrap_ethernet(l3, spec.src_mac, spec.dst_mac)
