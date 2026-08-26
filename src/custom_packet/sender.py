"""Sends one custom packet and captures the response.

Reuses packet_engine.interface.NetworkInterface so ad-hoc sends go
through the same send/receive path and the same pcap capture mechanism
as the automated suite — no separate logging pathway to keep in sync.
"""
from __future__ import annotations

from pathlib import Path

from scapy.packet import Packet

from src.custom_packet.builder import CustomPacketSpec, build_custom_packet
from src.packet_engine.interface import NetworkInterface


def send_custom_packet(
    spec: CustomPacketSpec,
    iface: str,
    *,
    timeout: float = 2.0,
    capture_path: Path | None = None,
) -> Packet | None:
    packet = build_custom_packet(spec)
    with NetworkInterface(iface, capture_path=capture_path) as net_iface:
        return net_iface.send_receive(packet, timeout=timeout, test_nodeid="custom_packet")
