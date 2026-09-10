"""Server-role primitives: wait for the DUT to initiate, then respond.

In CLIENT role the suite sends probes and validates the DUT's responder
behavior. In SERVER role the roles flip — the DUT is the initiator and the
suite must behave like a well-formed server/peer: accept a handshake it
didn't start, echo a datagram, answer an echo request. These helpers give
server-role tests those building blocks.

The reply *construction* is separated from the sniff/send orchestration so
the wire-format logic is unit-testable without a NIC: `build_*_reply()`
are pure functions over a received packet, and the `serve_*` functions are
thin loops that sniff for the DUT's packet, build the reply, and send it.
"""
from __future__ import annotations

import random
from collections.abc import Callable

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Packet, Raw

from src.packet_engine.interface import NetworkInterface
from src.utils.tcp_flags import ACK, MAX_SEQ, SYN, seq32

# ICMP message types (RFC 792).
ICMP_ECHO_REPLY = 0
ICMP_ECHO_REQUEST = 8


# --- Pure reply builders (unit-testable) -----------------------------------


def build_syn_ack_reply(
    syn: Packet, local_mac: str, *, server_isn: int | None = None, window: int | None = None
) -> Packet:
    """Given a SYN the DUT sent us, build the SYN-ACK a server returns.

    Swaps src/dst at L2/L3/L4, acknowledges the DUT's ISN+1, and uses our
    own (random unless pinned) ISN. `window` overrides the advertised
    receive window (defaults to mirroring the DUT's) — set 0 to force the
    DUT to respect a zero window immediately.
    """
    ip = syn[IP]
    tcp = syn[TCP]
    isn = server_isn if server_isn is not None else random.randint(0, MAX_SEQ)
    reply = (
        Ether(src=local_mac, dst=syn[Ether].src)
        / IP(src=ip.dst, dst=ip.src)
        / TCP(
            sport=tcp.dport,
            dport=tcp.sport,
            flags="SA",
            seq=isn,
            ack=seq32(tcp.seq + 1),
            window=window if window is not None else tcp.window,
        )
    )
    return reply


def _echo_payload(packet: Packet) -> bytes:
    """The L7 bytes to mirror back, or empty when the packet carried none."""
    return bytes(packet[Raw].load) if packet.haslayer(Raw) else b""


def _reply_headers(received: Packet, local_mac: str):
    """L2/L3 of a reply to `received`: source and destination swapped."""
    ip = received[IP]
    return Ether(src=local_mac, dst=received[Ether].src) / IP(src=ip.dst, dst=ip.src)


def build_udp_echo_reply(datagram: Packet, local_mac: str) -> Packet:
    """Echo a UDP datagram back to its sender (payload unchanged)."""
    udp = datagram[UDP]
    return (
        _reply_headers(datagram, local_mac)
        / UDP(sport=udp.dport, dport=udp.sport)
        / Raw(load=_echo_payload(datagram))
    )


def build_icmp_echo_reply(request: Packet, local_mac: str) -> Packet:
    """Build the ICMP Echo Reply (type 0) for a received Echo Request."""
    icmp = request[ICMP]
    return (
        _reply_headers(request, local_mac)
        / ICMP(type=ICMP_ECHO_REPLY, id=icmp.id, seq=icmp.seq)
        / Raw(load=_echo_payload(request))
    )


# --- Orchestration (sniff for the DUT's packet, reply) ----------------------
#
# All three responders below are the same shape: wait for one packet from the
# DUT matching a filter, build the reply, send it, return what arrived. The
# shape is factored into `_serve_once`; each public function keeps its own
# filter and docstring, which is where the per-protocol meaning lives.


def _addressed_to_us(local_ip: str, layer) -> Callable[[Packet], bool]:
    """The filter prefix every responder needs: the right L4 layer, an IP
    header, and destined for us — not merely present on the segment."""

    def match(packet: Packet) -> bool:
        return packet.haslayer(layer) and packet.haslayer(IP) and packet[IP].dst == local_ip

    return match


def _serve_once(
    interface: NetworkInterface,
    lfilter: Callable[[Packet], bool],
    build_reply: Callable[[Packet], Packet],
    *,
    timeout: float,
    test_nodeid: str | None,
) -> Packet | None:
    """Wait for one matching packet from the DUT, answer it, and return it
    (or None if nothing arrived within `timeout`)."""
    received = interface.sniff(count=1, timeout=timeout, lfilter=lfilter, test_nodeid=test_nodeid)
    if not received:
        return None
    interface.send(build_reply(received[0]), test_nodeid=test_nodeid)
    return received[0]


def serve_tcp_handshake(
    interface: NetworkInterface,
    local_ip: str,
    local_mac: str,
    listen_port: int,
    *,
    timeout: float = 5.0,
    test_nodeid: str | None = None,
) -> Packet | None:
    """Wait for the DUT to open a connection to `listen_port`, reply
    SYN-ACK, and return the DUT's final ACK (or None if it never arrived).

    A non-None return means the DUT completed a three-way handshake it
    initiated — i.e. its client-side connect path works.
    """
    to_us = _addressed_to_us(local_ip, TCP)
    syn = _serve_once(
        interface,
        lambda p: (
            to_us(p)
            and p[TCP].dport == listen_port
            and p[TCP].flags & SYN
            and not (p[TCP].flags & ACK)
        ),
        lambda p: build_syn_ack_reply(p, local_mac),
        timeout=timeout,
        test_nodeid=test_nodeid,
    )
    if syn is None:
        return None

    acks = interface.sniff(
        count=1,
        timeout=timeout,
        lfilter=lambda p: (
            to_us(p)
            and p[TCP].dport == listen_port
            and p[TCP].flags & ACK
            and not (p[TCP].flags & SYN)
        ),
        test_nodeid=test_nodeid,
    )
    return acks[0] if acks else None


def serve_udp_echo(
    interface: NetworkInterface,
    local_ip: str,
    local_mac: str,
    listen_port: int,
    *,
    timeout: float = 5.0,
    test_nodeid: str | None = None,
) -> Packet | None:
    """Wait for the DUT to send a UDP datagram to `listen_port`, echo it
    back, and return the datagram we received (or None on timeout)."""
    to_us = _addressed_to_us(local_ip, UDP)
    return _serve_once(
        interface,
        lambda p: to_us(p) and p[UDP].dport == listen_port,
        lambda p: build_udp_echo_reply(p, local_mac),
        timeout=timeout,
        test_nodeid=test_nodeid,
    )


def serve_icmp_echo(
    interface: NetworkInterface,
    local_ip: str,
    local_mac: str,
    *,
    timeout: float = 5.0,
    test_nodeid: str | None = None,
) -> Packet | None:
    """Wait for the DUT to send an ICMP Echo Request to us, reply with an
    Echo Reply, and return the request (or None on timeout)."""
    to_us = _addressed_to_us(local_ip, ICMP)
    return _serve_once(
        interface,
        lambda p: to_us(p) and p[ICMP].type == ICMP_ECHO_REQUEST,
        lambda p: build_icmp_echo_reply(p, local_mac),
        timeout=timeout,
        test_nodeid=test_nodeid,
    )
