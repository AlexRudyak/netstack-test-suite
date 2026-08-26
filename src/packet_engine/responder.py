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

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Packet, Raw

from src.packet_engine.interface import NetworkInterface

MAX_SEQ = 2**32 - 1
SYN = 0x02
ACK = 0x10


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
            ack=(tcp.seq + 1) & MAX_SEQ,
            window=window if window is not None else tcp.window,
        )
    )
    return reply


def build_udp_echo_reply(datagram: Packet, local_mac: str) -> Packet:
    """Echo a UDP datagram back to its sender (payload unchanged)."""
    ip = datagram[IP]
    udp = datagram[UDP]
    payload = bytes(datagram[Raw].load) if datagram.haslayer(Raw) else b""
    return (
        Ether(src=local_mac, dst=datagram[Ether].src)
        / IP(src=ip.dst, dst=ip.src)
        / UDP(sport=udp.dport, dport=udp.sport)
        / Raw(load=payload)
    )


def build_icmp_echo_reply(request: Packet, local_mac: str) -> Packet:
    """Build the ICMP Echo Reply (type 0) for a received Echo Request."""
    ip = request[IP]
    icmp = request[ICMP]
    payload = bytes(request[Raw].load) if request.haslayer(Raw) else b""
    return (
        Ether(src=local_mac, dst=request[Ether].src)
        / IP(src=ip.dst, dst=ip.src)
        / ICMP(type=0, id=icmp.id, seq=icmp.seq)
        / Raw(load=payload)
    )


# --- Orchestration (sniff for the DUT's packet, reply) ----------------------


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
    syns = interface.sniff(
        count=1,
        timeout=timeout,
        lfilter=lambda p: (
            p.haslayer(TCP)
            and p.haslayer(IP)
            and p[IP].dst == local_ip
            and p[TCP].dport == listen_port
            and p[TCP].flags & SYN
            and not (p[TCP].flags & ACK)
        ),
        test_nodeid=test_nodeid,
    )
    if not syns:
        return None
    syn = syns[0]
    interface.send(build_syn_ack_reply(syn, local_mac), test_nodeid=test_nodeid)

    acks = interface.sniff(
        count=1,
        timeout=timeout,
        lfilter=lambda p: (
            p.haslayer(TCP)
            and p[IP].dst == local_ip
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
    datagrams = interface.sniff(
        count=1,
        timeout=timeout,
        lfilter=lambda p: (
            p.haslayer(UDP) and p.haslayer(IP) and p[IP].dst == local_ip and p[UDP].dport == listen_port
        ),
        test_nodeid=test_nodeid,
    )
    if not datagrams:
        return None
    received = datagrams[0]
    interface.send(build_udp_echo_reply(received, local_mac), test_nodeid=test_nodeid)
    return received


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
    requests = interface.sniff(
        count=1,
        timeout=timeout,
        lfilter=lambda p: (
            p.haslayer(ICMP) and p.haslayer(IP) and p[IP].dst == local_ip and p[ICMP].type == 8
        ),
        test_nodeid=test_nodeid,
    )
    if not requests:
        return None
    request = requests[0]
    interface.send(build_icmp_echo_reply(request, local_mac), test_nodeid=test_nodeid)
    return request
