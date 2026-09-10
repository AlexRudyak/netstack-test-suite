"""TCP flag bits, sequence-space arithmetic, and reply predicates.

One home for the handful of protocol constants the suite kept
re-declaring. Before this module, `SYN = 0x02` / `ACK = 0x10` /
`RST = 0x04` / `FIN = 0x01` were spelled out independently in thirteen
modules, `MAX_SEQ = 2**32 - 1` in two, and the 32-bit wrap was written
inline as a bare `& 0xFFFFFFFF` in eighteen places — each an opportunity
for one copy to drift from the rest.

Scope is deliberately narrow: bit values, the sequence-space mask, and
predicates over a received packet's flags. Packet *construction* stays in
`src/packet_engine/builders.py`; connection bookkeeping stays in
`src/packet_engine/sequence.py`.
"""
from __future__ import annotations

from scapy.layers.inet import TCP
from scapy.packet import Packet

# --- Flag bits (RFC 9293 §3.1, header bit order) ----------------------------

FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80

# Combinations named often enough to be worth spelling once.
SYN_ACK = SYN | ACK
FIN_ACK = FIN | ACK

# Flag bit -> tshark-style name, in header bit order. Consumed by
# src/utils/debug_log.py to render the `[SYN, ACK]` column.
FLAG_NAMES: tuple[tuple[int, str], ...] = (
    (FIN, "FIN"),
    (SYN, "SYN"),
    (RST, "RST"),
    (PSH, "PSH"),
    (ACK, "ACK"),
    (URG, "URG"),
    (ECE, "ECE"),
    (CWR, "CWR"),
)

# --- Sequence space ---------------------------------------------------------

# TCP sequence and acknowledgement numbers are 32-bit and wrap.
MAX_SEQ = 2**32 - 1


def seq32(value: int) -> int:
    """Wrap a sequence/ack number into the 32-bit TCP sequence space.

    Replaces the inline `(x + n) & 0xFFFFFFFF` idiom, so the width is
    stated once rather than as a magic literal at each call site.
    """
    return value & MAX_SEQ


# --- Predicates over a received packet --------------------------------------


def flags_of(packet: Packet | None) -> int:
    """The TCP flag byte of `packet`, or 0 when it carries no TCP layer.

    Tolerates None so the common `reply = send_receive(...)` result can be
    tested without a separate None check at every call site.
    """
    if packet is None or not packet.haslayer(TCP):
        return 0
    return int(packet[TCP].flags)


def has_flags(packet: Packet | None, mask: int) -> bool:
    """True when *every* bit in `mask` is set on the packet's TCP flags.

    Note this is an all-of test, not any-of: `has_flags(pkt, SYN_ACK)` is
    the `flags & (SYN | ACK) == (SYN | ACK)` check written across the TCP
    suite, not a "SYN or ACK" test.
    """
    if not mask:
        return False
    return flags_of(packet) & mask == mask


def any_flags(packet: Packet | None, mask: int) -> bool:
    """True when *any* bit in `mask` is set — the counterpart to
    `has_flags`. `any_flags(pkt, SYN | RST)` is "is this a SYN or a RST",
    where `has_flags(pkt, SYN | RST)` would demand both."""
    return bool(flags_of(packet) & mask)


def is_syn_ack(packet: Packet | None) -> bool:
    """A SYN-ACK: both bits set. Says nothing about FIN/RST also being
    set — use `is_bare_syn_ack` when a scan pattern must be excluded."""
    return has_flags(packet, SYN_ACK)


def is_bare_syn_ack(packet: Packet | None) -> bool:
    """A SYN-ACK with neither FIN nor RST — i.e. a genuine acceptance of a
    connection request, not a response to a contradictory flag set."""
    return is_syn_ack(packet) and not (flags_of(packet) & (FIN | RST))


def is_bare_syn(packet: Packet | None) -> bool:
    """A connection request: SYN set, ACK clear."""
    return has_flags(packet, SYN) and not has_flags(packet, ACK)


def is_rst(packet: Packet | None) -> bool:
    return has_flags(packet, RST)


def is_ack(packet: Packet | None) -> bool:
    return has_flags(packet, ACK)


def flag_labels(flags: int) -> str:
    """tshark-style `[SYN, ACK]` rendering of a flag byte."""
    names = [name for bit, name in FLAG_NAMES if flags & bit]
    return "[" + ", ".join(names) + "]" if names else "[]"
