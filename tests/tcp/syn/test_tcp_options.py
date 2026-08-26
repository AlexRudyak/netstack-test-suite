"""TCP options parsing and negotiation.

A SYN carrying options (MSS, window scale, timestamps, SACK-permitted, or
unknown/padding) must be parsed correctly and still establish — the DUT
must not reject an optioned SYN. Covers RFC 9293 §3.1 (option format),
RFC 6691 (MSS), RFC 7323 (window scale, timestamps), RFC 2018 (SACK).
"""
from __future__ import annotations

import pytest
from scapy.layers.inet import IP, TCP

from src.packet_engine.builders import wrap_ethernet
from src.packet_engine.sequence import TCPSequenceTracker

pytestmark = [pytest.mark.tcp, pytest.mark.syn, pytest.mark.client]

SYN = 0x02
ACK = 0x10

_SPORT = iter(range(47000, 47100))


def _syn_ack_for_options(network_interface, dut_config, local_mac, dut_mac, local_ip, options, nodeid):
    tracker = TCPSequenceTracker.new()
    syn = wrap_ethernet(
        IP(src=local_ip, dst=dut_config.target_ip)
        / TCP(sport=next(_SPORT), dport=dut_config.target_port, flags="S", seq=tracker.seq, options=options),
        local_mac,
        dut_mac,
    )
    return network_interface.send_receive(syn, timeout=dut_config.timeout, test_nodeid=nodeid)


def _assert_syn_ack(reply, what: str) -> None:
    assert reply is not None, f"DUT did not answer a SYN carrying {what}"
    assert reply.haslayer(TCP)
    assert reply[TCP].flags & (SYN | ACK) == (SYN | ACK), (
        f"DUT did not SYN-ACK a SYN with {what} — it may fail to parse TCP options"
    )


def test_syn_with_mss_option_is_accepted(
    network_interface, dut_config, local_mac, dut_mac, local_ip
) -> None:
    """RFC 6691: a SYN with a Maximum Segment Size option (kind 2) must
    still establish."""
    reply = _syn_ack_for_options(
        network_interface, dut_config, local_mac, dut_mac, local_ip,
        [("MSS", 1460)], "test_syn_with_mss_option_is_accepted",
    )
    _assert_syn_ack(reply, "an MSS option")


def test_syn_with_window_scale_option_is_accepted(
    network_interface, dut_config, local_mac, dut_mac, local_ip
) -> None:
    """RFC 7323 §2: a SYN with a Window Scale option (kind 3) must be
    accepted (and ideally negotiated in the SYN-ACK)."""
    reply = _syn_ack_for_options(
        network_interface, dut_config, local_mac, dut_mac, local_ip,
        [("WScale", 7)], "test_syn_with_window_scale_option_is_accepted",
    )
    _assert_syn_ack(reply, "a Window Scale option")


def test_syn_with_timestamp_option_is_accepted(
    network_interface, dut_config, local_mac, dut_mac, local_ip
) -> None:
    """RFC 7323 §3: a SYN with a Timestamps option (kind 8) must be
    accepted."""
    reply = _syn_ack_for_options(
        network_interface, dut_config, local_mac, dut_mac, local_ip,
        [("Timestamp", (12345, 0))], "test_syn_with_timestamp_option_is_accepted",
    )
    _assert_syn_ack(reply, "a Timestamp option")


def test_syn_with_sack_permitted_option_is_accepted(
    network_interface, dut_config, local_mac, dut_mac, local_ip
) -> None:
    """RFC 2018: a SYN with the SACK-Permitted option (kind 4) must be
    accepted."""
    reply = _syn_ack_for_options(
        network_interface, dut_config, local_mac, dut_mac, local_ip,
        [("SAckOK", b"")], "test_syn_with_sack_permitted_option_is_accepted",
    )
    _assert_syn_ack(reply, "a SACK-Permitted option")


def test_syn_with_combined_options_is_accepted(
    network_interface, dut_config, local_mac, dut_mac, local_ip
) -> None:
    """A realistic modern SYN carries MSS + SACK-permitted + Timestamps +
    NOP padding + Window Scale together; the DUT must parse the whole
    option list and still establish."""
    reply = _syn_ack_for_options(
        network_interface, dut_config, local_mac, dut_mac, local_ip,
        [("MSS", 1460), ("SAckOK", b""), ("Timestamp", (12345, 0)), ("NOP", None), ("WScale", 7)],
        "test_syn_with_combined_options_is_accepted",
    )
    _assert_syn_ack(reply, "a combined option list")


def test_syn_with_unknown_option_is_ignored(
    network_interface, dut_config, local_mac, dut_mac, local_ip
) -> None:
    """RFC 9293 §3.1: a TCP option with an unrecognised kind MUST be
    skipped over using its length field, not cause the segment to be
    rejected. Sends a SYN with an experimental/unknown option kind (253)
    and expects the DUT to ignore it and still SYN-ACK."""
    reply = _syn_ack_for_options(
        network_interface, dut_config, local_mac, dut_mac, local_ip,
        [(253, b"\x00\x00")], "test_syn_with_unknown_option_is_ignored",
    )
    _assert_syn_ack(reply, "an unknown option kind")
