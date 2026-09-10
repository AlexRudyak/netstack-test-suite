"""TCP options parsing and negotiation.

A SYN carrying options (MSS, window scale, timestamps, SACK-permitted, or
unknown/padding) must be parsed correctly and still establish — the DUT
must not reject an optioned SYN. Covers RFC 9293 §3.1 (option format),
RFC 6691 (MSS), RFC 7323 (window scale, timestamps), RFC 2018 (SACK).
"""
from __future__ import annotations

import pytest
from scapy.layers.inet import IP, TCP

from src.packet_engine.sequence import TCPSequenceTracker
from src.utils.tcp_flags import is_syn_ack

pytestmark = [pytest.mark.tcp, pytest.mark.syn, pytest.mark.client]


def _syn_ack_for_options(network_interface, dut_config, craft, source_ports, options, nodeid):
    """Send a SYN carrying `options` and return whatever came back.

    Built from a raw IP()/TCP() rather than `craft.tcp()` because the
    option list is the point of the test — `build_tcp` deliberately has no
    options parameter.
    """
    tracker = TCPSequenceTracker.new()
    syn = craft.l3(
        IP(src=craft.local_ip, dst=craft.dut_ip)
        / TCP(
            sport=source_ports(),
            dport=craft.dut_port,
            flags="S",
            seq=tracker.seq,
            options=options,
        )
    )
    return network_interface.send_receive(syn, timeout=dut_config.timeout, test_nodeid=nodeid)


def _assert_syn_ack(reply, what: str) -> None:
    assert reply is not None, f"DUT did not answer a SYN carrying {what}"
    assert is_syn_ack(reply), (
        f"DUT did not SYN-ACK a SYN with {what} — it may fail to parse TCP options"
    )


def test_syn_with_mss_option_is_accepted(
    network_interface, dut_config, craft, source_ports, nodeid
) -> None:
    """RFC 6691: a SYN with a Maximum Segment Size option (kind 2) must
    still establish."""
    reply = _syn_ack_for_options(
        network_interface, dut_config, craft, source_ports, [("MSS", 1460)], nodeid
    )
    _assert_syn_ack(reply, "an MSS option")


def test_syn_with_window_scale_option_is_accepted(
    network_interface, dut_config, craft, source_ports, nodeid
) -> None:
    """RFC 7323 §2: a SYN with a Window Scale option (kind 3) must be
    accepted (and ideally negotiated in the SYN-ACK)."""
    reply = _syn_ack_for_options(
        network_interface, dut_config, craft, source_ports, [("WScale", 7)], nodeid
    )
    _assert_syn_ack(reply, "a Window Scale option")


def test_syn_with_timestamp_option_is_accepted(
    network_interface, dut_config, craft, source_ports, nodeid
) -> None:
    """RFC 7323 §3: a SYN with a Timestamps option (kind 8) must be
    accepted."""
    reply = _syn_ack_for_options(
        network_interface, dut_config, craft, source_ports, [("Timestamp", (12345, 0))], nodeid
    )
    _assert_syn_ack(reply, "a Timestamp option")


def test_syn_with_sack_permitted_option_is_accepted(
    network_interface, dut_config, craft, source_ports, nodeid
) -> None:
    """RFC 2018: a SYN with the SACK-Permitted option (kind 4) must be
    accepted."""
    reply = _syn_ack_for_options(
        network_interface, dut_config, craft, source_ports, [("SAckOK", b"")], nodeid
    )
    _assert_syn_ack(reply, "a SACK-Permitted option")


def test_syn_with_combined_options_is_accepted(
    network_interface, dut_config, craft, source_ports, nodeid
) -> None:
    """A realistic modern SYN carries MSS + SACK-permitted + Timestamps +
    NOP padding + Window Scale together; the DUT must parse the whole
    option list and still establish."""
    reply = _syn_ack_for_options(
        network_interface, dut_config, craft, source_ports,
        [("MSS", 1460), ("SAckOK", b""), ("Timestamp", (12345, 0)), ("NOP", None), ("WScale", 7)],
        nodeid,
    )
    _assert_syn_ack(reply, "a combined option list")


def test_syn_with_unknown_option_is_ignored(
    network_interface, dut_config, craft, source_ports, nodeid
) -> None:
    """RFC 9293 §3.1: a TCP option with an unrecognised kind MUST be
    skipped over using its length field, not cause the segment to be
    rejected. Sends a SYN with an experimental/unknown option kind (253)
    and expects the DUT to ignore it and still SYN-ACK."""
    reply = _syn_ack_for_options(
        network_interface, dut_config, craft, source_ports, [(253, b"\x00\x00")], nodeid
    )
    _assert_syn_ack(reply, "an unknown option kind")
