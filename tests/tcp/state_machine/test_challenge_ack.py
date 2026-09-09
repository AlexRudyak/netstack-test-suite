"""RFC 5961 — challenge-ACK behaviour for blind in-window attacks, and
the RFC 9293 §3.10.7.3 LISTEN-state rules.

RFC 5961 splits "in window" into two cases the original RFC 793 text
conflated:

  * exactly RCV.NXT      → act on the control bit (reset / whatever)
  * in window, not exact → send a challenge ACK, do NOT act

test_rst_edge_cases.py covers a RST far outside the window (ignored
outright). This module covers the harder middle ground: a RST or SYN
that lands *inside* the window but not exactly at RCV.NXT must only draw
a challenge ACK, leaving the connection ESTABLISHED.
"""
from __future__ import annotations

import pytest
from scapy.layers.inet import IP, TCP

from src.packet_engine.builders import build_tcp, wrap_ethernet

from .conftest import ACK, RST, SYN, connection_still_alive, segment

pytestmark = [pytest.mark.tcp, pytest.mark.state_machine, pytest.mark.client]


def test_in_window_non_exact_rst_draws_challenge_ack_only(
    established_tcp_connection, network_interface
) -> None:
    """RFC 5961 §3: a RST whose sequence number is within the receive
    window but not exactly RCV.NXT MUST NOT tear the connection down; the
    DUT should emit a challenge ACK and stay ESTABLISHED."""
    conn = established_tcp_connection
    nodeid = "test_in_window_non_exact_rst_draws_challenge_ack_only"

    # RCV.NXT + 100: comfortably inside a default (>=8 KiB) window, but not
    # the exact next-expected sequence number.
    rst = segment(conn, flags="R", seq=(conn.tracker.seq + 100) & 0xFFFFFFFF)
    network_interface.send(rst, test_nodeid=nodeid)

    assert connection_still_alive(conn, network_interface, nodeid=nodeid), (
        "DUT accepted an in-window RST that was not at RCV.NXT — RFC 5961 §3 requires a challenge ACK instead"
    )


def test_in_window_syn_draws_challenge_ack_not_reset(
    established_tcp_connection, network_interface
) -> None:
    """RFC 5961 §4: a SYN received on an ESTABLISHED connection MUST NOT
    silently reset it. The DUT should send a challenge ACK; if the SYN
    was spurious (it was) the connection stays up. A DUT that answers
    with RST here is vulnerable to a blind-SYN reset."""
    conn = established_tcp_connection
    nodeid = "test_in_window_syn_draws_challenge_ack_not_reset"

    syn = segment(conn, flags="S", seq=(conn.tracker.seq + 1) & 0xFFFFFFFF)
    reply = network_interface.send_receive(syn, timeout=1.5, test_nodeid=nodeid)

    if reply is not None and reply.haslayer(TCP):
        assert not (reply[TCP].flags & RST), (
            "DUT reset an ESTABLISHED connection on an in-window SYN — RFC 5961 §4 requires a challenge ACK"
        )
    assert connection_still_alive(conn, network_interface, nodeid=nodeid)


def test_exact_rcv_nxt_syn_is_still_not_a_reset_trigger(
    established_tcp_connection, network_interface
) -> None:
    """RFC 5961 §4: even a SYN whose sequence number is exactly RCV.NXT
    must draw a challenge ACK (not a reset). The DUT only tears down if
    the challenge ACK comes back proving the peer really restarted."""
    conn = established_tcp_connection
    nodeid = "test_exact_rcv_nxt_syn_is_still_not_a_reset_trigger"

    network_interface.send(segment(conn, flags="S", seq=conn.tracker.seq), test_nodeid=nodeid)

    assert connection_still_alive(conn, network_interface, nodeid=nodeid), (
        "DUT tore down the connection on a bare in-window SYN without waiting for a challenge-ACK confirmation"
    )


def test_ack_arriving_on_listen_port_elicits_rst(
    network_interface, dut_config, local_mac, dut_mac, local_ip
) -> None:
    """RFC 9293 §3.10.7.3 (LISTEN, first check): "Any acknowledgment is
    bad if it arrives on a connection still in the LISTEN state." The DUT
    MUST answer such a segment with <SEQ=SEG.ACK><CTL=RST>."""
    nodeid = "test_ack_arriving_on_listen_port_elicits_rst"
    seg_ack = 0xDEAD_BEEF
    packet = wrap_ethernet(
        build_tcp(
            local_ip, dut_config.target_ip, 46500, dut_config.target_port,
            flags="A", seq=1000, ack=seg_ack,
        ),
        local_mac,
        dut_mac,
    )

    reply = network_interface.send_receive(packet, timeout=dut_config.timeout, test_nodeid=nodeid)

    assert reply is not None and reply.haslayer(TCP), "DUT did not answer a bare ACK to a listening port"
    assert reply[TCP].flags & RST, "DUT did not RST a bare ACK arriving in LISTEN state (§3.10.7.3)"
    assert reply[TCP].seq == seg_ack, (
        f"RST sequence number is {reply[TCP].seq}, must equal our SEG.ACK {seg_ack} (§3.10.7.3)"
    )


def test_data_segment_to_listen_port_is_not_accepted(
    network_interface, dut_config, local_mac, dut_mac, local_ip
) -> None:
    """RFC 9293 §3.10.7.3: a segment with neither SYN nor ACK (nor RST)
    arriving in LISTEN is dropped. It must never produce a SYN-ACK — that
    would mean the DUT accepted data as a connection request."""
    nodeid = "test_data_segment_to_listen_port_is_not_accepted"
    packet = wrap_ethernet(
        build_tcp(
            local_ip, dut_config.target_ip, 46501, dut_config.target_port,
            flags="P", seq=1000, payload=b"unsolicited",
        ),
        local_mac,
        dut_mac,
    )
    network_interface.send(packet, test_nodeid=nodeid)

    syn_acks = network_interface.sniff(
        count=1,
        timeout=1.5,
        lfilter=lambda p: (
            p.haslayer(TCP)
            and p.haslayer(IP)
            and p[IP].dst == local_ip
            and p[TCP].dport == 46501
            and p[TCP].flags & (SYN | ACK) == (SYN | ACK)
        ),
        test_nodeid=nodeid,
    )
    assert not syn_acks, "DUT answered a bare data segment in LISTEN state with a SYN-ACK"
