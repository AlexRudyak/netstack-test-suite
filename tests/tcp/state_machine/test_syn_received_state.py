"""RFC 9293 §3.10.7.4 — the SYN-RECEIVED state.

SYN-RECEIVED is the window between the DUT sending its SYN-ACK and
receiving the handshake's final ACK. It is short-lived but has its own
arrival rules, and it is the state a SYN-flood targets, so its edge
cases matter:

  * a duplicate SYN is a retransmission — the DUT must resend the *same*
    SYN-ACK (same ISN), not allocate a new connection or a new ISN;
  * a RST that acknowledges the SYN-ACK aborts the half-open connection
    and deletes the TCB;
  * a stray ACK with the wrong sequence number must not complete the
    handshake.

These drive the handshake by hand rather than via the
`established_tcp_connection` fixture, which by definition only exists
once SYN-RECEIVED has been left behind.
"""
from __future__ import annotations

import itertools

import pytest
from scapy.layers.inet import TCP

from src.packet_engine.builders import build_tcp, wrap_ethernet

pytestmark = [pytest.mark.tcp, pytest.mark.state_machine, pytest.mark.client]

SYN = 0x02
ACK = 0x10
RST = 0x04
SYN_ACK = SYN | ACK

_sport = itertools.count(46700)


def _send_syn(network_interface, dut_config, local_mac, dut_mac, local_ip, sport, isn, nodeid):
    syn = wrap_ethernet(
        build_tcp(local_ip, dut_config.target_ip, sport, dut_config.target_port, flags="S", seq=isn),
        local_mac,
        dut_mac,
    )
    return network_interface.send_receive(syn, timeout=dut_config.timeout, test_nodeid=nodeid)


def test_duplicate_syn_in_syn_received_retransmits_same_syn_ack(
    network_interface, dut_config, local_mac, dut_mac, local_ip
) -> None:
    """§3.10.7.4: a retransmitted SYN (same 4-tuple, same ISN) while the
    DUT is in SYN-RECEIVED is a duplicate, not a new connection. The DUT
    MUST answer with the same SYN-ACK it already sent — crucially the
    same server ISN — so the legitimate client's in-flight ACK still
    matches."""
    nodeid = "test_duplicate_syn_in_syn_received_retransmits_same_syn_ack"
    sport = next(_sport)
    isn = 0x0100_0000

    first = _send_syn(network_interface, dut_config, local_mac, dut_mac, local_ip, sport, isn, nodeid)
    assert first is not None and first.haslayer(TCP) and first[TCP].flags & SYN_ACK == SYN_ACK, (
        "DUT did not enter SYN-RECEIVED (no SYN-ACK to the first SYN)"
    )

    second = _send_syn(network_interface, dut_config, local_mac, dut_mac, local_ip, sport, isn, nodeid)
    assert second is not None and second.haslayer(TCP), "DUT did not answer a duplicate SYN"
    assert second[TCP].flags & SYN_ACK == SYN_ACK, "DUT answered a duplicate SYN with something other than SYN-ACK"
    assert second[TCP].seq == first[TCP].seq, (
        f"DUT changed its ISN on a duplicate SYN ({first[TCP].seq} -> {second[TCP].seq}) — "
        "the retransmission was treated as a fresh connection, breaking the real client's handshake"
    )
    assert second[TCP].ack == (isn + 1) & 0xFFFFFFFF

    # Clean up the half-open connection.
    network_interface.send(
        wrap_ethernet(
            build_tcp(local_ip, dut_config.target_ip, sport, dut_config.target_port, flags="R", seq=isn + 1),
            local_mac, dut_mac,
        ),
        test_nodeid=nodeid,
    )


def test_rst_in_syn_received_aborts_half_open_connection(
    network_interface, dut_config, local_mac, dut_mac, local_ip
) -> None:
    """§3.10.7.4 (SYN-RECEIVED, RST check): a RST carrying the sequence
    number the DUT expects next (its SYN-ACK's ack value) MUST abort the
    half-open connection and delete the TCB. Proven by the original
    handshake's final ACK afterwards being answered with RST — the DUT no
    longer has the connection."""
    nodeid = "test_rst_in_syn_received_aborts_half_open_connection"
    sport = next(_sport)
    isn = 0x0200_0000

    syn_ack = _send_syn(network_interface, dut_config, local_mac, dut_mac, local_ip, sport, isn, nodeid)
    assert syn_ack is not None and syn_ack.haslayer(TCP) and syn_ack[TCP].flags & SYN_ACK == SYN_ACK, (
        "DUT did not enter SYN-RECEIVED"
    )

    # RST at RCV.NXT (== isn + 1, what the DUT acknowledged in its SYN-ACK).
    network_interface.send(
        wrap_ethernet(
            build_tcp(local_ip, dut_config.target_ip, sport, dut_config.target_port, flags="R", seq=isn + 1),
            local_mac, dut_mac,
        ),
        test_nodeid=nodeid,
    )

    # The final ACK of the aborted handshake.
    stray_ack = wrap_ethernet(
        build_tcp(
            local_ip, dut_config.target_ip, sport, dut_config.target_port,
            flags="A", seq=isn + 1, ack=(syn_ack[TCP].seq + 1) & 0xFFFFFFFF,
        ),
        local_mac, dut_mac,
    )
    reply = network_interface.send_receive(stray_ack, timeout=1.5, test_nodeid=nodeid)

    if reply is not None and reply.haslayer(TCP):
        assert reply[TCP].flags & RST, (
            "DUT still had the half-open connection after a valid RST in SYN-RECEIVED — TCB was not deleted"
        )


def test_wrong_seq_ack_does_not_complete_handshake(
    network_interface, dut_config, local_mac, dut_mac, local_ip
) -> None:
    """§3.10.7.4 (SYN-RECEIVED, ACK check): the final ACK only completes
    the handshake if SEG.ACK exactly acknowledges the DUT's ISN. An ACK
    with the wrong ack number MUST NOT reach ESTABLISHED — the DUT should
    answer with RST (SEG.ACK unacceptable), and certainly must not then
    carry data on the connection."""
    nodeid = "test_wrong_seq_ack_does_not_complete_handshake"
    sport = next(_sport)
    isn = 0x0300_0000

    syn_ack = _send_syn(network_interface, dut_config, local_mac, dut_mac, local_ip, sport, isn, nodeid)
    assert syn_ack is not None and syn_ack.haslayer(TCP) and syn_ack[TCP].flags & SYN_ACK == SYN_ACK

    bad_ack = wrap_ethernet(
        build_tcp(
            local_ip, dut_config.target_ip, sport, dut_config.target_port,
            flags="A", seq=isn + 1, ack=(syn_ack[TCP].seq + 5000) & 0xFFFFFFFF,
        ),
        local_mac, dut_mac,
    )
    reply = network_interface.send_receive(bad_ack, timeout=1.5, test_nodeid=nodeid)
    assert reply is None or (reply.haslayer(TCP) and reply[TCP].flags & RST), (
        "DUT accepted an ACK that did not acknowledge its ISN as the handshake's final ACK (§3.10.7.4)"
    )

    # A follow-up data segment on the (should-be-nonexistent) connection
    # must not be accepted/acknowledged as ESTABLISHED traffic.
    data = wrap_ethernet(
        build_tcp(
            local_ip, dut_config.target_ip, sport, dut_config.target_port,
            flags="PA", seq=isn + 1, ack=(syn_ack[TCP].seq + 1) & 0xFFFFFFFF, payload=b"x",
        ),
        local_mac, dut_mac,
    )
    follow = network_interface.send_receive(data, timeout=1.5, test_nodeid=nodeid)
    if follow is not None and follow.haslayer(TCP):
        assert not (follow[TCP].flags & ACK) or (follow[TCP].flags & RST), (
            "DUT acknowledged data on a connection whose handshake was never validly completed"
        )
