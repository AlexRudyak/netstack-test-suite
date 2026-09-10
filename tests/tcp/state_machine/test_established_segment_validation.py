"""RFC 9293 §3.10.7.4 — segment arrival processing on an ESTABLISHED
connection, plus the RFC 5961 blind-attack mitigations.

The first-check / second-check ordering in §3.10.7.4 is where a lot of
stacks get the state machine subtly wrong:

  1. sequence-number check  — is the segment in the receive window?
  2. RST check              — RFC 5961 §3 tightening
  3. SYN check              — RFC 5961 §4 challenge ACK
  4. ACK check              — RFC 5961 §5, and "ACK bit off ⇒ drop"

Every test here starts from a real three-way handshake (the
`established_tcp_connection` fixture) and pokes exactly one of those
checks with a single crafted segment, asserting the DUT neither tears
the connection down nor mis-accepts obviously invalid data.
"""
from __future__ import annotations

import pytest
from scapy.layers.inet import TCP

from src.utils.tcp_flags import is_ack

from .conftest import connection_still_alive, is_rst, seq32, segment

pytestmark = [pytest.mark.tcp, pytest.mark.state_machine, pytest.mark.client]


def test_in_window_data_is_cumulatively_acknowledged(
    established_tcp_connection, network_interface, nodeid
) -> None:
    """§3.10.7.4 step 1 + §3.8: valid in-window data MUST be acknowledged
    with ACK = SEG.SEQ + SEG.LEN (the byte after the data just received)."""
    conn = established_tcp_connection
    payload = b"netstack-conformance-probe"

    reply = network_interface.send_receive(
        conn.build(flags="PA", payload=payload), timeout=2.0, test_nodeid=nodeid
    )

    assert reply is not None and reply.haslayer(TCP), "DUT did not acknowledge in-window data"
    assert is_ack(reply)
    assert reply[TCP].ack == conn.tracker.seq, (
        f"DUT ACKed {reply[TCP].ack}, expected {conn.tracker.seq} "
        f"(SEG.SEQ + {len(payload)} bytes of payload) — cumulative ACK is wrong"
    )


def test_old_duplicate_data_is_acked_not_reset(
    established_tcp_connection, network_interface, nodeid
) -> None:
    """§3.10.7.4 step 1: a segment wholly to the left of RCV.NXT (data the
    DUT has already received) MUST be dropped and an ACK sent — never a
    RST. This is the normal case for a retransmission crossing an ACK."""
    conn = established_tcp_connection
    # First deliver some data so RCV.NXT has advanced.
    network_interface.send_receive(conn.build(flags="PA", payload=b"first"), timeout=2.0, test_nodeid=nodeid)

    stale = segment(conn, flags="PA", seq=seq32(conn.tracker.seq - 500), payload=b"stale")
    reply = network_interface.send_receive(stale, timeout=1.5, test_nodeid=nodeid)

    assert not is_rst(reply), "DUT sent RST for an old duplicate segment (§3.10.7.4 requires an ACK)"
    assert connection_still_alive(conn, network_interface, nodeid=nodeid)


def test_future_out_of_window_data_does_not_break_connection(
    established_tcp_connection, network_interface, nodeid
) -> None:
    """§3.10.7.4 step 1: a segment beyond the right window edge is not
    acceptable; the DUT MUST drop it and send an ACK (RCV.NXT), and MUST
    NOT deliver the data or reset. Verifies the connection survives and
    the DUT still reports its real RCV.NXT, not the bogus sequence."""
    conn = established_tcp_connection
    expected_ack = conn.tracker.seq

    future = segment(conn, flags="PA", seq=seq32(conn.tracker.seq + 2_000_000), payload=b"way-ahead")
    reply = network_interface.send_receive(future, timeout=1.5, test_nodeid=nodeid)

    assert not is_rst(reply), "DUT reset the connection for out-of-window data (must just ACK)"
    if is_ack(reply):
        assert reply[TCP].ack == expected_ack, (
            "DUT's ACK jumped to the out-of-window sequence — it accepted data it should have dropped"
        )
    assert connection_still_alive(conn, network_interface, nodeid=nodeid)


def test_segment_with_ack_bit_off_is_silently_dropped(
    established_tcp_connection, network_interface, nodeid
) -> None:
    """§3.10.7.4 step 4: "if the ACK bit is off, drop the segment and
    return." A data segment carrying no ACK flag on an ESTABLISHED
    connection must not elicit a RST and must not tear the connection
    down."""
    conn = established_tcp_connection
    reply = network_interface.send_receive(
        segment(conn, flags="P", payload=b"no-ack-flag"), timeout=1.5, test_nodeid=nodeid
    )
    assert not is_rst(reply), "DUT sent RST for a segment with the ACK bit clear (§3.10.7.4: just drop it)"
    assert connection_still_alive(conn, network_interface, nodeid=nodeid)


def test_ack_for_unsent_data_does_not_reset(
    established_tcp_connection, network_interface, nodeid
) -> None:
    """RFC 5961 §5: an ACK acknowledging data the DUT has never sent
    (SEG.ACK > SND.NXT) MUST be met with a plain ACK and the segment
    dropped — a blind data-injection attacker must not be able to reset
    the connection this way."""
    conn = established_tcp_connection
    bad_ack = segment(conn, flags="A", ack=seq32(conn.tracker.ack + 1_000_000))
    reply = network_interface.send_receive(bad_ack, timeout=1.5, test_nodeid=nodeid)

    assert not is_rst(reply), (
        "DUT reset the connection on an ACK for unsent data — RFC 5961 §5 requires an ACK, not a RST"
    )
    assert connection_still_alive(conn, network_interface, nodeid=nodeid)


def test_keepalive_probe_is_answered_with_current_ack(
    established_tcp_connection, network_interface, nodeid
) -> None:
    """RFC 1122 §4.2.3.6: a keep-alive probe is a segment with SEG.SEQ =
    SND.NXT - 1 and no data. A conformant peer answers it with an ACK for
    RCV.NXT without treating the (already-ACKed) byte as new data."""
    conn = established_tcp_connection
    expected_ack = conn.tracker.seq

    probe = segment(conn, flags="A", seq=seq32(conn.tracker.seq - 1))
    reply = network_interface.send_receive(probe, timeout=1.5, test_nodeid=nodeid)

    assert reply is not None and reply.haslayer(TCP), "DUT did not answer a keep-alive probe"
    assert is_ack(reply) and not is_rst(reply)
    assert reply[TCP].ack == expected_ack, (
        f"DUT ACKed {reply[TCP].ack} for a keep-alive probe, expected RCV.NXT {expected_ack}"
    )
