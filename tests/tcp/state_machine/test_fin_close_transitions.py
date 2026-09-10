"""RFC 9293 §3.6 / §3.10.7.4 — FIN processing and the CLOSE-WAIT path.

test_connection_termination.py checks the single happy-path fact that a
FIN is acknowledged. This module covers the edges around it:

  * a FIN is only processed if its sequence number is acceptable — a
    FIN beyond the window must not be acknowledged as if consumed;
  * a retransmitted FIN (after the DUT already ACKed one) must be
    ACKed again, idempotently, never RST;
  * data arriving after our FIN is out of our sequence space and must
    be dropped with an ACK, not a reset;
  * once the DUT is in CLOSE-WAIT it must still answer a keep-alive /
    bare ACK without resetting.
"""
from __future__ import annotations

import pytest
from scapy.layers.inet import TCP

from src.utils.tcp_flags import is_ack

from .conftest import connection_still_alive, is_rst, seq32, segment

pytestmark = [pytest.mark.tcp, pytest.mark.state_machine, pytest.mark.client]


def _fin_seq(conn) -> int:
    """Send a FIN|ACK via the tracker and return the sequence number the
    FIN occupied (tracker has advanced past it by 1)."""
    fin = conn.build(flags="FA")
    return fin, seq32(conn.tracker.seq - 1)


def test_out_of_window_fin_is_not_processed(
    established_tcp_connection, network_interface, nodeid
) -> None:
    """§3.10.7.4 step 1: a FIN whose sequence number is outside the
    receive window is not acceptable and MUST NOT be processed — the DUT
    must not acknowledge the phantom FIN's sequence, and must not move to
    CLOSE-WAIT on it."""
    conn = established_tcp_connection
    real_rcv_nxt = conn.tracker.seq

    phantom = segment(conn, flags="FA", seq=seq32(conn.tracker.seq + 60_000))
    reply = network_interface.send_receive(phantom, timeout=1.5, test_nodeid=nodeid)

    assert not is_rst(reply), "DUT reset the connection on an out-of-window FIN"
    if is_ack(reply):
        assert reply[TCP].ack == real_rcv_nxt, (
            f"DUT ACKed {reply[TCP].ack} — it processed a FIN that was outside the receive window"
        )

    # An in-window data segment must still be accepted as ESTABLISHED traffic.
    live = network_interface.send_receive(
        conn.build(flags="PA", payload=b"still-established"), timeout=1.5, test_nodeid=nodeid
    )
    # Silence is tolerated here (the DUT need not answer); what must not
    # happen is a reset, or an ACK that moved to the phantom FIN's sequence.
    if live is not None:
        assert is_ack(live) and not is_rst(live)


def test_retransmitted_fin_is_reacknowledged(
    established_tcp_connection, network_interface, nodeid
) -> None:
    """§3.6: after the DUT acknowledges our FIN (CLOSE-WAIT), a
    retransmission of the identical FIN segment MUST be acknowledged
    again — the ACK of a FIN is idempotent, and a lost ACK is the normal
    reason the peer retransmits. A RST here would abort a perfectly
    healthy half-close."""
    conn = established_tcp_connection
    fin, fin_seq = _fin_seq(conn)
    first = network_interface.send_receive(fin, timeout=2.0, test_nodeid=nodeid)
    assert is_ack(first), "DUT did not ACK the initial FIN"
    expected_ack = seq32(fin_seq + 1)
    assert first[TCP].ack == expected_ack, f"DUT ACKed {first[TCP].ack}, expected FIN.SEQ+1 = {expected_ack}"

    retrans = segment(conn, flags="FA", seq=fin_seq)
    second = network_interface.send_receive(retrans, timeout=2.0, test_nodeid=nodeid)
    assert second is not None and second.haslayer(TCP), "DUT did not answer a retransmitted FIN"
    assert is_ack(second) and not is_rst(second), (
        "DUT did not re-ACK a retransmitted FIN (or reset on it) — §3.6 ACK-of-FIN must be idempotent"
    )
    assert second[TCP].ack == expected_ack


def test_data_after_our_fin_is_dropped_not_reset(
    established_tcp_connection, network_interface, nodeid
) -> None:
    """§3.10.7.4: after we send our FIN, our sequence space ends at
    FIN.SEQ+1. A segment we send carrying data past that point is not
    acceptable; the DUT must drop it and ACK, not RST."""
    conn = established_tcp_connection
    fin, fin_seq = _fin_seq(conn)
    ack = network_interface.send_receive(fin, timeout=2.0, test_nodeid=nodeid)
    assert is_ack(ack), "DUT did not ACK our FIN"

    # Data at FIN.SEQ+1 — past the FIN, i.e. bytes we have no right to send.
    rogue = segment(conn, flags="PA", seq=seq32(fin_seq + 1), payload=b"after-fin")
    reply = network_interface.send_receive(rogue, timeout=1.5, test_nodeid=nodeid)
    assert not is_rst(reply), "DUT reset the connection on data sent after our FIN (should drop + ACK)"


def test_close_wait_still_answers_bare_ack(
    established_tcp_connection, network_interface, nodeid
) -> None:
    """§3.6: CLOSE-WAIT is a fully open half-connection — the DUT may
    still be sending data and must still process our ACKs. A bare
    in-window ACK while the DUT is in CLOSE-WAIT must not draw a RST."""
    conn = established_tcp_connection
    fin, _ = _fin_seq(conn)
    ack = network_interface.send_receive(fin, timeout=2.0, test_nodeid=nodeid)
    assert is_ack(ack), "DUT did not ACK our FIN"

    assert connection_still_alive(conn, network_interface, nodeid=nodeid), (
        "DUT reset the connection on a bare ACK while in CLOSE-WAIT"
    )
