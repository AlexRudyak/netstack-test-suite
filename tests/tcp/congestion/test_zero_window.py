"""TCP zero-window flow control (RFC 9293 §3.8.6, RFC 1122 §4.2.2.17).

A receiver advertising a zero window tells the sender to stop sending
data until the window reopens. A conformant sender must honour it (not
flood, not RST) and use the persist timer to probe.
"""
from __future__ import annotations

import pytest
from scapy.layers.inet import IP, TCP

from src.packet_engine.responder import build_syn_ack_reply
from src.packet_engine.sequence import TCPSequenceTracker
from src.utils.tcp_flags import RST, SYN, any_flags, is_bare_syn, is_rst, is_syn_ack

pytestmark = [pytest.mark.tcp, pytest.mark.congestion]


def _handshake(network_interface, dut_config, craft, sport, nodeid):
    tracker = TCPSequenceTracker.new()

    syn_seq = tracker.on_send(0, syn=True)  # advance past our SYN: next seq is ISN+1
    syn = craft.tcp(sport, flags="S", seq=syn_seq)
    syn_ack = network_interface.send_receive(syn, timeout=dut_config.timeout, test_nodeid=nodeid)
    assert is_syn_ack(syn_ack), "handshake did not reach SYN-ACK"
    tracker.on_receive(syn_ack[TCP].seq, 0, syn=True)

    # Complete the three-way handshake with the final ACK, or the DUT stays
    # in SYN-RECEIVED and every later segment is a bad-seq challenge / RST.
    ack = craft.tcp(sport, flags="A", seq=tracker.seq, ack=tracker.ack)
    network_interface.send(ack, test_nodeid=nodeid)
    return tracker


def _rst_to(local_ip: str, sport: int):
    """lfilter for a RST the DUT aimed back at this connection."""
    return lambda p: is_rst(p) and p[IP].dst == local_ip and p[TCP].dport == sport


@pytest.mark.client
def test_zero_window_advertisement_does_not_break_connection(
    network_interface, dut_config, craft, local_ip, source_port, nodeid
) -> None:
    """RFC 9293 §3.8.6: advertising a zero receive window is a legal
    flow-control state. Complete the handshake, ACK with window=0, and
    verify the DUT does not tear the connection down (no RST) — it must
    simply stop sending, not abort."""
    tracker = _handshake(network_interface, dut_config, craft, source_port, nodeid)

    zero_win = craft.tcp(source_port, flags="A", seq=tracker.seq, ack=tracker.ack, window=0)
    network_interface.send(zero_win, test_nodeid=nodeid)

    stray_rst = network_interface.sniff(
        count=1, timeout=1.5, lfilter=_rst_to(local_ip, source_port), test_nodeid=nodeid
    )
    assert not stray_rst, "DUT sent RST after we advertised a zero window (should just stop sending)"


@pytest.mark.client
def test_window_reopen_after_zero_is_accepted(
    network_interface, dut_config, craft, local_ip, source_port, nodeid
) -> None:
    """After a zero window, a window update reopening it must be accepted
    and keep the connection alive (RFC 9293 §3.8.6.2 window management —
    no RST to the update)."""
    tracker = _handshake(network_interface, dut_config, craft, source_port, nodeid)

    for win in (0, 8192):
        update = craft.tcp(source_port, flags="A", seq=tracker.seq, ack=tracker.ack, window=win)
        network_interface.send(update, test_nodeid=nodeid)

    stray_rst = network_interface.sniff(
        count=1, timeout=1.5, lfilter=_rst_to(local_ip, source_port), test_nodeid=nodeid
    )
    assert not stray_rst, "DUT sent RST after a window update reopening the window"


@pytest.mark.server
@pytest.mark.slow
def test_zero_window_persist_probe_from_dut(
    network_interface, dut_config, local_mac, local_ip, nodeid
) -> None:
    """SERVER role, RFC 1122 §4.2.2.17: the suite accepts the DUT's
    connection but advertises a zero window in its SYN-ACK. A DUT with data
    to send must not give up — it must send a zero-window (persist) probe
    rather than flooding or silently stalling.

    Precondition: the DUT must have data queued to send on this connection;
    otherwise there is nothing to probe for and the test times out."""
    listen_port = dut_config.target_port
    syns = network_interface.sniff(
        count=1,
        timeout=dut_config.timeout * 3,
        lfilter=lambda p: (
            is_bare_syn(p) and p[IP].dst == local_ip and p[TCP].dport == listen_port
        ),
        test_nodeid=nodeid,
    )
    assert syns, "No SYN from the DUT — it did not initiate a connection to probe."

    network_interface.send(build_syn_ack_reply(syns[0], local_mac, window=0), test_nodeid=nodeid)

    probes = network_interface.sniff(
        count=1,
        timeout=dut_config.timeout * 4,
        lfilter=lambda p: (
            p.haslayer(TCP)
            and p[IP].dst == local_ip
            and p[TCP].dport == listen_port
            and not any_flags(p, SYN | RST)
        ),
        test_nodeid=nodeid,
    )
    assert probes, (
        "DUT sent no persist probe against our zero window. Either it had no data to send, or it "
        "does not implement the persist timer (RFC 1122 §4.2.2.17)."
    )
