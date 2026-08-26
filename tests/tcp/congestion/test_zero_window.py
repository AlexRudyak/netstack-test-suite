"""TCP zero-window flow control (RFC 9293 §3.8.6, RFC 1122 §4.2.2.17).

A receiver advertising a zero window tells the sender to stop sending
data until the window reopens. A conformant sender must honour it (not
flood, not RST) and use the persist timer to probe.
"""
from __future__ import annotations

import pytest
from scapy.layers.inet import IP, TCP

from src.packet_engine.builders import build_tcp, wrap_ethernet
from src.packet_engine.responder import build_syn_ack_reply
from src.packet_engine.sequence import TCPSequenceTracker

pytestmark = [pytest.mark.tcp, pytest.mark.congestion]

SYN = 0x02
ACK = 0x10
RST = 0x04


def _handshake(network_interface, dut_config, local_mac, dut_mac, local_ip, sport):
    tracker = TCPSequenceTracker.new()
    syn = wrap_ethernet(
        build_tcp(local_ip, dut_config.target_ip, sport, dut_config.target_port, flags="S", seq=tracker.seq),
        local_mac,
        dut_mac,
    )
    syn_ack = network_interface.send_receive(syn, timeout=dut_config.timeout, test_nodeid="zero_window")
    assert syn_ack is not None and syn_ack.haslayer(TCP)
    assert syn_ack[TCP].flags & (SYN | ACK) == (SYN | ACK), "handshake did not reach SYN-ACK"
    tracker.on_receive(syn_ack[TCP].seq, 0, syn=True)
    return tracker


@pytest.mark.client
def test_zero_window_advertisement_does_not_break_connection(
    network_interface, dut_config, local_mac, dut_mac, local_ip
) -> None:
    """RFC 9293 §3.8.6: advertising a zero receive window is a legal
    flow-control state. Complete the handshake, ACK with window=0, and
    verify the DUT does not tear the connection down (no RST) — it must
    simply stop sending, not abort."""
    sport = 48000
    tracker = _handshake(network_interface, dut_config, local_mac, dut_mac, local_ip, sport)

    zero_win = wrap_ethernet(
        build_tcp(
            local_ip, dut_config.target_ip, sport, dut_config.target_port,
            flags="A", seq=tracker.seq, ack=tracker.ack, window=0,
        ),
        local_mac,
        dut_mac,
    )
    network_interface.send(zero_win, test_nodeid="zero_window")

    stray_rst = network_interface.sniff(
        count=1,
        timeout=1.5,
        lfilter=lambda p: (
            p.haslayer(TCP) and p[IP].dst == local_ip and p[TCP].dport == sport and bool(p[TCP].flags & RST)
        ),
        test_nodeid="zero_window",
    )
    assert not stray_rst, "DUT sent RST after we advertised a zero window (should just stop sending)"


@pytest.mark.client
def test_window_reopen_after_zero_is_accepted(
    network_interface, dut_config, local_mac, dut_mac, local_ip
) -> None:
    """After a zero window, a window update reopening it must be accepted
    and keep the connection alive (RFC 9293 §3.8.6.2 window management —
    no RST to the update)."""
    sport = 48001
    tracker = _handshake(network_interface, dut_config, local_mac, dut_mac, local_ip, sport)

    for win in (0, 8192):
        update = wrap_ethernet(
            build_tcp(
                local_ip, dut_config.target_ip, sport, dut_config.target_port,
                flags="A", seq=tracker.seq, ack=tracker.ack, window=win,
            ),
            local_mac,
            dut_mac,
        )
        network_interface.send(update, test_nodeid="zero_window")

    stray_rst = network_interface.sniff(
        count=1,
        timeout=1.5,
        lfilter=lambda p: (
            p.haslayer(TCP) and p[IP].dst == local_ip and p[TCP].dport == sport and bool(p[TCP].flags & RST)
        ),
        test_nodeid="zero_window",
    )
    assert not stray_rst, "DUT sent RST after a window update reopening the window"


@pytest.mark.server
@pytest.mark.slow
def test_zero_window_persist_probe_from_dut(
    network_interface, dut_config, local_mac, local_ip
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
            p.haslayer(TCP) and p[IP].dst == local_ip and p[TCP].dport == listen_port
            and p[TCP].flags & SYN and not (p[TCP].flags & ACK)
        ),
        test_nodeid="zero_window_persist",
    )
    assert syns, "No SYN from the DUT — it did not initiate a connection to probe."

    network_interface.send(
        build_syn_ack_reply(syns[0], local_mac, window=0), test_nodeid="zero_window_persist"
    )

    probes = network_interface.sniff(
        count=1,
        timeout=dut_config.timeout * 4,
        lfilter=lambda p: (
            p.haslayer(TCP) and p[IP].dst == local_ip and p[TCP].dport == listen_port
            and not (p[TCP].flags & (SYN | RST))
        ),
        test_nodeid="zero_window_persist",
    )
    assert probes, (
        "DUT sent no persist probe against our zero window. Either it had no data to send, or it "
        "does not implement the persist timer (RFC 1122 §4.2.2.17)."
    )
