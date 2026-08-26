"""RST robustness edge cases (RFC 9293 §3.10.7.1, RFC 5961).

Blindly honouring any RST enables off-path reset attacks, so RFC 5961
tightens acceptance: a RST whose sequence number is outside the receive
window MUST NOT tear the connection down.
"""
from __future__ import annotations

import pytest
from scapy.layers.inet import IP, TCP

pytestmark = [pytest.mark.tcp, pytest.mark.state_machine, pytest.mark.client]

ACK = 0x10
RST = 0x04


def test_out_of_window_rst_is_ignored(
    established_tcp_connection, network_interface, dut_config
) -> None:
    """RFC 5961 §3: a RST arriving with a sequence number well outside the
    current receive window must be ignored (at most a challenge ACK), not
    accepted. Sends such an out-of-window RST on an ESTABLISHED connection
    and verifies the connection is still alive — a follow-up ACK is not
    answered with RST.

    (The in-window, valid-RST case is covered by
    test_rst_handling.py::test_established_connection_accepts_valid_rst.)"""
    conn = established_tcp_connection

    # A RST whose seq is far outside anything the DUT expects on this
    # connection. build() advances the tracker; we override seq to a bogus,
    # clearly out-of-window value.
    bogus_rst = conn.build(flags="R")
    bogus_rst[TCP].seq = (conn.tracker.seq + 1_000_000) & 0xFFFFFFFF
    network_interface.send(bogus_rst, test_nodeid="test_out_of_window_rst_is_ignored")

    reply = network_interface.send_receive(
        conn.build(flags="A"), timeout=1.5, test_nodeid="test_out_of_window_rst_is_ignored"
    )
    if reply is not None and reply.haslayer(TCP):
        assert not (reply[TCP].flags & RST), (
            "DUT tore the connection down on an out-of-window RST — vulnerable to off-path reset "
            "(RFC 5961 §3 requires ignoring it)"
        )
