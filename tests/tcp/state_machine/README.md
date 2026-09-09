# tests/tcp/state_machine — TCP state transitions

## Files

| File | RFC clause(s) | What it tests |
|---|---|---|
| `test_connection_termination.py` | RFC 9293 §3.6 | FIN on an ESTABLISHED connection is ACKed |
| `test_rst_handling.py` | RFC 9293 §3.5.2, §3.10.7.1 | Closed-port segments elicit RST; valid RST aborts an ESTABLISHED connection |
| `test_rst_edge_cases.py` | RFC 5961 §3 | An out-of-window RST is ignored (off-path reset resistance) |
| `test_challenge_ack.py` | RFC 5961 §3, §4; RFC 9293 §3.10.7.3 | In-window (non-exact) RST and in-window SYN only draw a challenge ACK; LISTEN-state arrivals (bare ACK → RST, data dropped) |
| `test_established_segment_validation.py` | RFC 9293 §3.10.7.4; RFC 5961 §5; RFC 1122 §4.2.3.6 | Sequence/ACK arrival checks on ESTABLISHED: cumulative ACK, old/future segments, ACK-bit-off drop, ACK for unsent data, keep-alive probe |
| `test_syn_received_state.py` | RFC 9293 §3.10.7.4 | SYN-RECEIVED edges: duplicate SYN retransmits the same SYN-ACK, RST aborts the half-open TCB, a wrong final-ACK ack number does not establish |
| `test_fin_close_transitions.py` | RFC 9293 §3.6, §3.10.7.4 | FIN edges: out-of-window FIN not processed, retransmitted FIN re-ACKed, data after our FIN dropped, CLOSE-WAIT still answers a bare ACK |
| `test_simultaneous_open_close.py` | RFC 9293 §3.5.3 | Representative case: FIN sent before observing the peer's FIN is still ACKed |

## Test functions

| Test | Asserts |
|---|---|
| `test_fin_is_acknowledged` | A FIN on an ESTABLISHED connection is ACKed (toward CLOSE-WAIT). |
| `test_ack_to_closed_port_elicits_rst` | A segment to a closed port is answered with RST. |
| `test_established_connection_accepts_valid_rst` | An in-window RST aborts the connection (follow-up traffic no longer ACKed). |
| `test_fin_before_peer_fin_is_still_acknowledged` | A FIN sent before observing the peer's FIN is still ACKed. |
| `test_out_of_window_rst_is_ignored` | An RST with an out-of-window sequence number must NOT abort the connection (RFC 5961 §3 — off-path reset resistance). |
| `test_in_window_non_exact_rst_draws_challenge_ack_only` | An in-window RST that is not exactly at RCV.NXT draws a challenge ACK, not a teardown (RFC 5961 §3). |
| `test_in_window_syn_draws_challenge_ack_not_reset` | A SYN on an ESTABLISHED connection must not silently reset it (RFC 5961 §4). |
| `test_exact_rcv_nxt_syn_is_still_not_a_reset_trigger` | Even a SYN at exactly RCV.NXT only challenges — no teardown without a challenge-ACK confirmation. |
| `test_ack_arriving_on_listen_port_elicits_rst` | A bare ACK to a listening port is answered with `<SEQ=SEG.ACK><CTL=RST>` (RFC 9293 §3.10.7.3). |
| `test_data_segment_to_listen_port_is_not_accepted` | A non-SYN/non-ACK segment in LISTEN never produces a SYN-ACK. |
| `test_in_window_data_is_cumulatively_acknowledged` | Valid in-window data is ACKed with `SEG.SEQ + SEG.LEN`. |
| `test_old_duplicate_data_is_acked_not_reset` | A segment left of RCV.NXT is dropped with an ACK, never a RST. |
| `test_future_out_of_window_data_does_not_break_connection` | Data beyond the window edge is not delivered or reset; the ACK still reports the real RCV.NXT. |
| `test_segment_with_ack_bit_off_is_silently_dropped` | A data segment with the ACK bit clear is dropped silently (no RST). |
| `test_ack_for_unsent_data_does_not_reset` | An ACK for `SEG.ACK > SND.NXT` draws an ACK, not a RST (RFC 5961 §5). |
| `test_keepalive_probe_is_answered_with_current_ack` | A keep-alive probe (`SEG.SEQ = SND.NXT-1`) is answered with an ACK for RCV.NXT. |
| `test_duplicate_syn_in_syn_received_retransmits_same_syn_ack` | A duplicate SYN in SYN-RECEIVED resends the same SYN-ACK with the same ISN. |
| `test_rst_in_syn_received_aborts_half_open_connection` | A RST at RCV.NXT in SYN-RECEIVED deletes the TCB. |
| `test_wrong_seq_ack_does_not_complete_handshake` | A final ACK that does not acknowledge the DUT's ISN does not reach ESTABLISHED. |
| `test_out_of_window_fin_is_not_processed` | A FIN outside the receive window is not acknowledged as consumed and does not move the DUT to CLOSE-WAIT. |
| `test_retransmitted_fin_is_reacknowledged` | A retransmitted FIN is ACKed again (idempotent), never RST. |
| `test_data_after_our_fin_is_dropped_not_reset` | Data past `FIN.SEQ+1` is dropped with an ACK, not a RST. |
| `test_close_wait_still_answers_bare_ack` | In CLOSE-WAIT the DUT still answers a bare in-window ACK without resetting. |

`test_simultaneous_open_close.py` is intentionally a single representative
case, not full state-diagram coverage — see the module docstring for what
a fuller implementation (true simultaneous OPEN, CLOSING-state ACK
sequencing) would add.

Most tests here build on `tests/tcp/conftest.py`'s `established_tcp_connection`
fixture rather than re-driving the handshake — see [`../syn/`](../syn/README.md)
for handshake correctness itself. The exceptions drive the exchange by hand
because they target a state the fixture cannot sit in: the LISTEN-state
cases in `test_challenge_ack.py` (no connection at all) and every
`test_syn_received_state.py` case (the DUT must still be in SYN-RECEIVED).
`test_established_segment_validation.py`'s `conftest.py` adds a `segment()`
helper that builds a probe with a deliberately bogus seq/ack without
disturbing the fixture's sequence tracker.

## Running

```bash
netstack-cli run --module tcp --submodule state_machine --iface eth0 --dut-ip 10.0.0.5 --target-stack linux
```
