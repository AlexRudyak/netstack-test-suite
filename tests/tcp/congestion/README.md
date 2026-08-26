# tests/tcp/congestion — TCP congestion/flow control

## Files

| File | RFC clause(s) | What it tests |
|---|---|---|
| `test_window_scaling.py` | RFC 9293 §3.7.1 | Advertised window vs. the target-stack profile's reference range (informational) |
| `test_retransmission_timeout.py` | RFC 6298 | Unacknowledged SYN-ACK is retransmitted (`slow`) |
| `test_slow_start.py` | RFC 5681 | **Skipped placeholder** — see the module docstring for why genuine cwnd-growth measurement needs a DUT-side data stream this generic harness can't trigger |

## Test functions

| Test | Asserts |
|---|---|
| `test_syn_ack_window_matches_target_stack_profile` | The advertised window falls in the selected profile's reference range (informational — a mismatch flags a stack-characteristic difference, not an RFC violation). |
| `test_unacked_syn_ack_is_retransmitted` *(slow)* | With the final ACK withheld, the DUT retransmits its SYN-ACK (RFC 6298). |
| `test_congestion_window_grows_across_initial_round_trips` | **Skipped** — needs a DUT-side data stream; placeholder for a real cwnd-growth measurement. |
| `test_zero_window_advertisement_does_not_break_connection` | Advertising a zero receive window is a legal flow-control state — the DUT must not RST (RFC 9293 §3.8.6). |
| `test_window_reopen_after_zero_is_accepted` | A window update reopening a zero window keeps the connection alive (RFC 9293 §3.8.6.2). |
| `test_zero_window_persist_probe_from_dut` *(server, slow)* | SERVER role: the suite advertises a zero window; the DUT must send a persist probe rather than flood/stall (RFC 1122 §4.2.2.17). |

Window/retransmission checks use `target_profile` (see
[src/target_profiles/](../../../src/target_profiles/)) since these values
are implementation-defined, not RFC-mandated — a mismatch is flagged as
"doesn't match the claimed target stack," not an RFC violation.

## Running

```bash
netstack-cli run --module tcp --submodule congestion --iface eth0 --dut-ip 10.0.0.5 --target-stack linux
```
