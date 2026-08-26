# tests/tcp/state_machine — TCP state transitions

## Files

| File | RFC clause(s) | What it tests |
|---|---|---|
| `test_connection_termination.py` | RFC 9293 §3.6 | FIN on an ESTABLISHED connection is ACKed |
| `test_rst_handling.py` | RFC 9293 §3.5.2, §3.10.7.1 | Closed-port segments elicit RST; valid RST aborts an ESTABLISHED connection |
| `test_simultaneous_open_close.py` | RFC 9293 §3.5.3 | Representative case: FIN sent before observing the peer's FIN is still ACKed |

## Test functions

| Test | Asserts |
|---|---|
| `test_fin_is_acknowledged` | A FIN on an ESTABLISHED connection is ACKed (toward CLOSE-WAIT). |
| `test_ack_to_closed_port_elicits_rst` | A segment to a closed port is answered with RST. |
| `test_established_connection_accepts_valid_rst` | An in-window RST aborts the connection (follow-up traffic no longer ACKed). |
| `test_fin_before_peer_fin_is_still_acknowledged` | A FIN sent before observing the peer's FIN is still ACKed. |
| `test_out_of_window_rst_is_ignored` | An RST with an out-of-window sequence number must NOT abort the connection (RFC 5961 §3 — off-path reset resistance). |

`test_simultaneous_open_close.py` is intentionally a single representative
case, not full state-diagram coverage — see the module docstring for what
a fuller implementation (true simultaneous OPEN, CLOSING-state ACK
sequencing) would add.

All tests here build on `tests/tcp/conftest.py`'s `established_tcp_connection`
fixture rather than re-driving the handshake — see [`../syn/`](../syn/README.md)
for handshake correctness itself.

## Running

```bash
netstack-cli run --module tcp --submodule state_machine --iface eth0 --dut-ip 10.0.0.5 --target-stack linux
```
