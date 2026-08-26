# tests/tcp — TCP (RFC 9293) conformance

Split into three submodules by mechanic:

- [`syn/`](syn/README.md) — connection establishment: standard handshake, SYN flood, ISN predictability, invalid flag combinations.
- [`state_machine/`](state_machine/README.md) — connection termination and reset handling.
- [`congestion/`](congestion/README.md) — window/flow control behavior.

`conftest.py` provides `established_tcp_connection`, a fixture that
performs the standard three-way handshake and hands back a `TCPConnection`
tracker — used by `state_machine/` and `congestion/` tests that need an
ESTABLISHED connection as their starting point, so they don't each
re-implement the handshake (that correctness is `syn/`'s responsibility).

## Running

```bash
netstack-cli run --module tcp --iface eth0 --dut-ip 10.0.0.5 --target-stack linux
netstack-cli run --module tcp --submodule syn --iface eth0 --dut-ip 10.0.0.5 --target-stack linux
```
