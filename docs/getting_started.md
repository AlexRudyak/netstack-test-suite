# Getting started

## Install

```bash
pip install -e .            # CLI only
pip install -e ".[gui]"     # + GUI (PySide6, pyqtgraph)
pip install -e ".[gui,dev]" # + test-only deps (pytest-qt, pytest-cov)
```

## Raw Ethernet access — platform-specific setup

Raw packet send/receive needs elevated privileges. The mechanism differs
by host OS — see [`docs/architecture.md`](architecture.md) for why the
suite standardizes on L2-only sockets across both.

### Windows

1. Install [Npcap](https://npcap.com/). During setup, **leave "Restrict
   Npcap driver's access to Administrators only" unchecked** unless you
   specifically want to require Administrator for every run.
2. **The GUI self-elevates.** On launch, `netstack-gui` relaunches itself
   as Administrator via a UAC prompt (the standard pattern for
   packet-capture tools) — just accept the prompt; no admin shell needed.
   If you decline, it keeps running non-elevated and the preflight check
   explains the requirement when you try to run tests.
3. The **CLI** does not auto-elevate (that would spawn a detached admin
   console and lose its output) — run `netstack-cli` from an Administrator
   terminal.

### Linux

No extra driver is needed (native `AF_PACKET` sockets). Either:

- run as root, **or**
- (recommended — especially for the GUI, since running Qt apps as root
  causes its own problems with Wayland/X11 session permissions) grant
  capabilities once to the interpreter:

  ```bash
  sudo setcap cap_net_raw,cap_net_admin+eip "$(readlink -f "$(which python3)")"
  ```

`src/utils/permissions.py` checks for sufficient privileges before
opening any socket and prints the relevant remediation message above if
missing — it never attempts silent self-elevation.

## Preflight check

Both `netstack-cli run` and the GUI Run button first run a **preflight
connectivity check**: they validate the required configuration, verify
raw-socket privileges, and send an ARP request to the DUT, then report
the result. A hard blocker (blank target, missing privileges, an
interface that can't send) aborts before any test runs — so a
misconfiguration produces a clear message instead of a run that silently
does nothing. A *no ARP reply* is only a warning and the run proceeds,
since a custom stack under test may not implement ARP. Bypass it with
`--skip-preflight` (CLI).

## Running the suite

```bash
# Whole suite
netstack-cli run --iface eth0 --dut-ip 10.0.0.5 --target-stack linux

# One module / submodule / test
netstack-cli run --module tcp --submodule syn --iface eth0 --dut-ip 10.0.0.5 --target-stack linux
netstack-cli run --test test_syn_elicits_syn_ack --iface eth0 --dut-ip 10.0.0.5 --target-stack linux

# Server role — the DUT initiates, the suite responds (validates the DUT's client side)
netstack-cli run --role server --iface eth0 --dut-ip 10.0.0.5 --target-stack linux

# Including vuln-marked tests (SYN flood, Ping of Death, Teardrop, ...)
netstack-cli run --iface eth0 --dut-ip 10.0.0.5 --target-stack linux \
  --allowed-target 10.0.0.5/32 --confirm-vuln-tests

# GUI
netstack-gui
```

## Debug logging

Pass `--debug` to `run` to write a **tshark-style per-packet debug log**
to `reports/<run_id>/debug.log`. It records one line per packet each test
sends/receives — frame number, absolute + relative timestamps, direction
(TX/RX), the L3/L4 summary (ports, TCP flags, Seq/Ack/Win, payload Len),
the owning test, and the Python function that initiated the packet — with
test setup/call/teardown boundaries bracketing the packet lines.

```bash
netstack-cli run --iface eth0 --dut-ip 10.0.0.5 --target-stack linux --debug
```

Sample lines:

```
#000001 2026-08-25T13:00:00.123456+00:00 +0.000000s TX TCP 10.0.0.1:41100 -> 10.0.0.5:80 [SYN] Seq=1000 Ack=0 Win=8192 Len=0 {test=tests/tcp/syn/test_three_way_handshake.py::test_syn_elicits_syn_ack called_by=test_syn_elicits_syn_ack@test_three_way_handshake.py:34}
#000002 2026-08-25T13:00:00.123700+00:00 +0.000244s RX TCP 10.0.0.5:80 -> 10.0.0.1:41100 [SYN, ACK] Seq=555 Ack=1001 Win=64240 Len=0 {test=... called_by=...}
```

In the GUI, tick **Debug mode** in the DUT configuration group before
running. The log is a human-readable trace to sit alongside the machine-
readable `capture.pcap` — for full frame bytes, open the pcap in
Wireshark/tshark.

## Recording traffic to a .pcap

`netstack-cli record` is a passive on-wire recorder: it sniffs the
interface and writes every packet the app sends **and the associated
transmission back** to a `.pcap` file, independent of any test run. Use
it while exercising the DUT via `send`, the GUI, or a manual poke. It
writes incrementally, so the file stays valid even if you Ctrl+C it.

```bash
# Record the conversation with one host until Ctrl+C
netstack-cli record --iface eth0 --out capture.pcap --dut-ip 10.0.0.5

# Bounded by time or packet count
netstack-cli record --iface eth0 --out capture.pcap --duration 30
netstack-cli record --iface eth0 --out capture.pcap --count 500

# Explicit BPF filter (overrides the --dut-ip-derived one)
netstack-cli record --iface eth0 --out capture.pcap --filter "tcp port 80"
```

This is distinct from the per-run `reports/<run_id>/capture.pcap` the
automated suite writes: that one records the packets the suite
*programmatically* built; `record` captures what actually crossed the
wire (including OS retransmits and asymmetric reply paths the
programmatic capture can't see).

`--target-stack` selects the behavioral baseline (see
[`src/target_profiles/`](../src/target_profiles/)) tests compare
implementation-defined values against — it describes the **DUT**, not
the machine you're running this suite from.

## Validating the framework itself first

Before pointing any of this at a real DUT:

```bash
pytest tests_internal/
```

No DUT, interface, or elevated privileges required — see
[`tests_internal/README.md`](../tests_internal/README.md).
