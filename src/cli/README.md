# src/cli — `netstack-cli`

The command-line front end. A thin wrapper: `run` drives
[`src/runner.py`](../README.md#runnerpy); `send` drives
[`custom_packet/`](../custom_packet/README.md); `record` drives
[`packet_engine/recorder.py`](../packet_engine/README.md#recorderpy).
Nothing here is logic the GUI can't reach through the same modules.

Entry point: `cli` (a Click group). Installed as `netstack-cli`
(`pyproject.toml [project.scripts]`). Run any command with `--help`.

## `run` — execute the automated suite

Runs the whole suite or a module/submodule/test slice, then generates a
report. Exits non-zero if any test failed.

| Option | Default | Notes |
|---|---|---|
| `--module {ip,udp,tcp}` | all | |
| `--submodule {syn,state_machine,congestion}` | all | |
| `--test TEXT` | — | pytest `-k` substring match |
| `--marker TEXT` (repeatable) | — | extra `-m` term(s) |
| `--iface TEXT` | **required** | local interface facing the DUT |
| `--dut-ip TEXT` | **required** | |
| `--dut-mac TEXT` | — | |
| `--dut-port INT` | 80 | DUT port that port-specific tests target |
| `--dut-source-port INT` | — | optional fixed local source port; default lets each test pick its own |
| `--target-stack {linux,windows}` | **required** | selects the [target profile](../target_profiles/README.md) |
| `--role {client,server}` | `client` | client = suite initiates (validates DUT responder); server = suite responds (validates DUT client). Tests not marked for the role are skipped. |
| `--payload-mode {zeros,ones,random,custom}` | `random` | |
| `--payload-size INT` | 64 | |
| `--allowed-target CIDR` (repeatable) | — | authorizes `vuln` tests |
| `--confirm-vuln-tests` | off | required (with allow-list) for `vuln` tests |
| `--debug` | off | write [`debug.log`](../utils/README.md#debug_logpy) |
| `--skip-preflight` | off | skip the pre-run connectivity check (config, privileges, ARP probe) |
| `--report {pdf,html,none}` | `pdf` | |

Before launching the suite, `run` performs a **preflight check**
([`packet_engine/preflight.py`](../packet_engine/README.md#preflightpy)):
it validates the required config, checks raw-socket privileges, and sends
an ARP request to the DUT. A hard blocker (missing config, no privileges,
interface can't send) aborts with a clear message and exit code 2 — no
tests run. A no-ARP-reply is reported as a *warning* and the run proceeds
(a custom stack may not implement ARP). The end-of-run summary reports
`passed / failed / errored / total`, and the command exits non-zero if any
test failed **or errored** (a fixture/setup error, distinct from an
assertion failure).

```bash
netstack-cli run --iface eth0 --dut-ip 10.0.0.5 --target-stack linux
netstack-cli run --module tcp --submodule syn --iface eth0 --dut-ip 10.0.0.5 --target-stack windows --debug
netstack-cli run --iface eth0 --dut-ip 10.0.0.5 --target-stack linux \
  --allowed-target 10.0.0.5/32 --confirm-vuln-tests
```

## `send` — one ad-hoc packet

Craft and send a single L3/L4 packet with a custom/raw L7 payload and
print the response.

Required: `--proto {tcp,udp}`, `--iface`, `--src-ip`, `--dst-ip`,
`--src-port`, `--dst-port`, `--src-mac`, `--dst-mac`.
Optional: `--ttl 64`, `--tcp-flags S`, `--payload-mode random`,
`--payload-size 64`, and — for `--payload-mode custom` — exactly one of
`--payload TEXT` / `--payload-hex HEX` / `--payload-file PATH`
(missing all three is a usage error). `--timeout 2.0`, `--capture PATH`
(write this send to a pcap).

```bash
netstack-cli send --proto tcp --iface eth0 \
  --src-ip 10.0.0.1 --dst-ip 10.0.0.5 --src-port 40000 --dst-port 80 \
  --src-mac aa:bb:cc:dd:ee:ff --dst-mac 11:22:33:44:55:66 \
  --payload-mode custom --payload-hex deadbeef
```

## `record` — passive pcap capture

Sniff the interface and write every packet the app sends **and the
associated transmission back** to a `.pcap`, written incrementally.

Required: `--iface`, `--out PATH`.
Optional: `--dut-ip IP` (derives a `host <ip>` filter), `--filter BPF`
(overrides the derived filter), `--count N` / `--duration SEC` (bounds;
omit both to run until Ctrl+C).

```bash
netstack-cli record --iface eth0 --out capture.pcap --dut-ip 10.0.0.5
netstack-cli record --iface eth0 --out capture.pcap --filter "tcp port 80" --duration 30
```

## Functions

| Function | Description |
|---|---|
| `cli()` | Click group; configures logging. |
| `run(...)` | Builds a `RunRequest`, streams results (echoing each test outcome), generates the report, exits with pass/fail status. |
| `send(...)` | Resolves the payload, builds a `CustomPacketSpec`, sends, prints the reply summary. |
| `record(...)` | Builds a `PacketRecorder`, runs bounded (join) or until Ctrl+C, prints the packet count written. |
