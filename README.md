# Network Stack Test Suite

A modular test suite for validating a custom L3/L4 network stack (the
Device Under Test, DUT) over real Ethernet — RFC conformance and
known-vulnerability classes for IP, UDP, and TCP, driven by Scapy and
pytest, with both a CLI and a PySide6/pyqtgraph GUI.

## Highlights

- **CLI and GUI**, both driving the same subprocess-based orchestration layer (`src/runner.py`) — never diverging in how a run is invoked.
- **Runs against a Linux- or Windows-based DUT**, selected explicitly (`--target-stack`), independent of whichever OS the suite itself runs on (also Windows or Linux — see [`docs/architecture.md`](docs/architecture.md)).
- **Custom/raw L7 payloads** — zeros, ones, random, or user-supplied text/hex/file — usable both by the automated suite and via an ad-hoc Custom Packet sender.
- **Passive pcap recorder** (`netstack-cli record`) — captures everything the app sends and the associated transmission back to a `.pcap`, written incrementally, independent of any test run.
- **Opt-in debug log** (`run --debug`) — a tshark-style per-packet trace (timestamps, TCP flags/seq/ack, initiating function, owning test) written to `reports/<run_id>/debug.log`.
- **Real-time plotting** of sent/received traffic during a run (pyqtgraph, GUI), plus a **PDF/HTML report** per run.
- **Self-validated**: [`tests_internal/`](tests_internal/README.md) proves the framework's own packet crafting, interface wrapper, plotting, reporting, CLI, and GUI work — before any of it touches a DUT.

## Quickstart

```bash
pip install -e ".[gui,dev]"
pytest tests_internal/                                    # validate the framework itself first

netstack-cli run --iface eth0 --dut-ip 10.0.0.5 --target-stack linux
netstack-gui
```

See [`docs/getting_started.md`](docs/getting_started.md) for platform-specific
privilege setup (Npcap on Windows, `setcap` on Linux).

### Standalone Windows executable

Build a single double-clickable `.exe` (no Python needed on the target,
self-elevates via UAC):

```bash
python -m PyInstaller NetstackTestSuite.spec --noconfirm
```

Output: `dist\NetstackTestSuite.exe`. See [`packaging/`](packaging/README.md)
for the installer and details. Npcap is still required on the target for
raw packet access.

## Structure

```
src/                  Core framework (CLI, GUI, packet engine, plotting, reporting)
tests/                Automated suite: ip/, udp/, tcp/{syn,state_machine,congestion}/
tests_internal/       Framework self-validation — no DUT required
docs/                 Architecture, setup, RFC coverage matrix
reports/              Generated per-run artifacts (results.json, capture.pcap, report.pdf)
```

Every package has its own `README.md` documenting each module and its
public functions/classes.

### Framework (`src/`)

Start at [`src/README.md`](src/README.md) — the module map and the
config/runner reference. Per-package docs:

- [`src/packet_engine/`](src/packet_engine/README.md) — builders, interface, backends, payloads, recorder, sequence
- [`src/target_profiles/`](src/target_profiles/README.md) — Linux/Windows baselines
- [`src/reporting/`](src/reporting/README.md) — result models, PDF/HTML reports
- [`src/plotting/`](src/plotting/README.md) — live plot & static charts
- [`src/custom_packet/`](src/custom_packet/README.md) — ad-hoc craft & send
- [`src/utils/`](src/utils/README.md) — permissions, safety, debug log, logging
- [`src/cli/`](src/cli/README.md) — `netstack-cli` (`run` / `send` / `record`)
- [`src/gui/`](src/gui/README.md) — `netstack-gui`

### Test suites

- [`tests/README.md`](tests/README.md) — the DUT-facing suite (per-module + per-test docs)
- [`tests_internal/README.md`](tests_internal/README.md) — framework self-validation

## Documentation

- [`docs/architecture.md`](docs/architecture.md) — design decisions and why
- [`docs/getting_started.md`](docs/getting_started.md) — install and privilege setup
- [`docs/rfc_coverage.md`](docs/rfc_coverage.md) — RFC clause → test file matrix
