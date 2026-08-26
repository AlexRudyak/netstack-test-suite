# Network Stack Test Suite

![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey)
![Interface](https://img.shields.io/badge/interface-CLI%20%2B%20GUI-brightgreen)

A modular test suite for validating a custom L3/L4 network stack (the
Device Under Test, **DUT**) over real Ethernet — RFC conformance and
known-vulnerability classes for **IP, UDP, ICMP, and TCP**, driven by
Scapy and pytest, with both a CLI and a PySide6/pyqtgraph GUI.

The suite is built to produce a **developer-oriented report** (HTML/PDF)
that leads with the failures, the RFC clause each one violates, and what
the DUT actually did — so it can be handed to whoever fixes the stack.

## Highlights

- **CLI and GUI**, both driving the same subprocess-based orchestration layer (`src/runner.py`) — never diverging in how a run is invoked.
- **Runs against a Linux- or Windows-based DUT**, selected explicitly (`--target-stack`), independent of whichever OS the suite itself runs on. See [`docs/architecture.md`](docs/architecture.md).
- **Client or server role** (`--role`) — the suite can initiate (validating the DUT's responder) or respond while the DUT initiates (validating the DUT's client path).
- **Per-test catalog** — every test carries a description, RFC clause, and roles, surfaced in the GUI and the report appendix.
- **Custom/raw L7 payloads** — zeros, ones, random, or user-supplied text/hex/file — usable by the automated suite and via an ad-hoc Custom Packet sender.
- **Passive pcap recorder** (`netstack-cli record`) and an **opt-in tshark-style debug log** (`run --debug`) for wire-level forensics.
- **Real-time plotting** of traffic during a run (GUI), plus a **developer-oriented PDF/HTML report** with a findings section, artifacts/repro, and appendices (full test catalog + RFC index).
- **Self-validated**: [`tests_internal/`](tests_internal/README.md) proves the framework's own packet crafting, interface, plotting, reporting, CLI, and GUI work — before any of it touches a DUT.

## Download

The easiest way to run on Windows is the standalone executable from the
[**Releases**](../../releases) page:

1. Download `NetstackTestSuite.exe` from the latest release.
2. Double-click it — it self-elevates via UAC (raw sockets need Administrator).
3. Install [Npcap](https://npcap.com) if you haven't (the driver can't be bundled).

No Python needed on the target. See [`packaging/README.md`](packaging/README.md).

## Quickstart (from source)

```bash
pip install -e ".[gui,dev]"
pytest tests_internal/                                    # validate the framework itself first

netstack-cli run --iface eth0 --dut-ip 10.0.0.5 --target-stack linux
netstack-gui
```

See [`docs/getting_started.md`](docs/getting_started.md) for platform-specific
privilege setup (Npcap on Windows, `setcap` on Linux).

### Build the standalone executable

```bash
python -m PyInstaller NetstackTestSuite.spec --noconfirm
```

Output: `dist/NetstackTestSuite.exe` — a single UAC-elevating file that
doubles as its own pytest worker. Details in [`packaging/`](packaging/README.md).

## Repository layout

```
src/                  Core framework
  packet_engine/      Packet crafting, L2 I/O, capture, preflight, server responder
  target_profiles/    Linux/Windows behavioral baselines
  reporting/          Result models + developer PDF/HTML reports
  plotting/           Live plot + static charts
  custom_packet/      Ad-hoc craft & send
  cli/  gui/          netstack-cli and netstack-gui front ends
  utils/              Privileges, safety gate, debug log, paths
  catalog.py          Per-test metadata (description, RFC, roles)
  runner.py           Subprocess-based run orchestration
tests/                DUT-facing suite: ip/ udp/ icmp/ tcp/{syn,state_machine,congestion}/
tests_internal/       Framework self-validation — no DUT required
docs/                 Architecture, setup, RFC coverage matrix
packaging/            PyInstaller spec entry, build script, Inno Setup installer
reports/              Generated per-run artifacts (gitignored)
```

Every package has its own `README.md` documenting each module and its public API.

### Framework (`src/`)

Start at [`src/README.md`](src/README.md) — the module map. Per-package docs:
[`packet_engine`](src/packet_engine/README.md) ·
[`target_profiles`](src/target_profiles/README.md) ·
[`reporting`](src/reporting/README.md) ·
[`plotting`](src/plotting/README.md) ·
[`custom_packet`](src/custom_packet/README.md) ·
[`utils`](src/utils/README.md) ·
[`cli`](src/cli/README.md) ·
[`gui`](src/gui/README.md)

### Test suites

- [`tests/README.md`](tests/README.md) — the DUT-facing suite (per-module + per-test docs)
- [`tests_internal/README.md`](tests_internal/README.md) — framework self-validation

## Documentation

- [`docs/architecture.md`](docs/architecture.md) — design decisions and why
- [`docs/getting_started.md`](docs/getting_started.md) — install and privilege setup
- [`docs/rfc_coverage.md`](docs/rfc_coverage.md) — RFC clause → test file matrix

## Development

- **`main`** — stable; each [release](../../releases) is tagged from here.
- **`development`** — ongoing work; branch features off it and merge back.

Commits follow [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/)
(`type(scope): description`). Run the self-tests before pushing:

```bash
pytest tests_internal/
```
