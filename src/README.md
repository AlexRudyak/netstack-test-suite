# src/ — framework module map

The `src/` tree is the framework. `tests/` and `tests_internal/` are
consumers of it. Everything here is import-safe without a DUT or elevated
privileges *except* the moment a socket is actually opened
(`packet_engine.interface.NetworkInterface`) or a run is launched
(`runner.stream_run`).

## Package overview

| Package / module | Responsibility | Per-package docs |
|---|---|---|
| [`config.py`](#configpy) | `DUTConfig` + `Role` — where to send, which side to play, the safety allow-list | — |
| [`catalog.py`](#catalogpy) | Per-test metadata (description, RFC, roles) driving the GUI + docs | — |
| [`runner.py`](#runnerpy) | Subprocess-based run orchestration shared by CLI + GUI | — |
| [`packet_engine/`](packet_engine/README.md) | Packet crafting, L2 send/receive/sniff, pcap recording, seq tracking, payloads | ✔ |
| [`target_profiles/`](target_profiles/README.md) | Linux/Windows behavioral baselines; strict vs. informational | ✔ |
| [`reporting/`](reporting/README.md) | Canonical result models, JSON/PDF/HTML reports, live event log | ✔ |
| [`plotting/`](plotting/README.md) | Live pyqtgraph plot + static matplotlib charts for the PDF | ✔ |
| [`custom_packet/`](custom_packet/README.md) | Ad-hoc single-packet craft/send (the `send` command / GUI panel) | ✔ |
| [`utils/`](utils/README.md) | Privileges, vuln-test safety gate, debug log, logging config | ✔ |
| [`cli/`](cli/README.md) | `netstack-cli` — `run` / `send` / `record` | ✔ |
| [`gui/`](gui/README.md) | `netstack-gui` — PySide6 desktop app | ✔ |

## How a run flows through the packages

```
CLI run / GUI Run button
        │
        ▼
  runner.RunRequest ──► runner.build_pytest_args ──► pytest subprocess
        │                                                   │
        │                             conftest.py wires fixtures:
        │                             ├─ config.DUTConfig
        │                             ├─ target_profiles.get_profile
        │                             ├─ packet_engine.NetworkInterface
        │                             │     ├─ platform_backend (host OS socket)
        │                             │     ├─ utils.debug_log (if --debug)
        │                             │     └─ reporting.PacketEventLogWriter
        │                             └─ payload_settings (packet_engine.payloads)
        │                                                   │
        ▼                                                   ▼
  runner tails report_log.jsonl + packet_events.jsonl  tests/ exercise the DUT
        │                                                   │
        ▼                                                   ▼
  reporting.TestRunResult ──► reporting.pdf_report / plotting.static_charts
```

## Two platform axes (don't conflate them)

- **Host backend** — the OS the suite *runs on*. Auto-detected;
  `packet_engine/platform_backend.py`.
- **Target profile** — the OS stack the *DUT* is expected to behave like.
  User-selected (`--target-stack`); `target_profiles/`.

All four combinations are valid. See [`docs/architecture.md`](../docs/architecture.md).

---

## config.py

`DUTConfig` (frozen dataclass) — the addressing + authorization object
threaded through the CLI, GUI, and every DUT-facing fixture.

| Field | Meaning |
|---|---|
| `interface: str` | Local Ethernet interface facing the DUT |
| `target_ip: str` | DUT IP |
| `target_stack: "linux" \| "windows"` | Which target profile to assert against |
| `target_mac: str \| None` | DUT MAC (falls back to broadcast if unset) |
| `target_port: int \| None` | Port for tests that need one; `None` ⇒ each front end resolves it to one random ephemeral port for the session (`random_ephemeral_port()`) |
| `source_port: int \| None` | Optional fixed local source port; `None` ⇒ each test picks its own |
| `timeout: float = 2.0`, `retries: int = 2` | Send/receive timing |
| `allowed_targets: tuple[str, ...]` | CIDR ranges authorized for `vuln` tests |
| `role: Role` | Which side the suite plays — `Role.CLIENT` (initiator) or `Role.SERVER` (responder) |

`Role` (enum: `CLIENT` / `SERVER`) also lives here — client = the suite
initiates and validates the DUT responder; server = the DUT initiates and
the suite responds, validating the DUT client.

| Method | Signature | Description |
|---|---|---|
| `target_in_allowed_range` | `() -> bool` | True if `target_ip` falls in any `allowed_targets` CIDR. Enforced by [`utils/safety.py`](utils/README.md). |
| `from_file` / `to_file` | `(path=DEFAULT_CONFIG_PATH)` | JSON load/save (`~/.netstack_test_suite/config.json`). |

## catalog.py

The single source of truth for **per-test metadata**: each `TestSpec`
records a test's `title`, `description`, `rfc` clause, applicable `roles`,
and `markers`. Drives the GUI's per-test description panel and the RFC
coverage docs. `tests_internal/test_catalog.py` AST-checks it against the
real test functions so the catalog and the tests can't silently diverge.

| Symbol | Signature | Description |
|---|---|---|
| `TestSpec` | frozen dataclass | `.rel_path`, `.nodeid`, `.role_labels` derived properties. |
| `specs_for_rel_path` | `(rel_path) -> list[TestSpec]` | All specs defined in a test file (used by the GUI tree). |
| `find_by_nodeid` / `find_by_test` | `-> TestSpec \| None` | Lookups for the details panel. |

## runner.py

The single orchestration path both front ends drive. Runs pytest as a
**separate process** every time (never in-process `pytest.main()`), and
streams progress by tailing two JSON-lines files the subprocess writes.

| Symbol | Signature | Description |
|---|---|---|
| `RunRequest` | dataclass | Everything selecting a run: `config`, `module`, `submodule`, `test_name`, `markers`, `payload_mode`, `payload_size`, `confirm_vuln_tests`, `debug`. |
| `build_pytest_args` | `(request, run_dir) -> list[str]` | The canonical subprocess argv. **Reused verbatim by the GUI** (`gui/run_controller.py`) so CLI and GUI runs are byte-identical. |
| `new_run_dir` | `() -> tuple[str, Path]` | Allocates `reports/<run_id>/`. |
| `run_tests` | `(request, on_test_event=None, on_packet_event=None) -> TestRunResult` | Blocking convenience wrapper (used by the CLI). |
| `stream_run` | `(request, on_test_event=None, on_packet_event=None) -> Iterator[TestRunResult]` | Generator yielding the accumulating result each poll; final yield is complete and written to `results.json`. |
| `drain_test_events` | `(path, offset, result, callback) -> int` | Tails pytest's `--report-log`; appends `TestEvent`s. Exported so the GUI reuses it under a `QTimer`. |
| `drain_packet_events` | `(path, offset, result, callback) -> int` | Tails the live packet-event log; appends `PacketEvent`s. |
| `parse_report_log_line` | `(line) -> TestEvent \| None` | Maps one report-log JSON object (the `call` phase) to a `TestEvent`. |
