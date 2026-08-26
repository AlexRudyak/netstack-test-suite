# tests_internal/ — framework self-validation

Proves the test suite's own machinery works — packet crafting, the
interface wrapper, plotting, reporting, the CLI, and the GUI — **before**
any of it is trusted against a real DUT. None of these tests touch a real
network interface, require elevated privileges, or need `--target-stack`/
`--dut-ip`/`--dut-iface`.

## Files

| File | Validates |
|---|---|
| `test_packet_builders.py` | `src/packet_engine/builders.py` — layer composition, field values |
| `test_payload_handling.py` | `src/packet_engine/payloads.py` — generation, hex/text/file round-trips, attach point |
| `test_interface_mock.py` | `src/packet_engine/interface.py` — send/receive/capture logic, via monkeypatched Scapy calls |
| `test_recorder.py` | `src/packet_engine/recorder.py` — BPF filter, incremental writing, start/stop lifecycle, via monkeypatched AsyncSniffer/PcapWriter |
| `test_preflight.py` | `src/packet_engine/preflight.py` — config validation, privilege blocker, ARP reply/no-reply/send-error outcomes |
| `test_responder.py` | `src/packet_engine/responder.py` — server-role reply builders + serve_* orchestration via a fake interface |
| `test_catalog.py` | `src/catalog.py` — metadata completeness + AST drift check (every test cataloged, every entry real) |
| `test_debug_log.py` | `src/utils/debug_log.py` — tshark-style formatting, frame numbering, caller resolution, NetworkInterface integration |
| `test_runner_args.py` | `src/runner.py` — `build_pytest_args` (the shared CLI/GUI subprocess command), incl. `--debug` wiring |
| `test_plotting_engine.py` | `src/plotting/` — MetricsBuffer decimation, static chart PNG rendering |
| `test_reporting_pdf.py` | `src/reporting/` — PDF/HTML generation, `TestRunResult` JSON round-trip |
| `test_cli.py` | `src/cli/main.py` — argument parsing → `RunRequest`, via `click.testing.CliRunner` |
| `test_gui_smoke.py` | `src/gui/` — window/panel construction via `pytest-qt`, offscreen platform |

## Running

```bash
pytest tests_internal/
# or
netstack-cli run  # ...(tests_internal isn't wired into the CLI's --module
                   #      choices since it's not a DUT-facing module;
                   #      invoke it directly with pytest)
```

`test_gui_smoke.py` needs the `dev`/`gui` extras (`pip install -e ".[gui,dev]"`)
and is skipped automatically if they're absent.
