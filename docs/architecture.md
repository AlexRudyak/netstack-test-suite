# Architecture

## Two independent platform axes

This system has two separate, orthogonal platform choices — conflating
them is a real bug class, so it's worth stating explicitly:

1. **Host backend** (`src/packet_engine/platform_backend.py`) — which OS
   the test suite itself runs *on* (Windows/Linux). Auto-detected via
   `platform.system()`. Determines the Scapy socket backend
   (Npcap-backed L2 on Windows, native `AF_PACKET` L2 on Linux — both
   deliberately L2-only, since Windows L3 raw send is unreliable
   regardless of Npcap, and standardizing on L2 behaves identically on
   both hosts) and the privilege model (`src/utils/permissions.py`).
2. **Target stack profile** (`src/target_profiles/`) — which OS stack
   the **DUT** is expected to behave like. An explicit user choice
   (`--target-stack linux|windows`), independent of what the suite runs
   on. All four {host, target} combinations are valid — e.g. a Linux
   test-runner validating a Windows-based DUT.

## Roles: client vs. server

The suite can play either side of a conversation, selected with `--role`
(threaded through `RunRequest` → the `--role` pytest option):

- **client** — the suite initiates (sends SYNs/probes) and validates the
  DUT's *responder* behavior. The classic mode.
- **server** — the suite responds and the DUT initiates, validating the
  DUT's *client* behavior (it connects to us, sends data, pings us). The
  server-side primitives live in `packet_engine/responder.py` (wait for
  the DUT's SYN/datagram/echo, build and send the reply).

A test declares its role(s) with the `client` / `server` markers; a
`pytest_collection_modifyitems` hook skips the non-matching ones **at
collection time** (before any fixture — including the privileged
`network_interface` — is set up, which a function-scoped skip couldn't
guarantee). A test with no role marker defaults to client, so existing
tests are unaffected.

## Per-test metadata catalog

`src/catalog.py` is a machine-readable list of `TestSpec`s — each test's
description, RFC clause, applicable roles, and markers. It's the single
source of truth behind the GUI's per-test description panel and the RFC
coverage docs. `tests_internal/test_catalog.py` AST-checks it against the
actual test functions on disk (every function cataloged, every entry
real), so the catalog and the tests can't drift apart.

## Strict vs. informational assertions

RFCs leave plenty of TCP/IP behavior implementation-defined (default
TTL, default window size, fragment reassembly timeout, retry counts).
Every field on a `TargetProfile` (`src/target_profiles/base.py`) carries
a `Confidence`:

- **STRICT** — the RFC actually mandates this behavior; independent of
  target stack. Tests assert this directly, not via profile comparison.
- **INFORMATIONAL** — an implementation characteristic, not an RFC
  requirement. Only used by tests explicitly fingerprinting/comparing
  the DUT against its claimed target stack. A mismatch here is never
  treated as an RFC violation.

## Subprocess-based test execution

Both `netstack-cli run` and the GUI drive `src/runner.py`, which invokes
`pytest` as a **separate process** every time — never `pytest.main()` in
the same long-lived process. Repeated in-process invocation (as a GUI
would otherwise do across many runs in one session) risks module-cache
pollution and plugin/fixture state bleeding between runs, and a crash
inside a test could take the whole GUI down with it.

Progress streams back via two JSON-lines files the subprocess writes and
the caller tails as they grow:

- pytest's own `--report-log` (one JSON object per test lifecycle event;
  provided by the `pytest-reportlog` dependency)
- a live packet-events log, written by `NetworkInterface`'s `on_packet`
  callback (wired in the root `conftest.py`), so the GUI's live plot has
  something to show *during* a run, not just after it finishes

The subprocess's own stdout/stderr is redirected to
`reports/<run_id>/pytest_output.log` — **not** an unread pipe, which would
fill its OS buffer under verbose output and deadlock the subprocess while
the parent blocks on poll. Tailing reads only up to the last complete
newline, leaving any partial line the subprocess is mid-write on for the
next poll. The subprocess exit code is recorded on `TestRunResult`
(`pytest_returncode` / `.errored`) so a collection or usage error (2–5)
surfaces as a failure rather than a false "0 passed".

The report-log parser reads **every** phase, not just `call`: a failure
in the `setup` phase (the common "run did nothing" case — e.g. every test
erroring because a required fixture couldn't open a socket) is surfaced as
an `ERROR` outcome rather than silently dropped. Reports are upserted per
nodeid with worst-wins severity (a test that passes its call but errors in
teardown is an `ERROR`). `TestRunResult` exposes `.errors` alongside
`.passed`/`.failed`, and both the CLI and GUI report `passed / failed /
errored / total` and exit non-zero on errors.

Before launching the subprocess, both front ends run a **preflight check**
(`packet_engine/preflight.py`): config + privilege validation and an ARP
probe of the DUT. Hard blockers abort with a clear message before any test
runs; a no-ARP-reply is a warning (a custom stack may not implement ARP)
and the run proceeds.

`gui/run_controller.py` drives the equivalent subprocess via `QProcess`
(never blocking the Qt event loop) and reuses `runner.py`'s
`build_pytest_args`/`drain_test_events`/`drain_packet_events` directly,
so the CLI and GUI can never drift into constructing or parsing a run
differently.

## Live plotting cadence

Packet events can arrive far faster than any UI can render — a flood
test emits thousands of events in milliseconds. `src/plotting/metrics.py`'s
`MetricsBuffer` decouples ingestion (cheap, thread-safe append) from
rendering: `RealtimePlotWidget` pulls a decimated snapshot on a ~25Hz
`QTimer`, rather than reacting to every packet event individually.

## One canonical result model

`src/reporting/models.py` (`TestEvent`, `PacketEvent`, `TestRunResult`)
is the single source of truth everything downstream consumes — the
report-log parser, the packet-event log, the GUI's live view, and the
PDF/HTML report generator all normalize to these shapes rather than each
re-deriving their own notion of "what happened."

## Safety gate for vulnerability tests

Tests marked `vuln` (SYN flood, Ping of Death, Teardrop, ...) send real
attack traffic at a real MAC/IP over real Ethernet. `src/utils/safety.py`
requires **both** an explicit allow-list entry (`DUTConfig.allowed_targets`,
CIDR ranges) **and** an explicit confirmation flag
(`--confirm-vuln-tests` / the GUI's confirmation checkbox) before such a
test's body runs — a misconfigured target should never become a live
incident.

## Custom/raw L7 payload

`src/packet_engine/payloads.py`'s `PayloadMode` (`ZEROS`, `ONES`,
`RANDOM`, `CUSTOM`) is resolved through one dispatcher
(`resolve_payload`), used identically by the automated suite (via the
`--payload-mode`/`--payload-size` pytest options), the CLI `send`
subcommand, and the GUI's Custom Packet panel. This is scoped to
arbitrary *bytes* riding in a `Raw()` layer — no L7 protocol awareness
(no HTTP/DNS parsing), keeping the suite's testing scope at L3/L4 as
intended; `src/custom_packet/` is the ad-hoc send path for it, separate
from the RFC-assertion suite in `tests/`.

## Per-run artifacts

Every run (`reports/<run_id>/`) writes:

- `results.json` — the serialized `TestRunResult`
- `capture.pcap` — the full wire capture (everything `NetworkInterface`
  sent/received), **streamed** frame-by-frame via `PcapWriter` (bounded
  memory; valid even if the run is interrupted)
- `pytest_output.log` — the subprocess's raw stdout/stderr
- `report.pdf` / `report.html` — generated on demand from `results.json`,
  so a report can be regenerated without re-running the suite
- `debug.log` — **only when `--debug` is set** — a tshark-style
  human-readable per-packet trace (frame number, timestamps, TX/RX,
  ports/flags/seq/ack/win/len, owning test, initiating function),
  written by `src/utils/debug_log.py`. Complements `capture.pcap`: the
  pcap holds the raw frames for Wireshark, the debug log is the readable
  trace with the calling function attached to each packet.
