# Error Handling Audit — netstack-test-suite

**Date:** 2026-09-10
**Commit:** `4653b25` (branch `development`)
**Scope:** every `raise`, `except`, `assert`, exit code, thread boundary and
error-reporting path across `src/` (58 modules), `conftest.py`,
`tests/conftest.py`, `tests/`, `tests_internal/`, `packaging/`, `tools/`.
**Method:** full read of every `src/` module; `grep` census of all 36 `raise`
sites and all 30 `except` clauses; every thread entry point and Qt slot traced
to its enclosing handler; four findings reproduced at runtime in the project
venv (marked **Reproduced** below). Baseline before any change:
`pytest tests_internal/ -q` → **220 passed**, `ruff check .` → clean.

**Severity scale:** 1 = cosmetic, 10 = actively causing defects / safety-relevant.

---

## Scope note: what "error category" means here

This package exposes no request/response service: it is a Click CLI
(`netstack-cli`), a PySide6 desktop app (`netstack-gui`), a pytest subprocess,
and a raw-Ethernet packet engine. The categories that matter are therefore the
ones this codebase actually has, listed here so the findings below can refer to
them by name:

| Category | What it means here | Where it lives |
|---|---|---|
| Configuration / validation | Click and pytest option parsing, `ProxyConfig.__post_init__`, `DUTConfig.missing_required`, `run_preflight` | `cli/options.py`, `proxy/config.py:78`, `config.py:185`, `packet_engine/preflight.py` |
| Privilege | Raw-socket access on the host (`InsufficientPrivilegesError`) | `utils/permissions.py:69` |
| Authorization | The vuln-test safety gate: allow-list CIDR plus explicit confirmation | `utils/safety.py` |
| Lookup | Unknown target stack, unsupported host OS, unknown report format | `target_profiles/registry.py:14`, `packet_engine/platform_backend.py:84`, `reporting/formats.py:85` |
| Peer protocol | The DUT sent bytes that violate the RFC being tested | `proxy/tunnel.py`, `proxy/handshakes.py` |
| Unhandled | Exceptions escaping an entry point, a Qt slot, or a worker thread | F-02, F-08, F-09, F-11 |

---

## Status: all 22 findings applied

Every finding was applied on branch `development`, in the priority order
this report set out. Each finding below keeps its original analysis and
remediation snippet, so the record of *what was wrong and why* survives
alongside the fix.

Verification after the final change:

- `pytest tests_internal/ -q` -> **291 passed** (220 at `4653b25`, plus 71
  new tests covering the paths these findings describe)
- `pytest --collect-only -q` -> no import errors
- `ruff check .` -> clean, `C901` still enforced at max-complexity 10

| Finding | Commit | Note |
|---|---|---|
| F-05 vuln gate on the marker | `e3c70ba` | + `tests_internal/test_vuln_gate.py` |
| F-08 drain loop guards | `5955a96` | both reproductions became regression tests |
| F-01 exception hierarchy | `e0a69bd` | new `src/errors.py`, + an AST guard |
| F-02 entry-point boundaries | `3da3344` | CLI narrow, GUI wide; both pinned |
| F-13 client socket leak | `d47fe1d` | |
| F-12 backend partial start | `3704318` | also fixed restart-after-stop |
| F-09 QProcess launch failure | `cda1220` | the test caught a bug in the fix |
| F-16 + F-17 report failures | `77ff2bb` | CLI keeps the exit code; GUI stays open |
| F-18 capture teardown | `f622521` | out of the `finally:` |
| F-11 recorder sinks | `dc03f02` | `assert` -> a guard `-O` can't strip |
| F-10 jsonl writer lock | `31f921c` | |
| F-06 allow-list parsing | `2f8a0f4` | + parse-time CIDR validation |
| F-04 exit codes | `90a5e37` | `send`, `proxy-serve` |
| F-14 inducer backoff | `3005c0f` | + failure breakdown by type |
| F-19 – F-22 logging | `6847551` | GUI log file, `--verbose`, two logged reasons |
| F-03 error provenance | `dd77581` | + an IndexError in `read_socks5_reply` |
| F-07 CONNECT hints | `fe9aec3` | |
| F-15 dead `retries` field | `cdf9cdf` | removed, with the reasoning recorded |

Three fixes were adjusted by their own tests before landing, which is
worth recording: the F-09 timer was started after `QProcess.start`, whose
`errorOccurred` fires synchronously; F-01's guard test correctly rejected
`ProtocolViolation` being declared in `tunnel.py`; and F-03's first pass
labelled three encoder-input errors as the DUT's fault.

---

## Executive summary

The package's **decision logic** around errors is unusually good: `PreflightResult`
separates hard blockers from warnings with a documented rationale, `ProxyTunnelError`
carries the DUT's own error report so a conformance test can assert "refused
correctly", `_registered_markers` degrades to an empty set with a written
justification, and `parse_report_log_line` has a worst-wins severity table so a
teardown error can't be masked by a passing call phase.

What is missing is the **plumbing**: there is no exception hierarchy, no entry-point
error boundary, and — the sharpest edge — no guard on the JSON parsing that both
front ends run in a polling loop over a file another process is concurrently
writing. Three classes of defect dominate:

1. **Unbounded blast radius from one bad line.** `drain_test_events` /
   `drain_packet_events` (`runner.py:376`, `runner.py:474`) call `json.loads` and
   index required keys with no guard. In the CLI this aborts `stream_run` mid-run;
   in the GUI it throws out of a `QTimer` slot. (F-08, **Reproduced**)
2. **No error boundary at either entry point.** Any operational failure —
   a bad `--payload-hex`, a missing `--payload-file`, a Scapy send error — reaches
   the user as a raw Python traceback. (F-02, **Reproduced**)
3. **Safety gate is opt-in per test body.** `enforce_vuln_test_authorization` is
   called by 3 of the 4 `vuln`-marked tests. The fourth sends malformed ICMP at
   the DUT with no allow-list check and no confirmation. (F-05)

**Findings: 22.** Severity ≥7: 6. Severity 4–6: 11. Severity ≤3: 5.

| # | Finding | Sev | Area |
|---|---|---|---|
| F-01 | No exception hierarchy — 3 unrelated `RuntimeError` subclasses, no base | 5 | Consistency |
| F-02 | No error boundary at either entry point; raw tracebacks | 7 | Consistency |
| F-03 | Domain errors raised as bare builtins (20 sites in `tunnel.py`) | 4 | Consistency |
| F-04 | `send` / `record` / `proxy-serve` always exit 0 | 6 | Exit codes |
| F-05 | `vuln` safety gate is opt-in; one marked test bypasses it | 8 | Authorization |
| F-06 | `target_in_allowed_range` raises bare `ValueError` on bad CIDR | 5 | Authorization |
| F-07 | HTTP CONNECT refusals not sub-categorised the way SOCKS5 replies are | 3 | Peer protocol |
| F-08 | Unguarded `json.loads` in both drain loops kills the run | 8 | Async |
| F-09 | `QProcess.errorOccurred` never connected — silent hang | 7 | Async |
| F-10 | `PacketEventLogWriter` written from the sniffer thread unlocked | 5 | Async |
| F-11 | `PacketRecorder._handle` uses `assert`; sink errors kill the capture silently | 6 | Async |
| F-12 | `EchoBackend.start()` leaks a live TCP listener on UDP bind failure | 6 | Async |
| F-13 | `ProxyClient.connect()` leaks the socket when the handshake raises | 6 | Async |
| F-14 | `TrafficInducer` spins at 4 Hz through a permanent failure | 4 | Recovery |
| F-15 | `DUTConfig.retries` declared and never read — no retry anywhere | 5 | Recovery |
| F-16 | Report generation failure discards the run's verdict and exit code | 7 | Recovery |
| F-17 | `ReportPanel._export` unguarded — throws out of a Qt slot | 6 | Recovery |
| F-18 | `record`'s `finally: recorder.stop()` re-raises from the finally clause | 6 | Recovery |
| F-19 | `logging` configured but effectively unused; zero `logger.exception` | 5 | Information |
| F-20 | `_list_interface_names` swallows the reason; empty dropdown, no message | 5 | Information |
| F-21 | `is_elevated` reports a ctypes failure as "not elevated" | 3 | Information |
| F-22 | No verbosity/dev-vs-prod control; `configure_logging` is INFO-only | 3 | Information |

---

## 1. Error handling consistency

### F-01 — There is no exception hierarchy (severity 5)

**Location:** `src/proxy/handshakes.py:27`, `src/utils/permissions.py:18`,
`src/utils/safety.py:14`.

The package defines exactly three custom exceptions, in three packages, all
subclassing `RuntimeError` directly and sharing no base:

```
src/proxy/handshakes.py:27:class ProxyTunnelError(RuntimeError):
src/utils/permissions.py:18:class InsufficientPrivilegesError(RuntimeError):
src/utils/safety.py:14:class UnauthorizedTargetError(RuntimeError):
```

There is no `NetstackError`, so no caller can write "handle anything this package
raises deliberately, and let genuine bugs through". That is precisely the
distinction an entry-point boundary (F-02) needs to make, and its absence is why
every existing broad handler is `except Exception` (5 sites) rather than
`except NetstackError`.

**Remediation** — new file `src/errors.py`:

```python
"""The one base every deliberate failure in this package derives from.

A `NetstackError` means "the run cannot proceed, and we know why" — the
entry points render it as a message. Anything else escaping to a boundary
is a bug and keeps its traceback.
"""
from __future__ import annotations


class NetstackError(Exception):
    """Base for every error this package raises on purpose."""

    exit_code: int = 1


class ConfigurationError(NetstackError):
    """Invalid or missing run configuration."""

    exit_code = 2


class InsufficientPrivilegesError(NetstackError):
    """Raw-socket access is unavailable on this host."""

    exit_code = 2


class UnauthorizedTargetError(NetstackError):
    """The target is outside the run's authorization."""

    exit_code = 3


class UnsupportedHostError(NetstackError):
    """No socket backend / privilege check exists for this host OS."""

    exit_code = 2


class ProxyTunnelError(NetstackError):
    """The DUT refused or mishandled the tunnel handshake."""

    def __init__(self, message: str, details: object = None) -> None:
        super().__init__(message)
        self.details = details
```

Then re-home the three existing classes, keeping the current names importable so
no call site changes:

```python
# src/utils/safety.py
from src.errors import UnauthorizedTargetError  # re-exported; raise sites unchanged

# src/utils/permissions.py
from src.errors import InsufficientPrivilegesError

# src/proxy/handshakes.py
from src.errors import ProxyTunnelError
```

`src/proxy/client.py:24` already re-exports `ProxyTunnelError` for its callers, so
that alias keeps working unchanged.

---

### F-02 — Neither entry point has an error boundary (severity 7) — **Reproduced**

**Location:** `src/cli/main.py:60-63` (`cli()` group), `src/gui/app.py:20-54`
(`main()`).

`cli()` does nothing but `configure_logging()`. There is no
`try/except` around command dispatch and no `sys.excepthook`. Any operational
error — not a programming bug — reaches the operator as a traceback.

Reproduced in the project venv:

```
$ netstack-cli send --proto tcp ... --payload-mode custom --payload-hex zz
  File "src\cli\main.py", line 295, in send
    custom = resolve_custom_source(text=payload_text, hex_str=payload_hex, file=payload_file)
  File "src\packet_engine\payloads.py", line 45, in from_hex
    return bytes.fromhex(hex_str.replace(" ", "").replace(":", ""))
ValueError: non-hexadecimal number found in fromhex() arg at position 0
```

The same shape applies to `--payload-file /nonexistent` (`FileNotFoundError` from
`payloads.py:49`), a bad interface name (Scapy `OSError` from
`interface.py:80`), and an unknown `--target-stack` reaching
`registry.get_profile` (`ValueError`). The `send` command has *no* handler at all:
`src/cli/main.py:315` calls `send_custom_packet` bare.

`src/gui/app.py:51-54` is the same story for the GUI — no `sys.excepthook`, so an
exception escaping any slot goes to PySide6's default handler.

**Remediation** — CLI, `src/cli/main.py`:

```python
import click

from src.errors import NetstackError


class NetstackCLI(click.Group):
    """Renders a deliberate failure as a message; a bug keeps its traceback."""

    def invoke(self, ctx: click.Context) -> object:
        try:
            return super().invoke(ctx)
        except NetstackError as exc:
            click.echo(f"Error: {exc}", err=True)
            raise SystemExit(exc.exit_code) from None


@click.group(cls=NetstackCLI)
def cli() -> None:
    """Network Stack Test Suite — RFC conformance & vulnerability testing over Ethernet."""
    configure_logging()
```

Then make the two input-parsing paths raise something the boundary recognises.
`src/packet_engine/payloads.py`:

```python
def from_hex(hex_str: str) -> bytes:
    cleaned = hex_str.replace(" ", "").replace(":", "")
    try:
        return bytes.fromhex(cleaned)
    except ValueError as exc:
        raise ConfigurationError(f"--payload-hex is not valid hex: {exc}") from exc


def from_file(path: str | Path) -> bytes:
    try:
        return Path(path).read_bytes()
    except OSError as exc:
        raise ConfigurationError(f"--payload-file {path!r} could not be read: {exc}") from exc
```

GUI, `src/gui/app.py` — install a hook before `app.exec()` so a slot exception
becomes a dialog instead of PySide6's default (which, on PySide6 6.11 as pinned
here, terminates the process for an exception raised in a slot invoked from C++):

```python
    app = QApplication(sys.argv)

    def _excepthook(kind, value, tb) -> None:
        log.exception("Unhandled exception in the GUI", exc_info=(kind, value, tb))
        QMessageBox.critical(None, "Unexpected error", f"{kind.__name__}: {value}")

    sys.excepthook = _excepthook
    window = MainWindow()
```

(`from PySide6.QtWidgets import QApplication, QMessageBox`.)

---

### F-03 — Domain failures are raised as bare builtins (severity 4)

**Location:** `src/proxy/tunnel.py` — 12 `raise ValueError` and 2
`raise ConnectionError` at lines 69, 74, 78, 100, 103, 159, 166, 169, 183, 206,
218, 230, 233, 243. Also `src/proxy/client.py:71,81`,
`src/packet_engine/payloads.py:102,107`, `src/custom_packet/builder.py:67`.

Every one of these describes *the DUT sent us something malformed* — a test
result. They are indistinguishable from a `ValueError` raised by a bug in our own
encoder. `tests/proxy/` therefore cannot assert "the DUT violated RFC 1928" as
distinct from "our parser crashed".

This matters least where the parser is pure and well-tested (`tunnel.py` has
`tests_internal/test_proxy_tunnel.py` behind it), which is why the severity is 4
rather than 7 — but the type-level distinction is free:

```python
# src/proxy/tunnel.py
from src.errors import NetstackError


class ProtocolViolation(NetstackError, ValueError):
    """The peer's bytes do not conform to the protocol's RFC.

    Subclasses ValueError so every existing `except ValueError` caller —
    conftest.py:193, tunnel.py:77,180 — keeps working unchanged.
    """
```

then a mechanical `ValueError(` → `ProtocolViolation(` inside `tunnel.py`. The
`ValueError` base keeps `src/proxy/tunnel.py:77` and `:180` (which catch
`ValueError` from `int()` and `ipaddress`) working as-is.

One real bug is visible in the same file. `read_socks5_reply` (`tunnel.py:240`):

```python
    elif atyp == ATYP_DOMAINNAME:
        length = read(1)[0]      # IndexError if read() returns b""
```

The `Reader` docstring (`tunnel.py:22`) promises "raising on short read", and
`ProxyClient._recv_exact` honours it — but a test stub or a future reader that
returns `b""` produces `IndexError`, which no caller expects. Fix:

```python
    elif atyp == ATYP_DOMAINNAME:
        raw_len = read(1)
        if not raw_len:
            raise ConnectionError("proxy closed before the SOCKS5 domain length byte")
        host = read(raw_len[0]).decode("ascii", errors="replace")
```

---

## 2. Error categorisation

### F-05 — The `vuln` safety gate is opt-in, and one marked test bypasses it (severity 8)

**Location:** `src/utils/safety.py:18` (the gate);
`tests/icmp/test_icmp_errors.py:13-26` (the bypass).

`src/utils/safety.py`'s docstring states the contract plainly: *"these tests
require BOTH an explicit allow-list entry AND an explicit confirmation flag,
checked before the test body runs."* But enforcement is a manual call in each
test body. The census:

| `vuln`-marked test | Calls `enforce_vuln_test_authorization`? |
|---|---|
| `tests/tcp/syn/test_syn_flood.py::test_syn_flood_does_not_exhaust_connection_table` | Yes (`:27`) |
| `tests/ip/test_ip_malformed.py::test_oversized_reassembled_datagram_ping_of_death` | Yes (`:30`) |
| `tests/ip/test_ip_fragmentation.py::test_overlapping_fragments_teardrop_do_not_crash_dut` | Yes (`:54`) |
| `tests/icmp/test_icmp_errors.py::test_truncated_icmp_does_not_crash_dut` | **No** |

The fourth is `@pytest.mark.vuln` (`test_icmp_errors.py:13`) and its body
(`:23-24`) sends a structurally invalid ICMP Timestamp message at the configured
DUT with no allow-list check and no confirmation flag. It also does not request
the `dut_config` / `confirm_vuln_tests` fixtures, so nothing could have caught the
omission. `grep -rn enforce_vuln_test_authorization tests/` returns 3 call sites
for 4 marked tests.

The design already says where this belongs: `src/collection_policy.py`'s docstring
argues policy lives outside `conftest.py` because *"it is safety-relevant (a
role-mismatched test that runs anyway sends the wrong traffic at the DUT), so it
deserves direct unit tests"*. The same argument applies verbatim here, with a
worse consequence.

**Remediation** — make the marker itself the gate, in the root `conftest.py`, so a
new `@pytest.mark.vuln` test is covered the moment it is written:

```python
@pytest.fixture(autouse=True)
def _enforce_vuln_authorization(request: pytest.FixtureRequest) -> None:
    """Every `vuln`-marked test passes the safety gate before its body runs.

    Autouse and marker-driven rather than called by hand in each test: the
    hand-called form left tests/icmp/test_icmp_errors.py ungated, and nothing
    could detect that a test had simply forgotten the line.
    """
    if request.node.get_closest_marker("vuln") is None:
        return
    from src.utils.safety import enforce_vuln_test_authorization

    enforce_vuln_test_authorization(
        request.getfixturevalue("dut_config"),
        confirmed=request.getfixturevalue("confirm_vuln_tests"),
    )
```

The three explicit in-body calls then become redundant and should be deleted
(`test_syn_flood.py:27`, `test_ip_malformed.py:30`, `test_ip_fragmentation.py:54`)
along with the now-unused `confirm_vuln_tests` parameters in those signatures.

Add a regression test to `tests_internal/` proving no marked test can escape:

```python
# tests_internal/test_vuln_gate.py
import pytest


@pytest.mark.internal
def test_every_vuln_test_is_gated_by_the_autouse_fixture(pytestconfig):
    """The gate is the autouse fixture, so this asserts the fixture exists
    and is autouse — not that each test body remembered to call it."""
    from conftest import _enforce_vuln_authorization

    assert _enforce_vuln_authorization._pytestfixturefunction.autouse
```

---

### F-06 — `target_in_allowed_range` raises a bare `ValueError` on malformed input (severity 5)

**Location:** `src/config.py:194-201`, reached from `src/utils/safety.py:19`.

```python
    def target_in_allowed_range(self) -> bool:
        if not self.allowed_targets:
            return False
        addr = ipaddress.ip_address(self.target_ip)          # ValueError on a hostname
        return any(
            addr in ipaddress.ip_network(cidr, strict=False) # ValueError on a bad CIDR
            for cidr in self.allowed_targets
        )
```

`--allowed-target` is free text (`cli/main.py:146`, `multiple=True`) and
`--dut-ip` is unvalidated (`cli/main.py:143`). A typo — `--allowed-target
10.0.0.0/33` — makes every `vuln` test ERROR with
`ValueError: '10.0.0.0/33' does not appear to be an IPv4 or IPv6 network` instead
of `UnauthorizedTargetError`, from inside a function whose caller is the safety
gate. It fails closed, which is why this is 5 and not 8, but the operator is told
the wrong thing.

**Remediation** — `src/config.py`:

```python
    def target_in_allowed_range(self) -> bool:
        if not self.allowed_targets:
            return False
        try:
            addr = ipaddress.ip_address(self.target_ip)
        except ValueError as exc:
            raise ConfigurationError(
                f"--dut-ip {self.target_ip!r} is not an IP address, so it cannot be "
                "checked against the vuln-test allow-list."
            ) from exc
        for cidr in self.allowed_targets:
            try:
                network = ipaddress.ip_network(cidr, strict=False)
            except ValueError as exc:
                raise ConfigurationError(
                    f"--allowed-target {cidr!r} is not a valid CIDR range: {exc}"
                ) from exc
            if addr in network:
                return True
        return False
```

Better still, validate at parse time so the run never starts. `src/cli/main.py`:

```python
def _validate_cidrs(ctx, param, value: tuple[str, ...]) -> tuple[str, ...]:
    for cidr in value:
        try:
            ipaddress.ip_network(cidr, strict=False)
        except ValueError as exc:
            raise click.BadParameter(f"{cidr!r} is not a valid CIDR range: {exc}") from exc
    return value


@click.option("--allowed-target", "allowed_targets", multiple=True,
              callback=_validate_cidrs,
              help="CIDR authorized for vuln-marked tests.")
```

---

### F-04 — Three of four CLI commands always exit 0 (severity 6)

**Location:** `src/cli/main.py` — `send` (`:272`), `record` (`:341`),
`proxy_serve` (`:396`).

Only `run` sets an exit code (`:251`, via `_emit_results`, which is careful and
correct: it distinguishes pytest's own failure at `:118` from test failures at
`:134`). The other three fall off the end of the function and exit 0:

- `send`: prints `"No reply received within timeout."` (`:319`) and exits 0. A
  script cannot tell a reply from silence.
- `proxy-serve`: detects the diagnostic case explicitly — `"No connections were
  received — the DUT never dialled this backend"` (`:429-433`) — writes it to
  stderr, and still exits 0.
- `record`: exits 0 having written zero packets, even when the sniffer failed
  (see F-18).

**Remediation:**

```python
    # send, replacing lines 318-321
    if reply is None:
        click.echo("No reply received within timeout.", err=True)
        raise SystemExit(1)
    click.echo(reply.summary())
```

```python
    # proxy_serve, replacing lines 428-433
        if not stats.tcp_connections and not stats.udp_datagrams:
            click.echo(
                "No connections were received — the DUT never dialled this backend. "
                "Check the proxy's upstream/origin configuration and routing.",
                err=True,
            )
            raise SystemExit(1)
```

---

### F-07 — HTTP CONNECT refusals are not sub-categorised (severity 3)

**Location:** `src/proxy/handshakes.py:62-75`.

`HttpConnectHandshake.establish` treats every non-2xx identically. The SOCKS5 side
does this properly — `SOCKS5_REPLY_MESSAGES` (`tunnel.py:125-135`) maps all nine
RFC 1928 §6 REP codes to text, and `Socks5Reply.message` (`tunnel.py:152`) names
an unassigned code explicitly. The HTTP side has no equivalent, so a 407 (proxy
auth required) reads the same as a 502.

The raised error does carry the response object (`handshakes.py:73`), so a test
*can* assert on `.status`; this is about the message the operator reads.

**Remediation** — `src/proxy/handshakes.py`:

```python
# What a CONNECT refusal means, in the terms the operator has to act on.
_CONNECT_HINTS = {
    407: "the proxy requires authentication (RFC 9110 §11.7) — no HTTP proxy "
         "credentials are configured",
    403: "the proxy's ruleset forbids this origin",
    405: "the DUT does not implement the CONNECT method (RFC 9110 §9.3.6)",
    502: "the proxy could not reach the origin — is the backend instance running?",
    504: "the proxy timed out reaching the origin",
}


class HttpConnectHandshake:
    def establish(self, sock, read, origin) -> tunnel.HttpConnectResponse:
        host, port = origin
        sock.sendall(tunnel.build_http_connect_request(host, port))
        response = tunnel.parse_http_connect_response(tunnel.read_http_response_head(read))
        if not response.tunnel_established:
            hint = _CONNECT_HINTS.get(response.status)
            raise ProxyTunnelError(
                f"CONNECT {tunnel.format_authority(host, port)} was refused: "
                f"{response.status} {response.reason}".strip()
                + (f" — {hint}" if hint else ""),
                response,
            )
        return response
```

---

## 3. Async / concurrent error handling

### F-08 — Unguarded `json.loads` in both drain loops aborts the run (severity 8) — **Reproduced**

**Location:** `src/runner.py:434` (`parse_report_log_line`), `src/runner.py:479-486`
(`drain_packet_events`).

Both drains parse lines from files that a *different process* is appending to
concurrently, and neither guards the parse:

```python
# runner.py:434
def parse_report_log_line(line: str) -> TestEvent | None:
    data = json.loads(line)                    # no guard

# runner.py:479
    for line in lines:
        data = json.loads(line)                # no guard
        event = PacketEvent(
            timestamp=data["timestamp"],       # KeyError on any schema drift
            direction=PacketDirection(data["direction"]),
            ...
```

`read_new_lines` (`runner.py:340`) is carefully written — binary reads, consumes
only up to the last newline, `errors="replace"` — with a docstring explaining
exactly the concurrency hazard it defends against. That care stops at the parse.
A line can still be malformed if the writer is killed mid-write and the partial
line is later followed by a newline from the next write, if the pcap/debug writers
interleave, or if a future field is renamed.

Reproduced in the project venv:

```
drain_test_events   → RAISED JSONDecodeError: Expecting ',' delimiter: line 1 column 30
drain_packet_events → RAISED KeyError: 'direction'
```

Consequences differ by front end and both are bad:

- **CLI**: the exception propagates out of `stream_run`'s loop (`runner.py:322`),
  which is inside the `with artifacts.pytest_output.open(...)` block — so the
  pytest subprocess is orphaned (never waited on, never terminated) and
  `finalize_run` never runs, leaving no `results.json` for a run whose tests
  actually completed.
- **GUI**: `RunController._poll` → `_drain` (`run_controller.py:76-93`) is a
  `QTimer.timeout` slot. On PySide6 6.11 (pinned `>=6.6.0`, 6.11.2 installed here)
  an unhandled exception in a slot invoked from C++ terminates the process.

**Remediation** — `src/runner.py`. Skip the bad line, count it, keep the run:

```python
import logging

log = logging.getLogger(__name__)


def parse_report_log_line(line: str) -> TestEvent | None:
    """Map one report-log TestReport to a TestEvent, or None to ignore it.

    A line that is not parseable JSON, or is missing the fields a TestReport
    must have, is dropped with a warning rather than raised: this is called
    in a polling loop over a file another process is still appending to, and
    one bad line must not end a run whose tests are still executing.
    """
    try:
        data = json.loads(line)
    except json.JSONDecodeError:
        log.warning("Skipping unparseable report-log line: %.120r", line)
        return None
    if not isinstance(data, dict) or data.get("$report_type") != "TestReport":
        return None
    ...  # unchanged from here


def drain_packet_events(
    path: Path, offset: int, result: TestRunResult, callback: PacketEventCallback | None
) -> int:
    lines, new_offset = read_new_lines(path, offset)
    for line in lines:
        try:
            data = json.loads(line)
            event = PacketEvent(
                timestamp=data["timestamp"],
                direction=PacketDirection(data["direction"]),
                summary=data["summary"],
                size_bytes=data["size_bytes"],
                test_nodeid=data.get("test_nodeid"),
            )
        except (json.JSONDecodeError, KeyError, ValueError, TypeError):
            log.warning("Skipping unparseable packet-event line: %.120r", line)
            continue
        result.packet_events.append(event)
        if callback:
            callback(event)
    return new_offset
```

Cover it in `tests_internal/` (this suite already has `test_runner_args.py` and
`test_report_data.py` to extend):

```python
@pytest.mark.internal
def test_a_malformed_line_does_not_abort_the_drain(tmp_path):
    """One corrupt line must cost one event, not the whole run."""
    good = json.dumps({"$report_type": "TestReport", "when": "call",
                       "outcome": "passed", "nodeid": "t::a", "duration": 0.1})
    path = tmp_path / "report_log.jsonl"
    path.write_text(f"{{truncated\n{good}\n", encoding="utf-8")
    result = _blank_result()
    drain_test_events(path, 0, result, None)
    assert [t.nodeid for t in result.tests] == ["t::a"]
```

`_SEVERITY` (`runner.py:368`) has the same shape of exposure at `runner.py:397`:
`_SEVERITY[event.outcome]` is a total mapping over `TestOutcome` today, so it is
safe — noted only so a future outcome value is added to both.

---

### F-09 — `QProcess.errorOccurred` is never connected: a failed start hangs silently (severity 7)

**Location:** `src/gui/run_controller.py:48-64`.

```python
        self._process = QProcess(self)
        self._process.setWorkingDirectory(str(paths.project_root()))
        self._process.setProcessChannelMode(QProcess.ProcessChannelMode.MergedChannels)
        self._process.readyReadStandardOutput.connect(self._on_output)
        self._process.finished.connect(self._on_finished)
        self._process.start(args[0], args[1:])
        self._timer.start()
```

`errorOccurred` is not connected, and `start()`'s return is not checked. When the
process fails to start — `FailedToStart` from a missing interpreter, a frozen build
whose `sys.executable` moved (`runner._launcher`, `runner.py:176-190`), a
working-directory that does not exist — Qt emits `errorOccurred` and **not**
`finished`. So `_on_finished` never runs, `finalize_run` is never called, the
`finished` signal never reaches `MainWindow._on_finished` (`main_window.py:360`),
and `self._timer` polls a file that will never exist, forever. The Log tab shows
`"Starting run…"` and nothing else. The CLI has no equivalent problem: `Popen`
raises, which F-02's boundary would then render.

Related and cheaper to fix at the same time: `stop()` (`run_controller.py:66-68`)
calls `kill()` but never stops `self._timer`, relying on `finished` firing.

**Remediation** — `src/gui/run_controller.py`:

```python
    error = Signal(str)  # emits a human-readable failure reason

    def start(self, request: RunRequest) -> None:
        ...
        self._process.readyReadStandardOutput.connect(self._on_output)
        self._process.finished.connect(self._on_finished)
        self._process.errorOccurred.connect(self._on_error)
        self._process.start(args[0], args[1:])
        self._timer.start()

    def _on_error(self, error: QProcess.ProcessError) -> None:
        """A QProcess that fails to start never emits `finished`, so without
        this the run's timer polls a file that will never exist and the GUI
        reports nothing at all."""
        if error is not QProcess.ProcessError.FailedToStart:
            return  # Crashed/Timedout still deliver `finished`
        self._timer.stop()
        proc = self._process
        self.error.emit(
            f"Could not start the test runner: {proc.errorString() if proc else 'unknown error'}"
        )
        if self._result is not None and self._run_dir is not None:
            self.finished.emit(finalize_run(self._result, self._run_dir, None))
```

And in `src/gui/main_window.py:60-64`:

```python
        self._controller.error.connect(self._on_controller_error)
```

```python
    def _on_controller_error(self, message: str) -> None:
        self._log_panel.append_line(message)
```

---

### F-11 — `PacketRecorder._handle` uses `assert`, and sink errors kill the capture in silence (severity 6)

**Location:** `src/packet_engine/recorder.py:89-96`.

```python
    def _handle(self, packet: Packet) -> None:
        # Called from the sniffer thread for every matching frame.
        assert self._writer is not None
        self._writer.write(packet)
        with self._lock:
            self._packet_count += 1
        for sink in self._sinks:
            sink(packet)
```

Two problems, both on the sniffer thread:

1. `assert` is stripped under `python -O`, turning a genuine ordering bug
   (`_handle` after `_close_writer`) into `AttributeError: 'NoneType' object has no
   attribute 'write'` — still on the sniffer thread. This is the recorder's only
   invariant check and it is the one construct that can be compiled away.
2. Any exception from `self._writer.write` (disk full, path removed) or from a
   sink propagates into Scapy's `AsyncSniffer`, whose `_run_catch`
   (`scapy/sendrecv.py:1163-1168`) stores it on `self.exception` and ends the
   thread. Nothing reads that attribute until `stop()`/`join()`, so the capture
   ends and the CLI keeps printing `"Press Ctrl+C to stop."` over a dead sniffer.

Note `NetworkInterface.subscribe` (`interface.py:66-77`) documents the opposite
policy deliberately — sink exceptions are *not* caught, because there they run on
the test's own thread and a broken sink should fail the test. That reasoning does
not carry over to a background sniffer thread, where the exception is invisible.

**Remediation** — `src/packet_engine/recorder.py`:

```python
import logging

log = logging.getLogger(__name__)


    def _handle(self, packet: Packet) -> None:
        """Called from the sniffer thread for every matching frame.

        Nothing here may raise: an exception on this thread is stored by
        Scapy's AsyncSniffer and silently ends the capture, so a failing
        sink would stop the recording without any caller finding out.
        """
        writer = self._writer
        if writer is None:  # not an assert: `-O` would strip the only guard
            log.warning("Dropping a frame recorded after the writer closed")
            return
        writer.write(packet)
        with self._lock:
            self._packet_count += 1
        for sink in self._sinks:
            try:
                sink(packet)
            except Exception:
                log.exception("A recorder sink raised; continuing the capture")
```

---

### F-18 — `record`'s `finally: recorder.stop()` re-raises out of the finally clause (severity 6)

**Location:** `src/cli/main.py:376-387`, `src/packet_engine/recorder.py:119-124`.

```python
    try:
        if count or duration:
            recorder.join()
        else:
            click.echo("Press Ctrl+C to stop.")
            while True:
                time.sleep(0.5)
    except KeyboardInterrupt:
        click.echo("\nStopping…")
    finally:
        written = recorder.stop()
        click.echo(f"Wrote {written} packet(s) to {output_path}")
```

Scapy's `AsyncSniffer` sets `self.running = True` *before* opening the socket
(`scapy/sendrecv.py:1196`), so when the socket fails (bad `--iface`, invalid
`--filter` BPF expression) the thread dies with `running` still true and the
exception stored. `PacketRecorder.stop()` (`recorder.py:121`) then calls
`self._sniffer.stop()`, which re-raises that stored exception
(`scapy/sendrecv.py:1412-1413`). Because that happens inside `finally:`:

- the operator gets a raw traceback rather than "could not capture on `eth9`";
- `_close_writer()` (`recorder.py:123`) is never reached, leaking the `PcapWriter`;
- the `"Wrote N packet(s)"` line never prints;
- during a Ctrl+C shutdown, the new exception replaces the `KeyboardInterrupt`
  path's clean exit.

`recorder.join()` on the bounded path (`cli/main.py:378`) has the same shape:
`AsyncSniffer.join` re-raises at `scapy/sendrecv.py:1430-1431`, and the only
handler in scope catches `KeyboardInterrupt`.

**Remediation** — surface the failure where it happens, and never let the cleanup
path raise. `src/packet_engine/recorder.py`:

```python
    def stop(self) -> int:
        """Stop an unbounded capture. Returns the number of packets written.

        Scapy stores a sniffer-thread exception and re-raises it here, so it
        is translated rather than escaping from a caller's `finally:` block.
        """
        try:
            if self._sniffer is not None and self._sniffer.running:
                self._sniffer.stop()
        except Exception as exc:
            raise CaptureError(
                f"Capture on {self.iface!r} failed: {exc}. Check the interface name "
                f"and the BPF filter ({self.bpf_filter!r})."
            ) from exc
        finally:
            self._close_writer()
        return self.packet_count
```

with `class CaptureError(NetstackError)` added to `src/errors.py`. The F-02
boundary then renders it as one line. `join()` deserves the identical treatment.

---

### F-12 — `EchoBackend.start()` leaks a live TCP listener when the UDP bind fails (severity 6)

**Location:** `src/proxy/backend.py:97-113`, `src/gui/proxy_panel.py:91-112`.

`start()` binds TCP, spawns the accept thread, then binds UDP:

```python
        self._spawn(self._accept_loop, "echo-backend-tcp")
        self._emit(f"TCP echo backend listening on {self.host}:{self.bound_port}")

        if self.enable_udp:
            self._udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._udp_socket.bind((self.host, self.bound_port))   # can raise
```

If the UDP bind raises `OSError` (the port is taken by another process's UDP
socket — common, since `SO_REUSEADDR` was set only on this socket), the exception
leaves `start()` with the TCP listener bound and its accept thread running. In the
GUI (`proxy_panel.py:94-105`) the `except OSError` correctly reports the failure —
but `self._backend = backend` at `:106` is never reached, so the panel holds no
reference, `_stop()` is a no-op, and `MainWindow.closeEvent`'s
`self._proxy_panel.shutdown()` (`main_window.py:242`) cannot release the port.
The listener survives until the process exits, and "Start backend" can be clicked
again to bind another.

**Remediation** — make `start()` atomic. `src/proxy/backend.py`:

```python
    def start(self) -> None:
        """Bind and serve. All-or-nothing: a partial start releases whatever
        it already bound, so a failed start never leaves an orphan listener
        that only process exit can reclaim."""
        try:
            self._tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._tcp_socket.bind((self.host, self.port))
            self._bound_port = self._tcp_socket.getsockname()[1]
            self._tcp_socket.listen(64)
            self._tcp_socket.settimeout(0.5)

            if self.enable_udp:
                self._udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self._udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self._udp_socket.bind((self.host, self.bound_port))
                self._udp_socket.settimeout(0.5)
        except OSError:
            self.stop()
            raise

        self._spawn(self._accept_loop, "echo-backend-tcp")
        self._emit(f"TCP echo backend listening on {self.host}:{self.bound_port}")
        if self.enable_udp:
            self._spawn(self._udp_loop, "echo-backend-udp")
            self._emit(f"UDP echo backend listening on {self.host}:{self.bound_port}")
```

Both sockets are now bound before either thread starts, so `stop()`'s existing
close-and-join (`backend.py:115-127`) cleans up correctly on any failure.

---

### F-13 — `ProxyClient.connect()` leaks the socket when the handshake raises (severity 6)

**Location:** `src/proxy/client.py:41-53`.

```python
    def connect(self) -> "ProxyClient":
        host, port = self.config.dial_target
        self._sock = socket.create_connection((host, port), timeout=self.config.timeout)
        self._sock.settimeout(self.config.timeout)
        handshake = handshakes.for_config(self.config)
        try:
            self.details = handshake.establish(self._sock, self._recv_exact, self.config.origin)
        except ProxyTunnelError as exc:
            self.details = exc.details
            raise
        return self
```

The `except` records `details` and re-raises without closing `self._sock`. And
`__enter__` (`:62-63`) *is* `connect()`, so when `connect()` raises, Python never
calls `__exit__` — the `with ProxyClient(...)` form leaks too.

This is exercised constantly: `TrafficInducer._loop` (`inducer.py:88-93`) opens a
`with ProxyClient(...)` every 250 ms for the whole session. Against a DUT that
refuses CONNECT, that is ~4 leaked sockets per second — ~14,000 over an hour-long
back-leg run, exhausting the file-descriptor limit long before that. The
`ProxyTunnelError` path is the *expected* result for the refusal-conformance tests
in `tests/proxy/test_proxy_http_connect.py` and `test_proxy_socks5.py`.

Note the handler also only catches `ProxyTunnelError`; a `ConnectionError` or
`ValueError` from `tunnel.py` leaks identically with no `details` recorded.

**Remediation** — `src/proxy/client.py`:

```python
    def connect(self) -> "ProxyClient":
        host, port = self.config.dial_target
        self._sock = socket.create_connection((host, port), timeout=self.config.timeout)
        self._sock.settimeout(self.config.timeout)
        handshake = handshakes.for_config(self.config)
        try:
            self.details = handshake.establish(
                self._sock, self._recv_exact, self.config.origin
            )
        except BaseException as exc:
            # `connect()` IS `__enter__`, so raising here means `__exit__`
            # never runs — this is the only place the socket can be released.
            self.details = getattr(exc, "details", None)
            self.close()
            raise
        return self
```

`close()` (`:55-60`) is already idempotent and nulls `_sock`, so a later `close()`
from the caller is harmless.

---

### F-10 — `PacketEventLogWriter` is written from the sniffer thread without a lock (severity 5)

**Location:** `src/reporting/collector.py:17-31`, wired at `conftest.py:239-246`,
called from `NetworkInterface._record` (`interface.py:133-134`).

```python
    def __call__(self, event: PacketEvent) -> None:
        self._file.write(json.dumps(event.to_dict()) + "\n")
        self._file.flush()

    def close(self) -> None:
        self._file.close()
```

`NetworkInterface._record` runs on whichever thread produced the frame. `sniff()`
(`interface.py:105`) returns on the caller's thread, but `DebugLogger` — the
other per-packet writer — takes an explicit `threading.Lock` for exactly this
reason and says so (`debug_log.py:85-88`: *"Packet lines may arrive from the
sniffer thread as well as the main test thread, so every write is serialized"*).
`_record` even takes `self._lock` for the pcap write (`interface.py:116`). The
jsonl writer is the one per-packet sink with no lock, and it is the one the
parent process tails.

Second issue: teardown ordering in `conftest.py:247-250` is `iface.close()` then
`writer.close()`, which is right — but nothing prevents a late frame from calling
a closed writer, which raises `ValueError: I/O operation on closed file` from
inside `_record`.

**Remediation** — `src/reporting/collector.py`:

```python
class PacketEventLogWriter:
    """Appends PacketEvents as JSON lines, flushing immediately so a
    tailing reader (src/runner.py, in the parent process) sees them
    promptly rather than waiting on OS write buffering.

    Writes are serialized: events reach this sink from the sniffer thread as
    well as the test thread (the same reason DebugLogger holds a lock), and
    two interleaved writes would hand the tailing parser a corrupt line.
    """

    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._file = path.open("a", encoding="utf-8")
        self._lock = threading.Lock()
        self._closed = False

    def __call__(self, event: PacketEvent) -> None:
        line = json.dumps(event.to_dict())
        with self._lock:
            if self._closed:
                return  # a frame recorded after teardown is not worth raising over
            self._file.write(line + "\n")
            self._file.flush()

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._closed = True
                self._file.close()
```

(`import threading` at the top.) This mirrors `DebugLogger.close`
(`debug_log.py:137-141`), which already guards on `self._file.closed`.

---

### F-14 — `TrafficInducer` spins through a permanent failure for the whole session (severity 4)

**Location:** `src/proxy/inducer.py:84-97`.

```python
            except Exception as exc:  # refusal/timeout is a DUT result, not our error
                with self._lock:
                    self._last_error = f"{type(exc).__name__}: {exc}"
```

The module docstring justifies counting rather than raising, and that is right for
a *refusal*. But the handler cannot tell a refusal from a permanent
misconfiguration — an unresolvable `--backend-host` (`socket.gaierror`) or a
`ValueError` from `ProxyConfig` — and only the *last* error survives, so a run
that failed identically 14,000 times reports one string at teardown
(`tests/conftest.py:56`). Every server-role test in the run then times out with no
indication that the inducer never connected once.

**Remediation** — keep counting, but distinguish and escalate:

```python
    def _loop(self) -> None:
        consecutive_failures = 0
        while not self._stop.is_set():
            with self._lock:
                self._attempts += 1
            try:
                with ProxyClient(self.config) as client:
                    client.roundtrip(self.payload)
            except Exception as exc:  # refusal/timeout is a DUT result, not our error
                consecutive_failures += 1
                with self._lock:
                    self._last_error = f"{type(exc).__name__}: {exc}"
                    self._error_counts[type(exc).__name__] = (
                        self._error_counts.get(type(exc).__name__, 0) + 1
                    )
                # Back off once it is clearly not transient: at 4 Hz an
                # unreachable backend otherwise burns the whole session.
                if consecutive_failures >= 10:
                    self._stop.wait(min(self.interval * consecutive_failures, 5.0))
            else:
                consecutive_failures = 0
                with self._lock:
                    self._successes += 1
            self._stop.wait(self.interval)

    def summary(self) -> str:
        with self._lock:
            text = f"induced {self._successes}/{self._attempts} connections through the proxy"
            if self._error_counts:
                breakdown = ", ".join(
                    f"{name}×{count}" for name, count in sorted(self._error_counts.items())
                )
                text += f" (failures: {breakdown}; last: {self._last_error})"
            return text
```

with `self._error_counts: dict[str, int] = {}` added to `__init__`.

---

## 4. Error recovery

### F-15 — `DUTConfig.retries` is declared and never read (severity 5)

**Location:** `src/config.py:163`.

```python
    timeout: float = 2.0
    retries: int = 2
```

`grep -rn retries src/ tests/ conftest.py` finds the declaration, the unrelated
`syn_ack_retries` profile field, and one test that sets it
(`tests_internal/test_proxy_leg.py:57`). No production code reads it. Meanwhile
`dut_config.timeout` is read at 31 sites across `tests/`. A reader of the config
object reasonably concludes the suite retries; it does not, anywhere.

This is a genuine design question, not a pure oversight: for RFC conformance
testing, a silent retry can *mask* the defect under test (a DUT that answers the
second SYN but not the first has a bug the retry would hide). But that argument
should be written down, and the field removed if it holds.

**Remediation, option A (recommended)** — delete the field and say why:

```python
    timeout: float = 2.0
    # There is deliberately no `retries` here. A conformance suite that
    # silently retries hides the defect it exists to find: a DUT that answers
    # the second probe but not the first has a bug, and a retry would report
    # it as a pass. Tests that legitimately need repetition (the congestion
    # and flood suites) loop explicitly, where the count is part of the
    # assertion.
```

Then drop `retries=7` from `tests_internal/test_proxy_leg.py:57`.

**Option B** — honour it in the one place a retry is defensible, the
preflight ARP probe (`preflight.py:66-71`), where a lost ARP is genuinely
transient and not the thing under test:

```python
        reply = None
        for attempt in range(1 + max(config.retries, 0)):
            reply = srp1(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=config.target_ip),
                iface=config.interface, timeout=timeout, verbose=False,
            )
            if reply is not None:
                break
```

Pick one; the current state (declared, documented by its name, never honoured) is
the only option that misleads.

---

### F-16 — A report-generation failure discards the run's verdict (severity 7)

**Location:** `src/cli/main.py:107-134`.

```python
def _emit_results(result, run_dir: Path, *, report: str, debug: bool) -> int:
    ...
    fmt = formats.BY_KEY.get(report)
    if fmt is not None:
        click.echo(f"{fmt.label} report: {fmt.generate(result, artifacts.report(fmt.key))}")

    return 1 if (result.failed or result.errors) else 0
```

`--report pdf` is the **default** (`cli/main.py:154`). `generate_pdf_report`
(`pdf_report.py:53-133`) runs reportlab's `doc.build`, two matplotlib renders
(`static_charts.py:32`, via a `TemporaryDirectory`), and `result.started_at.isoformat()`
at `pdf_report.py:69` — which raises `AttributeError` if `started_at` is ever
`None`. Any of these failing (no write permission on `reports/`, a full disk, a
matplotlib backend problem, a font issue) raises *after* every test has already
run against the DUT, and:

- the `return` at `:134` never executes, so the process exits on the traceback
  instead of the run's real pass/fail code;
- the operator loses the verdict of a run that may have taken an hour;
- `results.json` was already written by `finalize_run` (`runner.py:274`), so the
  data survives — but nothing tells the operator that, or that
  `reporting.collector.load_run_result` can regenerate the report from it.

The GUI has the mirror-image bug at `ReportPanel._export` — see F-17.

**Remediation** — `src/cli/main.py`:

```python
def _emit_results(result, run_dir: Path, *, report: str, debug: bool) -> int:
    """Print the run's outcome, write the report, and return the exit code.

    Report generation is best-effort on purpose: the tests have already run
    against the DUT by this point, and a reportlab/matplotlib failure must
    not cost the operator the run's verdict. results.json is already on disk,
    so the report can be regenerated with reporting.collector.load_run_result.
    """
    artifacts = RunArtifacts(run_dir)
    ...
    fmt = formats.BY_KEY.get(report)
    if fmt is not None:
        try:
            output = fmt.generate(result, artifacts.report(fmt.key))
            click.echo(f"{fmt.label} report: {output}")
        except Exception as exc:
            log.exception("Report generation failed")
            click.echo(
                f"Could not write the {fmt.label} report: {exc}\n"
                f"The run itself completed; its data is in {artifacts.results} and the "
                "report can be regenerated from it.",
                err=True,
            )

    return 1 if (result.failed or result.errors) else 0
```

---

### F-17 — `ReportPanel._export` is unguarded inside a Qt slot (severity 6)

**Location:** `src/gui/report_panel.py:49-67`.

```python
        if path_str:
            output = fmt.generate(self._result, Path(path_str))
            self._status_label.setText(f"{fmt.label} written to {output}")
```

Reached from `button.clicked.connect(...)` at `:29`. Same failure modes as F-16 —
plus the likeliest one here, since `QFileDialog.getSaveFileName` lets the user
pick any path, including a read-only directory. With no handler, the exception
leaves a Qt slot (see F-08 on what PySide6 6.11 does with that).

**Remediation** — `src/gui/report_panel.py`:

```python
        if not path_str:
            return
        try:
            output = fmt.generate(self._result, Path(path_str))
        except Exception as exc:
            self._status_label.setText(f"Could not write the {fmt.label} report: {exc}")
            QMessageBox.warning(
                self,
                f"{fmt.label} export failed",
                f"{exc}\n\nThe run's data is unaffected — try a different location.",
            )
            return
        self._status_label.setText(f"{fmt.label} written to {output}")
```

(add `QMessageBox` to the `PySide6.QtWidgets` import at `:7`).

The same pattern is needed at `MainWindow._on_run_clicked`
(`main_window.py:245-272`), which calls `_current_dut_config()` → `Role(...)`,
`_split_host_port`, and `run_preflight` — all inside a `clicked` slot with no
handler. `run_preflight` itself is well-defended (`preflight.py:72` catches
`Exception` around the ARP probe), but `_current_dut_config` is not.

---

## 5. Error information

### F-19 — `logging` is configured but effectively unused; zero `logger.exception` calls (severity 5)

**Location:** `src/utils/logging_config.py`, and the absence of loggers everywhere else.

`configure_logging()` is called by both entry points (`cli/main.py:63`,
`gui/app.py:35`). A census of what uses it:

```
src/gui/app.py:34:    log = logging.getLogger(__name__)
```

That is the only `getLogger` in `src/`. Every other error is reported by
`click.echo(..., err=True)` (CLI) or by appending to a `QPlainTextEdit` (GUI).
Consequences:

- No error in the GUI is ever written anywhere durable. `LogPanel` caps at 10,000
  blocks (`log_panel.py:14`) and `_on_run_clicked` clears it at the start of every
  run (`main_window.py:248`) — so the evidence of a failed run is destroyed by
  starting the next one.
- Nothing calls `logger.exception`, so no traceback is ever recorded with context.
  The five `except Exception` sites (`gui/custom_packet_panel.py:189`,
  `gui/main_window.py:408`, `packet_engine/preflight.py:72`,
  `proxy/inducer.py:91`, `utils/permissions.py:29`) all discard the traceback,
  keeping at most `str(exc)`.
- The subprocess's raw output *is* captured well (`runner.py:316`,
  `RunArtifacts.PYTEST_OUTPUT`) and both front ends point at it on failure
  (`cli/main.py:115`, `main_window.py:366`) — this is the one piece of the picture
  that is done properly, and it is worth matching for the parent process.

**Remediation** — add a per-run file handler alongside the stream handler:

```python
"""Central logging configuration, shared by the CLI and GUI entry points."""
from __future__ import annotations

import logging
import sys
from pathlib import Path

LOG_FORMAT = "%(asctime)s %(levelname)-8s %(name)s: %(message)s"


def configure_logging(level: int = logging.INFO, *, log_file: Path | None = None) -> None:
    """Console logging, plus an optional durable file.

    The GUI's log panel is cleared at the start of every run and capped at
    10,000 blocks, so without a file the only record of a failed run is gone
    the moment the next one starts.
    """
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stdout)]
    if log_file is not None:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(log_file, encoding="utf-8"))
    logging.basicConfig(
        level=level, format=LOG_FORMAT, datefmt="%H:%M:%S", handlers=handlers, force=True
    )
```

and in `src/gui/app.py:35`:

```python
    from src import paths

    configure_logging(log_file=paths.reports_base() / "reports" / "gui.log")
```

`paths.reports_base()` (`paths.py:270`) is already the frozen-aware writable base,
so this lands next to the exe in a packaged build.

---

### F-20 — `_list_interface_names` swallows the reason; the operator sees an empty dropdown (severity 5)

**Location:** `src/gui/main_window.py:403-409`.

```python
def _list_interface_names() -> list[str]:
    try:
        from scapy.interfaces import get_working_ifaces

        return [iface.name for iface in get_working_ifaces()]
    except Exception:
        return []
```

The most likely cause of this failing on Windows is that Npcap is not installed —
which is exactly the condition `remediation_message()` (`permissions.py:52-58`)
exists to explain. Instead, the Interface combo box (`main_window.py:91`) is
silently empty, `_current_dut_config` produces `interface=""`,
`missing_required()` reports "Interface", and the preflight says
`Missing required configuration: Interface` — which reads as *you forgot to pick
one*, not *the packet driver is missing*.

**Remediation** — `src/gui/main_window.py`:

```python
def _list_interface_names() -> list[str]:
    """Working interfaces, or an empty list with the reason logged.

    An empty combo box here almost always means the packet driver is missing
    (Npcap on Windows), which reads to the operator as "you forgot to pick an
    interface" — so the reason must not be discarded.
    """
    try:
        from scapy.interfaces import get_working_ifaces

        return [iface.name for iface in get_working_ifaces()]
    except Exception:
        logging.getLogger(__name__).exception("Could not enumerate network interfaces")
        return []
```

and surface it in the UI where the user is looking:

```python
        self._iface_combo = QComboBox()
        names = _list_interface_names()
        self._iface_combo.addItems(names)
        if not names:
            self._iface_combo.setToolTip(remediation_message())
            self._iface_combo.setPlaceholderText("No interfaces found — see tooltip")
```

(`from src.utils.permissions import remediation_message`.)

---

### F-21 — `is_elevated` reports a ctypes failure as "not elevated" (severity 3)

**Location:** `src/utils/permissions.py:22-35`.

```python
    if system == "Windows":
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
```

Failing closed is right. But the caller chain — `require_elevation` (`:69`) →
`InsufficientPrivilegesError(remediation_message())` → `run_preflight` (`:52`) →
`"Insufficient privileges to open a raw socket."` — then tells an operator who
*is* running as Administrator to re-run as Administrator. Logging the swallowed
exception costs one line and makes the impossible-looking case diagnosable:

```python
        except Exception:
            logging.getLogger(__name__).exception(
                "The Windows elevation check failed; assuming not elevated"
            )
            return False
```

---

### F-22 — No verbosity control; `configure_logging` is INFO-only (severity 3)

**Location:** `src/utils/logging_config.py:8`, `src/cli/main.py:63`.

`configure_logging()` is called with no arguments from both entry points, so the
level is always INFO and there is no `--verbose` / `--quiet` flag anywhere. A
development-vs-production split in error detail mostly does not apply to a
locally-run engineering tool — there is no untrusted user to withhold a stack
trace from, and exposing one is the right default here. What *is* missing is the
opposite direction: no way to turn detail *up* when diagnosing a problem.

Note `--debug` already exists and is well-built, but it is a different thing: it
writes the per-packet tshark-style trace (`utils/debug_log.py`), not application
logging.

**Remediation** — `src/cli/main.py`:

```python
@click.group(cls=NetstackCLI)
@click.option("-v", "--verbose", is_flag=True, default=False,
              help="DEBUG-level application logging (distinct from --debug, "
                   "which writes the per-packet trace).")
def cli(verbose: bool) -> None:
    """Network Stack Test Suite — RFC conformance & vulnerability testing over Ethernet."""
    configure_logging(logging.DEBUG if verbose else logging.INFO)
```

---

## What is already done well

Worth recording so a future change does not undo it:

- **`PreflightResult`** (`preflight.py:25-38`) separates blockers from warnings
  with the rationale written down — *no ARP reply is a warning, not a blocker,
  because the DUT may deliberately not implement ARP*. Both front ends honour the
  distinction identically (`cli/main.py:222-224`, `main_window.py:318-320`).
- **`ProxyTunnelError.details`** (`handshakes.py:36-38`) carries the DUT's own
  error report, which is what lets a conformance test assert "refused with a
  defined code" rather than merely "raised".
- **`parse_report_log_line`** (`runner.py:423-471`) derives an outcome from
  whichever pytest phase carries the verdict, and `drain_test_events`
  (`runner.py:397`) applies a worst-wins severity table — the comment at
  `runner.py:382-385` records that the previous call-only parser dropped every
  setup-phase error, i.e. exactly the "run did nothing" case.
- **`result.errored`** (`models.py:225-229`) distinguishes *pytest failed to run*
  from *tests failed*, and both front ends report it distinctly and point at
  `pytest_output.log` (`cli/main.py:112-118`, `main_window.py:362-367`).
- **`_registered_markers`** (`runner.py:57-78`) degrades to an empty set with the
  consequence spelled out: *"reports then show no markers, which is a cosmetic
  loss, never a failed run."* That is the model the rest of the package should
  follow.
- **The undrained-PIPE hazard** is handled and documented (`runner.py:311-315`) —
  subprocess output goes to a file precisely because an unread PIPE would deadlock
  pytest under `-v`.
- **`open_pcap`'s `sync=True`** (`pcap.py:16-24`) keeps a capture valid across an
  abrupt exit, and `DebugLogger` flushes every line (`debug_log.py:128`).

---

## Suggested order of application

1. **F-05** (vuln gate) — safety-relevant and self-contained.
2. **F-08** (drain guards) — highest-frequency crash, both front ends, with a
   reproduction and a regression test already written above.
3. **F-01 + F-02** (hierarchy + boundary) — F-03, F-06, F-16, F-18 all depend on
   the base class existing.
4. **F-09, F-12, F-13** (lifecycle leaks) — each is a small, local edit.
5. **F-16, F-17, F-18** (recovery around report generation and capture teardown).
6. **F-11, F-10, F-14** (thread-boundary hardening).
7. **F-19 – F-22** (information), **F-04, F-07, F-15** (categorisation cleanups).

After each step: `pytest tests_internal/ -q` (220 passing at `4653b25`),
`pytest --collect-only -q`, `ruff check .` (`C901`, max-complexity 10 — the
`try/except` additions in F-08 and F-16 add branches to functions currently at or
near the limit, so re-check rather than assume).
