# Code Duplication Audit — netstack-test-suite

**Date:** 2026-09-10
**Commit:** `db76783` (branch `development`)
**Scope:** all 12,162 lines of Python across `src/`, `tests/`, `tests_internal/`, `conftest.py`, `tools/`, `packaging/`, plus `pyproject.toml`, `NetstackTestSuite.spec` and `.github/workflows/`.
**Method:** full read of every `src/` module and every test module; pattern counting with `grep` for repeated constants, call shapes and assertion idioms.

---

## Executive summary

The `src/` layer is, on the whole, well factored — `runner.py` is genuinely shared by both front ends, `packet_engine/builders.py` is the single packet factory, `report_data.py` is the single enrichment layer for both reports. The duplication that exists clusters in four places:

| Cluster | Where | Weight |
|---|---|---|
| Protocol constants re-declared per module | 13 test modules + 2 `src/` modules | ~60 duplicated declarations |
| Test-crafting / assertion boilerplate | 23 test modules under `tests/` | ~51 `wrap_ethernet(build_*(...))` blocks, 63 hand-typed node ids |
| The proxy-leg → role → retarget rule | `cli/main.py`, `conftest.py`, `gui/main_window.py` | 3 independent implementations of one safety-relevant rule |
| CLI option surface | `cli/main.py` vs `conftest.py` | ~20 options declared twice with copy-pasted help text |

Nineteen findings follow, ordered by importance. **All nineteen have since been applied** — see the status section immediately below. Each finding keeps its original analysis and its remediation snippet, so the record of *what was wrong and why* survives alongside the fix.

**Duplication percentage** below means: identical lines ÷ lines of the smaller of the two blocks compared, counted on non-blank, non-comment lines.

---

## Status: all 19 findings applied

Every finding below was applied on branch `development`, in the priority order
this report set out. Verification after the final change:

- `pytest tests_internal/ -q` -> **176 passed** (172 originally, plus 4 new
  regression guards)
- `pytest tests/ --collect-only -q` -> **81 tests collected**, no import errors
- `pyflakes src/ tests/ tests_internal/ conftest.py` -> clean

New shared modules created in the process:

| Module | Replaces |
|---|---|
| `src/utils/tcp_flags.py` | flag bits in 15 modules, `MAX_SEQ` in 2, `& 0xFFFFFFFF` in 18 places |
| `src/cli/options.py` | ~12 options declared twice (click + pytest) |
| `src/packet_engine/pcap.py` | duplicate `PcapWriter` construction |
| `.github/workflows/build.yml` | two near-identical build jobs |
| `tests_internal/test_no_duplication_regressions.py` | nothing — new guards so four of these patterns cannot return |

New shared fixtures in `tests/conftest.py`: `nodeid`, `craft`, `source_port`,
`source_ports`, `assert_dut_alive`. New shared helpers: `resolve_role`,
`resolve_leg_target`, `back_leg_requirement_error` (`src/config.py`);
`new_run_result`, `finalize_run` (`src/runner.py`); `counts_summary`,
`summary_line`, `OUTCOME_STYLE` (`src/reporting/models.py`); the report copy
constants in `src/reporting/report_data.py`.

Net: **1,210 insertions, 1,412 deletions across 67 files** — a little over
200 lines removed, with the shared definitions being the larger part of what
was added.

Two things worth flagging:

- **The guards are verified to fail.** Injecting a `SYN = 0x02`, a hardcoded
  `sport=41100`, and a literal `test_nodeid=` into a test file made three of
  the four guards fail as intended; the injections were then reverted.
- **`tests_internal/test_proxy_relay.py::test_transparent_roundtrip_echoes_payload`
  flaked once** during this work and passed on eight consecutive re-runs plus
  three full-suite runs. It is a real-socket loopback echo test with timeouts.
  The two edits touching that path were value-identical constant extractions
  (`RECV_CHUNK`, `DEFAULT_BACKEND_PORT`), so this looks pre-existing rather
  than introduced — but it is called out rather than passed over.

What was **deliberately not** shared, and why, is recorded in the module
docstring of `src/cli/options.py`: `--dut-ip` / `--target-stack` are required
on the CLI but optional for pytest, `--iface` and `--dut-iface` are different
flag names, and `--allowed-target(s)` differs in both name and mechanism
(click `multiple=True` vs pytest `action="append"`). Forcing those through the
shared declaration would have needed a special case each, which is worse than
two honest declarations.

---

## The utilities module

**`src/utils/tcp_flags.py`** — TCP flag bits, the 32-bit sequence-space mask, and predicates over a received packet.

Exports: `FIN SYN RST PSH ACK URG ECE CWR`, `SYN_ACK`, `FIN_ACK`, `FLAG_NAMES`, `MAX_SEQ`, `seq32()`, `flags_of()`, `has_flags()`, `any_flags()`, `is_syn_ack()`, `is_bare_syn_ack()`, `is_bare_syn()`, `is_rst()`, `is_ack()`, `flag_labels()`.

`has_flags` is an all-of test and `any_flags` an any-of test — the distinction matters, because `flags & (SYN | RST)` in the original code meant "SYN *or* RST" while `flags & (SYN | ACK) == (SYN | ACK)` meant "SYN *and* ACK". Both idioms appeared, and collapsing them into one predicate would have silently changed several assertions.

Adopted across `src/` (`sequence.py`, `responder.py`, `debug_log.py`) and every TCP test module. `sequence.py` re-exports `MAX_SEQ` via `__all__` so nothing importing it breaks.

---

## Findings

### F-01 — TCP flag constants re-declared in 13 modules · **Importance 9/10** · EXACT DUPLICATE

**Duplication: 100%** — the same four assignments, byte-identical, in 13 files.

`SYN = 0x02` / `ACK = 0x10` / `RST = 0x04` / `FIN = 0x01` appear independently at:

| File | Lines |
|---|---|
| `tests/tcp/state_machine/conftest.py` | 18–21 |
| `tests/tcp/state_machine/test_syn_received_state.py` | 30–32 |
| `tests/tcp/state_machine/test_rst_edge_cases.py` | 14–15 |
| `tests/tcp/state_machine/test_rst_handling.py` | 11 |
| `tests/tcp/state_machine/test_connection_termination.py` | 9 |
| `tests/tcp/state_machine/test_simultaneous_open_close.py` | 19 |
| `tests/tcp/syn/test_invalid_syn_flags.py` | 19–22 |
| `tests/tcp/syn/test_three_way_handshake.py` | 12–14 |
| `tests/tcp/syn/test_tcp_options.py` | 18–19 |
| `tests/tcp/syn/test_syn_flood.py` | 14–15 |
| `tests/tcp/syn/test_server_handshake.py` | 15–16 |
| `tests/tcp/congestion/test_zero_window.py` | 18–20 |
| `tests/tcp/congestion/test_retransmission_timeout.py` | 13–14 |

Plus `_SYN_ACK = 0x12` at `tests/tcp/conftest.py:18` and `SYN_ACK = SYN | ACK` at `test_syn_received_state.py:33` — two spellings of one value.

**Why it matters:** these are wire-format constants. A single wrong digit in one file produces a test that silently asserts the wrong thing against a DUT, and there is no cross-check between the copies.

**Status:** applied. All 15 local declarations removed; `tests_internal/test_no_duplication_regressions.py::test_no_locally_redefined_tcp_flags` now fails the build if one returns.

**Remediation** — per test module, delete the local block and import:

```python
# tests/tcp/syn/test_three_way_handshake.py — replace lines 12-14
from src.utils.tcp_flags import ACK, RST, SYN          # noqa: F401  (used in lfilters)
```

and collapse the assertion idiom:

```python
# before
assert reply.haslayer(TCP)
assert reply[TCP].flags & (SYN | ACK) == (SYN | ACK)
# after
from src.utils.tcp_flags import is_syn_ack
assert is_syn_ack(reply), "DUT did not answer the SYN with a SYN-ACK"
```

`tests/tcp/state_machine/conftest.py` keeps its re-export so the `from .conftest import ACK, RST, SYN, ...` lines in `test_challenge_ack.py:23`, `test_established_segment_validation.py:184` and `test_fin_close_transitions.py:329` need no edit:

```python
# tests/tcp/state_machine/conftest.py — replace lines 18-21
from src.utils.tcp_flags import ACK, FIN, RST, SYN     # noqa: F401  (re-exported to sibling modules)
```

**Effort:** 1.5 h (13 files, mechanical, `pytest tests/ --collect-only` verifies).

---

### F-02 — The proxy-leg rule is implemented three times · **Importance 9/10** · NEAR DUPLICATE

**Duplication: ~80%** structurally; three implementations, three slightly different behaviours.

One rule — *a proxy leg determines the role, and a FRONT leg retargets the run to the proxy's front address and port* — is written independently in:

- `src/cli/main.py:142-159` (CLI path)
- `conftest.py:30-46` + `conftest.py:185-215` (pytest subprocess path)
- `src/gui/main_window.py:194-223` (GUI path)

They already differ. `cli/main.py:153` sets the front port only `if dut_port is None`; `conftest.py:210` uses `if leg is ProxyLeg.FRONT and target_port is None`; `main_window.py:211` uses `if not self._dst_port.value() and front_port`. `selected_proxy_leg()` (`conftest.py:30`) and `_selected_proxy_leg()` (`main_window.py:194`) are the same two-line function under two names.

**Why it matters:** this decides *which host the suite fires traffic at*. Three copies of an addressing rule that gates a safety-checked target is the highest-consequence duplication in the repo. The CLI also re-does the work `conftest.py` will redo inside the subprocess, so a divergence shows up as the GUI and CLI probing different ports for the same configuration.

**Remediation** — hoist the rule into `src/config.py` beside `ProxyLeg`, and have all three call it:

```python
# src/config.py — add below ProxyLeg
def resolve_leg_target(
    leg: "ProxyLeg | None",
    *,
    target_ip: str,
    target_port: int | None,
    proxy_host: str | None,
    proxy_port: int | None,
) -> tuple[str, int | None, "Role"]:
    """The single definition of how a proxy leg redirects a run.

    FRONT probes the proxy's client-facing stack, so it retargets to the
    front address and — unless a port was given explicitly — the front
    port (the one port known to be open; a random ephemeral one would
    only measure closed-port behaviour). BACK keeps the configured
    address. The leg always determines the role.
    """
    if leg is None:
        return target_ip, target_port, Role.CLIENT
    if leg is ProxyLeg.FRONT:
        return (
            proxy_host or target_ip,
            target_port if target_port is not None else proxy_port,
            leg.implied_role,
        )
    return target_ip, target_port, leg.implied_role
```

Then each front end becomes a single call; `conftest.dut_config` keeps the `random_ephemeral_port()` fallback for a still-`None` port.

**Effort:** 3 h including a `tests_internal` table test over the three leg values × port-given/omitted.

---

### F-03 — CLI options declared twice, help text copy-pasted · **Importance 8/10** · STRUCTURAL + DATA DUPLICATE

**Duplication: ~90%** on the overlapping options.

`src/cli/main.py:46-108` (`click.option`) and `conftest.py:90-177` (`pytest_addoption`) declare the same option surface twice, with the help strings copied verbatim:

| Option | `cli/main.py` | `conftest.py` | Help text |
|---|---|---|---|
| `--proxy-host` | 98 | 122 | identical: *"Proxy DUT front address (explicit modes)."* |
| `--proxy-port` | 99 | 123 | identical |
| `--backend-port` | 101 | 129 | identical: *"Backend instance listen port."*, default `9099` both |
| `--dut-source-port` | 60-65 | 140-145 | identical: *"Optional fixed local source port for tests that honor it (default: per-test)."* |
| `--proxy-leg` | 89-97 | 113-121 | 9-line paragraph, near-identical |
| `--target-stack` | 66 | 92-97 | choices `["linux", "windows"]` in both |
| `--role`, `--proxy-mode`, `--payload-mode`, `--payload-size`, `--dut-ip`, `--dut-iface`, `--dut-mac`, `--dut-port`, `--allowed-target(s)`, `--confirm-vuln-tests` | 45-108 | 90-177 | overlapping |

`runner.build_pytest_args` (lines 140-190) is the bridge, so the two lists must agree — the module docstring at `conftest.py:5-7` already says so ("must stay in lockstep"), which is a comment where a shared definition belongs.

**Remediation** — declare each shared option once as data and generate both surfaces:

```python
# src/cli/options.py (new)
from dataclasses import dataclass

@dataclass(frozen=True)
class SharedOption:
    name: str            # "--dut-source-port"
    help: str
    type: type | None = None
    default: object = None
    choices: tuple[str, ...] | None = None

SHARED_OPTIONS: tuple[SharedOption, ...] = (
    SharedOption("--proxy-host", "Proxy DUT front address (explicit modes)."),
    SharedOption("--proxy-port", "Proxy DUT front port (explicit modes).", type=int),
    SharedOption("--backend-port", "Backend instance listen port.", type=int, default=9099),
    SharedOption(
        "--dut-source-port",
        "Optional fixed local source port for tests that honor it (default: per-test).",
        type=int,
    ),
    # …
)
```

```python
# conftest.py — replace the hand-written addoption calls for shared options
from src.cli.options import SHARED_OPTIONS

def pytest_addoption(parser):
    group = parser.getgroup("netstack")
    for opt in SHARED_OPTIONS:
        kwargs = {"default": opt.default, "help": opt.help}
        if opt.choices:
            kwargs["choices"] = list(opt.choices)
        elif opt.type:
            kwargs["type"] = opt.type
        group.addoption(opt.name, **kwargs)
    # …run-only options stay here
```

```python
# src/cli/main.py
def shared_options(fn):
    for opt in reversed(SHARED_OPTIONS):
        kwargs = {"default": opt.default, "help": opt.help}
        kwargs["type"] = click.Choice(list(opt.choices)) if opt.choices else opt.type
        fn = click.option(opt.name, **kwargs)(fn)
    return fn
```

**Effort:** 5 h — the largest item here, because the option semantics differ subtly (click `multiple=True` vs pytest `action="append"` for `--allowed-target(s)`, and the flag names themselves differ: singular in click, plural in pytest). Consider doing only the ~10 straightforwardly identical options first; that is a 2 h slice with most of the value.

---

### F-04 — `TestRunResult` construction + `results.json` write duplicated across the two front ends · **Importance 8/10** · EXACT DUPLICATE

**Duplication: 95%** (11 of 11 lines identical bar the assignment target).

`src/runner.py:226-236`:

```python
result = TestRunResult(
    run_id=run_id,
    started_at=datetime.now(timezone.utc),
    finished_at=None,
    target_ip=request.config.target_ip,
    target_stack=request.config.target_stack,
    host_platform=platform.system(),
    payload_mode=request.payload_mode.value,
    role=request.role.value,
    proxy_leg=request.proxy_leg,
)
```

`src/gui/run_controller.py:47-57` is the same eleven lines with `self._result =`. The finish sequence duplicates too — `runner.py:264-266` and `run_controller.py:102-106` both set `pytest_returncode`, set `finished_at`, and write `results.json` with `json.dumps(..., indent=2)`.

This is the *stated* purpose of `runner.py` ("the one code path the CLI and the GUI both drive, so they can never diverge") leaking. `run_controller.py` already reuses `build_pytest_args`, `new_run_dir`, `drain_test_events` and `drain_packet_events` — these two blocks are the leftovers.

**Remediation** — two functions in `src/runner.py`, called from both:

```python
# src/runner.py
def new_run_result(run_id: str, request: RunRequest) -> TestRunResult:
    """The canonical run-header both front ends start from."""
    return TestRunResult(
        run_id=run_id,
        started_at=datetime.now(timezone.utc),
        finished_at=None,
        target_ip=request.config.target_ip,
        target_stack=request.config.target_stack,
        host_platform=platform.system(),
        payload_mode=request.payload_mode.value,
        role=request.role.value,
        proxy_leg=request.proxy_leg,
    )


def finalize_run(result: TestRunResult, run_dir: Path, returncode: int | None) -> TestRunResult:
    """Stamp the outcome and persist results.json — the file
    reporting/collector.load_run_result() reads back."""
    result.pytest_returncode = returncode
    result.finished_at = datetime.now(timezone.utc)
    (run_dir / "results.json").write_text(
        json.dumps(result.to_dict(), indent=2), encoding="utf-8"
    )
    return result
```

```python
# src/runner.py stream_run — replace lines 226-236
    result = new_run_result(run_id, request)
# …and lines 264-266
    finalize_run(result, run_dir, proc.returncode)

# src/gui/run_controller.py start() — replace lines 47-57
        self._result = new_run_result(run_id, request)
# …_on_finished, replace lines 102-106
        finalize_run(self._result, self._run_dir, exit_code)
```

**Effort:** 45 min. Covered by existing `tests_internal/test_runner_args.py`.

---

### F-05 — Per-test hand-typed node ids · **Importance 7/10** · STRUCTURAL DUPLICATE

**63 occurrences** across `tests/`. Every test repeats its own function name as a string literal:

```python
# tests/tcp/syn/test_three_way_handshake.py:23
reply = network_interface.send_receive(
    packet, timeout=dut_config.timeout, test_nodeid="test_syn_elicits_syn_ack"
)
```

`test_tcp_options.py` threads it through a helper parameter (`nodeid` at lines 27, 60, 71, 82, 93, 104, 118); `test_challenge_ack.py`, `test_established_segment_validation.py` and `test_fin_close_transitions.py` assign `nodeid = "<own name>"` as the first statement of every test.

**Why it matters:** the literal is what stitches a packet in `capture.pcap` / `debug.log` to the test that sent it. Rename a test and the literal silently goes stale — nothing checks it, and the trace then attributes packets to a test that no longer exists. `tests/tcp/congestion/test_zero_window.py` already drifted: all four of its tests report `test_nodeid="zero_window"` / `"zero_window_persist"`, matching no test name.

**Remediation** — one autouse-free fixture in `tests/conftest.py`, and pass it instead of a literal:

```python
# tests/conftest.py
@pytest.fixture
def nodeid(request: pytest.FixtureRequest) -> str:
    """This test's real pytest node id, for packet attribution in the
    pcap/debug log. Always accurate under rename and parametrization —
    unlike the hand-typed literals it replaces."""
    return request.node.nodeid
```

```python
# any test
def test_syn_elicits_syn_ack(network_interface, dut_config, local_mac, dut_mac, local_ip, nodeid):
    reply = network_interface.send_receive(packet, timeout=dut_config.timeout, test_nodeid=nodeid)
```

This also fixes parametrized cases for free: `test_invalid_syn_flags.py:33` currently rebuilds the parametrized id by hand as `f"test_contradictory_flag_combination_does_not_establish_connection[{label}]"`.

**Effort:** 2 h (63 sites, mechanical). Add a `tests_internal` guard that greps `tests/` for `test_nodeid="` literals to stop the pattern coming back.

---

### F-06 — The craft-a-TCP-segment block, 51 times · **Importance 7/10** · NEAR DUPLICATE

**Duplication: ~85%** between instances; only the flags/seq/port vary.

```python
packet = wrap_ethernet(
    build_tcp(local_ip, dut_config.target_ip, <sport>, dut_config.target_port, flags="S", seq=tracker.seq),
    local_mac,
    dut_mac,
)
```

51 `wrap_ethernet(...)` call sites across 23 files; the five-fixture signature `(network_interface, dut_config, local_mac, dut_mac, local_ip)` is repeated **60 times**. Three files already grew private helpers that are themselves near-duplicates of each other:

- `tests/tcp/syn/test_tcp_options.py:27` `_syn_ack_for_options(...)`
- `tests/tcp/state_machine/test_syn_received_state.py:598` `_send_syn(...)`
- `tests/tcp/congestion/test_zero_window.py:31` `_handshake(...)`
- `tests/ip/test_ip_options.py:19` `_echo_with(...)`

`_send_syn` and `_syn_ack_for_options` are ~90% identical — same body, one builds via `build_tcp`, the other via raw `IP()/TCP()` to attach options.

**Remediation** — one fixture that closes over the addressing, in `tests/conftest.py`:

```python
# tests/conftest.py
from dataclasses import dataclass
from scapy.packet import Packet
from src.packet_engine.builders import build_tcp, build_udp, wrap_ethernet


@dataclass(frozen=True)
class Craft:
    """Addressing for this run, pre-bound. Removes the five-fixture
    signature and the wrap_ethernet(build_*(...)) block from every test."""

    local_ip: str
    local_mac: str
    dut_ip: str
    dut_mac: str
    dut_port: int

    def tcp(self, sport: int, **kwargs) -> Packet:
        return wrap_ethernet(
            build_tcp(self.local_ip, self.dut_ip, sport, kwargs.pop("dport", self.dut_port), **kwargs),
            self.local_mac,
            self.dut_mac,
        )

    def udp(self, sport: int, **kwargs) -> Packet:
        return wrap_ethernet(
            build_udp(self.local_ip, self.dut_ip, sport, kwargs.pop("dport", self.dut_port), **kwargs),
            self.local_mac,
            self.dut_mac,
        )

    def l3(self, layer: Packet) -> Packet:
        """Wrap an already-built L3 layer (options, malformed headers)."""
        return wrap_ethernet(layer, self.local_mac, self.dut_mac)


@pytest.fixture(scope="session")
def craft(local_ip, local_mac, dut_config, dut_mac) -> Craft:
    return Craft(local_ip, local_mac, dut_config.target_ip, dut_mac, dut_config.target_port)
```

Call sites shrink from six lines to one:

```python
# before (tests/tcp/syn/test_three_way_handshake.py:17-21)
packet = wrap_ethernet(
    build_tcp(local_ip, dut_config.target_ip, 41100, dut_config.target_port, flags="S", seq=tracker.seq),
    local_mac,
    dut_mac,
)
# after
packet = craft.tcp(41100, flags="S", seq=tracker.seq)
```

**Effort:** 6 h across 23 files. High payoff — this is the single largest volume of duplicated code in the repo — but it touches every DUT-facing test, so land it on its own branch and verify with `pytest tests/ --collect-only` plus one real DUT run.

---

### F-07 — Hardcoded source ports, three allocation schemes · **Importance 7/10** · DATA DUPLICATION

Source ports are picked by four incompatible mechanisms:

| Scheme | Location | Values |
|---|---|---|
| `itertools.count` | `tests/tcp/conftest.py:23` | 41000+ |
| `itertools.count` | `tests/tcp/state_machine/test_syn_received_state.py:595` | 46700+ |
| `iter(range(...))` | `tests/tcp/syn/test_tcp_options.py:21` | 47000–47100 (**exhausts after 100 tests** — `next()` raises `StopIteration`) |
| bare literals | 12 files | 40000, 40001, 40100, 40200, 40201, 40202, 41100, 41101, 41200, 42000, 43000, 44000, 45000, 46000, 46100, 46500, 46501, 48000, 48001 |

**Why it matters:** two literals colliding means a DUT holding the first 4-tuple in `TIME_WAIT` corrupts the second test's handshake — exactly the hazard the comment at `tests/tcp/conftest.py:20-22` describes and then only solves for one fixture. The ranges are also undocumented and unreserved against each other; `test_syn_flood.py:38` sweeps `42000 + (i % 5000)`, i.e. **42000–46999**, which straddles the literals at 43000, 44000, 45000, 46000, 46100, 46500 and 46501 and the `_sport` counter's 46700 base.

**Remediation** — one session-scoped allocator, and delete every literal:

```python
# tests/conftest.py
import itertools

# One monotonic ephemeral-port sequence for the whole session, so no two
# tests can ever share a 4-tuple the DUT may still hold in TIME_WAIT.
# Starts above the SYN-flood sweep in tests/tcp/syn/test_syn_flood.py.
_source_ports = itertools.count(49152)


@pytest.fixture
def source_port(dut_config: DUTConfig) -> int:
    """A source port unique to this test, unless one was pinned with
    --dut-source-port (in which case the operator's choice wins)."""
    return dut_config.source_port or next(_source_ports)
```

Then `tests/tcp/conftest.py:23` and `test_syn_received_state.py:595` both drop their counters and take `source_port`; `test_tcp_options.py:21`'s bounded `iter(range(...))` bug disappears with them.

**Effort:** 3 h. Note `dut_config.source_port` is currently honoured by *no* test — this fixture is also the fix for that.

---

### F-08 — Build jobs duplicated between two workflows · **Importance 6/10** · EXACT DUPLICATE (config)

**Duplication: 80%** — `build-check.yml` is `release.yml`'s build jobs minus the staging/upload steps.

- `.github/workflows/build-check.yml:11-27` `build-windows` ≡ `.github/workflows/release.yml:18-34`
- `.github/workflows/build-check.yml:29-50` `build-linux` ≡ `.github/workflows/release.yml:52-77`

The "Install Qt runtime libraries" `apt-get` step appears **three** times: `build-check.yml:39-42`, `release.yml:63-66`, `ci.yml:27-30` — with the same four packages (`libegl1 libgl1 libxkbcommon0 libdbus-1-3`) and a different comment each time.

**Remediation** — a reusable workflow:

```yaml
# .github/workflows/build.yml (new)
name: Build
on:
  workflow_call:
    inputs:
      ref:      { type: string, required: false, default: "" }
      upload:   { type: boolean, required: false, default: false }

jobs:
  build:
    strategy:
      fail-fast: false
      matrix:
        include:
          - { os: windows-latest, name: windows, artifact: NetstackTestSuite.exe,  asset: NetstackTestSuite-windows-x64.exe }
          - { os: ubuntu-latest,  name: linux,   artifact: NetstackTestSuite,      asset: NetstackTestSuite-linux-x86_64 }
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
        with: { ref: "${{ inputs.ref }}" }
      - uses: actions/setup-python@v5
        with: { python-version: "3.12", cache: pip }
      - name: Install Qt runtime libraries
        if: runner.os == 'Linux'
        run: sudo apt-get update && sudo apt-get install -y libegl1 libgl1 libxkbcommon0 libdbus-1-3
      - run: pip install -e ".[gui,dev]"
      - run: python -m PyInstaller NetstackTestSuite.spec --noconfirm
      - name: Stage artifact
        if: inputs.upload
        shell: bash
        run: mkdir -p out && cp "dist/${{ matrix.artifact }}" "out/${{ matrix.asset }}" && chmod +x "out/${{ matrix.asset }}"
      - uses: actions/upload-artifact@v4
        if: inputs.upload
        with: { name: "${{ matrix.name }}", path: out/* }
```

`build-check.yml` then becomes four lines (`uses: ./.github/workflows/build.yml`), and `release.yml`'s two build jobs become one `uses:` with `upload: true`.

**Effort:** 2 h, including one throwaway tag to prove the release path still publishes both assets.

---

### F-09 — Sample `TestRunResult` builders, 7 copies · **Importance 6/10** · NEAR DUPLICATE (tests)

**Duplication: ~80%** — same six required fields, same `10.0.0.5` / `"TestOS"` values.

| Function | File:line |
|---|---|
| `_result()` | `tests_internal/test_report_data.py:19` |
| `_sample_result()` | `tests_internal/test_reporting_pdf.py:16` |
| `_sample_result()` | `tests_internal/test_plotting_engine.py:42` |
| `stub_result()` fixture | `tests_internal/test_cli.py:18` |
| `_run_result()` | `tests_internal/test_runner_args.py:286` |
| inline | `tests_internal/test_runner_args.py:346` |
| `_result(code)` | `tests_internal/test_runner_args.py:365` |

Two names (`_sample_result`) for two different bodies is the worst of it — a reader can't tell which shape a test is asserting against.

**Remediation** — one factory in `tests_internal/conftest.py`:

```python
# tests_internal/conftest.py
from datetime import datetime, timezone
from src.reporting.models import TestEvent, TestOutcome, TestRunResult


def make_run_result(**overrides) -> TestRunResult:
    """A minimal valid run result. Pass overrides for the field under
    test; everything else gets a stable, obviously-fake default."""
    now = datetime.now(timezone.utc)
    defaults = dict(
        run_id="r1",
        started_at=now,
        finished_at=now,
        target_ip="10.0.0.5",
        target_stack="linux",
        host_platform="TestOS",
    )
    return TestRunResult(**{**defaults, **overrides})


@pytest.fixture
def run_result() -> TestRunResult:
    return make_run_result()
```

Call sites become `make_run_result(tests=[...])` / `make_run_result(pytest_returncode=2)`.

**Effort:** 1.5 h. Fully covered by the existing self-tests.

---

### F-10 — Report copy written twice, HTML and PDF · **Importance 5/10** · DATA DUPLICATION

The same prose is maintained in two generators, already drifting:

| Text | HTML | PDF |
|---|---|---|
| "Purpose: findings for a developer to fix the DUT's network stack. Failures first, full results next, spec references in the appendix." | `html_report.py:204` | `pdf_report.py:77-78` |
| "No failures or errors — every test that ran passed…" | `html_report.py:32-33` | `pdf_report.py:125-126` (different tail: *"and the catalog in Appendix A"* vs *"See the full results and appendix below"*) |
| "N test(s) failed or errored, …most-severe first…" | `html_report.py:52-53` | `pdf_report.py:135-136` |
| Artifacts list (`capture.pcap` / `debug.log` / `pytest_output.log`) | `html_report.py:89-92` | `pdf_report.py:188-193` (HTML lists `results.json`; PDF does not) |
| "Every test in the suite, what it checks, the RFC clause…" | `html_report.py:137-138` | `pdf_report.py:211-212` |
| "Specifications exercised by this suite — the reading list…" | `html_report.py:151` | `pdf_report.py:258` |
| Informational-check note | `html_report.py:96-98` | `pdf_report.py:197-200` |

`report_data.py` already exists as the shared enrichment layer — the strings belong there.

**Remediation:**

```python
# src/reporting/report_data.py — the wording both generators render
PURPOSE = (
    "Purpose: findings for a developer to fix the DUT's network stack. "
    "Failures first, full results next, spec references in the appendix."
)
NO_FINDINGS = (
    "No failures or errors — every test that ran passed. "
    "See the full results below and the catalog in Appendix A."
)
CATALOG_INTRO = (
    "Every test in the suite, what it checks, the RFC clause it maps to, and which "
    "role(s) it runs in. Use this to map a finding to the spec and to see what else is covered."
)
RFC_INTRO = "Specifications exercised by this suite — the reading list for interpreting the findings."
ARTIFACTS = (
    ("capture.pcap", "every frame the suite sent and received."),
    ("debug.log", "tshark-style per-packet trace (present only if Debug mode was on)."),
    ("pytest_output.log", "raw test-runner output."),
    ("results.json", "this run in machine-readable form."),
)

def findings_intro(count: int) -> str:
    return (
        f"{count} test(s) failed or errored, listed most-severe first. Each names the RFC "
        "clause it exercises, what it checks, and what the DUT actually did."
    )

def informational_note(target_stack: str) -> str:
    return (
        f"Note: informational checks (e.g. advertised window size) compare the DUT against the "
        f"selected {target_stack} stack profile — a mismatch flags a behavioural difference, "
        "not necessarily an RFC violation."
    )
```

**Effort:** 2 h.

---

### F-11 — Outcome colour palette maintained in three places · **Importance 5/10** · DATA DUPLICATION

The same four outcome colours are declared three times, in three formats:

- `src/reporting/pdf_report.py:27-32` — `_OUTCOME_COLORS`, the authoritative hex values (`#1a7f37`, `#b71c1c`, `#8a1a9b`, `#616161` + backgrounds `#e8f5e9`, `#ffebee`, `#f3e5f5`, `#f5f5f5`).
- `src/reporting/html_report.py:15-20` + `:168-184` — `_OUTCOME_CLASS` mapping to CSS class names, with the identical hex values re-typed inside `_STYLE`.
- `src/plotting/static_charts.py:59` — `["tab:green", "tab:red", "tab:gray"]`, matplotlib names for the same three states.
- `src/gui/log_panel.py:9-14` — `_OUTCOME_PREFIX`, a fourth per-outcome table.

**Remediation** — one table in `src/reporting/models.py` beside `TestOutcome`:

```python
# src/reporting/models.py
# Presentation table for TestOutcome. Any renderer (HTML, PDF, matplotlib,
# GUI log) reads its column here rather than re-typing the palette.
OUTCOME_STYLE: dict[TestOutcome, dict[str, str]] = {
    TestOutcome.PASSED:  {"css": "passed",  "fg": "#1a7f37", "bg": "#e8f5e9", "mpl": "tab:green", "prefix": "PASS"},
    TestOutcome.FAILED:  {"css": "failed",  "fg": "#b71c1c", "bg": "#ffebee", "mpl": "tab:red",   "prefix": "FAIL"},
    TestOutcome.ERROR:   {"css": "error",   "fg": "#8a1a9b", "bg": "#f3e5f5", "mpl": "tab:purple", "prefix": "ERR"},
    TestOutcome.SKIPPED: {"css": "skipped", "fg": "#616161", "bg": "#f5f5f5", "mpl": "tab:gray",  "prefix": "SKIP"},
}
```

`pdf_report._OUTCOME_COLORS` becomes a comprehension over it; `html_report._STYLE` becomes an f-string; `log_panel._OUTCOME_PREFIX` disappears.

**Effort:** 2 h. `tests_internal/test_reporting_pdf.py` and `test_plotting_engine.py` cover the output paths.

---

### F-12 — Run-summary string written three times · **Importance 5/10** · EXACT DUPLICATE

**Duplication: 100%** on the format string.

```
"{passed} passed, {failed} failed, {errors} errored, {skipped} skipped, {total} total"
```

- `src/cli/main.py:227-229`
- `src/gui/main_window.py:339-340`
- `src/gui/report_panel.py:45-47`

The per-test line duplicates too — `src/cli/main.py:207` builds `f"[{outcome:7}] {nodeid} ({duration:.3f}s)"` and `src/gui/log_panel.py:29-32` builds `f"[{prefix:5}] {nodeid} ({duration:.3f}s)"`, the same line with a different label width.

**Remediation** — properties on the model that already owns the counts:

```python
# src/reporting/models.py — on TestRunResult
@property
def counts_summary(self) -> str:
    """The one-line tally every front end prints."""
    return (
        f"{self.passed} passed, {self.failed} failed, {self.errors} errored, "
        f"{self.skipped} skipped, {self.total} total"
    )
```

```python
# src/reporting/models.py — on TestEvent
def summary_line(self, label_width: int = 7) -> str:
    line = f"[{self.outcome.value.upper():{label_width}}] {self.nodeid} ({self.duration_s:.3f}s)"
    return f"{line} — {self.message}" if self.message else line
```

**Effort:** 45 min.

---

### F-13 — `report_panel._export_pdf` / `_export_html` · **Importance 4/10** · NEAR DUPLICATE

**Duplication: 85%** — 10 lines each, differing in four tokens.

`src/gui/report_panel.py:50-59` and `:61-70`.

**Remediation:**

```python
# src/gui/report_panel.py — replace both methods
def _export(self, *, suffix: str, label: str, generate) -> None:
    if self._result is None:
        return
    default_path = reports_dir() / self._result.run_id / f"report.{suffix}"
    path_str, _ = QFileDialog.getSaveFileName(
        self, f"Export {label} report", str(default_path), f"{label} files (*.{suffix})"
    )
    if path_str:
        self._status_label.setText(f"{label} written to {generate(self._result, Path(path_str))}")

def _export_pdf(self) -> None:
    self._export(suffix="pdf", label="PDF", generate=generate_pdf_report)

def _export_html(self) -> None:
    self._export(suffix="html", label="HTML", generate=generate_html_report)
```

**Effort:** 20 min. `tests_internal/test_gui_smoke.py` covers the panel.

---

### F-14 — Two identical reportlab `TableStyle` blocks · **Importance 4/10** · EXACT DUPLICATE

**Duplication: 88%** — 7 of 8 directives identical.

`src/reporting/pdf_report.py:238-247` (`_catalog_flowables`) and `:299-308` (`_build_detail_table`) share `GRID`, `BACKGROUND` header, `VALIGN`, and all four paddings. The `ParagraphStyle` pair is duplicated with them: `cell`/`head` at `:208-209` vs `cell`/`header` at `:281-282`, both `fontSize=7, leading=8.5, wordWrap="CJK"`.

**Remediation:**

```python
# src/reporting/pdf_report.py — module level
_TABLE_BASE = [
    ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#333333")),
    ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ("LEFTPADDING", (0, 0), (-1, -1), 4),
    ("RIGHTPADDING", (0, 0), (-1, -1), 4),
    ("TOPPADDING", (0, 0), (-1, -1), 2),
    ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
]
_CELL = ParagraphStyle("cell", fontSize=7, leading=8.5, wordWrap="CJK")
_CELL_HEAD = ParagraphStyle("cellhead", parent=_CELL, textColor=colors.white)
```

Then `t.setStyle(TableStyle(list(_TABLE_BASE)))` in both, with `_build_detail_table` continuing to `.add(...)` its per-row backgrounds.

**Effort:** 30 min.

---

### F-15 — `static_charts` save-and-close tail · **Importance 4/10** · EXACT DUPLICATE

**Duplication: 100%** — four identical lines.

`src/plotting/static_charts.py:47-50` and `:65-68`:

```python
output_path.parent.mkdir(parents=True, exist_ok=True)
fig.savefig(output_path, dpi=150)
plt.close(fig)
return output_path
```

The cumulative-series loop at `:25-36` is also a re-implementation of `MetricsBuffer.add()` (`src/plotting/metrics.py:51-65`) — same running counters, same elapsed-since-first computation, ~70% duplicate logic in a different shape.

**Remediation:**

```python
# src/plotting/static_charts.py
CHART_DPI = 150

def _save(fig, output_path: Path) -> Path:
    """Write a figure and release it — matplotlib figures are not GC'd
    promptly, and a report renders several per run."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output_path, dpi=CHART_DPI)
    plt.close(fig)
    return output_path
```

For the loop, feed a `MetricsBuffer` and take a snapshot:

```python
def render_packet_timeline(result: TestRunResult, output_path: Path) -> Path:
    buffer = MetricsBuffer()
    for event in sorted(result.packet_events, key=lambda e: e.timestamp):
        buffer.add(event)
    snap = buffer.snapshot()
    fig, ax = plt.subplots(figsize=(7, 3.5))
    ax.plot(snap.elapsed_s, snap.sent_cumulative, label="Sent", color="tab:green")
    ax.plot(snap.elapsed_s, snap.received_cumulative, label="Received", color="tab:blue")
    ...
    return _save(fig, output_path)
```

**Effort:** 45 min. Covered by `tests_internal/test_plotting_engine.py`.

---

### F-16 — Three `serve_*` responders share one shape · **Importance 4/10** · STRUCTURAL DUPLICATE

**Duplication: ~70%** structural, ~40% textual.

`src/packet_engine/responder.py:89-134` (`serve_tcp_handshake`), `:137-160` (`serve_udp_echo`), `:163-185` (`serve_icmp_echo`) are all: sniff one packet matching an lfilter → return None if none → build a reply → send it → return the received packet. Each repeats the same signature (`interface, local_ip, local_mac, [listen_port], *, timeout=5.0, test_nodeid=None`) and the same `p.haslayer(X) and p.haslayer(IP) and p[IP].dst == local_ip` filter prefix.

Separately, `build_udp_echo_reply` (`:60-70`) and `build_icmp_echo_reply` (`:73-83`) are ~75% identical — both extract `bytes(pkt[Raw].load) if pkt.haslayer(Raw) else b""` and build `Ether(swap)/IP(swap)/L4/Raw(payload)`.

**Remediation** — keep the three public functions (their docstrings carry real per-protocol meaning) and factor the plumbing:

```python
# src/packet_engine/responder.py
def _addressed_to_us(local_ip: str, layer) -> Callable[[Packet], bool]:
    """The common filter prefix: the right L4 layer, IP present, and
    destined for us — not just anything on the segment."""
    def match(p: Packet) -> bool:
        return p.haslayer(layer) and p.haslayer(IP) and p[IP].dst == local_ip
    return match


def _serve_once(
    interface: NetworkInterface,
    lfilter: Callable[[Packet], bool],
    build_reply: Callable[[Packet], Packet],
    *,
    timeout: float,
    test_nodeid: str | None,
) -> Packet | None:
    """Wait for one matching packet from the DUT, answer it, return it."""
    received = interface.sniff(count=1, timeout=timeout, lfilter=lfilter, test_nodeid=test_nodeid)
    if not received:
        return None
    interface.send(build_reply(received[0]), test_nodeid=test_nodeid)
    return received[0]


def _echo_payload(packet: Packet) -> bytes:
    return bytes(packet[Raw].load) if packet.haslayer(Raw) else b""
```

**Effort:** 2 h. `tests_internal/test_responder.py` covers the builders.

---

### F-17 — `PcapWriter` construction and pcap bookkeeping duplicated · **Importance 3/10** · NEAR DUPLICATE

**Duplication: ~65%.**

`src/packet_engine/interface.py:98-104` and `src/packet_engine/recorder.py:93-96` both do `mkdir(parents=True)` → `PcapWriter(str(path), append=False, sync=True)` → guarded increment of a lock-protected `_packet_count`, with the same `sync=True` rationale re-explained in both comments (`interface.py:52-56`, `recorder.py:94-95`). Both classes also carry an identical `__enter__`/`__exit__` pair (`interface.py:133-137`, `recorder.py:125-129`).

Not a bug — the two have genuinely different lifecycles (lazy-on-first-packet vs eager-on-start) — but the writer construction itself is one fact stated twice.

**Remediation:**

```python
# src/packet_engine/pcap.py (new)
def open_pcap(path: Path) -> PcapWriter:
    """A pcap writer that flushes each frame as written, so a long or
    abruptly-terminated capture still yields a valid, complete file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    return PcapWriter(str(path), append=False, sync=True)
```

**Effort:** 30 min. **Importance is low deliberately** — the shared code is four lines and the surrounding lifecycles differ enough that over-unifying would cost more than it saves.

---

### F-18 — Missing-required-config check written twice · **Importance 3/10** · NEAR DUPLICATE

**Duplication: 85%** — same list-comprehension, different labels and failure mode.

`src/packet_engine/preflight.py:43-56` builds `missing` from `("Target IP", config.target_ip), ("Interface", …), ("Target stack", …)` and returns a `PreflightResult`; `conftest.py:193-206` builds the same list from `("--dut-ip", …), ("--dut-iface", …), ("--target-stack", …)` and calls `pytest.fail`.

**Remediation** — one predicate on `DUTConfig`, with the two callers formatting their own message:

```python
# src/config.py — on DUTConfig
REQUIRED_FIELDS: ClassVar[tuple[tuple[str, str], ...]] = (
    ("target_ip", "--dut-ip"),
    ("interface", "--dut-iface"),
    ("target_stack", "--target-stack"),
)

def missing_required(self) -> list[str]:
    """CLI flag names for the required fields that are unset."""
    return [flag for attr, flag in self.REQUIRED_FIELDS if not getattr(self, attr)]
```

**Effort:** 45 min. Low importance because both copies are short and currently agree.

---

### F-19 — Assorted magic literals · **Importance 3/10** · DATA DUPLICATION

| Literal | Occurrences | Note |
|---|---|---|
| `65536` recv chunk | `src/proxy/backend.py:25` (`RECV_CHUNK`), `src/proxy/client.py:161` (bare literal) | client should import the named constant |
| `9099` backend port | `src/cli/main.py:101`, `:392`, `conftest.py:129`, `src/proxy/backend.py:57`, `src/gui/proxy_panel.py:44` | 5 copies of one default |
| `["linux", "windows"]` | `src/cli/main.py:66`, `conftest.py:94`, `src/gui/main_window.py:98`, `src/config.py:19` (`TargetStackName`) | `target_profiles.list_profiles()` already returns exactly this |
| `"Unsupported host platform: {system!r}"` | `src/utils/permissions.py:33`, `:64`, `src/packet_engine/platform_backend.py:65` | 3 copies |
| `& 0xFFFFFFFF` | 18 sites in `tests/` | superseded by `seq32()` — see F-01 |
| Marker names | `pyproject.toml:35-48` (13 markers) and `src/runner.py:57-73` (`KNOWN_MARKERS`, same 13) | a new marker must be added to both or it vanishes from every report |

The marker one is the most consequential: `runner.KNOWN_MARKERS` filters the report-log keywords, so a marker registered in `pyproject.toml` but not mirrored into the frozenset is silently dropped from every generated report.

**Remediation** for the markers:

```python
# src/runner.py — replace the hand-maintained frozenset at lines 57-73
import tomllib


def _registered_markers() -> frozenset[str]:
    """The markers declared in pyproject.toml, read once. pytest's
    report-log "keywords" dict is polluted with the nodeid, filename and
    module name, so reports filter against this known set — and reading
    it from the declaration means a new marker can't be forgotten here."""
    pyproject = paths.project_root() / "pyproject.toml"
    try:
        data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return frozenset()
    entries = data.get("tool", {}).get("pytest", {}).get("ini_options", {}).get("markers", [])
    return frozenset(entry.split(":", 1)[0].strip() for entry in entries)


KNOWN_MARKERS = _registered_markers()
```

`pyproject.toml` is already bundled into the frozen build (`NetstackTestSuite.spec:29`), so `paths.project_root()` resolves it in both modes. **Alternative if you prefer no file read at import time:** keep the frozenset and add a `tests_internal` assertion that it equals the parsed `pyproject.toml` markers — cheaper, and it fails loudly on drift.

**Effort:** 2 h for the group.

---

## What was applied, in order

| Wave | Findings | Outcome |
|---|---|---|
| **1 — utilities module** | F-01 (`src/` half) | `src/utils/tcp_flags.py` created and adopted |
| **2 — correctness** | F-02, F-07, F-19 | The three-way proxy-leg divergence collapsed to one rule; four port-allocation schemes and 19 literals replaced by one allocator (which also fixed the bounded `iter(range(47000, 47100))`); `KNOWN_MARKERS` now read from `pyproject.toml` |
| **3 — cheap wins** | F-04, F-12, F-13, F-14, F-15 | Run header/finalisation, summary strings, export flow, table styles, chart save-tail |
| **4 — volume** | F-01 (tests half), F-05, F-06 | 63 literal node ids → the `nodeid` fixture; ~51 crafting blocks → the `craft` fixture; five liveness-ping tails → `assert_dut_alive` |
| **5 — polish** | F-03, F-08, F-09, F-10, F-11, F-16, F-17, F-18 | Shared option declarations, reusable build workflow, one result factory, shared report copy and palette, responder plumbing, pcap writer, required-field check |
| **6 — guards** | new | Four regression tests, each verified to fail against an injected violation |

Two behaviours were deliberately preserved rather than "cleaned up", because
changing them would have altered what the suite asserts:

- In `test_fin_close_transitions.py::test_out_of_window_fin_is_not_processed`,
  a *missing* reply to the follow-up data segment was tolerated by the
  original guard. Collapsing it to `assert is_ack(live)` would have made
  silence a failure, so the tolerance is now explicit and commented.
- `test_zero_window.py`'s persist-probe filter is "not (SYN or RST)", not
  "is an ACK". That is why `any_flags` exists alongside `has_flags`.

## What was checked and found clean

Worth recording so a later audit doesn't re-derive it:

- `src/proxy/tunnel.py` — no duplication. The HTTP and SOCKS5 halves look parallel but share no extractable logic; both are thin, RFC-cited encoders.
- `src/catalog.py` — 605 lines of `TestSpec(...)` entries. Repetitive *by design*: it is a data table, and `tests_internal/test_catalog.py` AST-checks it against the real test tree. Not duplication.
- `src/target_profiles/{linux,windows}_profile.py` — parallel structure, entirely different values. Correct as-is.
- `src/runner.py` ↔ `src/gui/run_controller.py` — already share `build_pytest_args`, `new_run_dir`, `drain_test_events`, `drain_packet_events`. Only the two blocks in F-04 remain.
- `src/reporting/report_data.py` — genuinely shared by both report generators; only the prose (F-10) escaped it.

## Unable to verify

- **Whether `tests/tcp/syn/test_tcp_options.py:21`'s bounded `iter(range(47000, 47100))` has ever raised `StopIteration` in practice.** The file defines 6 tests, so a single run consumes 6 of 100. It would only surface under `--count`-style repetition or a future parametrize. Proof would need a run log showing `StopIteration` from `next(_SPORT)`.
- **Whether the source-port literals in F-07 have actually collided against a real DUT.** Establishing it needs a `capture.pcap` from a full-suite run plus the DUT's `TIME_WAIT` timeout; the collision risk is structural and visible in the source, the *impact* is not.
- **Runtime behaviour of anything under `tests/`.** Every DUT-facing test needs real hardware, raw-socket privileges and a live target. This audit verified them by collection (`81 tests collected`, no import errors) and by reading, not by execution.
