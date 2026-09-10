# Code Complexity Audit — netstack-test-suite

**Date:** 2026-09-10
**Commit:** `7100ad0` (branch `development`)
**Scope:** all 12,454 lines of Python across `src/`, `tests/`, `tests_internal/`, `conftest.py`, `tools/`, `packaging/`.
**Method:** a purpose-built AST pass over all 134 `.py` files (755 function/class definitions) computing, per function: McCabe cyclomatic complexity, a SonarSource-style cognitive complexity, maximum nesting depth of control structures, and physical line span. Coupling was computed by resolving every `import` / `from … import` (including the `from pkg import submodule` form) against the set of `src.*` modules, giving efferent coupling (Ce, `src/`-internal only), afferent coupling (Ca, counting `tests/` and `tests_internal/` importers too) and instability `I = Ce / (Ce + Ca)`. Coupling and cohesion findings were then confirmed by reading the modules involved.

> Reproduction: the analyzer is not checked in. Any of `radon cc -s src/`, `radon mi src/`, or `flake8 --max-complexity=10` reproduces the cyclomatic figures within ±1 (the ±1 is the usual disagreement over whether the function itself counts as a decision point; figures below count it).

---

## Executive summary

**This codebase is not complex.** Of 673 functions, exactly **three** exceed cyclomatic complexity 10 in `src/`, only **six** exceed 50 lines in `src/`, no `src/` class exceeds 310 lines, and maximum control-flow nesting anywhere in `src/` is **4**. There are no recursive call chains, no `switch`-equivalent `match` statements, and no god-object. The preceding duplication audit (`audits/code-duplication-audit.md`, 19 findings, all applied) visibly did its job: the shared `runner.py`/`options.py`/`report_data.py` layers are exactly where complexity would otherwise have been triplicated.

The complexity that does exist is concentrated in the **three front-end assembly points** — the two functions that translate user configuration into a pytest invocation, and the one that translates GUI widget state into the same thing:

| Hotspot | CC | Cog | Depth | LOC | Character |
|---|---|---|---|---|---|
| [`build_pytest_args`](src/runner.py:118) | **21** | **26** | 2 | 81 | 17 sequential flat `if request.x: args.append(...)` |
| [`cli.main.run`](src/cli/main.py:90) | **17** | 18 | 2 | **128** | 5 distinct phases in one function body |
| [`MainWindow._on_run_clicked`](src/gui/main_window.py:244) | **16** | 16 | 2 | 84 | the same 5 phases, in Qt idiom |

All three are *wide, not deep* — long chains of independent guard clauses rather than tangled nesting. That is the benign kind of high complexity: each `if` is trivially readable in isolation. The risk they carry is not comprehension, it is **fan-out** — `cli/main.py` (Ce=15, I=0.94) and `gui/main_window.py` (Ce=15, I=0.83) each reach into 15 of the 58 `src/` modules, which is what makes them the two files most likely to need editing for any change anywhere.

Ten findings follow, ordered by importance. Eight are actionable (F-01 … F-07a); the last two are "measured and confirmed healthy" entries, recorded so a future audit doesn't re-litigate them.

**Severity scale:** 1 = cosmetic, 10 = actively causing defects.

---

## Status: all 8 actionable findings applied

Every actionable finding was applied on branch `development`, in the priority
order this report set out. F-08 and F-09 are "no action" by design. Each
finding below keeps its original analysis and remediation snippet, so the
record of *what was measured and why* survives alongside the fix.

Verification after the final change:

- `pytest tests_internal/ -q` -> **193 passed** (176 originally, plus 17 new
  tests covering the extracted logic)
- `pytest --collect-only -q` -> **272 collected**, no import errors
- `ruff check .` -> clean, with `C901` enforced at max-complexity 10
- Import-cycle DFS over `src/` -> **none** (was 1)

### Measured effect

| Function | CC | Cognitive | LOC |
|---|---|---|---|
| `build_pytest_args` | 21 → **10** | 26 → **6** | 81 → **46** |
| `cli.main.run` | 17 → **5** | 18 → **5** | 128 → **91** |
| `MainWindow._on_run_clicked` | 16 → **9** | 16 → **8** | 84 → **28** |
| `pytest_collection_modifyitems` | 10 → **3** | 17 → **3** | 39 → **16** |
| `cli.main.send` | 8 → **6** | 12 → **5** | 55 → **50** |
| `conftest.payload_settings` | 5 → **3** | 10 → **3** | 17 → **16** |

**No function in `src/` or `conftest.py` now exceeds cyclomatic complexity 10**
(was three), so the ceiling is enforced in CI rather than re-audited.

### New modules and helpers

| Added | Replaces |
|---|---|
| `src/collection_policy.py` (`skip_reason`, `applicable_roles`) | the two policies tangled in one collection-hook loop |
| `runner._optional_flags` / `_topology_flags` / `_test_targets` / `_launcher` | the 17-branch flag ladder |
| `cli.main._resolve_topology` / `_emit_results` | phases 1 and 5 of the 128-line `run` |
| `MainWindow._report_topology` / `_preflight_and_report` / `_warn_role_mismatches` / `_build_run_request` | the four phases of `_on_run_clicked` |
| `payloads.resolve_custom_source` | the text>hex>file cascade written three times |
| `catalog._BY_NODEID` / `_BY_PATH` / `_BY_PATH_AND_TEST` | three linear scans |

### Verification beyond the test suite

Two refactors changed code with no direct test coverage, so both were
checked by differential testing against the pre-refactor implementation:

- **F-06 (skip policy):** the old inline policy and the new `skip_reason`
  were run against every really-collected item for every (role, proxy_mode)
  combination — **2,176 decisions compared, 0 differences.**
- **F-07 (catalog indices):** the old linear scans and the new dict lookups
  were compared over every spec plus absolute, backslash and missing-key
  probes — **1,267 lookups compared, 0 differences.**

### Deviations from the report as written

- **F-05's `_PHASE_POLICY` table was NOT applied.** The report flagged it as
  "genuinely marginal" and warned it risked obscuring the setup-skip case;
  on inspection that was the right call, so the phase dispatch stays as a
  flat `elif` chain. F-05's higher-value half — tests — was applied instead:
  the four `longrepr` shapes `_extract_message` handles were uncovered and
  now are.
- **F-06's policy landed in `src/collection_policy.py`, not `conftest.py`.**
  The report's snippet put the helpers in the root conftest. That breaks:
  `tests/conftest.py` shadows the root `conftest` module name, so a test
  importing `from conftest import skip_reason` gets the wrong file and the
  full run fails at collection. The policy moved to `src/` instead, which
  also gives it a home that doesn't depend on pytest.
- **F-01 forwarded two extra helper extractions.** The flag table alone left
  `build_pytest_args` at CC 14; pulling out `_test_targets` and `_launcher`
  brought it to 10 so the CI ceiling could be set without an exemption.
- **F-03 extracted a fourth method** (`_report_topology`) beyond the three
  the report listed, for the same reason — `_on_run_clicked` sat at CC 12
  after the first three.

### Applied but not in the original report

- **`ruff` added as a dev dependency, configured in `pyproject.toml`, and
  wired into `.github/workflows/ci.yml`.** The report proposed the config;
  it had to be installed and validated to be worth committing. `select`
  is `["F", "C90"]` — the complexity ceiling plus unused-import detection,
  which the project previously ran ad hoc via `pyflakes`.
- **One pre-existing unused import removed** (`PacketDirection` in
  `tests_internal/test_debug_log.py`), which the new `F` rule surfaced.

---

## Metric tables

### Cyclomatic complexity > 10 (whole repo)

| CC | Cog | Depth | LOC | Location |
|---:|---:|---:|---:|---|
| 21 | 26 | 2 | 81 | [`src/runner.py:118`](src/runner.py:118) `build_pytest_args` |
| 17 | 18 | 2 | 128 | [`src/cli/main.py:90`](src/cli/main.py:90) `run` |
| 16 | 16 | 2 | 84 | [`src/gui/main_window.py:244`](src/gui/main_window.py:244) `_on_run_clicked` |
| 11 | 0 | 0 | 36 | [`tests_internal/test_cli.py:202`](tests_internal/test_cli.py:202) `test_record_command_bounded_capture_wires_recorder` |
| 10 | 17 | 3 | 39 | [`conftest.py:62`](conftest.py:62) `pytest_collection_modifyitems` |
| 10 | 17 | 4 | 28 | [`src/runner.py:336`](src/runner.py:336) `drain_test_events` |
| 10 | 18 | 4 | 49 | [`src/runner.py:383`](src/runner.py:383) `parse_report_log_line` |
| 10 | 3 | 0 | 8 | [`tests_internal/test_responder.py:27`](tests_internal/test_responder.py:27) (all-`assert` test) |

The two CC-10/11 *test* functions are assertion-dense, zero-branch bodies — `assert` counts as a decision point in McCabe but carries no cognitive load (Cog 0–3). They are noise in this table; ignore them.

### Cognitive complexity ≥ 10

`build_pytest_args` (26) · `parse_report_log_line` (18) · `cli.main.run` (18) · `pytest_collection_modifyitems` (17) · `drain_test_events` (17) · `_on_run_clicked` (16) · `cli.main.send` (12) · `EchoBackend._handle_tcp` (12) · `ProxyClient._socks5_connect` (11) · `conftest.payload_settings` (10) · `runner._extract_message` (10).

### Functions over 50 lines (all of them, whole repo)

| LOC | CC | Location |
|---:|---:|---|
| 128 | 17 | [`src/cli/main.py:90`](src/cli/main.py:90) `run` |
| 106 | 3 | [`tools/generate_screenshots.py:49`](tools/generate_screenshots.py:49) `sample_result` — literal fixture data |
| 105 | 3 | [`src/gui/custom_packet_panel.py:32`](src/gui/custom_packet_panel.py:32) `__init__` — Qt widget construction |
| 84 | 16 | [`src/gui/main_window.py:244`](src/gui/main_window.py:244) `_on_run_clicked` |
| 82 | 3 | [`src/reporting/pdf_report.py:52`](src/reporting/pdf_report.py:52) `generate_pdf_report` — linear flowable assembly |
| 81 | 21 | [`src/runner.py:118`](src/runner.py:118) `build_pytest_args` |
| 75 | 4 | [`src/gui/main_window.py:85`](src/gui/main_window.py:85) `_build_config_group` — Qt widget construction |
| 63 | 1 | [`src/cli/options.py:52`](src/cli/options.py:52) `shared_options` — a `return (...)` of literals |
| 57 | 5 | [`src/packet_engine/preflight.py:41`](src/packet_engine/preflight.py:41) `run_preflight` |
| 55 | 8 | [`src/cli/main.py:238`](src/cli/main.py:238) `send` |
| 54 | 1 | [`src/gui/proxy_panel.py:34`](src/gui/proxy_panel.py:34) `__init__` |
| 54 | 4 | [`src/reporting/pdf_report.py:136`](src/reporting/pdf_report.py:136) `_findings_flowables` |

### Files over 300 lines

| LOC | File | Verdict |
|---:|---|---|
| 605 | `src/catalog.py` | Data table (F-08). Not a split candidate. |
| 450 | `src/runner.py` | Cohesive; see F-05. |
| 428 | `tools/generate_screenshots.py` | Dev tool, outside the shipped package. |
| 408 | `src/cli/main.py` | Split candidate (F-02). |
| 386 | `src/gui/main_window.py` | Split candidate (F-03). |
| 359 / 320 / 313 | `tests_internal/test_runner_args.py`, `conftest.py`, `tests_internal/test_gui_smoke.py` | Test/fixture surfaces. |

### Classes over 100 lines (`src/` only)

| LOC | Class |
|---:|---|
| 307 | [`MainWindow`](src/gui/main_window.py:49) — 16 methods |
| 158 | [`CustomPacketPanel`](src/gui/custom_packet_panel.py:31) |
| 158 | [`EchoBackend`](src/proxy/backend.py:49) |
| 133 | [`ProxyClient`](src/proxy/client.py:36) |
| 128 | [`TestRunResult`](src/reporting/models.py:90) |
| 124 | [`TestTreeWidget`](src/gui/test_tree_widget.py:39) |
| 101 | [`NetworkInterface`](src/packet_engine/interface.py:37) |

**No class in the repo exceeds 500 lines.** The 500-line threshold is not approached by anything.

### Coupling (`src/` modules, Ca counts test importers)

| Module | Ce | Ca | I | Reading |
|---|---:|---:|---:|---|
| `src.gui.main_window` | **15** | 3 | 0.83 | Maximally unstable; correct for a top-level UI shell, but Ce=15 is high (F-03). |
| `src.cli.main` | **15** | 1 | **0.94** | Same shape (F-02). |
| `src.runner` | 4 | 7 | 0.36 | Healthy: the shared orchestration layer, more depended-on than depending. |
| `src.packet_engine.interface` | 4 | 5 | 0.44 | Balanced. |
| `src.gui.report_panel` | 4 | 2 | 0.67 | Fine for a leaf panel. |
| `src.proxy.client` | 3 | 6 | 0.33 | Stable and reused. |
| `src.reporting.models` | 0 | **22** | **0.00** | Ideal stable-abstraction kernel. |
| `src.utils.tcp_flags` | 0 | **18** | **0.00** | Ideal. |
| `src.config` | 0 | 14 | 0.00 | Ideal. |
| `src.proxy.config` | 0 | 12 | 0.00 | Ideal. |
| `src.packet_engine.payloads` | 0 | 11 | 0.00 | Ideal. |
| `src.catalog` | 1 | 8 | 0.11 | Ideal. |
| `src.packet_engine.sequence` | 1 | 8 | 0.11 | Ideal. |

A depth-first search over the `src/` import graph finds **exactly one cycle**, `src.proxy` ⇄ `src.proxy.client` (F-07a) — benign, but real. Every other module forms a clean DAG. The zero-Ce/high-Ca cluster (`reporting.models`, `utils.tcp_flags`, `config`, `proxy.config`, `packet_engine.payloads`) is exactly the stable kernel Martin's metric asks for. This is the strongest structural result in the audit.

---

## Findings

### F-01 — `build_pytest_args` is a 21-branch flag ladder · **Importance 7/10**

**Location:** [`src/runner.py:118-198`](src/runner.py:118) · CC 21 · Cog 26 · 81 LOC.

The highest-complexity function in the repo, and the one with real consequences: it is the *canonical* definition of the subprocess command line, consumed by both `stream_run` and `gui/run_controller.py`. Every optional flag is one hand-written conditional:

```python
if request.config.target_mac:
    args.append(f"--dut-mac={request.config.target_mac}")
if request.config.target_port is not None:
    args.append(f"--dut-port={request.config.target_port}")
if request.config.source_port is not None:
    args.append(f"--dut-source-port={request.config.source_port}")
...
```

Seventeen such blocks. The failure mode is silent: adding a `RunRequest` field and forgetting its `if` here produces a run that *succeeds* while ignoring the setting. The truthiness inconsistency is already visible in the existing code — `target_mac` uses truthiness (an empty MAC string is correctly dropped), `target_port` uses `is not None` (port 0 would be forwarded), and `proxy_port` at line 190 uses truthiness (`if request.proxy_port:`), so a legitimately-configured `--proxy-port` of 0 is silently dropped. That inconsistency is invisible in the ladder form and obvious in table form.

**Remediation.** Replace the flat ladder with a data table. Complexity drops from CC 21 to CC ~6, and a new option becomes a one-line tuple entry rather than a new branch:

```python
# src/runner.py — replace lines 161-179 (the flag ladder up to --allowed-targets)

#: (flag, value) pairs emitted only when the value is not None. Declaring
#: them as data rather than 17 `if` blocks means adding a RunRequest field
#: can't silently forget to forward it — and makes the None-vs-falsy rule
#: uniform (0 and "" are forwarded; only None is dropped).
def _optional_flags(request: "RunRequest") -> list[tuple[str, object | None]]:
    return [
        ("--dut-mac", request.config.target_mac or None),
        ("--dut-port", request.config.target_port),
        ("--dut-source-port", request.config.source_port),
        ("-k", request.test_name or None),
        ("-m", " and ".join(request.markers) if request.markers else None),
        ("--proxy-mode", request.proxy_mode),
        ("--proxy-leg", request.proxy_leg),
    ]


_TOPOLOGY_FLAGS = ("--proxy-host", "--proxy-port", "--backend-host", "--backend-port")

# ...inside build_pytest_args, after the base `args` list:
    for flag, value in _optional_flags(request):
        if value is None:
            continue
        args += [flag, str(value)] if flag in ("-k", "-m") else [f"{flag}={value}"]

    if request.confirm_vuln_tests:
        args.append("--confirm-vuln-tests")
    args += [f"--allowed-targets={cidr}" for cidr in request.config.allowed_targets]
    if request.debug:
        args.append(f"--debug-log={run_dir / 'debug.log'}")

    # The topology addresses are emitted whenever they're set, not only for
    # --proxy-mode: a front-leg run needs --proxy-host/--proxy-port to know
    # what to retarget to, even with no proxy-marked tests selected.
    if request.proxy_mode or request.proxy_leg:
        topology = (request.proxy_host, request.proxy_port,
                    request.backend_host, request.backend_port)
        args += [f"{flag}={value}" for flag, value in zip(_TOPOLOGY_FLAGS, topology)
                 if value is not None]
    return args
```

`tests_internal/test_runner_args.py` (359 lines) already pins this function's output, so the refactor is verifiable in one `pytest tests_internal/test_runner_args.py` run. **Note the behaviour change:** the snippet above makes port `0` forwarded rather than dropped. If a 0 port must stay suppressed, keep `or None` on those two entries — but decide it explicitly rather than inheriting it from a typo.

---

### F-02 — `cli.main.run` is five phases in one 128-line body · **Importance 6/10**

**Location:** [`src/cli/main.py:90-217`](src/cli/main.py:90) · CC 17 · Cog 18 · 128 LOC · 22 parameters.

The longest function in `src/`. It performs, in sequence: (1) proxy-leg resolution and validation, lines 124-140; (2) `DUTConfig` construction, 142-153; (3) preflight, 155-162; (4) `RunRequest` construction and the run, 164-186; (5) result reporting and report generation, 188-217. Each phase is individually clear — the cost is that the function cannot be tested below the level of "invoke the whole CLI", and phases 1 and 5 are the parts most likely to change.

Depth is only 2 and cognitive complexity (18) is well below the branch count (17), confirming this is *length*, not tangle. The 22 parameters are click's doing, not a design choice.

**Remediation.** Extract the two phases that are logic rather than plumbing:

```python
# src/cli/main.py

def _resolve_topology(
    proxy_leg: str | None, *, dut_ip: str, dut_port: int | None,
    proxy_host: str | None, proxy_port: int | None, backend_host: str | None,
) -> tuple[ProxyLeg | None, Role, str, int]:
    """Phase 1: leg -> role -> retarget -> validate. Raises UsageError."""
    leg = ProxyLeg(proxy_leg) if proxy_leg else None
    role = resolve_role(leg, Role(role_opt))
    if leg is not None:
        click.echo(f"Proxy leg '{leg.value}' selected — running as {role.value}.")
    dut_ip, dut_port = resolve_leg_target(
        leg, target_ip=dut_ip, target_port=dut_port,
        proxy_host=proxy_host, proxy_port=proxy_port,
    )
    blocked = back_leg_requirement_error(leg, proxy_mode=proxy_mode, backend_host=backend_host)
    if blocked:
        raise click.UsageError(blocked)
    if dut_port is None:
        dut_port = random_ephemeral_port()
        click.echo(f"No --dut-port given — using random destination port {dut_port} for this run.")
    return leg, role, dut_ip, dut_port


def _emit_results(result, run_dir: Path, *, report: str, debug: bool) -> int:
    """Phase 5: print the outcome, write the report, return the exit code."""
    if result.errored:
        click.echo(
            f"\npytest exited with code {result.pytest_returncode} "
            f"(collection/usage error or no tests). See {run_dir / 'pytest_output.log'}",
            err=True,
        )
        return result.pytest_returncode or 2
    click.echo(f"\n{result.counts_summary}")
    if result.total == 0:
        click.echo(
            "No tests ran. Check your --module/--submodule/--test selection and "
            f"the target configuration. Raw output: {run_dir / 'pytest_output.log'}",
            err=True,
        )
    if debug:
        click.echo(f"Debug log: {run_dir / 'debug.log'}")
    if report == "pdf":
        click.echo(f"PDF report: {generate_pdf_report(result, run_dir / 'report.pdf')}")
    elif report == "html":
        click.echo(f"HTML report: {generate_html_report(result, run_dir / 'report.html')}")
    return 1 if (result.failed or result.errors) else 0
```

`run` then reads as: resolve topology → build config → preflight → build request → `sys.exit(_emit_results(...))`, roughly 45 lines at CC ~5. `_emit_results` becomes directly unit-testable against a stub `TestRunResult` — and `tests_internal/` already has a shared run-result factory (added by the duplication audit's F-09) to feed it.

---

### F-03 — `MainWindow` carries 15 dependencies and a 5-phase click handler · **Importance 6/10**

**Location:** [`src/gui/main_window.py`](src/gui/main_window.py) · class 307 LOC · Ce **15**, I **0.83**. `_on_run_clicked` at [line 244](src/gui/main_window.py:244): CC 16, Cog 16, 84 LOC.

`_on_run_clicked` mirrors `cli.main.run` phase for phase — clear/reset UI, leg validation, preflight, role-mismatch warnings, request construction, start. It is the GUI's single largest source of behaviour and it is bound directly to a Qt signal, so none of it is reachable from a test without a `QApplication`.

The 15-way efferent coupling is the more structural point: `main_window.py` imports every panel (7), plus `config`, `preflight`, `proxy.config`, `plotting.metrics`, `plotting.realtime_plotter`, `reporting.models`, `runner`, `target_profiles`. Any change to run configuration touches this file.

**Remediation.** Extract the phases that aren't Qt, which also removes four of the fifteen imports from the shell:

```python
# src/gui/main_window.py

def _preflight_and_report(self, config: DUTConfig) -> bool:
    """Run preflight, echo it into the log panel, and say whether to proceed."""
    self._log_panel.append_line("Preflight connectivity check…")
    QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
    try:
        pre = run_preflight(config)
    finally:
        QApplication.restoreOverrideCursor()
    for line in pre.render_lines():
        self._log_panel.append_line("  " + line)
    if not pre.ok:
        self._log_panel.append_line("Preflight failed — not starting the run.")
    return pre.ok

def _warn_role_mismatches(self, config: DUTConfig) -> None:
    """Warn up front if a checked test won't run under the selected role
    (otherwise it just silently skips — the confusing case)."""
    for spec in self._tree.checked_specs():
        if config.role not in spec.roles:
            self._log_panel.append_line(
                f"Note: '{spec.test}' applies to role(s) [{spec.role_labels}] but the Role is "
                f"'{config.role.value}' — it will be SKIPPED. Change the Role selector to run it."
            )

def _build_run_request(self, config: DUTConfig) -> RunRequest:
    """Widget state -> RunRequest. The GUI's counterpart to cli.main.run."""
    proxy_host, proxy_port = _split_host_port(self._proxy_front.text())
    backend_host, backend_port = _split_host_port(self._proxy_backend.text())
    return RunRequest(
        config=config,
        targets=tuple(self._tree.checked_targets()),
        confirm_vuln_tests=self._confirm_vuln.isChecked(),
        debug=self._debug.isChecked(),
        role=config.role,
        proxy_mode=self._proxy_mode.currentData(),
        proxy_leg=config.proxy_leg.value if config.proxy_leg else None,
        proxy_host=proxy_host, proxy_port=proxy_port,
        backend_host=backend_host, backend_port=backend_port,
    )
```

`_on_run_clicked` then drops to roughly 30 lines at CC ~6. `tests_internal/test_gui_smoke.py` covers the tree/details path; `_build_run_request` becomes assertable there directly.

Longer term, `_build_config_group` ([line 85](src/gui/main_window.py:85), 75 LOC, CC 4) is pure widget construction and belongs in its own `gui/dut_config_panel.py` alongside `_resolved_dst_port`, `_selected_proxy_leg` and `_current_dut_config` — that single move takes `MainWindow` from 307 to roughly 180 lines and its Ce from 15 to 11. Low urgency (CC 4, no logic), but it is the cleanest available split.

---

### F-04 — The custom-payload cascade is written three times · **Importance 5/10** · COHESION

**Locations:** [`src/cli/main.py:260-267`](src/cli/main.py:260) · [`conftest.py:235-244`](conftest.py:235) · [`src/gui/custom_packet_panel.py:154-161`](src/gui/custom_packet_panel.py:154).

`payloads.py` deliberately stops at `resolve_payload`, documenting that resolving text/hex/file is "a CLI/GUI input-parsing concern, not this function's". The result is that the *same three-way precedence rule* — text beats hex beats file, none is an error — exists in three places, each with its own error type (`click.UsageError`, `pytest.UsageError`, `ValueError`) and its own wording. Add a fourth source (say `--payload-base64`) and three sites must change. This is a single responsibility that has no home.

Cognitive cost is measurable: `conftest.payload_settings` scores Cog 10 at depth 4 for what is a three-line rule.

**Remediation.** Give the rule a home in `payloads.py`, keeping the caller's exception type its own concern:

```python
# src/packet_engine/payloads.py

def resolve_custom_source(
    *, text: str | None = None, hex_str: str | None = None, file: str | Path | None = None
) -> bytes | None:
    """Resolve CUSTOM payload bytes from the first source that is set.

    Precedence is text > hex > file, matching every front end. Returns None
    when no source is given, so each caller can raise its own idiomatic
    "custom mode needs a source" error (click.UsageError / pytest.UsageError /
    ValueError) rather than this module inventing a shared exception type.
    """
    if text:
        return from_text(text)
    if hex_str:
        return from_hex(hex_str)
    if file:
        return from_file(file)
    return None
```

Then each site collapses to two lines — e.g. `conftest.py`:

```python
    custom = None
    if mode is PayloadMode.CUSTOM:
        custom = resolve_custom_source(
            text=pytestconfig.getoption("--payload-text"),
            hex_str=pytestconfig.getoption("--payload-hex"),
            file=pytestconfig.getoption("--payload-file"),
        )
        if custom is None:
            raise pytest.UsageError(
                "--payload-mode=custom requires one of --payload-text, --payload-hex, --payload-file"
            )
```

`cli.main.send` drops from CC 8 / depth 4 to CC ~4 / depth 2. `tests_internal/test_payload_handling.py` is the natural home for the precedence test that currently exists nowhere.

---

### F-05 — Report-log parsing is the deepest logic in `src/` · **Importance 4/10**

**Locations:** [`parse_report_log_line`](src/runner.py:383) CC 10 / Cog 18 / depth 4 · [`drain_test_events`](src/runner.py:336) CC 10 / Cog 17 / depth 4 · [`_extract_message`](src/runner.py:366) CC 9 / Cog 10.

These three carry the highest *cognitive-to-cyclomatic ratio* in the repo (1.8× and 1.7×), which is the signature of genuinely intricate logic rather than a long flag list. Together they encode three interacting rules: pytest's phase semantics (setup/call/teardown), the worst-wins severity merge, and the four shapes `longrepr` can take. The nesting reaches depth 4 in both.

This is, however, **essential complexity, well-handled**. Each function has a docstring that states its rule; `_SEVERITY` is a named table rather than inline comparisons; the phase dispatch is a flat `elif` chain, not nested. The `when == "call"` branch already uses the dict-lookup form that F-01 recommends elsewhere. Attempting to flatten it further would likely obscure it.

**Remediation.** No structural change recommended. One low-cost readability improvement — lift the phase rules into a table so the three-way policy is visible at a glance:

```python
# src/runner.py — replace the when/outcome elif chain at lines 398-415

_CALL_OUTCOMES = {
    "passed": TestOutcome.PASSED,
    "failed": TestOutcome.FAILED,
    "skipped": TestOutcome.SKIPPED,
}
#: Per-phase policy: (outcomes that are ignored, outcome for everything else).
#: A passing setup/teardown is ignored — the call phase carries the verdict.
_PHASE_POLICY = {
    "call":     (frozenset(), None),                       # None => use _CALL_OUTCOMES
    "setup":    (frozenset({"passed"}), TestOutcome.ERROR),  # skipped handled below
    "teardown": (frozenset({"passed", "skipped", "failed"}) - {"failed"}, TestOutcome.ERROR),
}
```

Given the subtlety of the setup-skip case, this is genuinely marginal — flag it as optional. The higher-value action here is a **test**, not a refactor: `tests_internal/` should pin the setup-ERROR and teardown-ERROR paths explicitly, since they encode the "run did nothing" diagnosis the docstring calls out as a past bug.

---

### F-06 — `pytest_collection_modifyitems` mixes two independent gates · **Importance 4/10** · COHESION

**Location:** [`conftest.py:62-100`](conftest.py:62) · CC 10 · Cog 17 · depth 3.

One loop applies two unrelated policies to every item: the *proxy opt-in* gate (lines 78-88, with an early `continue` that also exempts proxy tests from role filtering) and the *role* gate (lines 90-100). The `continue` is load-bearing — it is what makes proxy tests role-neutral — but that is a policy decision buried mid-loop, expressed as control flow.

**Remediation.** Split the policies into predicates so each is independently readable and testable:

```python
# conftest.py

_PROXY_SKIP_REASON = (
    "proxy: needs --proxy-mode and a backend instance "
    "(`netstack-cli proxy-serve`); see docs/proxy_testing.md"
)


def _applicable_roles(item: pytest.Item) -> set[str]:
    """Roles a test declares. Neither marker => client-only (the default)."""
    roles = {name for name in ("client", "server") if item.get_closest_marker(name)}
    return roles or {"client"}


def _skip_reason(item: pytest.Item, *, role: str, proxy_mode: str | None) -> str | None:
    """The single reason this item should be skipped, or None to run it."""
    if item.get_closest_marker("internal"):
        return None
    if item.get_closest_marker("proxy") is not None:
        # Proxy tests are opt-in and deliberately NOT role-filtered: the
        # topology, not the --role selector, decides whether they apply.
        return None if proxy_mode else _PROXY_SKIP_REASON
    applicable = _applicable_roles(item)
    if role in applicable:
        return None
    return f"role: applies to {sorted(applicable)}, running as {role}"


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Skip tests that don't apply to the selected --role or topology, at
    collection time (before any fixture — including the privileged
    network_interface — is set up, which a function-scoped skip fixture
    can't guarantee)."""
    role = effective_role(config).value
    proxy_mode = config.getoption("--proxy-mode")
    for item in items:
        reason = _skip_reason(item, role=role, proxy_mode=proxy_mode)
        if reason:
            item.add_marker(pytest.mark.skip(reason=reason))
```

The hook drops to CC 3 / depth 2, and `_skip_reason` becomes a pure function testable from `tests_internal/` with a stub item — currently this safety-relevant filter has no direct unit test.

---

### F-07 — `catalog.py` lookups are three linear scans · **Importance 2/10**

**Location:** [`src/catalog.py:586-605`](src/catalog.py:586) — `specs_for_rel_path`, `find_by_nodeid`, `find_by_test`.

Each walks all ~90 `TestSpec` entries. `find_by_nodeid` is called once per test event during a run, and `test_details_panel` calls into the catalog per tree selection. At 90 entries this is genuinely free — flagged only because the catalog grows monotonically (it is the file every new test must edit) and the fix is four lines.

**Remediation.** Build the indices once at import, next to `CATALOG`:

```python
# src/catalog.py — after the CATALOG literal

_BY_NODEID: dict[str, TestSpec] = {s.nodeid: s for s in CATALOG}
_BY_PATH: dict[str, list[TestSpec]] = {}
for _spec in CATALOG:
    _BY_PATH.setdefault(_spec.rel_path, []).append(_spec)


def specs_for_rel_path(rel_path: str) -> list[TestSpec]:
    """All test specs defined in the given test file (posix rel path)."""
    return list(_BY_PATH.get(rel_path.replace("\\", "/"), ()))


def find_by_nodeid(nodeid: str) -> TestSpec | None:
    normalized = nodeid.replace("\\", "/")
    hit = _BY_NODEID.get(normalized)
    if hit is not None:
        return hit
    # Absolute/prefixed node ids still need the suffix match.
    return next((s for s in CATALOG if normalized.endswith(s.nodeid)), None)
```

Keep `find_by_test` as-is or derive it from `_BY_PATH`. `tests_internal/test_catalog.py` already asserts catalog/disk agreement, so this is covered.

---

### F-07a — One import cycle: `src.proxy` ⇄ `src.proxy.client` · **Importance 3/10** · COUPLING

**Locations:** [`src/proxy/__init__.py:2`](src/proxy/__init__.py:2) imports `src.proxy.client`; [`src/proxy/client.py:17`](src/proxy/client.py:17) does `from src.proxy import tunnel`, which re-enters the package `__init__`.

The only cycle in the codebase. **It does not currently break** — verified both entry orders:

```
python -c "import src.proxy.client"  -> OK
python -c "import src.proxy"         -> OK
```

It survives only because of the *form* of the import. `from src.proxy import tunnel` requests a **submodule**, and by the time `client.py` runs, the parent `__init__` has already completed the `client` line that pulled it in — so the partially-initialized `src.proxy` module object is enough. Change that line to import a *name* re-exported by `__init__` (e.g. `from src.proxy import ProxyConfig`) and it becomes an immediate `ImportError: cannot import name … (most likely due to a circular import)`. The cycle is a latent trap, not a live bug.

**Remediation.** One line. Import the submodule directly and the edge disappears:

```python
# src/proxy/client.py:17
-from src.proxy import tunnel
+from src.proxy import tunnel  # noqa: F401  <- replace with:
+import src.proxy.tunnel as tunnel
```

or, equivalently and more in keeping with the file's other imports:

```python
from src.proxy import tunnel   ->   from src.proxy.tunnel import (
                                        AUTH_NONE, AUTH_NO_ACCEPTABLE, AUTH_USERNAME_PASSWORD,
                                        CMD_CONNECT, HttpConnectResponse, Socks5Reply,
                                        build_http_connect_request, build_socks5_greeting,
                                        build_socks5_request, build_socks5_userpass_auth,
                                        format_authority, parse_http_connect_response,
                                        parse_socks5_method_selection, parse_socks5_userpass_result,
                                        read_http_response_head, read_socks5_reply,
                                    )
```

The first form is preferable — `client.py` uses 16 names from `tunnel` and the `tunnel.` prefix is load-bearing for readability. Same applies to [`tests/proxy/test_proxy_socks5.py:14`](tests/proxy/test_proxy_socks5.py:14) and [`tests_internal/test_proxy_relay.py:19`](tests_internal/test_proxy_relay.py:19), though those are outside the package and carry no cycle risk. Verify with `python -c "import src.proxy.client"` and `pytest tests_internal/test_proxy_tunnel.py -q`.

---

### F-08 — Measured and healthy: `catalog.py` at 605 lines is not a split candidate · **Importance 1/10** · NO ACTION

`src/catalog.py` is the largest file in the repo and would fail any naive "files over 300 lines" rule. It is 530 lines of `TestSpec(...)` literals with three trailing lookup functions — CC 1 throughout, zero nesting. Splitting it per-module (`catalog/ip.py`, `catalog/tcp.py`, …) would trade one obvious file for six plus an aggregator, and would break the property the module docstring relies on: that "keep an entry here" names exactly one place. **Leave it.** The same applies to `tools/generate_screenshots.py:49 sample_result` (106 LOC, CC 3 — literal fixture data) and to `src/cli/options.py:52 shared_options` (63 LOC, **CC 1** — a `return` of a tuple of literals).

Likewise the three Qt `__init__` / `_build_*` methods (`CustomPacketPanel.__init__` 105 LOC CC 3, `_build_config_group` 75 LOC CC 4, `ProxyBackendPanel.__init__` 54 LOC **CC 1**): long widget-construction bodies are the idiomatic Qt form, and their complexity scores confirm there is no logic hiding in them. Splitting them for line count alone would add indirection without removing a decision.

---

### F-09 — Measured and healthy: the stable-kernel structure and the proxy layer · **Importance 1/10** · NO ACTION

Recorded so it is not re-audited:

- **One import cycle only** (`src.proxy` ⇄ `src.proxy.client`, F-07a); the rest of the graph is a clean DAG.
- **The stable kernel is textbook.** Five modules have Ce=0 with Ca between 11 and 22 (`reporting.models` 22, `utils.tcp_flags` 18, `config` 14, `proxy.config` 12, `packet_engine.payloads` 11). Zero-instability modules with high afferent coupling are exactly what the metric asks for, and it means the widely-used abstractions cannot drag dependencies behind them.
- **`runner.py` (Ce 4, Ca 7, I 0.36)** is correctly positioned as the shared orchestration layer: more depended-upon than depending, importing only `config`, `payloads`, `reporting.models` and `paths`. Its 450 lines are three cohesive groups — request/args (F-01), subprocess streaming, and log parsing (F-05) — each with a section comment. No split warranted.
- **The proxy layer is otherwise the best-factored subsystem measured** (its one cycle is F-07a). `proxy/tunnel.py` (246 LOC) is 13 pure functions over bytes, **Ce 0**, and every one is independently unit-tested (`tests_internal/test_proxy_tunnel.py`). `ProxyClient._socks5_connect` (CC 9, Cog 11) and `EchoBackend._handle_tcp` (CC 7, Cog 12) score above the noise floor purely because protocol error handling *is* branchy — each branch is a distinct RFC-mandated failure mode with its own message. Refactoring them would erase RFC traceability for no measurable gain.
- **`preflight.run_preflight`** (57 LOC, CC 5, Cog 4) is five sequential guard clauses that each `return` a complete `PreflightResult`. Long, flat, and clear — the right shape.

---

## Priority order

| # | Finding | Importance | Effort | Verified by |
|---|---|---:|---|---|
| 1 | F-01 `build_pytest_args` flag table | 7 | ~1h | `tests_internal/test_runner_args.py` |
| 2 | F-02 split `cli.main.run` | 6 | ~1h | `tests_internal/test_cli.py` |
| 3 | F-03 split `_on_run_clicked` | 6 | ~1h | `tests_internal/test_gui_smoke.py` |
| 4 | F-04 `resolve_custom_source` | 5 | ~30m | `tests_internal/test_payload_handling.py` (new test) |
| 5 | F-06 split the collection hook | 4 | ~30m | new `tests_internal/` unit test |
| 6 | F-05 report-log parsing tests | 4 | ~45m | new `tests_internal/` unit tests |
| 7 | F-07a break the proxy import cycle | 3 | ~5m | `python -c "import src.proxy.client"` |
| 8 | F-07 catalog indices | 2 | ~10m | `tests_internal/test_catalog.py` |

F-01 through F-03 are the same refactor applied three times: **move the phase logic out of the entry point, leave the plumbing behind.** Doing F-01 first is worthwhile because it is the one whose failure mode (a silently-ignored option) is invisible.

### Suggested guardrail

Once F-01/F-02/F-03 are applied, nothing in `src/` exceeds CC 10, so the threshold can be enforced rather than re-audited:

```toml
# pyproject.toml
[tool.ruff.lint]
select = ["C90"]           # mccabe

[tool.ruff.lint.mccabe]
max-complexity = 10

[tool.ruff.lint.per-file-ignores]
# Assertion-dense test bodies inflate McCabe without adding cognitive load.
"tests/**" = ["C901"]
"tests_internal/**" = ["C901"]
```

Verified against the measurements above: the only `src/` functions this would reject today are `build_pytest_args` (21), `cli.main.run` (17), `_on_run_clicked` (16), `drain_test_events` (10) and `parse_report_log_line` (10) — the first three are F-01/F-02/F-03, and the last two land exactly on the boundary (add `# noqa: C901` with a pointer to F-05, or set `max-complexity = 11`).

---

## Unable to verify

- **Runtime hot paths.** Every figure here is static. Whether `find_by_nodeid`'s linear scan (F-07) or the 0.2 s `POLL_INTERVAL_S` drain loop dominates a long run would need `cProfile` output from an actual DUT run — not reproducible without hardware and elevated privileges. F-07's importance rating assumes it does not.
- **Cognitive-complexity absolute values.** The implementation follows SonarSource's published rules (nesting-weighted increments, +1 per `BoolOp` sequence, +1 for direct recursion) but is not Sonar itself; treat the numbers as *comparable within this report*, not as Sonar scores. The rankings are what the findings rest on, and those are robust — `build_pytest_args` leads on both metrics by a wide margin.
- **The F-01 port-0 behaviour change.** Whether `--proxy-port 0` or `--dut-port 0` is a configuration anyone uses is not determinable from the code; `random_ephemeral_port()` only ever returns 49152-65535, and no test exercises port 0. Confirming it would take either a stated requirement or a `tests_internal/test_runner_args.py` case asserting the intended behaviour for 0. **Add that test as part of F-01** rather than picking a behaviour silently.
- **GUI-side dependency counts under lazy imports.** `main_window.py`'s Ce=15 counts module-level imports only. If any panel imports further `src/` modules at call time (the `payload_settings` fixture does exactly this at `conftest.py:231`), the effective fan-out is higher than measured. A runtime import trace during a GUI session would settle it.
