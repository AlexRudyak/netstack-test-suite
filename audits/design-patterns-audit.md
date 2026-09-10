# Design Patterns Audit — netstack-test-suite

**Date:** 2026-09-10
**Commit:** `cbe4af1` (branch `development`)
**Scope:** all 12,544 lines of Python across `src/` (58 modules, 51 classes, 20 dataclasses, 2 `typing.Protocol`s), `tests/`, `tests_internal/`, `conftest.py`, `tools/`, `packaging/`.
**Method:** full read of every `src/` module, `conftest.py`, `tests/conftest.py` and the three sub-conftests; every class and every dispatch site (`if`/`elif` chains over an `Enum` or a string discriminator) classified against the GoF creational/structural/behavioral catalogue and the Fowler PoEAA domain catalogue. Cross-module coupling and cycle claims were confirmed by grep over the import graph.

**Severity scale:** 1 = cosmetic, 10 = actively causing defects.

---

## Executive summary

**This codebase is under-patterned rather than over-patterned, and that is mostly the right call.** There is no Singleton anywhere (no `__new__` override, no `_instance` global, no `get_logger()` accessor), no abstract-base-class hierarchy, no visitor, no dependency-injection container. Almost every "pattern" present is the *lightweight Python form* of it: a frozen dataclass instead of a Value Object class, a module-level dict instead of a Registry singleton, a `typing.Protocol` instead of an abstract Adapter base, a plain function instead of a Strategy object. For a 12.5k-line desktop tool with two front ends, that is proportionate.

Where the design is genuinely good, it is good on purpose:

| Pattern | Where | Verdict |
|---|---|---|
| **Command** | [`RunRequest`](src/runner.py:84) → [`build_pytest_args`](src/runner.py:177) | Correct and load-bearing. One serializable request object rendered into a subprocess argv, consumed identically by CLI and GUI. |
| **Facade** | [`src/runner.py`](src/runner.py:1) | Correct. The single orchestration seam; both front ends go through it, which is why they cannot drift. |
| **Adapter** | [`SocketBackend`](src/packet_engine/platform_backend.py:34) Protocol | Correct shape, over-built for its content (F-11). |
| **Observer** | [`RunController`](src/gui/run_controller.py:30) Qt signals; [`_DebugBoundaryPlugin`](conftest.py:265) pytest hooks | Correct. Idiomatic for the framework in each case. |
| **Registry** | [`target_profiles/registry.py`](src/target_profiles/registry.py:5), [`catalog._BY_NODEID`](src/catalog.py:590) | Correct and appropriately boring. |
| **Value Object** | [`TestSpec`](src/catalog.py:27), [`ProxyConfig`](src/proxy/config.py:52), [`RangeField`](src/target_profiles/base.py:31), [`DUTConfig`](src/config.py:151) | Correct — frozen, behaviour-bearing, no identity. |
| **Chain of responsibility** | [`collection_policy.skip_reason`](src/collection_policy.py:43) | Correct, and correctly *not* built as a chain of objects — three ordered guards in 20 lines. |

The problems cluster in four places, and three of the four are **missing** patterns, not misapplied ones:

1. **No Repository for the run directory.** The eight artifact filenames (`results.json`, `report_log.jsonl`, `packet_events.jsonl`, `capture.pcap`, `debug.log`, `pytest_output.log`, `report.pdf`, `report.html`) are string literals scattered across five modules, and the write of `results.json` ([`runner.finalize_run`](src/runner.py:257)) is 220 lines and one module away from its read ([`collector.load_run_result`](src/reporting/collector.py:37)). — **F-01**
2. **Serialization written three times per DTO.** `DUTConfig` and `TestRunResult` each state their field list in the dataclass body, again in `to_dict`/`to_file`, and again in `from_dict`/`from_file`. A new field is silently dropped by two of the three. — **F-02**, **F-08**
3. **Enum dispatch by `if`/`elif` where a table is shorter.** Four sites: proxy handshake selection, report-format selection, protocol selection, payload mode. Only one of them (the proxy handshake) actually warrants Strategy. — **F-04**, **F-05**, **F-13**
4. **Two DTOs carry the same two fields with different types.** `RunRequest.role`/`proxy_leg` duplicate `DUTConfig.role`/`proxy_leg`, and `proxy_leg` is `str | None` on one and `ProxyLeg | None` on the other. Nothing enforces agreement. — **F-03**

Sixteen findings follow, ordered by importance. Findings F-14 … F-16 are "measured and confirmed healthy" entries, recorded so a future audit does not re-litigate them.

---

## 1. Creational patterns

### F-01 — No Repository for the run directory; eight artifact filenames are literals in five modules — **Severity 7**

**What is there.** Nothing. A run directory is a bare `Path` created by [`new_run_dir()`](src/runner.py:225), and every module that wants a file inside it re-types the filename:

| File | Written at | Read at | Also named at |
|---|---|---|---|
| `results.json` | [`runner.py:257`](src/runner.py:257) | [`collector.py:37`](src/reporting/collector.py:37) | [`report_data.py:69`](src/reporting/report_data.py:69) |
| `report_log.jsonl` | [`runner.py:184`](src/runner.py:184) (as a flag) | [`runner.py:291`](src/runner.py:291), [`run_controller.py:81`](src/gui/run_controller.py:81) | — |
| `packet_events.jsonl` | [`runner.py:191`](src/runner.py:191) | [`runner.py:292`](src/runner.py:292), [`run_controller.py:87`](src/gui/run_controller.py:87) | — |
| `capture.pcap` | [`runner.py:192`](src/runner.py:192) | — | [`report_data.py:66`](src/reporting/report_data.py:66) |
| `debug.log` | [`runner.py:211`](src/runner.py:211) | — | [`cli/main.py:128`](src/cli/main.py:128), [`report_data.py:67`](src/reporting/report_data.py:67) |
| `pytest_output.log` | [`runner.py:300`](src/runner.py:300) | — | [`cli/main.py:114`](src/cli/main.py:114), [`cli/main.py:123`](src/cli/main.py:123), [`gui/main_window.py:364`](src/gui/main_window.py:364), [`report_data.py:68`](src/reporting/report_data.py:68) |
| `report.pdf` | [`cli/main.py:130`](src/cli/main.py:130), [`report_panel.py:56`](src/gui/report_panel.py:56) | — | — |
| `report.html` | [`cli/main.py:132`](src/cli/main.py:132), [`report_panel.py:56`](src/gui/report_panel.py:56) | — | — |

**Why it matters.** The `report_data.ARTIFACTS` tuple exists *specifically* to tell the reader of a report what files a run produced — and it is a fourth independent copy of the same names. Renaming `pytest_output.log` requires finding six sites, one of which is inside an f-string in a Qt callback. This is the classic symptom of a missing Repository: the persistence schema (which files, named what, in which directory) has no owner.

The read/write split is the sharper edge. `finalize_run` serializes `TestRunResult` to `results.json`; `load_run_result` deserializes it — in a different package, with no import between them and no shared constant. A change to the on-disk shape has to be made in two places that nothing links.

**Remediation.** One value object owning the layout, in `src/runner.py` (or a new `src/run_artifacts.py` if you prefer `runner` to stay orchestration-only):

```python
@dataclass(frozen=True)
class RunArtifacts:
    """The one description of what a run directory contains.

    Every producer and consumer of a run's files addresses them through
    here, so a rename is one edit and the report's artifact list cannot
    drift from what was actually written.
    """

    root: Path

    RESULTS = "results.json"
    REPORT_LOG = "report_log.jsonl"
    PACKET_EVENTS = "packet_events.jsonl"
    CAPTURE = "capture.pcap"
    DEBUG_LOG = "debug.log"
    PYTEST_OUTPUT = "pytest_output.log"

    # (filename, what it holds) — the report's artifact list, generated
    # from the same names the runner actually writes.
    DESCRIPTIONS: ClassVar[tuple[tuple[str, str], ...]] = (
        (CAPTURE, "every frame the suite sent and received."),
        (DEBUG_LOG, "tshark-style per-packet trace (present only if Debug mode was on)."),
        (PYTEST_OUTPUT, "raw test-runner output."),
        (RESULTS, "this run in machine-readable form."),
    )

    @property
    def results(self) -> Path: return self.root / self.RESULTS
    @property
    def report_log(self) -> Path: return self.root / self.REPORT_LOG
    @property
    def packet_events(self) -> Path: return self.root / self.PACKET_EVENTS
    @property
    def capture(self) -> Path: return self.root / self.CAPTURE
    @property
    def debug_log(self) -> Path: return self.root / self.DEBUG_LOG
    @property
    def pytest_output(self) -> Path: return self.root / self.PYTEST_OUTPUT

    def save(self, result: TestRunResult) -> None:
        self.results.write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")

    def load(self) -> TestRunResult:
        return TestRunResult.from_dict(json.loads(self.results.read_text(encoding="utf-8")))
```

Then `new_run_dir()` returns `tuple[str, RunArtifacts]`, `finalize_run` becomes `artifacts.save(result)`, `collector.load_run_result(run_dir)` becomes `RunArtifacts(run_dir).load()` (keep the old name as a one-line shim so the existing callers and `tests_internal/test_reporting_pdf.py` keep working), and `report_data.ARTIFACTS` becomes `RunArtifacts.DESCRIPTIONS`.

---

### F-02 — `TestRunResult` states its field list three times; a new field is silently dropped — **Severity 7**

**Where.** [`src/reporting/models.py:90`](src/reporting/models.py:90) (dataclass body, 13 fields), [`:168` `to_dict`](src/reporting/models.py:168), [`:184` `from_dict`](src/reporting/models.py:184).

**Why it matters.** This is a Data Transfer Object doing its own marshalling by hand, and the three copies are only kept in sync by discipline. The failure is silent and asymmetric:

- A field added to the dataclass but not `to_dict` → never persisted; a regenerated report loses it with no error.
- A field added to `to_dict` but not `from_dict` → written to `results.json`, then discarded on reload.

`proxy_leg` is the live proof this is a real risk, not a theoretical one: its docstring ([`models.py:102`](src/reporting/models.py:102)) records that reports previously "read as if a plain host was tested" — exactly the class of bug an unpropagated field produces. The GUI path makes it worse: `RunController` builds the result in-process and never round-trips it, so a `to_dict`/`from_dict` gap is invisible in a GUI session and only appears when someone regenerates a report from disk.

**The existing guard does not catch this.** [`tests_internal/test_reporting_pdf.py:55-63`](tests_internal/test_reporting_pdf.py:55) asserts exactly five things after a round-trip: `run_id`, `passed`, `failed`, `len(tests)`, `len(packet_events)`. A field dropped from `to_dict` — `target_stack`, `host_platform`, `payload_mode`, `role`, `proxy_leg`, `pytest_returncode`, or the per-`TestEvent` `markers`/`message` — passes this test silently. Strengthening the assertion is the cheaper half of the fix and worth doing even if the serializer stays hand-written:

```python
def test_results_json_round_trip() -> None:
    result = _sample_result()
    # Compare the serialized forms, not a handful of fields: a field added
    # to the dataclass but forgotten in to_dict/from_dict is exactly what
    # this needs to catch, and naming fields here would miss the new one.
    assert TestRunResult.from_dict(result.to_dict()).to_dict() == result.to_dict()
```

That catches an asymmetric gap (in `to_dict` but not `from_dict`). It does *not* catch a field missing from both — for that, add `assert set(result.to_dict()) == {f.name for f in fields(TestRunResult)}`.

**Remediation.** Keep the hand-written form for the two non-trivial fields and derive the rest, so adding a scalar field needs no serializer edit at all:

```python
from dataclasses import fields

# Fields that are not JSON scalars and need their own conversion.
_DATETIME_FIELDS = ("started_at", "finished_at")
_NESTED = {"tests": TestEvent, "packet_events": PacketEvent}


def to_dict(self) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for f in fields(self):
        value = getattr(self, f.name)
        if f.name in _DATETIME_FIELDS:
            out[f.name] = value.isoformat() if value else None
        elif f.name in _NESTED:
            out[f.name] = [item.to_dict() for item in value]
        else:
            out[f.name] = value
    return out


@classmethod
def from_dict(cls, data: dict[str, Any]) -> "TestRunResult":
    kwargs: dict[str, Any] = {}
    for f in fields(cls):
        if f.name in _DATETIME_FIELDS:
            raw = data.get(f.name)
            kwargs[f.name] = datetime.fromisoformat(raw) if raw else None
        elif f.name in _NESTED:
            kwargs[f.name] = [_NESTED[f.name].from_dict(d) for d in data.get(f.name, [])]
        elif f.name in data:
            kwargs[f.name] = data[f.name]
    return cls(**kwargs)
```

This needs a `from_dict` on `TestEvent` and `PacketEvent` (both are two-liners over their existing `to_dict`, with the one enum coercion each). The `elif f.name in data` guard preserves the current tolerance for older `results.json` files missing newer keys.

---

### F-03 — `RunRequest` and `DUTConfig` both carry `role` and `proxy_leg`, with divergent types — **Severity 6**

**Where.** [`RunRequest.role: Role`](src/runner.py:100) and [`RunRequest.proxy_leg: str | None`](src/runner.py:111) versus [`DUTConfig.role: Role`](src/config.py:168) and [`DUTConfig.proxy_leg: ProxyLeg | None`](src/config.py:173) — and `RunRequest.config` *is* a `DUTConfig`.

**Why it matters.** The Command object embeds the configuration it commands, then shadows two of its fields. [`build_pytest_args`](src/runner.py:186) reads `request.role.value` and [`:137`](src/runner.py:137) reads `request.proxy_leg` — never `request.config.role` / `request.config.proxy_leg`. So the value that reaches the subprocess is the `RunRequest` copy, while the value that reaches `preflight`, the safety allow-list check and the GUI's topology echo is the `DUTConfig` copy. Nothing checks they agree.

Both current call sites happen to set them consistently — the CLI passes `resolved_role` to both ([`cli/main.py:213`](src/cli/main.py:213) and [`:236`](src/cli/main.py:236)), the GUI passes `config.role` and `config.proxy_leg.value` ([`gui/main_window.py:341`](src/gui/main_window.py:341)) — but that is a convention held in two places, not an invariant. A third caller (a future `--rerun` from a saved run, say) that sets one and not the other produces a run whose *preflight* and *reports* say `client` while the *pytest subprocess* runs as `server`. That is the highest-consequence divergence in the codebase, because role decides which direction traffic is sent at the DUT.

The type divergence (`str | None` vs `ProxyLeg | None`) also forces every GUI construction site to write `config.proxy_leg.value if config.proxy_leg else None` — the exact stringly-typed conversion the `ProxyLeg` enum exists to avoid.

**Remediation.** Delete both shadow fields and read through the config. Minimal, mechanical:

```python
# src/runner.py — RunRequest
@dataclass
class RunRequest:
    config: DUTConfig
    ...
    # role and proxy_leg REMOVED — they live on `config`, which already
    # resolved them via src.config.resolve_role / resolve_leg_target.

    @property
    def role(self) -> Role:
        return self.config.role

    @property
    def proxy_leg(self) -> str | None:
        return self.config.proxy_leg.value if self.config.proxy_leg else None
```

Properties (rather than an outright delete) keep `build_pytest_args`, `new_run_result` and `gui/main_window._on_run_clicked`'s `request.proxy_mode` logging unchanged; only the two `RunRequest(...)` construction sites lose their `role=` / `proxy_leg=` arguments. Note `runner.py` already imports `Role`, so no new import.

---

### F-04 — Payload construction is a Factory with an `if`-chain; a mapping is shorter and closes the fall-through — **Severity 3**

**Where.** [`resolve_payload`](src/packet_engine/payloads.py:75) — four `if mode is PayloadMode.X` branches plus a trailing `raise ValueError(f"Unhandled PayloadMode: {mode!r}")`.

**Why it matters.** Barely. This is a correct, well-documented Factory Method and the fall-through raise is honest. The only real cost is that the generator functions (`zeros`, `ones`, `random_bytes`) are already one-arg callables with an identical signature, so the branch structure is pure ceremony — and adding a fifth mode means editing two places (the enum and the chain) rather than one.

**Remediation.** Optional; take it only if a fifth mode is on the horizon.

```python
# Size-driven modes, as a table. CUSTOM is deliberately not here: its bytes
# come from the caller, not from a generator.
_GENERATORS: dict[PayloadMode, Callable[[int], bytes]] = {
    PayloadMode.ZEROS: zeros,
    PayloadMode.ONES: ones,
    PayloadMode.RANDOM: random_bytes,
}


def resolve_payload(mode: PayloadMode, size: int = 0, custom: bytes | None = None) -> bytes:
    if mode is PayloadMode.CUSTOM:
        if custom is None:
            raise ValueError("PayloadMode.CUSTOM requires `custom` bytes")
        return custom
    try:
        return _GENERATORS[mode](size)
    except KeyError:
        raise ValueError(f"Unhandled PayloadMode: {mode!r}") from None
```

---

### F-05 — `build_custom_packet` dispatches on a `str` proto, not an enum — **Severity 4**

**Where.** [`src/custom_packet/builder.py:37-52`](src/custom_packet/builder.py:37) — `if spec.proto == "tcp" … elif spec.proto == "udp" … else raise ValueError`.

**Why it matters.** `CustomPacketSpec.proto` is typed `str` with a `# "tcp" | "udp"` comment ([`builder.py:18`](src/custom_packet/builder.py:18)). Every other discriminator in this codebase is an `Enum` (`PayloadMode`, `ProxyMode`, `Role`, `ProxyLeg`, `TestOutcome`, `PacketDirection`, `Confidence`) — this is the one holdout, and it is the one that reaches the wire. The valid set is declared three more times as string literals: [`cli/main.py:255`](src/cli/main.py:255) (`click.Choice(["tcp", "udp"])`) and [`gui/custom_packet_panel.py:36`](src/gui/custom_packet_panel.py:36) (`addItems(["tcp", "udp"])`). Typing `"TCP"` in either front end reaches `build_custom_packet` and raises at send time rather than being rejected at parse time.

**Remediation.** A three-member enum and a builder table, matching the `PayloadMode` idiom already used one import line away:

```python
# src/custom_packet/builder.py
class Proto(Enum):
    TCP = "tcp"
    UDP = "udp"


# Each entry takes (src_ip, dst_ip, sport, dport) plus the kwargs the
# protocol accepts, so the spec fans out to exactly one call.
_L3_BUILDERS: dict[Proto, Callable[..., Packet]] = {
    Proto.TCP: lambda s, d, sp, dp, spec: build_tcp(
        s, d, sp, dp, flags=spec.tcp_flags, ttl=spec.ttl, payload=spec.resolved_payload()
    ),
    Proto.UDP: lambda s, d, sp, dp, spec: build_udp(
        s, d, sp, dp, ttl=spec.ttl, payload=spec.resolved_payload()
    ),
}
```

If that reads as more machinery than the two branches it replaces (defensible — it is), take only the enum half and keep the `if`/`elif`: `proto: Proto` on the spec, `click.Choice([p.value for p in Proto])` in the CLI, `addItems([p.value for p in Proto])` in the panel. That alone removes the three literal lists and moves the error from send time to parse time, which is the whole benefit.

---

## 2. Structural patterns

### F-06 — `reporting/models.py` is the domain model *and* the render palette — **Severity 5**

**Where.** [`OUTCOME_STYLE`](src/reporting/models.py:51) — a 14-line table of CSS class names, hex colours (`#1a7f37`), matplotlib colour names (`tab:green`) and console prefixes (`PASS`), living in the module whose own docstring calls itself "Canonical result models … One source of truth avoids each consumer re-deriving its own notion of *what happened*."

**Why it matters.** Consolidating the palette was clearly the right call — it is read by [`html_report._palette_css`](src/reporting/html_report.py:20), [`pdf_report._OUTCOME_COLORS`](src/reporting/pdf_report.py:28), [`static_charts.render_pass_fail_summary`](src/plotting/static_charts.py:399) and [`TestEvent.summary_line`](src/reporting/models.py:82). But putting it *here* inverts the dependency the module was built to establish. `models.py` is imported by `runner.py`, `collector.py`, `interface.py`, `metrics.py` and every GUI panel — none of which render anything. Every one of them now transitively carries the report stylesheet, and a designer changing a hex value edits the file that defines what a test result *is*.

The concrete tell: `models.py` currently has zero presentation-free consumers. Adding one (a JSON API, a CSV export, a headless CI summary) means importing the palette to get `TestOutcome`.

**Remediation.** Move the table to a sibling; it is a pure lift with no logic change.

```python
# src/reporting/palette.py  (new)
"""Outcome → presentation, in one table.

Every renderer reads its own column here rather than re-typing the palette:
the HTML report's CSS class and hex values, the PDF's text/background
colours, the matplotlib bar colour, and the GUI log panel's short label.
Kept out of models.py so the result model stays free of presentation.
"""
from src.reporting.models import TestOutcome

OUTCOME_STYLE: dict[TestOutcome, dict[str, str]] = {...}  # unchanged
```

Nothing has to move with it: [`TestEvent.summary_line`](src/reporting/models.py:82) formats `outcome.value.upper()` directly and reads neither `OUTCOME_STYLE` nor its `"prefix"` column. Grep confirms **`"prefix"` has no consumer at all** — it is defined on all four outcomes ([`models.py:53,56,59,62`](src/reporting/models.py:53)) and read nowhere. Either delete the column while moving the table, or wire `summary_line` to it (`OUTCOME_STYLE[self.outcome]["prefix"]`), which is presumably what it was added for — the `label_width=5`/`label_width=7` parameter the CLI and GUI pass exists to pad `PASSED`/`SKIPPED`, and fixed 4-char prefixes would make it unnecessary.

---

### F-07 — `src/proxy/__init__.py` creates a real import cycle that `client.py` works around by hand — **Severity 5**

**Where.** [`src/proxy/client.py:17-21`](src/proxy/client.py:17), a five-line comment explaining that `import src.proxy.tunnel as tunnel` must be written in the submodule form because `from src.proxy import tunnel` "re-enters the package `__init__`, which imports this module back — a real import cycle that only survives because `tunnel` is a submodule."

**Why it matters.** The cycle is `src/proxy/__init__.py` → `client.py` → (`src.proxy` package) → `__init__.py`. It exists solely because the package `__init__` is a re-export Facade ([`__init__.py:1-13`](src/proxy/__init__.py:1)) listing seven names. That Facade has, per grep, **no consumer** — every importer in the codebase reaches for the submodule directly (`from src.proxy.client import ProxyClient` in `inducer.py` and `tests/proxy/conftest.py`; `from src.proxy.config import ...` in `conftest.py`, `cli/main.py`, `gui/main_window.py`, `gui/proxy_panel.py`; `from src.proxy.backend import EchoBackend` in `cli/main.py` and `gui/proxy_panel.py`).

So a Facade nobody uses is imposing an import-order constraint that a comment has to defend. The complexity audit records the `src/` import graph as cycle-free — this one survives that check only because the submodule-import form dodges it.

**Remediation.** Delete the re-export block. `src/target_profiles/__init__.py` is the counter-example where the same pattern is *earning* its keep — it is imported as `from src.target_profiles import list_profiles` by `cli/main.py`, `gui/main_window.py` and `conftest.py`, and its submodules do not import each other cyclically.

```python
# src/proxy/__init__.py
"""Proxy-DUT testing: config, the echo backend, the tunnelling client.

Deliberately empty: importing the submodules here made `client.py` import
the package that imports it back. Import the submodule you need directly
(`from src.proxy.client import ProxyClient`) — which is what every caller
already does.
"""
```

Then `client.py:17-21`'s workaround comment and the `import src.proxy.tunnel as tunnel` form can revert to the ordinary `from src.proxy import tunnel`.

---

### F-08 — `DUTConfig.to_file`/`from_file` is an unused Active Record with a third copy of the field list — **Severity 4**

**Where.** [`src/config.py:207-244`](src/config.py:207), plus [`DEFAULT_CONFIG_PATH`](src/config.py:24).

**Why it matters.** Two distinct problems in one place.

*Pattern-wise:* a frozen Value Object that knows its own file path is an Active Record. `DUTConfig`'s own docstring positions it as "the single object threaded through the CLI, the GUI, and every pytest fixture" — a pure DTO. Giving it a default `Path.home() / ".netstack_test_suite" / "config.json"` hard-wires a persistence location into the object every layer passes around.

*Practically:* grep finds **no production caller**. `to_file`/`from_file` are exercised only by [`tests_internal/test_proxy_leg.py:39-46`](tests_internal/test_proxy_leg.py:39), which uses them to assert `proxy_leg` survives a round-trip. Neither the CLI nor the GUI offers a save/load-configuration action. So 38 lines of hand-written serialization — a third statement of the 11-field list, with the same silent-drop failure mode as F-02 — exist to be tested and nothing else.

**Remediation.** Pick one:

- **If config persistence is planned** (a GUI "Save profile" button is the obvious use), keep the methods but derive them, and move the path out of the model:

```python
    @classmethod
    def from_dict(cls, data: dict) -> "DUTConfig":
        return cls(
            **{f.name: data[f.name] for f in fields(cls) if f.name in data and f.name not in _COERCED},
            allowed_targets=tuple(data.get("allowed_targets", ())),
            role=Role(data.get("role", "client")),
            proxy_leg=ProxyLeg(data["proxy_leg"]) if data.get("proxy_leg") else None,
        )

    def to_dict(self) -> dict:
        d = asdict(self)
        d["allowed_targets"] = list(self.allowed_targets)
        d["role"] = self.role.value
        d["proxy_leg"] = self.proxy_leg.value if self.proxy_leg else None
        return d
```

  …and let the *caller* own the path (`DEFAULT_CONFIG_PATH.write_text(json.dumps(config.to_dict()))`), which also makes `test_proxy_leg.py`'s round-trip test simpler.

- **If it is not planned**, delete `to_file`, `from_file` and `DEFAULT_CONFIG_PATH`, and rewrite the two tests against `to_dict`/`from_dict` (or delete them — they are testing a feature that does not ship).

---

### F-09 — `proxy/client.py` imports a buffer-size constant from `proxy/backend.py` — **Severity 3**

**Where.** [`src/proxy/client.py:22`](src/proxy/client.py:22): `from src.proxy.backend import RECV_CHUNK`, used once at [`client.py:166`](src/proxy/client.py:166) in `read_until_eof`.

**Why it matters.** The two halves of the proxy test topology are meant to be independent — they run in *different processes on different machines* (`config.py`'s docstring diagram). Importing the backend module into the client for a 65536 literal creates a compile-time dependency between them that the runtime topology does not have. It also means the client pulls in `socket`, `threading`, `BackendStats` and `EchoBackend` for one integer.

**Remediation.** Move it to the module both already import.

```python
# src/proxy/config.py
# Socket read size for both instances. Not a protocol constant — just the
# chunk size a relay reads in; stated once so the two sides match.
RECV_CHUNK = 65536
```

Then `backend.py` and `client.py` both do `from src.proxy.config import RECV_CHUNK`, and `client.py` loses its `backend` import entirely.

---

### F-10 — `TestSpec` lookup falls back to an O(n) scan on the interactive path — **Severity 3**

**Where.** [`catalog.find_by_nodeid`](src/catalog.py:604) — a dict hit on `_BY_NODEID`, then `next((spec for spec in CATALOG if normalized.endswith(spec.nodeid)), None)` on a miss.

**Why it matters.** Small but real. The module comment at [`catalog.py:586`](src/catalog.py:586) explicitly notes these lookups "are on the interactive path". The dict is the fast path for the exact-match case; the scan is the fallback for absolute or prefixed node ids. But the *most common* caller is [`report_data.build_findings`](src/reporting/report_data.py:112), which calls it once per failed test — and a failing run is exactly when the catalog is fullest of misses. With ~90 specs and a 272-test suite, worst case is ~24k string `endswith` calls. Not a performance problem today; it is a scan that will silently become one, and the fallback is unbounded in a way the dict is not.

**Remediation.** Index the suffix key too. The distinguishing part of a nodeid is `<file stem>.py::<test>`, which is unique across the catalog:

```python
_BY_SUFFIX: dict[str, TestSpec] = {
    f"{spec.file}.py::{spec.test}": spec for spec in CATALOG
}


def find_by_nodeid(nodeid: str) -> TestSpec | None:
    normalized = nodeid.replace("\\", "/")
    exact = _BY_NODEID.get(normalized)
    if exact is not None:
        return exact
    # Absolute / prefixed node ids: match on the file+test tail, which is
    # unique across the catalog (asserted in tests_internal/test_catalog.py).
    tail = normalized.rsplit("/", 1)[-1]
    return _BY_SUFFIX.get(tail)
```

Add one line to `tests_internal/test_catalog.py` asserting `len(_BY_SUFFIX) == len(CATALOG)`, which makes the uniqueness assumption checked rather than assumed.

---

### F-11 — `SocketBackend` is a two-implementation Adapter whose implementations differ by one boolean — **Severity 2**

**Where.** [`src/packet_engine/platform_backend.py:34-74`](src/packet_engine/platform_backend.py:34) — a `Protocol`, two `@dataclass` implementations, and a `get_backend()` factory. `WindowsBackend.configure()` sets `conf.use_pcap = True`; `LinuxBackend.configure()` sets it to `False`. That is the entire difference.

**Why it matters.** Not much, and the module's docstring makes a good case for the structure: it documents *why* both platforms use L2 exclusively, and the seam is what lets `NetworkInterface(backend=...)` and `PacketRecorder(backend=...)` take a stub in tests (`tests_internal/test_interface_mock.py` relies on this). Keeping the Protocol is right.

The one thing worth noting is that this is the codebase's only place where a global is mutated as a side effect of construction — both [`NetworkInterface.__init__`](src/packet_engine/interface.py:50) and [`PacketRecorder.__init__`](src/packet_engine/recorder.py:69) call `self._backend.configure()`, so constructing either object reaches into Scapy's process-global `conf`. Two objects alive at once with different backends is a silent last-writer-wins. In practice the CLI never does that, so this is a note, not a defect.

**Remediation.** If you ever want the two classes collapsed, the Protocol survives:

```python
@dataclass
class ScapyConfBackend:
    host_name: str
    use_pcap: bool  # Windows: Npcap-backed L2. Linux: native AF_PACKET.

    def configure(self) -> None:
        from scapy.config import conf
        conf.use_pcap = self.use_pcap


_BACKENDS = {
    "Windows": ScapyConfBackend("Windows", use_pcap=True),
    "Linux": ScapyConfBackend("Linux", use_pcap=False),
}


def get_backend() -> SocketBackend:
    try:
        return _BACKENDS[platform.system()]
    except KeyError:
        raise RuntimeError(unsupported_host_message(platform.system())) from None
```

I would rate taking this as marginal — the current version is more self-documenting, and the docstring is the real asset here.

---

## 3. Behavioral patterns

### F-12 — `ProxyClient.connect()` is the one site that genuinely wants Strategy — **Severity 5**

**Where.** [`src/proxy/client.py:50-58`](src/proxy/client.py:50):

```python
if self.config.mode is ProxyMode.HTTP_CONNECT:
    self._http_connect()
elif self.config.mode is ProxyMode.SOCKS5:
    self._socks5_connect()
```

…with [`_http_connect`](src/proxy/client.py:81) (12 lines) and [`_socks5_connect`](src/proxy/client.py:94) (35 lines) as private methods on the client, plus [`TunnelDetails`](src/proxy/client.py:31) — a three-field record where each field belongs to exactly one mode (`http_response` to one, `socks_method`/`socks_reply` to the other) and is `None` for the others.

**Why it matters.** This is the textbook shape: a mode enum, per-mode algorithms of non-trivial size, per-mode result data, and a documented intent to grow (`config.py`'s `ProxyMode` docstring reads as a taxonomy, and `tunnel.py` already carries unused SOCKS5 primitives — `CMD_BIND`, `CMD_UDP_ASSOCIATE` at [`tunnel.py:117-118`](src/proxy/tunnel.py:117) — suggesting more modes are anticipated).

Three consequences today:

1. `ProxyClient` is 172 lines of which 47 are handshake-specific, and its `TunnelDetails` is a union type pretending to be a record. A test asserting on `details.socks_reply` has no type-level indication it only applies in one mode.
2. `ProxyMode.is_explicit` ([`config.py:45`](src/proxy/config.py:45)) exists to answer "does this mode need a handshake" — a question a Strategy answers by existing or not.
3. Adding a fourth mode (SOCKS4, a vendor CONNECT variant) means editing `ProxyClient`, `TunnelDetails`, and the `if`/`elif`, in addition to `tunnel.py` where the wire format actually belongs.

Note the *good* half: `tunnel.py` is already correctly factored — pure functions over bytes and a `read(n)` callable, unit-testable without a socket. The Strategy objects would be thin, because the algorithms already are.

**Remediation.** A protocol plus two implementations, in `tunnel.py` (where the wire logic lives) or a new `src/proxy/handshakes.py`:

```python
class TunnelHandshake(Protocol):
    """Establishes a tunnel over an already-connected socket.

    Raises ProxyTunnelError if the DUT refuses or mishandles it; returns
    whatever the DUT reported, for tests that assert on the RFC fields
    rather than merely on success.
    """

    def establish(self, sock: socket.socket, recv_exact: Reader, origin: tuple[str, int]) -> object: ...


class TransparentHandshake:
    """No in-band negotiation — the DUT is inline (RFC 9293 only)."""

    def establish(self, sock, recv_exact, origin) -> None:
        return None


class HttpConnectHandshake:
    """RFC 9110 §9.3.6 / RFC 9112 CONNECT tunnel."""

    def establish(self, sock, recv_exact, origin) -> HttpConnectResponse:
        host, port = origin
        sock.sendall(build_http_connect_request(host, port))
        response = parse_http_connect_response(read_http_response_head(recv_exact))
        if not response.tunnel_established:
            raise ProxyTunnelError(
                f"CONNECT {format_authority(host, port)} was refused: "
                f"{response.status} {response.reason}".strip()
            )
        return response


HANDSHAKES: dict[ProxyMode, Callable[[ProxyConfig], TunnelHandshake]] = {
    ProxyMode.TRANSPARENT: lambda cfg: TransparentHandshake(),
    ProxyMode.HTTP_CONNECT: lambda cfg: HttpConnectHandshake(),
    ProxyMode.SOCKS5: lambda cfg: Socks5Handshake(cfg.username, cfg.password),
}
```

`ProxyClient.connect()` collapses to:

```python
def connect(self) -> "ProxyClient":
    host, port = self.config.dial_target
    self._sock = socket.create_connection((host, port), timeout=self.config.timeout)
    self._sock.settimeout(self.config.timeout)
    self.details = HANDSHAKES[self.config.mode](self.config).establish(
        self._sock, self._recv_exact, self.config.origin
    )
    return self
```

`TunnelDetails` disappears; `self.details` becomes whatever the mode's handshake returned (`None`, an `HttpConnectResponse`, or a `Socks5Result`), which is stronger typing than the current three-optional-field union. The existing tests in `tests/proxy/test_proxy_http_connect.py` and `test_proxy_socks5.py` already run under mode-gating fixtures (`http_connect_config` / `socks5_config`), so each knows which type it is looking at.

**Cost note:** this is the largest change in this report. It is worth doing only if a fourth mode is actually coming. If SOCKS5 and CONNECT are the whole universe, two branches and a three-field record are defensible and I would leave them.

---

### F-13 — Report format selection is an `if`/`elif` in three places instead of a registry — **Severity 5**

**Where.**

- [`cli/main.py:129-132`](src/cli/main.py:129): `if report == "pdf": … elif report == "html": …`
- [`cli/main.py:154`](src/cli/main.py:154): `click.Choice(["pdf", "html", "none"])` — the format list, retyped
- [`gui/report_panel.py:64-68`](src/gui/report_panel.py:64): `_export_pdf` and `_export_html`, two three-line methods differing only in the three arguments they pass to `_export`

**Why it matters.** [`ReportPanel._export`](src/gui/report_panel.py:48) already did the hard part — its docstring notes "The PDF and HTML exports differ only in extension, dialog wording, and which generator runs, so they share one flow" and it takes `generate: Callable[..., Path]`. The parameterisation is right there; it just has no table to drive it, so the three varying values get hardcoded into two wrapper methods and, separately, into the CLI's branch and the CLI's `click.Choice`. Four places know the format list.

Both generators already share the exact same signature — `(result: TestRunResult, output_path: Path) -> Path` ([`html_report.py:209`](src/reporting/html_report.py:209), [`pdf_report.py:52`](src/reporting/pdf_report.py:52)) — which is what makes the registry a drop-in. A third format (Markdown, JSON, JUnit XML) currently costs four edits.

**Remediation.** One table in the reporting package, read by both front ends:

```python
# src/reporting/formats.py  (new)
"""The report formats the app can produce, in one table.

Both front ends read this rather than each spelling out the format list:
the CLI's --report choices and its dispatch, and the GUI's export buttons.
Every generator has the same (result, output_path) -> path signature, so
adding a format is one entry here plus its generator module.
"""
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from src.reporting.html_report import generate_html_report
from src.reporting.models import TestRunResult
from src.reporting.pdf_report import generate_pdf_report

Generator = Callable[[TestRunResult, Path], Path]


@dataclass(frozen=True)
class ReportFormat:
    key: str       # --report value, and the file extension
    label: str     # human name, for the GUI's button and save dialog
    generate: Generator

    def filename(self) -> str:
        return f"report.{self.key}"


FORMATS: tuple[ReportFormat, ...] = (
    ReportFormat("pdf", "PDF", generate_pdf_report),
    ReportFormat("html", "HTML", generate_html_report),
)

BY_KEY = {f.key: f for f in FORMATS}
```

CLI, replacing the branch and the literal choice list:

```python
@click.option("--report", type=click.Choice([*formats.BY_KEY, "none"]), default="pdf")
...
fmt = formats.BY_KEY.get(report)
if fmt is not None:
    click.echo(f"{fmt.label} report: {fmt.generate(result, run_dir / fmt.filename())}")
```

GUI, replacing `_export_pdf` / `_export_html` with a generated button per format:

```python
buttons = QHBoxLayout()
for fmt in formats.FORMATS:
    button = QPushButton(f"Export {fmt.label}")
    button.clicked.connect(lambda _checked=False, f=fmt: self._export(f))
    buttons.addWidget(button)
```

…and `_export(self, fmt: ReportFormat)` uses `fmt.key`, `fmt.label`, `fmt.generate` in place of its three parameters. Note the `_checked=False, f=fmt` default-argument binding — Qt passes the checked state as the first positional argument, and the late-binding closure over `fmt` is the classic loop-variable bug otherwise.

Combined with **F-01**, `run_dir / fmt.filename()` becomes `artifacts.report(fmt)`, and `report.pdf` / `report.html` stop being literals anywhere.

---

### F-14 — `NetworkInterface` has three hardcoded packet sinks where it advertises one callback — **Severity 4**

**Where.** [`NetworkInterface._record`](src/packet_engine/interface.py:96) — three sequential `if x is not None:` blocks for the pcap writer, the debug logger, and `on_packet`. Each sink was added by widening the constructor: [`interface.py:40-47`](src/packet_engine/interface.py:40) now takes `capture_path`, `on_packet`, `backend` and `debug_logger`.

**Why it matters.** This is an Observer with a fixed subscriber list baked into the subject. The three sinks do the same job — "here is a packet that crossed this interface, in this direction, attributed to this test" — but each has its own constructor parameter, its own None check, and its own call shape (`writer.write(packet)` vs `logger.log_packet(packet, "TX", test_nodeid=...)` vs `callback(PacketEvent(...))`).

Two costs, both visible:

1. `conftest.py`'s [`network_interface` fixture](conftest.py:227) has to thread the debug logger through a `getattr(pytestconfig, "_netstack_debug_logger", None)` — reaching into a private attribute stashed on the pytest `Config` object at [`conftest.py:289`](conftest.py:289) — because there is no way to *add* a sink after construction.
2. Only *one* `on_packet` callback is possible. The GUI's live plot and the jsonl writer cannot both subscribe; the jsonl file exists partly as the workaround (the subprocess writes it, the parent tails it). That is the right architecture for the *process boundary*, but within one process a second in-process consumer has nowhere to attach.

`PacketRecorder` has the same single-callback shape ([`recorder.py:61`](src/packet_engine/recorder.py:61)) with the same limit.

**Remediation.** Keep the constructor arguments (they are the convenient case) and add a subscribe method:

```python
    def __init__(self, ..., on_packet: PacketCallback | None = None, ...) -> None:
        ...
        # Sinks are a list, not a single slot: the pcap writer and debug
        # logger are just sinks with fixed shapes, and a second in-process
        # consumer (a live view alongside the jsonl writer) needs somewhere
        # to attach without displacing the first.
        self._sinks: list[PacketCallback] = [on_packet] if on_packet else []

    def subscribe(self, sink: PacketCallback) -> None:
        """Add a packet sink. Sinks are called in subscription order; an
        exception in one is not caught — a broken sink is a bug, not a
        condition to swallow mid-capture."""
        self._sinks.append(sink)

    def _record(self, packet, direction, test_nodeid) -> None:
        if self._capture_path is not None:
            with self._lock:
                if self._pcap_writer is None:
                    self._pcap_writer = open_pcap(self._capture_path)
                self._pcap_writer.write(packet)
                self._packet_count += 1
        if self._debug_logger is not None:
            self._debug_logger.log_packet(packet, _DEBUG_DIRECTION[direction], test_nodeid=test_nodeid)
        if self._sinks:
            event = PacketEvent(
                timestamp=time.time(), direction=direction,
                summary=packet.summary(), size_bytes=len(packet), test_nodeid=test_nodeid,
            )
            for sink in self._sinks:
                sink(event)
```

Note the pcap writer and debug logger stay as dedicated branches rather than being wrapped into sinks: they need the raw `Packet`, not the lossy `PacketEvent` (`summary()` is a string). Collapsing all three into one list would mean the pcap only ever sees a summary — a real regression. This is the case where *not* generalising all the way is correct.

---

### F-15 — Four lifecycle classes reimplement the same start/stop/context-manager shape — **Severity 2**

**Where.** [`EchoBackend`](src/proxy/backend.py:49), [`TrafficInducer`](src/proxy/inducer.py:29), [`PacketRecorder`](src/packet_engine/recorder.py:47), and (partially) [`NetworkInterface`](src/packet_engine/interface.py:37) and [`ProxyClient`](src/proxy/client.py:40). Each has `start()`/`stop()` (or `connect()`/`close()`), `__enter__`, `__exit__`, and three of the five carry a `threading.Lock` guarding counters plus a `threading.Event` for stop signalling.

**Why it matters.** Barely — and I recommend leaving it. The shapes rhyme but the internals genuinely differ (a Scapy `AsyncSniffer`, an accept loop with per-connection threads, a reconnect loop, a socket). Extracting a `ManagedLifecycle` base would save perhaps 15 lines of `__enter__`/`__exit__` at the cost of an inheritance edge between the proxy and packet-engine packages, which currently share nothing. The duplication audit's own standard — "identical lines ÷ lines of the smaller block" — puts these well under any threshold worth acting on.

**Recorded so a future audit does not propose the base class.** The one thing worth keeping consistent is the `__exit__` signature: all five use `def __exit__(self, *exc_info: object) -> None`, which is already uniform.

---

## 4. Domain patterns

### F-16 — Confirmed healthy: Service Layer, DTOs, Value Objects, and the deliberate absence of a Repository for test data

Recorded so a future audit does not re-derive these.

**Service layer — present and correctly placed.** `src/runner.py` is the service layer, and it is the reason this codebase has two front ends without two implementations. `build_pytest_args` is the contract; `stream_run` (blocking, CLI) and `RunController` (QTimer, GUI) are two *transport* adaptations of it that share `drain_test_events`, `drain_packet_events`, `new_run_dir`, `new_run_result` and `finalize_run` verbatim. The comment at [`runner.py:318-321`](src/runner.py:318) makes the intent explicit ("Exported (no leading underscore) so gui/run_controller.py can reuse them verbatim"). This is the single best structural decision in the codebase.

**DTOs — correct, apart from their hand-written marshalling (F-02, F-08).** `TestEvent`, `PacketEvent`, `TestRunResult`, `RunRequest`, `PreflightResult`, `MetricsSnapshot`, `BackendStats`, `Finding` are all plain dataclasses with no behaviour beyond derived properties. None of them reach out to I/O (except the two flagged), none of them are mutable where they should be frozen.

**Value Objects — correct.** `DUTConfig`, `ProxyConfig`, `TestSpec`, `RangeField`, `TargetProfile`, `HttpConnectResponse`, `Socks5Reply` are `@dataclass(frozen=True)` with meaningful derived behaviour (`ProxyConfig.dial_target`, `RangeField.contains`, `TestSpec.nodeid`, `Socks5Reply.succeeded`) and a `__post_init__` invariant where one applies ([`ProxyConfig.__post_init__`](src/proxy/config.py:72) rejects an explicit mode without a front address). Textbook.

**Domain Model — thin, and correctly so.** `TCPSequenceTracker` ([`sequence.py:13`](src/packet_engine/sequence.py:13)) is the only object with genuine domain behaviour (sequence-space arithmetic), and it is 37 lines. Everything else is either a value or a service. For a test *harness* — where the domain logic being exercised lives on the DUT, not here — an anaemic model is the right answer. There is no case for pushing behaviour onto `TestRunResult` or `DUTConfig`.

**No Repository for test definitions — deliberate and correct.** `src/catalog.py` is a 614-line literal `list[TestSpec]` with import-time indices. That would be a smell in an application; here it is the point. `tests_internal/test_catalog.py` AST-checks the catalog against the test functions actually on disk, so the literal cannot drift, and `cli/main.py` derives its `--module`/`--submodule` choices from it ([`main.py:46-47`](src/cli/main.py:46)) rather than retyping them. A database or a file-scan would add failure modes to something whose whole value is being statically verifiable.

**One note on import-time work.** [`KNOWN_MARKERS = _registered_markers()`](src/runner.py:80) reads and parses `pyproject.toml` at module import, and `catalog.py` builds three indices at import. Both are cheap and both are guarded (the TOML read catches `OSError`/`TOMLDecodeError` and degrades to an empty set; `test_known_markers_match_pyproject` asserts the result matches the declaration). Importing `src.runner` therefore touches the filesystem — worth knowing if `runner` is ever imported somewhere latency-sensitive, but not worth changing now.

---

## Priority order

If these are taken, this is the order I would take them in — each is independent except where noted.

| # | Finding | Severity | Effort | Note |
|---|---|---|---|---|
| 1 | **F-03** RunRequest/DUTConfig shadow fields | 6 | ~20 min | Highest consequence-per-line. Safety-relevant. |
| 2 | **F-01** RunArtifacts repository | 7 | ~1 h | Enables the F-13 filename cleanup. |
| 3 | **F-02** TestRunResult round-trip | 7 | ~45 min | Verify the existing round-trip test's strength first. |
| 4 | **F-13** Report format registry | 5 | ~40 min | Do after F-01 so `report.pdf` lands in the same place. |
| 5 | **F-07** Delete the unused `proxy/__init__` facade | 5 | ~10 min | Removes a documented import cycle. |
| 6 | **F-06** Move `OUTCOME_STYLE` to `palette.py` | 5 | ~20 min | Pure lift; also drops the unread `"prefix"` column. |
| 7 | **F-08** Resolve `DUTConfig.to_file` (derive or delete) | 4 | ~20 min | Decide whether config persistence is a feature. |
| 8 | **F-14** `NetworkInterface.subscribe` | 4 | ~30 min | Do not collapse the pcap/debug sinks into it. |
| 9 | **F-05** `Proto` enum for custom packets | 4 | ~20 min | Take the enum half; skip the builder table. |
| 10 | **F-09** Move `RECV_CHUNK` to `proxy/config.py` | 3 | ~5 min | |
| 11 | **F-10** Index the catalog suffix lookup | 3 | ~15 min | |
| 12 | **F-12** Tunnel handshake Strategy | 5 | ~2 h | **Only if a fourth proxy mode is coming.** |
| — | F-04, F-11, F-15, F-16 | ≤3 | — | Leave as they are. |

**Overall assessment: 7.5/10.** The pattern choices that matter — Command for the run request, Facade for the runner, Protocol over ABC, frozen dataclasses over hand-rolled value classes — are right, and the restraint (no Singleton, no DI container, no abstract hierarchies) is a feature. What is missing is a small amount of *structure around persistence*: a Repository for the run directory and derived serialization for two DTOs would close the four highest-severity findings, and together they are under three hours of work.
