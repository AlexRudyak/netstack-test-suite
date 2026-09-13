# Naming & Readability Audit — netstack-test-suite

**Date:** 2026-09-13
**Commit:** `8133e54` (branch `development`)
**Scope:** `src/` (68 files: `target_profiles/`, `reporting/`, `packet_engine/`, `utils/`, `plotting/`, `custom_packet/`, `cli/`, `gui/`, `proxy/`, plus root modules `catalog.py`, `collection_policy.py`, `config.py`, `errors.py`, `runner.py`, `paths.py`, `run_artifacts.py`), `tests/`, `tests_internal/`. `.venv/` excluded.
**Method:** manual read-through of the ~25 largest/most central modules (prioritizing `runner.py`, `catalog.py`, `config.py`, `collection_policy.py`, `errors.py`, `packet_engine/*`, `proxy/*`, `reporting/*`, `cli/*`, `gui/*`, `target_profiles/*`, `custom_packet/*`, `utils/*`) against the four review axes: naming conventions, naming consistency, code readability, function-signature hygiene. Every finding below was independently re-verified against the file on disk before inclusion (line numbers and snippets quoted below were re-read after the initial pass).

**Severity scale:** 1 = cosmetic nitpick, 10 = actively harms readability/maintainability.

---

## Executive summary

**This codebase's naming and readability discipline is strong — there is no systemic problem to fix.** Across the reviewed modules: `snake_case` is used with no exceptions outside genuine Qt API overrides (which are explicitly `# noqa`-flagged); abbreviations are applied consistently (`config`, never `cfg`; `packet`, never `pkt`); constants are `UPPER_CASE` throughout; every custom exception derives from one base and follows a single `<Noun>Error` naming pattern; boolean constructor parameters are consistently keyword-only; and spelling (British, used consistently in prose/docstrings/comments) never mixes with American spelling except where an external library's own API forces it (e.g. matplotlib's `color=` kwarg).

Only **two** findings surfaced that are worth recording, both minor (importance ≤ 7), plus a positive-patterns section that should be treated as the de facto style guide going forward — codifying what's already being done well is more valuable here than inventing new rules to chase down two small items.

---

## Status: both findings applied

- **F-01** applied: `TestSpec.roles`/`TestSpec.markers` are now `kw_only` dataclass fields; all 74 `CATALOG` call sites were mechanically updated to pass `roles=...` and `markers=...` by keyword.
- **F-02** applied: `_report_topology` renamed to `_report_and_validate_topology`, matching the `_preflight_and_report` naming shape already used beside it.

Verification after both changes: `pytest tests_internal/ -q` → **287 passed, 1 skipped** (same as before the changes — behavior is unaffected, this was a pure naming/signature change).

---

## Findings

### F-01 — `TestSpec` catalog entries rely on ~60 unlabelled positional arguments

- **File:** [src/catalog.py:26-70](../src/catalog.py) (dataclass at line 26-36; first of ~60 repeating call sites at line 57)
- **Snippet:**
  ```python
  @dataclass(frozen=True)
  class TestSpec:
      module: str
      submodule: str | None
      file: str
      test: str
      title: str
      description: str
      rfc: str
      roles: tuple[Role, ...] = CLIENT
      markers: tuple[str, ...] = ()

  CATALOG: list[TestSpec] = [
      TestSpec(
          "ip", None, "test_ip_header_validation", "test_ttl_expiry_generates_icmp_time_exceeded",
          "TTL expiry → ICMP Time Exceeded",
          "Sends a datagram with TTL=1 and expects the hop...",
          "RFC 791 §3.2, RFC 792", CLIENT, ("ip",),
      ),
      ...  # repeated ~60 times
  ]
  ```
- **Problem:** `TestSpec` has 9 fields, and every one of the ~60 catalog entries passes all of them positionally. At the call site, `CLIENT` and `("ip",)` are indistinguishable from any other tuple without cross-referencing the class definition first — a reviewer can't tell `roles` from `markers` by inspection, and a transposed pair of same-typed fields (e.g. `file`/`test`, both `str`) would fail silently. This is the file most exposed to routine edits (adding a new test), so the ergonomics compound.
- **Fix:** Make the trailing, easily-confused fields keyword-only so every call site is forced to self-document:
  ```python
  from dataclasses import dataclass, field

  @dataclass(frozen=True)
  class TestSpec:
      module: str
      submodule: str | None
      file: str
      test: str
      title: str
      description: str
      rfc: str
      roles: tuple[Role, ...] = field(default=CLIENT, kw_only=True)
      markers: tuple[str, ...] = field(default=(), kw_only=True)
  ```
  and update call sites to `roles=CLIENT, markers=("ip",)`. (Requires Python ≥ 3.10 for per-field `kw_only`; the project already uses `from __future__ import annotations` and `X | None` syntax, so 3.10+ is already assumed.) A `sed`/codemod pass can mechanically append `roles=`/`markers=` to the ~60 trailing tuple arguments.
- **Importance: 7/10** — not a correctness bug (the self-validating test in `tests_internal/test_catalog.py` would still catch a broken reference), but it's the highest-traffic file in the repo for routine changes and currently offers no protection against a positional mix-up.

### F-02 — `_report_topology`'s name doesn't signal that it also gates run validity

- **File:** [src/gui/main_window.py:303-330](../src/gui/main_window.py)
- **Problem:** The `_report_` prefix reads as a pure logging/output action, but the function also performs validation (checks `back_leg_requirement_error`) and returns a `bool` that the caller uses to decide whether the run proceeds — a meaningful control-flow side effect that the name doesn't advertise.
- **Fix:** Either rename to make the dual role explicit (e.g. `_report_and_validate_topology`), or split into a pure `_log_topology(...) -> None` and a `_topology_error(...) -> str | None`, mirroring the existing `_preflight_and_report` naming shape already used elsewhere in the same file.
- **Importance: 2/10** — the function's docstring already clarifies the behavior on first read; this is a minor "name vs. behavior" mismatch, not a source of real confusion.

*(A third candidate — `Craft.l3` in `tests/conftest.py:142`, a wrapper delegating to `builders.wrap_ethernet` — was considered but judged not worth a standalone entry: the abbreviation is domain-standard networking terminology (L3), immediately adjacent to `.tcp()`/`.udp()`, and covered by a docstring. Noted here rather than promoted to a full finding.)**

---

## Consistent / Good Patterns (de facto style guide)

These are observed, established conventions — not aspirational ones. New code should continue to match them.

1. **`snake_case` everywhere, with zero accidental exceptions.** Every method, attribute, and local variable in `src/gui/*.py` (the Qt-facing layer, the most likely place for `camelCase` to leak in from Qt's own API) is `snake_case`. The only `camelCase` identifiers are genuine Qt overrides/signals (`closeEvent`, `itemChanged`, `currentItemChanged`), and the override itself is explicitly flagged: `src/gui/main_window.py:259` → `def closeEvent(self, event) -> None:  # noqa: N802 - Qt naming`.
2. **Underscore-prefix convention for "private" helpers is applied deliberately, with documented exceptions.** `src/runner.py:374-378` explicitly comments that `read_new_lines`/`drain_test_events`/`drain_packet_events` are *not* underscore-prefixed because `src/gui/run_controller.py` reuses them across module boundaries — an intentional, explained deviation rather than an inconsistency.
3. **Enums replace bare string/int constants wherever a small closed set exists**, each documented: `PayloadMode`, `ProxyMode`, `ProxyLeg`, `Role`, `Proto`, `TestOutcome`, `Confidence`. `src/custom_packet/builder.py:17-25` explicitly documents *why* `Proto` is an enum rather than a plain `str`.
4. **A single exception hierarchy, one naming pattern.** All custom exceptions derive from `NetstackError` and follow `<Noun>Error` (`ConfigurationError`, `InsufficientPrivilegesError`, `UnauthorizedTargetError`, `ProxyTunnelError`) or a clear domain noun (`ProtocolViolation`) — see `src/errors.py`.
5. **No abbreviation drift.** `config` is used uniformly (never `cfg`); `packet` is used uniformly (never `pkt`) across `packet_engine/`, `proxy/`, `reporting/`. The one deliberate abbreviation, `iface` (for "interface"), is applied uniformly everywhere it appears — CLI flags, fixtures, `NetworkInterface.__init__`.
6. **Module-level constants are `UPPER_CASE` without exception**: `DEFAULT_TTL`, `DEFAULT_WINDOW` (`src/packet_engine/builders.py`), `MAX_SEQ`, `SYN`/`ACK`/`RST`/`FIN` (`src/utils/tcp_flags.py`), `EPHEMERAL_PORT_RANGE`, `POLL_INTERVAL_S`, `DEFAULT_BACKEND_PORT`, `KNOWN_MARKERS`.
7. **Boolean/flag constructor and function parameters are keyword-only** (e.g. `enable_udp`, `as_flags`, `confirmed`), which avoids the classic `func(x, y, True, False)` ambiguity at call sites — see `src/packet_engine/builders.py:17-71` for the pattern applied to every builder function (`*,` before any optional/flag parameter).
8. **British spelling used consistently in prose** ("colour", "behaviour", "favour" in docstrings/comments/UI strings), with the only "color" occurrences being forced by external library APIs used correctly (CSS `color:` properties, matplotlib's `color=` kwarg) — not an inconsistency.
9. **Serialization is uniformly `to_dict`/`from_dict`**, derived from `dataclasses.fields()` rather than hand-duplicated field lists, across every model (`PacketEvent`, `TestEvent`, `TestRunResult`, `DUTConfig` in `src/reporting/models.py`), which is explicitly called out in comments as a drift-prevention measure.
10. **"Re-exported for a stable import path" is a recurring, self-documented pattern**, not an accidental duplicate name: `src/proxy/client.py:25`, `src/proxy/handshakes.py:27-36`, `src/utils/safety.py:14-18`, `src/utils/permissions.py:19-29` each comment why the re-export exists.

---

## Items marked "Unable to verify"

None — every finding above and every positive pattern cited was read directly from the file at the stated line and re-confirmed before inclusion in this report. If a future pass wants to extend coverage, the modules *not* yet read in full during this audit are: `src/gui/test_details_panel.py`, `src/gui/test_tree_widget.py`, `src/gui/log_panel.py`, `src/gui/report_panel.py`, `src/gui/custom_packet_panel.py`, `src/plotting/realtime_plotter.py`, `src/plotting/static_charts.py`, `src/target_profiles/linux_profile.py`, `src/target_profiles/windows_profile.py`, and the bulk of `tests/` (only `tests/conftest.py` was sampled). A future audit pass reading those would strengthen confidence that no findings were missed there, though nothing in the modules already reviewed suggests those files diverge from the patterns above.

---

## Recommended next step

Given only two low-to-moderate findings, the highest-value action is **F-01** (catalog keyword-only fields) since it's mechanical, low-risk, and protects the highest-churn file in the repo. F-02 is optional polish. No repo-wide style-guide document, linter rule, or naming convention change is warranted beyond what's already enforced — the existing discipline (documented in the "Consistent / Good Patterns" section above) is the style guide.

---

🤖 Generated with [Claude Code](https://claude.com/claude-code)
