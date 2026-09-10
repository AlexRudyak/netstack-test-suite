"""Shared test-execution orchestration — the one code path the CLI and the
GUI both drive, so they can never diverge in how a run is invoked.

Runs pytest as a SEPARATE PROCESS every time (never in-process
pytest.main() calls) to avoid module-cache pollution and plugin/fixture
state bleeding across the many repeated runs a long-lived GUI session
will make, and so a crash inside a test (e.g. a bad raw-socket call)
can never take the GUI process down with it.

Progress streams back via two JSON-lines files the subprocess writes and
this module tails as they grow:
  - pytest's own `--report-log` (one JSON object per test lifecycle event)
  - a live packet-events log, written by NetworkInterface's on_packet
    callback (wired in tests/conftest.py) so the GUI's realtime plot has
    something to show *during* the run, not just after it finishes.

The GUI does not call `run_tests`/`stream_run` directly — see
gui/run_controller.py, which drives the equivalent subprocess via QProcess
so the Qt event loop is never blocked. This module is the CLI's blocking
entry point and the canonical definition of the subprocess arguments both
front ends must agree on.
"""
from __future__ import annotations

import json
import logging
import platform
import subprocess
import sys
import time
import tomllib
import uuid
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from src import paths
from src.config import DUTConfig, Role
from src.errors import RunArtifactError
from src.packet_engine.payloads import PayloadMode
from src.reporting.models import (
    PacketDirection,
    PacketEvent,
    TestEvent,
    TestOutcome,
    TestRunResult,
)
from src.run_artifacts import RunArtifacts

POLL_INTERVAL_S = 0.2

log = logging.getLogger(__name__)


def reports_dir() -> Path:
    """Writable directory for run artifacts (frozen-aware)."""
    return paths.reports_base() / "reports"


def _registered_markers() -> frozenset[str]:
    """The markers declared in pyproject.toml.

    pytest's report-log "keywords" dict is polluted with the nodeid,
    filename and module name, so reports filter against this known set
    rather than treating every keyword as a marker. Reading it from the
    declaration means a marker registered in pyproject.toml can't be
    forgotten here and silently vanish from every generated report.

    pyproject.toml is bundled into the frozen build (NetstackTestSuite.spec),
    so this resolves in both source and packaged modes. An unreadable file
    yields an empty set — reports then show no markers, which is a cosmetic
    loss, never a failed run.
    """
    try:
        data = tomllib.loads(
            (paths.project_root() / "pyproject.toml").read_text(encoding="utf-8")
        )
    except (OSError, tomllib.TOMLDecodeError):
        return frozenset()
    entries = data.get("tool", {}).get("pytest", {}).get("ini_options", {}).get("markers", [])
    return frozenset(entry.split(":", 1)[0].strip() for entry in entries)


KNOWN_MARKERS = _registered_markers()


@dataclass
class RunRequest:
    config: DUTConfig
    module: str | None = None  # "tcp", "udp", "ip"
    submodule: str | None = None  # "syn", "state_machine", "congestion"
    test_name: str | None = None  # -k substring match
    # Explicit pytest targets (paths / nodeids), e.g. ("tests/ip",
    # "tests/tcp/syn/test_x.py::test_a"). When set, these are passed as
    # positional args and take precedence over module/submodule/test_name —
    # this is how the GUI runs an arbitrary set of checked tree nodes in one
    # invocation. Empty ⇒ fall back to the module/submodule/test_name form.
    targets: tuple[str, ...] = field(default_factory=tuple)
    markers: tuple[str, ...] = field(default_factory=tuple)  # extra -m terms
    payload_mode: PayloadMode = PayloadMode.RANDOM
    payload_size: int = 64
    confirm_vuln_tests: bool = False
    debug: bool = False  # write a tshark-style per-packet debug log for the run
    # Proxy-DUT topology. Setting proxy_mode enables the `proxy`-marked tests
    # (they're skipped otherwise) and requires a backend instance running
    # `netstack-cli proxy-serve` at backend_host:backend_port.
    proxy_mode: str | None = None
    proxy_host: str | None = None
    proxy_port: int | None = None
    backend_host: str | None = None
    backend_port: int | None = None

    # `role` and `proxy_leg` are NOT fields: they are read off `config`,
    # which already resolved them together via src.config.resolve_role /
    # resolve_leg_target. Carrying second copies here let the value that
    # reached the pytest subprocess disagree with the one preflight, the
    # vuln allow-list check and the reports used — and role decides which
    # direction traffic is sent at the DUT, so that divergence is the
    # highest-consequence one available. Set them on the config instead.

    @property
    def role(self) -> Role:
        """Which side the suite plays (client/server)."""
        return self.config.role

    @property
    def proxy_leg(self) -> str | None:
        """The proxy leg the ordinary endpoint suites are aimed at
        ("front"/"back"), as the subprocess flag spells it."""
        return self.config.proxy_leg.value if self.config.proxy_leg else None


TestEventCallback = Callable[[TestEvent], None]
PacketEventCallback = Callable[[PacketEvent], None]


def _optional_flags(request: RunRequest) -> list[tuple[str, object | None]]:
    """`--flag=value` pairs, emitted only when the value is not None.

    Declared as data rather than one `if` per flag so that adding a
    RunRequest field can't silently forget to forward it — a dropped option
    produces a run that *succeeds* while ignoring the setting, which is the
    worst failure shape available here.

    The None-vs-falsy rule is uniform: only None means "unset". An empty
    string is normalized to None (an unset text field, not a value), but a
    port of 0 IS forwarded — silently substituting a different port than the
    operator asked for is worse than letting the subprocess reject it.
    """
    return [
        ("--dut-mac", request.config.target_mac or None),
        # None ⇒ let the subprocess conftest pick one random port for its session.
        ("--dut-port", request.config.target_port),
        ("--dut-source-port", request.config.source_port),
        ("--proxy-mode", request.proxy_mode or None),
        ("--proxy-leg", request.proxy_leg or None),
    ]


def _topology_flags(request: RunRequest) -> list[tuple[str, object | None]]:
    """The proxy front/backend addresses — see the call site for when these apply."""
    return [
        ("--proxy-host", request.proxy_host or None),
        ("--proxy-port", request.proxy_port),
        ("--backend-host", request.backend_host or None),
        ("--backend-port", request.backend_port),
    ]


def _test_targets(request: RunRequest) -> list[str]:
    """Positional pytest targets: explicit `targets` if given, else the
    single module/submodule path (with test_name applied as a -k filter)."""
    if request.targets:
        return list(request.targets)
    parts = ["tests", request.module, request.submodule]
    return ["/".join(p for p in parts if p)]


def _launcher() -> list[str]:
    """How to invoke pytest, which differs between source and frozen builds.

    Source: `python -m pytest`. Frozen: the exe has no `-m pytest`, so
    re-invoke the exe with a sentinel that routes to pytest.main() (see
    src/gui/app.py). The subprocess runs with cwd = project_root (set in
    stream_run) so the relative test path resolves in both modes.

    A frozen build also loses pytest's entry-point plugin discovery, so the
    report-log plugin (which the whole progress stream depends on) must be
    loaded explicitly with `-p`.
    """
    if paths.is_frozen():
        return [sys.executable, paths.PYTEST_SENTINEL, "-p", "pytest_reportlog.plugin"]
    return [sys.executable, "-m", "pytest"]


def build_pytest_args(request: RunRequest, run_dir: Path) -> list[str]:
    """The canonical subprocess argument list — also used directly by
    gui/run_controller.py's QProcess invocation, so CLI and GUI runs are
    byte-for-byte the same command."""
    artifacts = RunArtifacts(run_dir)
    args = [
        *_launcher(),
        *_test_targets(request),
        f"--report-log={artifacts.report_log}",
        f"--target-stack={request.config.target_stack}",
        f"--role={request.role.value}",
        f"--dut-ip={request.config.target_ip}",
        f"--dut-iface={request.config.interface}",
        f"--payload-mode={request.payload_mode.value}",
        f"--payload-size={request.payload_size}",
        f"--live-events-log={artifacts.packet_events}",
        f"--capture-pcap={artifacts.capture}",
        "-v",
    ]
    args += [f"{flag}={value}" for flag, value in _optional_flags(request) if value is not None]

    # Two-token pytest flags, not the --flag=value form the table emits.
    if request.test_name:
        args += ["-k", request.test_name]
    if request.markers:
        args += ["-m", " and ".join(request.markers)]

    if request.confirm_vuln_tests:
        args.append("--confirm-vuln-tests")
    # The allow-list gates every `vuln`-marked test (src/utils/safety.py),
    # and it lives on the DUTConfig — forward each CIDR to the subprocess or
    # those tests error out with UnauthorizedTargetError despite the operator
    # having authorized the target. conftest's --allowed-targets is append.
    args += [f"--allowed-targets={cidr}" for cidr in request.config.allowed_targets]
    if request.debug:
        args.append(f"--debug-log={artifacts.debug_log}")

    # The topology addresses are emitted whenever they're set, not only for
    # --proxy-mode: a front-leg run needs --proxy-host/--proxy-port to know
    # what to retarget to, even with no proxy-marked tests selected.
    if request.proxy_mode or request.proxy_leg:
        args += [
            f"{flag}={value}"
            for flag, value in _topology_flags(request)
            if value is not None
        ]
    return args


def new_run_dir() -> tuple[str, Path]:
    run_id = f"{datetime.now(timezone.utc):%Y%m%dT%H%M%S}-{uuid.uuid4().hex[:6]}"
    run_dir = reports_dir() / run_id
    try:
        run_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        # Translated here rather than left bare: this is the first thing both
        # front ends do, and in the GUI it runs inside a `clicked` slot, where
        # an unhandled exception ends the process instead of the run.
        raise RunArtifactError(f"Could not create the run directory {run_dir}: {exc}") from exc
    return run_id, run_dir


def new_run_result(run_id: str, request: RunRequest) -> TestRunResult:
    """The canonical run header both front ends start from.

    Shared with gui/run_controller.py so a GUI-driven run and a CLI-driven
    run describe themselves identically in results.json and the reports.
    """
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
    """Stamp the outcome and persist the run — the file
    reporting/collector.load_run_result() reads back to regenerate a report
    without re-running the suite. Both sides go through RunArtifacts."""
    result.pytest_returncode = returncode
    result.finished_at = datetime.now(timezone.utc)
    RunArtifacts(run_dir).save(result)
    return result


def run_tests(
    request: RunRequest,
    on_test_event: TestEventCallback | None = None,
    on_packet_event: PacketEventCallback | None = None,
) -> TestRunResult:
    """Blocking convenience wrapper for the CLI. Runs to completion."""
    result: TestRunResult | None = None
    for result in stream_run(request, on_test_event, on_packet_event):
        pass
    assert result is not None
    return result


def stream_run(
    request: RunRequest,
    on_test_event: TestEventCallback | None = None,
    on_packet_event: PacketEventCallback | None = None,
) -> Iterator[TestRunResult]:
    """Runs pytest as a subprocess, tailing both jsonl files as they grow.

    Yields the accumulating TestRunResult on each poll; the final yield is
    the completed run, which has also been written to results.json.

    An interrupt — Ctrl+C in the CLI, or a consumer closing this generator —
    terminates the subprocess and still persists what was collected, so a
    run stopped part-way is reportable rather than lost.
    """
    run_id, run_dir = new_run_dir()
    result = new_run_result(run_id, request)

    args = build_pytest_args(request, run_dir)

    artifacts = RunArtifacts(run_dir)
    report_log = artifacts.report_log
    events_log = artifacts.packet_events
    report_offset = events_offset = 0

    # Redirect the subprocess's stdout/stderr to a file rather than an
    # unread PIPE. Progress comes from the jsonl files we tail below; an
    # undrained PIPE would fill its OS buffer under -v output and deadlock
    # pytest (it blocks on write while we block on poll). The file keeps the
    # raw output available for debugging without that risk.
    try:
        out = artifacts.pytest_output.open("w", encoding="utf-8")
    except OSError as exc:
        raise RunArtifactError(
            f"Could not open {artifacts.pytest_output} for the runner's output: {exc}"
        ) from exc

    with out:
        proc = subprocess.Popen(
            args, stdout=out, stderr=subprocess.STDOUT, text=True, cwd=str(paths.project_root())
        )

        try:
            while proc.poll() is None:
                report_offset = drain_test_events(report_log, report_offset, result, on_test_event)
                events_offset = drain_packet_events(
                    events_log, events_offset, result, on_packet_event
                )
                yield result
                time.sleep(POLL_INTERVAL_S)
        except (KeyboardInterrupt, GeneratorExit):
            # Interrupting the parent must not leave the child running: it is
            # sending real frames at the DUT, and nothing would be watching it.
            # (On a terminal Ctrl+C the console signal usually reaches the whole
            # process group anyway; this covers the cases where it does not.)
            proc.terminate()
            proc.wait(timeout=10)
            raise
        finally:
            # Final drain in case data was written between the last poll and
            # the exit — and then persist, on every path. An interrupted run
            # used to write no results.json at all, so an hour of testing left
            # nothing that could be re-reported without touching the DUT again.
            report_offset = drain_test_events(report_log, report_offset, result, on_test_event)
            events_offset = drain_packet_events(events_log, events_offset, result, on_packet_event)
            finalize_run(result, run_dir, proc.returncode)

    yield result


# --- Shared file-tailing helpers -------------------------------------------
# Exported (no leading underscore) so gui/run_controller.py can reuse them
# verbatim under a QTimer instead of a blocking loop, rather than
# re-implementing this parsing a second time.


def read_new_lines(path: Path, offset: int) -> tuple[list[str], int]:
    """Read complete lines appended since `offset`, returning them and the
    new byte offset.

    Reads in binary and only consumes up to the last newline, so a partial
    trailing line the subprocess is still writing is left for the next
    call. This avoids the text-mode `tell()`/read-ahead hazard and the
    corrupt-fragment crash that mixing iteration with `tell()` produces
    when tailing a file that's being appended to concurrently.
    """
    if not path.exists():
        return [], offset
    with path.open("rb") as f:
        f.seek(offset)
        data = f.read()
    if not data:
        return [], offset
    last_newline = data.rfind(b"\n")
    if last_newline == -1:
        return [], offset  # no complete line yet
    consumed = data[: last_newline + 1]
    new_offset = offset + len(consumed)
    lines = [ln for ln in consumed.decode("utf-8", errors="replace").splitlines() if ln.strip()]
    return lines, new_offset


# Worst-wins ordering when a test produces reports in several phases
# (e.g. call PASSED but teardown ERROR → the test is an ERROR).
_SEVERITY = {
    TestOutcome.PASSED: 0,
    TestOutcome.SKIPPED: 1,
    TestOutcome.FAILED: 2,
    TestOutcome.ERROR: 3,
}


def drain_test_events(
    path: Path, offset: int, result: TestRunResult, callback: TestEventCallback | None
) -> int:
    lines, new_offset = read_new_lines(path, offset)
    if not lines:
        return new_offset
    # One TestEvent per nodeid, upserted across phases so a failure in
    # setup/teardown isn't lost (the common "run did nothing" case is every
    # test erroring in the setup phase, which the old call-only parser
    # dropped entirely).
    index = {t.nodeid: t for t in result.tests}
    for line in lines:
        event = parse_report_log_line(line)
        if event is None:
            continue
        existing = index.get(event.nodeid)
        if existing is None:
            result.tests.append(event)
            index[event.nodeid] = event
            if callback:
                callback(event)
        elif _SEVERITY[event.outcome] > _SEVERITY[existing.outcome]:
            existing.outcome = event.outcome
            existing.message = event.message or existing.message
            existing.duration_s += event.duration_s
            if callback:
                callback(existing)
    return new_offset


def _extract_message(data: dict) -> str | None:
    longrepr = data.get("longrepr")
    if not longrepr:
        return None
    if isinstance(longrepr, dict):
        return (longrepr.get("reprcrash") or {}).get("message")
    # Skips are serialized as [path, lineno, "Skipped: <reason>"].
    if isinstance(longrepr, (list, tuple)):
        if len(longrepr) == 3 and isinstance(longrepr[2], str):
            return longrepr[2]
        return str(longrepr)
    if isinstance(longrepr, str):
        stripped = longrepr.strip()
        return stripped.splitlines()[-1] if stripped else None
    return str(longrepr)


def parse_report_log_line(line: str) -> TestEvent | None:
    """Map one report-log TestReport to a TestEvent, or None to ignore it.

    pytest emits a report per phase (setup/call/teardown). We derive the
    test's outcome from whichever phase carries the verdict:
    - call: the normal passed/failed/skipped outcome.
    - setup: only when it didn't pass — a setup failure is an ERROR (the
      test body never ran), a setup skip is a SKIP.
    - teardown: only a failure, surfaced as ERROR.
    A passing setup/teardown is ignored (the call phase carries the result).

    A line that isn't parseable JSON is dropped with a warning rather than
    raised. This runs in a polling loop over a file a *separate process* is
    still appending to, so a truncated or interleaved line is a condition of
    the medium, not a bug — and letting it raise cost the whole run: in the
    CLI it aborts stream_run with the pytest subprocess still running and no
    results.json written, and in the GUI it leaves a QTimer slot.
    """
    try:
        data = json.loads(line)
    except json.JSONDecodeError:
        log.warning("Skipping unparseable report-log line: %.120r", line)
        return None
    if not isinstance(data, dict) or data.get("$report_type") != "TestReport":
        return None

    when = data.get("when")
    outcome_str = data.get("outcome", "")
    if when == "call":
        outcome = {
            "passed": TestOutcome.PASSED,
            "failed": TestOutcome.FAILED,
            "skipped": TestOutcome.SKIPPED,
        }.get(outcome_str, TestOutcome.ERROR)
    elif when == "setup":
        if outcome_str == "passed":
            return None
        outcome = TestOutcome.SKIPPED if outcome_str == "skipped" else TestOutcome.ERROR
    elif when == "teardown":
        if outcome_str != "failed":
            return None
        outcome = TestOutcome.ERROR
    else:
        return None

    message = (
        _extract_message(data)
        if outcome in (TestOutcome.FAILED, TestOutcome.ERROR, TestOutcome.SKIPPED)
        else None
    )
    # Filter the noisy report-log "keywords" (which include the nodeid,
    # filename, and module) down to markers we actually registered.
    markers = [k for k in data.get("keywords", {}) if k in KNOWN_MARKERS]
    return TestEvent(
        nodeid=data.get("nodeid", "<unknown>"),
        outcome=outcome,
        duration_s=data.get("duration", 0.0),
        markers=markers,
        message=message,
    )


def drain_packet_events(
    path: Path, offset: int, result: TestRunResult, callback: PacketEventCallback | None
) -> int:
    """Parse appended packet-event lines into the result.

    Malformed lines are skipped for the same reason as in
    parse_report_log_line: this tails a file another process is writing, and
    one bad line must cost one plot point rather than the run.
    """
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
        except (json.JSONDecodeError, KeyError, TypeError, ValueError):
            log.warning("Skipping unparseable packet-event line: %.120r", line)
            continue
        result.packet_events.append(event)
        if callback:
            callback(event)
    return new_offset
