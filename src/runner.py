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
import platform
import subprocess
import sys
import time
import uuid
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from src import paths
from src.config import DUTConfig, Role
from src.packet_engine.payloads import PayloadMode
from src.reporting.models import (
    PacketDirection,
    PacketEvent,
    TestEvent,
    TestOutcome,
    TestRunResult,
)

POLL_INTERVAL_S = 0.2


def reports_dir() -> Path:
    """Writable directory for run artifacts (frozen-aware)."""
    return paths.reports_base() / "reports"

# The markers we register (pyproject.toml). pytest's report-log "keywords"
# dict is polluted with the nodeid, filename, and module name, so we filter
# to this known set rather than treating every keyword as a marker.
KNOWN_MARKERS = frozenset(
    {"ip", "udp", "tcp", "syn", "state_machine", "congestion", "vuln", "slow", "internal"}
)


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
    role: Role = Role.CLIENT  # which side the suite plays (client/server)


TestEventCallback = Callable[[TestEvent], None]
PacketEventCallback = Callable[[PacketEvent], None]


def build_pytest_args(request: RunRequest, run_dir: Path) -> list[str]:
    """The canonical subprocess argument list — also used directly by
    gui/run_controller.py's QProcess invocation, so CLI and GUI runs are
    byte-for-byte the same command."""
    # Positional pytest targets: explicit `targets` if given, else the
    # single module/submodule path (with test_name as a -k filter below).
    if request.targets:
        test_targets = list(request.targets)
    else:
        parts = ["tests"]
        if request.module:
            parts.append(request.module)
        if request.submodule:
            parts.append(request.submodule)
        test_targets = ["/".join(parts)]

    # Source: `python -m pytest`. Frozen: the exe has no `-m pytest`, so
    # re-invoke the exe with a sentinel that routes to pytest.main() (see
    # src/gui/app.py). The subprocess runs with cwd = project_root (set in
    # stream_run) so the relative test path resolves in both modes.
    #
    # A frozen build loses pytest's entry-point plugin discovery, so the
    # report-log plugin (which the whole progress stream depends on) must be
    # loaded explicitly with `-p`.
    if paths.is_frozen():
        launcher = [sys.executable, paths.PYTEST_SENTINEL, "-p", "pytest_reportlog.plugin"]
    else:
        launcher = [sys.executable, "-m", "pytest"]

    args = [
        *launcher,
        *test_targets,
        f"--report-log={run_dir / 'report_log.jsonl'}",
        f"--target-stack={request.config.target_stack}",
        f"--role={request.role.value}",
        f"--dut-ip={request.config.target_ip}",
        f"--dut-iface={request.config.interface}",
        f"--payload-mode={request.payload_mode.value}",
        f"--payload-size={request.payload_size}",
        f"--live-events-log={run_dir / 'packet_events.jsonl'}",
        f"--capture-pcap={run_dir / 'capture.pcap'}",
        "-v",
    ]
    if request.config.target_mac:
        args.append(f"--dut-mac={request.config.target_mac}")
    # None ⇒ let the subprocess conftest pick one random port for its session.
    if request.config.target_port is not None:
        args.append(f"--dut-port={request.config.target_port}")
    if request.config.source_port is not None:
        args.append(f"--dut-source-port={request.config.source_port}")
    if request.test_name:
        args += ["-k", request.test_name]
    if request.markers:
        args += ["-m", " and ".join(request.markers)]
    if request.confirm_vuln_tests:
        args.append("--confirm-vuln-tests")
    if request.debug:
        args.append(f"--debug-log={run_dir / 'debug.log'}")
    return args


def new_run_dir() -> tuple[str, Path]:
    run_id = f"{datetime.now(timezone.utc):%Y%m%dT%H%M%S}-{uuid.uuid4().hex[:6]}"
    run_dir = reports_dir() / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    return run_id, run_dir


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
    """
    run_id, run_dir = new_run_dir()

    result = TestRunResult(
        run_id=run_id,
        started_at=datetime.now(timezone.utc),
        finished_at=None,
        target_ip=request.config.target_ip,
        target_stack=request.config.target_stack,
        host_platform=platform.system(),
        payload_mode=request.payload_mode.value,
    )

    args = build_pytest_args(request, run_dir)

    report_log = run_dir / "report_log.jsonl"
    events_log = run_dir / "packet_events.jsonl"
    report_offset = events_offset = 0

    # Redirect the subprocess's stdout/stderr to a file rather than an
    # unread PIPE. Progress comes from the jsonl files we tail below; an
    # undrained PIPE would fill its OS buffer under -v output and deadlock
    # pytest (it blocks on write while we block on poll). The file keeps the
    # raw output available for debugging without that risk.
    with (run_dir / "pytest_output.log").open("w", encoding="utf-8") as out:
        proc = subprocess.Popen(
            args, stdout=out, stderr=subprocess.STDOUT, text=True, cwd=str(paths.project_root())
        )

        while proc.poll() is None:
            report_offset = drain_test_events(report_log, report_offset, result, on_test_event)
            events_offset = drain_packet_events(events_log, events_offset, result, on_packet_event)
            yield result
            time.sleep(POLL_INTERVAL_S)

        # Final drain in case data was written between the last poll and exit.
        report_offset = drain_test_events(report_log, report_offset, result, on_test_event)
        events_offset = drain_packet_events(events_log, events_offset, result, on_packet_event)

    result.pytest_returncode = proc.returncode
    result.finished_at = datetime.now(timezone.utc)
    (run_dir / "results.json").write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
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
    """
    data = json.loads(line)
    if data.get("$report_type") != "TestReport":
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
    lines, new_offset = read_new_lines(path, offset)
    for line in lines:
        data = json.loads(line)
        event = PacketEvent(
            timestamp=data["timestamp"],
            direction=PacketDirection(data["direction"]),
            summary=data["summary"],
            size_bytes=data["size_bytes"],
            test_nodeid=data.get("test_nodeid"),
        )
        result.packet_events.append(event)
        if callback:
            callback(event)
    return new_offset
