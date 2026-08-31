"""Unit tests for src/runner.py: build_pytest_args (the canonical
subprocess command shared by CLI and GUI) plus the file-tailing and
report-log parsing helpers. No subprocess is spawned."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from src.config import DUTConfig
from src.packet_engine.payloads import PayloadMode
from src.reporting.models import TestOutcome, TestRunResult
from src.runner import (
    RunRequest,
    build_pytest_args,
    drain_test_events,
    parse_report_log_line,
    read_new_lines,
)

pytestmark = [pytest.mark.internal]


def _config() -> DUTConfig:
    return DUTConfig(interface="eth0", target_ip="10.0.0.5", target_stack="linux")


def test_debug_flag_adds_debug_log_arg(tmp_path: Path) -> None:
    request = RunRequest(config=_config(), debug=True)
    args = build_pytest_args(request, tmp_path)
    debug_args = [a for a in args if a.startswith("--debug-log=")]
    assert len(debug_args) == 1
    assert debug_args[0].endswith(str(tmp_path / "debug.log"))


def test_no_debug_flag_omits_debug_log_arg(tmp_path: Path) -> None:
    request = RunRequest(config=_config(), debug=False)
    args = build_pytest_args(request, tmp_path)
    assert not any(a.startswith("--debug-log=") for a in args)


def test_module_and_submodule_build_test_path(tmp_path: Path) -> None:
    request = RunRequest(config=_config(), module="tcp", submodule="syn")
    args = build_pytest_args(request, tmp_path)
    assert "tests/tcp/syn" in args


def test_explicit_targets_are_passed_positionally(tmp_path: Path) -> None:
    """Checking a module (and other nodes) runs them all as explicit pytest
    targets, taking precedence over module/submodule."""
    request = RunRequest(
        config=_config(),
        targets=("tests/ip", "tests/tcp/syn/test_x.py::test_a"),
    )
    args = build_pytest_args(request, tmp_path)
    assert "tests/ip" in args
    assert "tests/tcp/syn/test_x.py::test_a" in args
    # No single bare "tests" path when explicit targets are given.
    assert "tests" not in args


def test_no_selection_runs_whole_suite(tmp_path: Path) -> None:
    args = build_pytest_args(RunRequest(config=_config()), tmp_path)
    assert "tests" in args


def test_payload_and_target_stack_are_passed(tmp_path: Path) -> None:
    request = RunRequest(config=_config(), payload_mode=PayloadMode.ZEROS, payload_size=128)
    args = build_pytest_args(request, tmp_path)
    assert "--payload-mode=zeros" in args
    assert "--payload-size=128" in args
    assert "--target-stack=linux" in args


def test_dut_port_arg_is_opt_in(tmp_path: Path) -> None:
    # Unset ⇒ not passed; the subprocess conftest picks one random port.
    args = build_pytest_args(RunRequest(config=_config()), tmp_path)
    assert not any(a.startswith("--dut-port=") for a in args)
    custom = DUTConfig(interface="eth0", target_ip="10.0.0.5", target_stack="linux", target_port=8080)
    assert "--dut-port=8080" in build_pytest_args(RunRequest(config=custom), tmp_path)


def test_random_ephemeral_port_is_in_iana_dynamic_range() -> None:
    from src.config import EPHEMERAL_PORT_RANGE, random_ephemeral_port

    lo, hi = EPHEMERAL_PORT_RANGE
    for _ in range(200):
        assert lo <= random_ephemeral_port() <= hi


def test_source_port_arg_is_opt_in(tmp_path: Path) -> None:
    args = build_pytest_args(RunRequest(config=_config()), tmp_path)
    assert not any(a.startswith("--dut-source-port=") for a in args)
    with_src = DUTConfig(
        interface="eth0", target_ip="10.0.0.5", target_stack="linux", source_port=41000
    )
    assert "--dut-source-port=41000" in build_pytest_args(RunRequest(config=with_src), tmp_path)


def test_role_is_passed(tmp_path: Path) -> None:
    from src.config import Role

    assert "--role=client" in build_pytest_args(RunRequest(config=_config()), tmp_path)
    assert "--role=server" in build_pytest_args(
        RunRequest(config=_config(), role=Role.SERVER), tmp_path
    )


# --- read_new_lines: robust incremental tailing ---------------------------


def test_read_new_lines_returns_complete_lines_and_advances(tmp_path: Path) -> None:
    path = tmp_path / "log.jsonl"
    path.write_bytes(b"a\nb\n")  # explicit bytes — avoid OS newline translation
    lines, offset = read_new_lines(path, 0)
    assert lines == ["a", "b"]
    assert offset == 4


def test_read_new_lines_holds_back_partial_trailing_line(tmp_path: Path) -> None:
    """A line the writer hasn't finished (no trailing newline yet) must not
    be consumed — the offset stays before it so the completed line is read
    whole on the next call."""
    path = tmp_path / "log.jsonl"
    path.write_bytes(b'{"a":1}\n{"b":2')  # second line incomplete
    lines, offset = read_new_lines(path, 0)
    assert lines == ['{"a":1}']
    assert offset == len(b'{"a":1}\n')

    # Writer finishes the second line; next read picks it up whole.
    with path.open("ab") as f:
        f.write(b"}\n")
    lines, offset = read_new_lines(path, offset)
    assert lines == ['{"b":2}']


def test_read_new_lines_no_complete_line_yet(tmp_path: Path) -> None:
    path = tmp_path / "log.jsonl"
    path.write_bytes(b"partial")
    lines, offset = read_new_lines(path, 0)
    assert lines == []
    assert offset == 0


def test_read_new_lines_missing_file(tmp_path: Path) -> None:
    assert read_new_lines(tmp_path / "nope.jsonl", 0) == ([], 0)


# --- parse_report_log_line: outcome + marker filtering --------------------


def _report_log_line(**overrides) -> str:
    base = {
        "$report_type": "TestReport",
        "when": "call",
        "nodeid": "tests/tcp/syn/test_x.py::test_a",
        "outcome": "passed",
        "duration": 0.05,
        # keywords is polluted with nodeid/file/module in real reportlog output
        "keywords": {
            "test_a": 1,
            "test_x.py": 1,
            "tcp": 1,
            "syn": 1,
            "vuln": 1,
        },
    }
    base.update(overrides)
    return json.dumps(base)


def test_parse_report_log_line_filters_markers_to_known_set() -> None:
    event = parse_report_log_line(_report_log_line())
    assert event is not None
    assert set(event.markers) == {"tcp", "syn", "vuln"}
    assert "test_a" not in event.markers
    assert "test_x.py" not in event.markers


def test_parse_report_log_line_ignores_passing_setup_phase() -> None:
    # A passing setup carries no verdict — the call phase does.
    assert parse_report_log_line(_report_log_line(when="setup", outcome="passed")) is None


def test_parse_report_log_line_setup_failure_is_error() -> None:
    """The 'run did nothing' case: a fixture error in the setup phase must
    surface as an ERROR, not be dropped."""
    line = _report_log_line(
        when="setup",
        outcome="failed",
        longrepr={"reprcrash": {"message": "Failed: requires --dut-ip"}},
    )
    event = parse_report_log_line(line)
    assert event is not None
    assert event.outcome is TestOutcome.ERROR
    assert event.message == "Failed: requires --dut-ip"


def test_parse_report_log_line_setup_skip_is_skipped() -> None:
    event = parse_report_log_line(_report_log_line(when="setup", outcome="skipped"))
    assert event is not None
    assert event.outcome is TestOutcome.SKIPPED


def test_parse_report_log_line_skip_captures_reason() -> None:
    """The reported bug: a skipped test must carry its reason (skips
    serialize longrepr as [path, lineno, 'Skipped: <reason>'])."""
    line = _report_log_line(
        when="setup",
        outcome="skipped",
        longrepr=["/path/test_x.py", 19, "Skipped: role: applies to ['server'], running as client"],
    )
    event = parse_report_log_line(line)
    assert event is not None
    assert event.outcome is TestOutcome.SKIPPED
    assert event.message == "Skipped: role: applies to ['server'], running as client"


def test_parse_report_log_line_teardown_failure_is_error() -> None:
    event = parse_report_log_line(_report_log_line(when="teardown", outcome="failed"))
    assert event is not None
    assert event.outcome is TestOutcome.ERROR


def test_parse_report_log_line_teardown_pass_ignored() -> None:
    assert parse_report_log_line(_report_log_line(when="teardown", outcome="passed")) is None


def test_parse_report_log_line_failed_captures_message() -> None:
    line = _report_log_line(
        outcome="failed",
        longrepr={"reprcrash": {"message": "assert False"}},
    )
    event = parse_report_log_line(line)
    assert event is not None
    assert event.outcome is TestOutcome.FAILED
    assert event.message == "assert False"


def _run_result() -> TestRunResult:
    return TestRunResult(
        run_id="r",
        started_at=datetime.now(timezone.utc),
        finished_at=None,
        target_ip="10.0.0.5",
        target_stack="linux",
        host_platform="TestOS",
    )


def test_drain_surfaces_setup_errors_as_error_events(tmp_path: Path) -> None:
    """End-to-end for the reported bug: every test erroring in setup must
    appear as ERROR events (not a silent empty result)."""
    path = tmp_path / "report_log.jsonl"
    lines = [
        _report_log_line(
            nodeid="tests/ip/test_x.py::test_a",
            when="setup",
            outcome="failed",
            longrepr={"reprcrash": {"message": "Failed: requires --dut-ip"}},
        ),
        _report_log_line(
            nodeid="tests/ip/test_x.py::test_b",
            when="setup",
            outcome="failed",
            longrepr={"reprcrash": {"message": "Failed: requires --dut-ip"}},
        ),
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = _run_result()
    drain_test_events(path, 0, result, None)

    assert result.total == 2
    assert result.errors == 2
    assert result.passed == 0 and result.failed == 0
    assert all("requires --dut-ip" in t.message for t in result.tests)


def test_drain_upserts_worst_outcome_per_nodeid(tmp_path: Path) -> None:
    """A test that passes its call phase but errors in teardown is an ERROR
    (worst-wins), reported once per nodeid."""
    path = tmp_path / "report_log.jsonl"
    lines = [
        _report_log_line(nodeid="tests/x.py::t", when="call", outcome="passed"),
        _report_log_line(nodeid="tests/x.py::t", when="teardown", outcome="failed"),
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = _run_result()
    drain_test_events(path, 0, result, None)

    assert result.total == 1  # one event per nodeid
    assert result.errors == 1


def test_drain_test_events_appends_and_calls_back(tmp_path: Path) -> None:
    path = tmp_path / "report_log.jsonl"
    path.write_text(_report_log_line() + "\n", encoding="utf-8")
    result = TestRunResult(
        run_id="r",
        started_at=datetime.now(timezone.utc),
        finished_at=None,
        target_ip="10.0.0.5",
        target_stack="linux",
        host_platform="TestOS",
    )
    seen = []
    offset = drain_test_events(path, 0, result, seen.append)
    assert len(result.tests) == 1
    assert len(seen) == 1
    assert offset > 0


# --- pytest_returncode / errored ------------------------------------------


def test_errored_property_reflects_returncode() -> None:
    def _result(code):
        return TestRunResult(
            run_id="r",
            started_at=datetime.now(timezone.utc),
            finished_at=None,
            target_ip="10.0.0.5",
            target_stack="linux",
            host_platform="TestOS",
            pytest_returncode=code,
        )

    assert _result(0).errored is False
    assert _result(1).errored is False  # test failures are not a run error
    assert _result(2).errored is True   # usage/collection error
    assert _result(5).errored is True   # no tests collected
    assert _result(None).errored is False
