"""Unit tests for src/runner.py: build_pytest_args (the canonical
subprocess command shared by CLI and GUI) plus the file-tailing and
report-log parsing helpers. No subprocess is spawned."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.config import DUTConfig
from src.packet_engine.payloads import PayloadMode
from src.reporting.models import TestOutcome, TestRunResult
from src.runner import (
    RunRequest,
    build_pytest_args,
    drain_packet_events,
    drain_test_events,
    parse_report_log_line,
    read_new_lines,
)

from .conftest import make_run_result

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


def test_proxy_topology_is_passed_through(tmp_path: Path) -> None:
    """Proxy options must reach the subprocess, or the proxy tests skip."""
    request = RunRequest(
        config=_config(),
        proxy_mode="socks5",
        proxy_host="10.0.0.5",
        proxy_port=1080,
        backend_host="10.0.0.9",
        backend_port=9099,
    )
    args = build_pytest_args(request, tmp_path)
    assert "--proxy-mode=socks5" in args
    assert "--proxy-host=10.0.0.5" in args
    assert "--proxy-port=1080" in args
    assert "--backend-host=10.0.0.9" in args
    assert "--backend-port=9099" in args


def test_allowed_targets_are_forwarded_to_subprocess(tmp_path: Path) -> None:
    """The vuln-test allow-list lives on the DUTConfig; if build_pytest_args
    drops it, every vuln-marked test raises UnauthorizedTargetError in the
    subprocess even though the operator authorized the target."""
    config = DUTConfig(
        interface="eth0",
        target_ip="192.168.1.254",
        target_stack="linux",
        allowed_targets=("192.168.1.0/24", "10.0.0.5/32"),
    )
    args = build_pytest_args(RunRequest(config=config), tmp_path)
    assert "--allowed-targets=192.168.1.0/24" in args
    assert "--allowed-targets=10.0.0.5/32" in args


def test_allowed_targets_omitted_when_empty(tmp_path: Path) -> None:
    args = build_pytest_args(RunRequest(config=_config()), tmp_path)
    assert not any(a.startswith("--allowed-targets") for a in args)


def test_proxy_options_omitted_when_mode_unset(tmp_path: Path) -> None:
    args = build_pytest_args(RunRequest(config=_config()), tmp_path)
    assert not any(a.startswith("--proxy-mode") for a in args)
    assert not any(a.startswith("--backend-host") for a in args)


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


def test_only_none_means_unset_never_a_falsy_value(tmp_path: Path) -> None:
    """Port 0 is forwarded, not dropped.

    The flag table treats None as "unset" uniformly. Port 0 is a nonsense
    DUT/proxy port, but forwarding it lets the subprocess fail visibly on it;
    dropping it would silently run against a *different* port than the one
    asked for, which is the harder failure to diagnose. An empty MAC string
    is a different case — an unset text field — so it stays dropped.
    """
    config = DUTConfig(
        interface="eth0", target_ip="10.0.0.5", target_stack="linux",
        target_mac="", target_port=0, source_port=0,
    )
    args = build_pytest_args(
        RunRequest(config=config, proxy_mode="socks5", proxy_port=0, backend_port=0), tmp_path
    )
    assert "--dut-port=0" in args
    assert "--dut-source-port=0" in args
    assert "--proxy-port=0" in args
    assert "--backend-port=0" in args
    assert not any(a.startswith("--dut-mac") for a in args)


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
    """The role reaching the subprocess is the one on the config — the only
    copy there is, so it cannot disagree with what preflight and the vuln
    allow-list check saw."""
    from src.config import Role

    assert "--role=client" in build_pytest_args(RunRequest(config=_config()), tmp_path)
    server = DUTConfig(
        interface="eth0", target_ip="10.0.0.5", target_stack="linux", role=Role.SERVER
    )
    assert "--role=server" in build_pytest_args(RunRequest(config=server), tmp_path)


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


# --- _extract_message: the four shapes pytest serializes longrepr as -------
# The most intricate logic in runner.py (highest cognitive-to-cyclomatic
# ratio in the codebase). Each branch below is a real reportlog shape.


def test_extract_message_handles_every_longrepr_shape() -> None:
    def message_for(longrepr) -> str | None:
        event = parse_report_log_line(_report_log_line(outcome="failed", longrepr=longrepr))
        assert event is not None
        return event.message

    # dict: the normal failure shape.
    assert message_for({"reprcrash": {"message": "assert 1 == 2"}}) == "assert 1 == 2"
    # dict without reprcrash: no message rather than a KeyError.
    assert message_for({"sections": []}) is None
    # list of 3 with a trailing string: the skip shape.
    assert message_for(["/p/test_x.py", 19, "Skipped: no DUT"]) == "Skipped: no DUT"
    # list of another length: stringified whole, not silently dropped.
    assert message_for(["a", "b"]) == str(["a", "b"])
    # plain string: the LAST line carries the assertion, not the traceback head.
    assert message_for("Traceback...\n  File x\nE   assert False") == "E   assert False"
    # whitespace-only string is not a message.
    assert message_for("   \n  ") is None
    # absent/empty longrepr.
    assert message_for(None) is None
    assert message_for("") is None


def test_passing_call_carries_no_message() -> None:
    """Messages are only extracted for FAILED/ERROR/SKIPPED outcomes."""
    event = parse_report_log_line(
        _report_log_line(outcome="passed", longrepr={"reprcrash": {"message": "ignored"}})
    )
    assert event is not None
    assert event.message is None


def test_non_testreport_lines_are_ignored() -> None:
    """The report log also carries CollectReport and session lines."""
    assert parse_report_log_line(json.dumps({"$report_type": "CollectReport"})) is None
    assert parse_report_log_line(json.dumps({"nodeid": "x"})) is None


def test_unknown_call_outcome_falls_back_to_error() -> None:
    event = parse_report_log_line(_report_log_line(outcome="bogus"))
    assert event is not None
    assert event.outcome is TestOutcome.ERROR


def _run_result() -> TestRunResult:
    return make_run_result(run_id="r", finished_at=None)


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
    result = _run_result()
    seen = []
    offset = drain_test_events(path, 0, result, seen.append)
    assert len(result.tests) == 1
    assert len(seen) == 1
    assert offset > 0


# --- Malformed input: one bad line must not cost the run ------------------
# Both drains tail a file the pytest subprocess is still appending to, so a
# truncated or interleaved line is a property of the medium, not a bug.
# Letting it raise aborted stream_run with the subprocess still running and
# no results.json written, and in the GUI it left a QTimer slot.


def test_drain_test_events_skips_a_truncated_line(tmp_path: Path) -> None:
    path = tmp_path / "report_log.jsonl"
    truncated = '{"$report_type": "TestReport", "when": "cal'
    survivor = _report_log_line(nodeid="tests/x.py::survivor")
    path.write_text(f"{truncated}\n{survivor}\n", encoding="utf-8")

    result = _run_result()
    drain_test_events(path, 0, result, None)

    assert [t.nodeid for t in result.tests] == ["tests/x.py::survivor"]


def test_drain_test_events_skips_a_non_object_line(tmp_path: Path) -> None:
    """Valid JSON that isn't a report object — `data.get` would raise."""
    path = tmp_path / "report_log.jsonl"
    path.write_text(f"[1, 2, 3]\n{_report_log_line()}\n", encoding="utf-8")

    result = _run_result()
    drain_test_events(path, 0, result, None)

    assert result.total == 1


def _packet_event_line(**overrides) -> str:
    base = {
        "timestamp": 1000.0,
        "direction": "sent",
        "summary": "Ether / IP / TCP",
        "size_bytes": 54,
        "test_nodeid": "tests/x.py::t",
    }
    base.update(overrides)
    return json.dumps(base)


def test_drain_packet_events_skips_a_line_missing_a_field(tmp_path: Path) -> None:
    path = tmp_path / "packet_events.jsonl"
    incomplete = json.dumps({"timestamp": 1.0})
    path.write_text(f"{incomplete}\n{_packet_event_line()}\n", encoding="utf-8")

    result = _run_result()
    seen = []
    drain_packet_events(path, 0, result, seen.append)

    assert len(result.packet_events) == 1
    assert len(seen) == 1


def test_drain_packet_events_skips_an_unknown_direction(tmp_path: Path) -> None:
    """PacketDirection("sideways") raises ValueError, not KeyError."""
    path = tmp_path / "packet_events.jsonl"
    bad = _packet_event_line(direction="sideways")
    path.write_text(f"{bad}\n{_packet_event_line()}\n", encoding="utf-8")

    result = _run_result()
    drain_packet_events(path, 0, result, None)

    assert len(result.packet_events) == 1


def test_a_malformed_line_still_advances_the_offset(tmp_path: Path) -> None:
    """Otherwise the next poll re-reads the same bad line forever."""
    path = tmp_path / "packet_events.jsonl"
    path.write_text("{oops\n", encoding="utf-8")

    offset = drain_packet_events(path, 0, _run_result(), None)

    assert offset == path.stat().st_size


# --- pytest_returncode / errored ------------------------------------------


def test_errored_property_reflects_returncode() -> None:
    def _result(code):
        return make_run_result(run_id="r", finished_at=None, pytest_returncode=code)

    assert _result(0).errored is False
    assert _result(1).errored is False  # test failures are not a run error
    assert _result(2).errored is True   # usage/collection error
    assert _result(5).errored is True   # no tests collected
    assert _result(None).errored is False


# --- Interruption ----------------------------------------------------------
# An interrupted run used to write no results.json and leave the pytest
# subprocess running: the parent unwound out of stream_run's poll loop, past
# the only call to finalize_run, with the child still sending at the DUT.


class _NeverExitingProc:
    """A subprocess stand-in that never finishes on its own."""

    def __init__(self) -> None:
        self.returncode: int | None = None
        self.terminated = False

    def poll(self) -> int | None:
        return None

    def terminate(self) -> None:
        self.terminated = True
        self.returncode = -15

    def wait(self, timeout: float | None = None) -> int | None:
        return self.returncode


def _fake_run(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> _NeverExitingProc:
    import subprocess

    from src import paths, runner

    proc = _NeverExitingProc()
    monkeypatch.setattr(paths, "reports_base", lambda: tmp_path)
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: proc)
    monkeypatch.setattr(runner.time, "sleep", lambda _seconds: None)
    return proc


def _only_run_dir(tmp_path: Path) -> Path:
    runs = list((tmp_path / "reports").iterdir())
    assert len(runs) == 1
    return runs[0]


def test_interrupting_a_run_terminates_the_subprocess(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from src.runner import stream_run

    proc = _fake_run(monkeypatch, tmp_path)
    stream = stream_run(RunRequest(config=_config()))
    next(stream)  # first poll: the run is under way
    stream.close()  # the consumer went away (Ctrl+C unwinding, or a GUI close)

    assert proc.terminated, "the child was left running against the DUT"


def test_interrupting_a_run_still_writes_results_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from src.run_artifacts import RunArtifacts
    from src.runner import stream_run

    _fake_run(monkeypatch, tmp_path)
    stream = stream_run(RunRequest(config=_config()))
    next(stream)
    stream.close()

    results = _only_run_dir(tmp_path) / RunArtifacts.RESULTS
    assert results.exists(), "an interrupted run left nothing that could be re-reported"
    assert RunArtifacts(results.parent).load().finished_at is not None
