"""Unit tests for src/run_artifacts.py — the run directory's layout.

Before this module the eight artifact filenames were literals repeated
across five modules, and `results.json` was written in `runner` but read in
`reporting.collector` with nothing linking the two. These tests pin the
things that were previously only true by coincidence.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from src.reporting import report_data
from src.reporting.collector import load_run_result
from src.run_artifacts import RunArtifacts
from src.runner import RunRequest, build_pytest_args, finalize_run

from .conftest import make_run_result

pytestmark = [pytest.mark.internal]


def test_every_artifact_sits_under_the_run_root(tmp_path: Path) -> None:
    artifacts = RunArtifacts(tmp_path)
    paths = [
        artifacts.results,
        artifacts.report_log,
        artifacts.packet_events,
        artifacts.capture,
        artifacts.debug_log,
        artifacts.pytest_output,
        artifacts.report("pdf"),
    ]
    assert all(p.parent == tmp_path for p in paths)
    assert len({p.name for p in paths}) == len(paths), "two artifacts share a filename"


def test_save_and_load_round_trip(tmp_path: Path) -> None:
    """The write and the read are the same object's two methods, so they
    cannot name the file differently — that split was the original bug."""
    artifacts = RunArtifacts(tmp_path / "run")
    result = make_run_result()
    artifacts.save(result)

    assert artifacts.results.exists()
    assert artifacts.load().to_dict() == result.to_dict()


def test_load_run_result_reads_what_finalize_run_wrote(tmp_path: Path) -> None:
    """The cross-package path: runner writes, reporting.collector reads."""
    result = finalize_run(make_run_result(), tmp_path, returncode=1)
    restored = load_run_result(tmp_path)

    assert restored.run_id == result.run_id
    assert restored.pytest_returncode == 1


def test_subprocess_flags_use_the_shared_names(tmp_path: Path) -> None:
    """build_pytest_args tells the subprocess where to write; those paths
    must be the ones the parent then tails and the reports then cite."""
    from src.config import DUTConfig

    config = DUTConfig(interface="eth0", target_ip="10.0.0.5", target_stack="linux")
    args = build_pytest_args(RunRequest(config=config, debug=True), tmp_path)
    artifacts = RunArtifacts(tmp_path)

    assert f"--report-log={artifacts.report_log}" in args
    assert f"--live-events-log={artifacts.packet_events}" in args
    assert f"--capture-pcap={artifacts.capture}" in args
    assert f"--debug-log={artifacts.debug_log}" in args


def test_reports_artifact_list_is_generated_not_retyped() -> None:
    """report_data.ARTIFACTS documents the run directory for a report's
    reader. It used to be a fourth independent copy of the filenames."""
    assert report_data.ARTIFACTS is RunArtifacts.DESCRIPTIONS

    named = {name for name, _ in RunArtifacts.DESCRIPTIONS}
    written = {
        RunArtifacts.CAPTURE,
        RunArtifacts.DEBUG_LOG,
        RunArtifacts.PYTEST_OUTPUT,
        RunArtifacts.RESULTS,
    }
    assert named == written, "the reports describe files the runner does not write, or vice versa"
    assert all(description.strip() for _, description in RunArtifacts.DESCRIPTIONS)


def test_an_unwritable_run_directory_raises_a_netstack_error(tmp_path: Path) -> None:
    """A bare OSError here is not renderable by either entry point: the CLI
    boundary catches NetstackError only (deliberately), and in the GUI these
    writes happen inside Qt slots, where an escape ends the process."""
    from src.errors import NetstackError, RunArtifactError

    blocker = tmp_path / "not-a-directory"
    blocker.write_text("", encoding="utf-8")

    with pytest.raises(RunArtifactError) as caught:
        RunArtifacts(blocker / "run-1").save(make_run_result())

    assert isinstance(caught.value, NetstackError)
    assert "results.json" in str(caught.value)
    assert "already on disk" in str(caught.value), "the operator is not told what survived"
