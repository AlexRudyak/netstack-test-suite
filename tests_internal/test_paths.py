"""Unit tests for src/paths.py — source vs. frozen path resolution."""
from __future__ import annotations

from pathlib import Path

import pytest

import src.paths as paths

pytestmark = [pytest.mark.internal]


def test_source_mode_uses_repo_root() -> None:
    assert not paths.is_frozen()
    root = paths.project_root()
    assert (root / "pyproject.toml").exists()
    assert paths.tests_root() == root / "tests"
    # In source mode, artifacts live under the repo root.
    assert paths.reports_base() == root


def test_frozen_reports_base_is_next_to_exe(monkeypatch, tmp_path) -> None:
    """The reported bug: frozen artifacts must land next to the exe, not in
    a temp/LOCALAPPDATA folder."""
    fake_exe = tmp_path / "app" / "NetstackTestSuite.exe"
    fake_exe.parent.mkdir(parents=True)
    fake_exe.write_bytes(b"")

    monkeypatch.setattr(paths.sys, "frozen", True, raising=False)
    monkeypatch.setattr(paths.sys, "executable", str(fake_exe))

    assert paths.reports_base() == fake_exe.parent
    # And it's distinct from the bundle/extraction dir used for tests.
    monkeypatch.setattr(paths.sys, "_MEIPASS", str(tmp_path / "extract"), raising=False)
    assert paths.project_root() == Path(str(tmp_path / "extract"))
    assert paths.reports_base() != paths.project_root()
