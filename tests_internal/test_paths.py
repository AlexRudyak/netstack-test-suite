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


def test_app_icon_is_present_and_bundled() -> None:
    """The window icon must exist on disk under the name the spec bundles.

    Both halves matter: `app_icon()` resolving to a missing file gives a
    null QIcon and a blank title bar with no error, and the spec bundles
    this exact relative path — so a move that updates one and not the other
    only shows up in a packaged build.
    """
    icon = paths.app_icon()
    assert icon.exists(), f"missing app icon: {icon}"
    assert icon.relative_to(paths.project_root()) == Path("packaging") / "icon.png"
    assert icon.read_bytes()[:8] == b"\x89PNG\r\n\x1a\n"
