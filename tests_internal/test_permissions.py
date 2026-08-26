"""Unit tests for src/utils/permissions.py auto-elevation decision logic.
ShellExecute is stubbed so no real elevation happens."""
from __future__ import annotations

import pytest

import src.utils.permissions as permissions
from src.utils.permissions import ElevationResult, relaunch_module_as_admin

pytestmark = [pytest.mark.internal]


def test_non_windows_is_unsupported(monkeypatch) -> None:
    monkeypatch.setattr(permissions.platform, "system", lambda: "Linux")
    assert relaunch_module_as_admin() == ElevationResult.UNSUPPORTED


def test_already_elevated_does_not_relaunch(monkeypatch) -> None:
    monkeypatch.setattr(permissions.platform, "system", lambda: "Windows")
    monkeypatch.setattr(permissions, "is_elevated", lambda: True)
    called = {"n": 0}
    monkeypatch.setattr(
        permissions, "_shell_execute_runas", lambda *a: called.__setitem__("n", called["n"] + 1) or 42
    )
    assert relaunch_module_as_admin() == ElevationResult.ALREADY
    assert called["n"] == 0  # never attempted to elevate


def test_relaunch_when_not_elevated_and_uac_accepted(monkeypatch) -> None:
    monkeypatch.setattr(permissions.platform, "system", lambda: "Windows")
    monkeypatch.setattr(permissions, "is_elevated", lambda: False)
    captured = {}

    def fake_exec(program, params, directory):
        captured.update(program=program, params=params, directory=directory)
        return 42  # > 32 == success

    monkeypatch.setattr(permissions, "_shell_execute_runas", fake_exec)
    assert relaunch_module_as_admin("src.gui.app") == ElevationResult.RELAUNCHED
    assert "-m src.gui.app" in captured["params"]


def test_declined_uac_returns_declined(monkeypatch) -> None:
    monkeypatch.setattr(permissions.platform, "system", lambda: "Windows")
    monkeypatch.setattr(permissions, "is_elevated", lambda: False)
    monkeypatch.setattr(permissions, "_shell_execute_runas", lambda *a: 5)  # <= 32 == cancelled
    assert relaunch_module_as_admin() == ElevationResult.DECLINED
