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


# --- Malformed allow-list input -------------------------------------------
# --dut-ip and --allowed-target are free text. A typo used to reach
# ipaddress and make every vuln-marked test ERROR with a message about
# network syntax rather than naming the flag to fix.


def test_a_malformed_cidr_names_the_flag_not_the_parser() -> None:
    from src.config import DUTConfig
    from src.errors import ConfigurationError

    config = DUTConfig(
        interface="eth0",
        target_ip="10.0.0.5",
        target_stack="linux",
        allowed_targets=("10.0.0.0/33",),
    )

    with pytest.raises(ConfigurationError, match="not a valid CIDR range"):
        config.target_in_allowed_range()


def test_a_non_ip_target_is_reported_as_configuration() -> None:
    from src.config import DUTConfig
    from src.errors import ConfigurationError

    config = DUTConfig(
        interface="eth0",
        target_ip="dut.example.test",
        target_stack="linux",
        allowed_targets=("10.0.0.0/24",),
    )

    with pytest.raises(ConfigurationError, match="not an IP address"):
        config.target_in_allowed_range()


def test_a_valid_allow_list_still_decides_membership() -> None:
    from src.config import DUTConfig

    inside = DUTConfig(
        interface="eth0", target_ip="10.0.0.5", target_stack="linux",
        allowed_targets=("192.168.1.0/24", "10.0.0.0/24"),
    )
    outside = DUTConfig(
        interface="eth0", target_ip="172.16.0.9", target_stack="linux",
        allowed_targets=("10.0.0.0/24",),
    )

    assert inside.target_in_allowed_range() is True
    assert outside.target_in_allowed_range() is False


def test_the_cli_rejects_a_bad_cidr_before_the_run_starts() -> None:
    """The allow-list is only read once a vuln test is about to run, which on
    a long suite is many minutes in."""
    from click.testing import CliRunner

    import src.cli.main as cli_main

    result = CliRunner().invoke(
        cli_main.cli,
        [
            "run", "--iface", "eth0", "--dut-ip", "10.0.0.5",
            "--target-stack", "linux", "--allowed-target", "10.0.0.0/33",
        ],
    )

    assert result.exit_code != 0
    assert "not a valid CIDR range" in result.output
