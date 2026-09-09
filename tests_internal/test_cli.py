"""Unit tests for the CLI: verifies argument parsing constructs the
correct RunRequest, without invoking pytest or a DUT (run_tests is
monkeypatched)."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest
from click.testing import CliRunner

import src.cli.main as cli_main
from src.reporting.models import TestRunResult

pytestmark = [pytest.mark.internal]


@pytest.fixture
def stub_result() -> TestRunResult:
    now = datetime.now(timezone.utc)
    return TestRunResult(
        run_id="stub-run",
        started_at=now,
        finished_at=now,
        target_ip="10.0.0.5",
        target_stack="linux",
        host_platform="TestOS",
    )


def test_run_command_builds_expected_request(monkeypatch, stub_result) -> None:
    captured = {}

    def fake_run_tests(request, on_test_event=None):
        captured["request"] = request
        return stub_result

    monkeypatch.setattr(cli_main, "run_tests", fake_run_tests)
    monkeypatch.setattr(cli_main, "generate_pdf_report", lambda result, path: path)

    runner = CliRunner()
    result = runner.invoke(
        cli_main.cli,
        [
            "run",
            "--module", "tcp",
            "--submodule", "syn",
            "--iface", "eth0",
            "--dut-ip", "10.0.0.5",
            "--target-stack", "linux",
            "--report", "none",
            "--skip-preflight",  # preflight needs a real socket; not under test here
        ],
    )

    assert result.exit_code == 0, result.output
    request = captured["request"]
    assert request.module == "tcp"
    assert request.submodule == "syn"
    assert request.config.interface == "eth0"
    assert request.config.target_ip == "10.0.0.5"
    assert request.config.target_stack == "linux"


def test_module_choices_cover_every_catalogued_module() -> None:
    """--module must accept every module that actually has tests, or the CLI
    silently can't run them (this regressed once when icmp/proxy were added)."""
    from src.catalog import CATALOG

    assert set(cli_main.TEST_MODULES) == {spec.module for spec in CATALOG}
    for expected in ("ip", "udp", "tcp", "icmp", "proxy"):
        assert expected in cli_main.TEST_MODULES


def test_run_accepts_each_module(monkeypatch, stub_result) -> None:
    def fake_run_tests(request, on_test_event=None):
        return stub_result

    monkeypatch.setattr(cli_main, "run_tests", fake_run_tests)
    runner = CliRunner()
    for module in cli_main.TEST_MODULES:
        result = runner.invoke(
            cli_main.cli,
            [
                "run", "--module", module,
                "--iface", "eth0", "--dut-ip", "10.0.0.5", "--target-stack", "linux",
                "--report", "none", "--skip-preflight",
            ],
        )
        assert result.exit_code == 0, f"--module {module} rejected: {result.output}"


def test_proxy_front_leg_retargets_and_forces_client_role(monkeypatch, stub_result) -> None:
    """`--proxy-leg front` aims the ordinary suites at the proxy's
    client-facing address and runs them as client, whatever --role says."""
    from src.config import ProxyLeg, Role

    captured = {}

    def fake_run_tests(request, on_test_event=None):
        captured["request"] = request
        return stub_result

    monkeypatch.setattr(cli_main, "run_tests", fake_run_tests)

    runner = CliRunner()
    result = runner.invoke(
        cli_main.cli,
        [
            "run",
            "--iface", "eth0",
            "--dut-ip", "10.0.0.5",
            "--target-stack", "linux",
            "--role", "server",            # deliberately contradictory
            "--proxy-leg", "front",
            "--proxy-host", "192.0.2.7",
            "--proxy-port", "1080",
            "--report", "none", "--skip-preflight",
        ],
    )

    assert result.exit_code == 0, result.output
    request = captured["request"]
    assert request.proxy_leg == "front"
    assert request.config.target_ip == "192.0.2.7"
    assert request.config.target_port == 1080
    assert request.config.role is Role.CLIENT
    assert request.config.proxy_leg is ProxyLeg.FRONT


def test_proxy_back_leg_without_a_topology_is_refused(monkeypatch) -> None:
    """A back-leg run needs a way to induce traffic; without one every
    server-role test would just time out, so the CLI refuses up front."""
    def fake_run_tests(request, on_test_event=None):
        raise AssertionError("run_tests should not be reached")

    monkeypatch.setattr(cli_main, "run_tests", fake_run_tests)

    runner = CliRunner()
    result = runner.invoke(
        cli_main.cli,
        [
            "run",
            "--iface", "eth0", "--dut-ip", "10.0.0.5", "--target-stack", "linux",
            "--proxy-leg", "back",
            "--report", "none", "--skip-preflight",
        ],
    )

    assert result.exit_code != 0
    assert "--backend-host" in result.output


def test_run_command_requires_dut_ip() -> None:
    runner = CliRunner()
    result = runner.invoke(cli_main.cli, ["run", "--iface", "eth0", "--target-stack", "linux"])
    assert result.exit_code != 0


def test_run_command_aborts_when_preflight_fails(monkeypatch) -> None:
    """A failed preflight must abort with a non-zero exit before any tests
    run (and before run_tests is even called)."""
    from src.packet_engine.preflight import PreflightResult

    called = {"run_tests": False}

    def fake_run_tests(request, on_test_event=None):
        called["run_tests"] = True
        raise AssertionError("run_tests should not be reached on preflight failure")

    monkeypatch.setattr(cli_main, "run_tests", fake_run_tests)
    monkeypatch.setattr(
        cli_main,
        "run_preflight",
        lambda config: PreflightResult(ok=False, errors=["Missing required configuration: Target IP."]),
    )

    runner = CliRunner()
    result = runner.invoke(
        cli_main.cli,
        ["run", "--iface", "eth0", "--dut-ip", "10.0.0.5", "--target-stack", "linux"],
    )

    assert result.exit_code == 2
    assert "Preflight failed" in result.output
    assert called["run_tests"] is False


def test_send_command_requires_payload_source_for_custom_mode() -> None:
    runner = CliRunner()
    result = runner.invoke(
        cli_main.cli,
        [
            "send",
            "--proto", "tcp",
            "--iface", "eth0",
            "--src-ip", "10.0.0.1",
            "--dst-ip", "10.0.0.2",
            "--src-port", "1111",
            "--dst-port", "2222",
            "--src-mac", "aa:aa:aa:aa:aa:aa",
            "--dst-mac", "bb:bb:bb:bb:bb:bb",
            "--payload-mode", "custom",
        ],
    )
    assert result.exit_code != 0
    assert "requires --payload" in result.output


def test_record_command_bounded_capture_wires_recorder(monkeypatch, tmp_path) -> None:
    """A bounded (--count) record run constructs the recorder with the
    --dut-ip-derived filter and joins rather than looping on Ctrl+C."""
    captured = {}

    class _FakeRecorder:
        def __init__(self, iface, output_path, *, bpf_filter, on_packet):
            captured["iface"] = iface
            captured["output_path"] = output_path
            captured["bpf_filter"] = bpf_filter

        def start(self, *, count=0, timeout=None):
            captured["count"] = count
            captured["timeout"] = timeout

        def join(self):
            captured["joined"] = True

        def stop(self):
            return 7

    monkeypatch.setattr(cli_main, "PacketRecorder", _FakeRecorder)

    out = tmp_path / "capture.pcap"
    runner = CliRunner()
    result = runner.invoke(
        cli_main.cli,
        ["record", "--iface", "eth0", "--out", str(out), "--dut-ip", "10.0.0.5", "--count", "3"],
    )

    assert result.exit_code == 0, result.output
    assert captured["iface"] == "eth0"
    assert captured["bpf_filter"] == "host 10.0.0.5"
    assert captured["count"] == 3
    assert captured["joined"] is True
    assert "Wrote 7 packet(s)" in result.output


def test_record_command_explicit_filter_overrides_dut_ip(monkeypatch, tmp_path) -> None:
    captured = {}

    class _FakeRecorder:
        def __init__(self, iface, output_path, *, bpf_filter, on_packet):
            captured["bpf_filter"] = bpf_filter

        def start(self, *, count=0, timeout=None):
            pass

        def join(self):
            pass

        def stop(self):
            return 0

    monkeypatch.setattr(cli_main, "PacketRecorder", _FakeRecorder)

    runner = CliRunner()
    result = runner.invoke(
        cli_main.cli,
        [
            "record",
            "--iface", "eth0",
            "--out", str(tmp_path / "c.pcap"),
            "--dut-ip", "10.0.0.5",
            "--filter", "tcp port 80",
            "--count", "1",
        ],
    )

    assert result.exit_code == 0, result.output
    assert captured["bpf_filter"] == "tcp port 80"
