"""Root pytest configuration: custom CLI options and the session-scoped
fixtures every test module builds on (DUT config, target profile, the
live Ethernet interface, payload settings).

The option names registered here and the subprocess flags src/runner.py
emits must stay in lockstep — runner.py is the canonical caller of this
CLI surface for both the CLI and the GUI front ends.

None of these options are `required=True`: tests_internal/ must be able
to run standalone (self-validation, no DUT involved) without supplying
any of them. Tests that actually need a DUT (everything under tests/)
request the `dut_config` fixture, which fails fast with a clear message
if the required values weren't supplied.
"""
from __future__ import annotations

import platform
from pathlib import Path

import pytest

from src.config import DUTConfig, Role
from src.packet_engine.interface import NetworkInterface
from src.packet_engine.payloads import PayloadMode
from src.reporting.collector import PacketEventLogWriter
from src.target_profiles import TargetProfile, get_profile


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Skip tests that don't apply to the selected --role, at collection
    time (before any fixture — including the privileged network_interface —
    is set up, which a function-scoped skip fixture can't guarantee).

    Role is declared per test with the `client` / `server` markers; a test
    with neither defaults to client-only. `internal` tests (tests_internal/)
    are never role-filtered.
    """
    role = config.getoption("--role")
    skip_marker = pytest.mark.skip
    for item in items:
        if item.get_closest_marker("internal"):
            continue
        has_client = item.get_closest_marker("client") is not None
        has_server = item.get_closest_marker("server") is not None
        applicable = {"client"} if not (has_client or has_server) else set()
        if has_client:
            applicable.add("client")
        if has_server:
            applicable.add("server")
        if role not in applicable:
            item.add_marker(
                skip_marker(reason=f"role: applies to {sorted(applicable)}, running as {role}")
            )


def pytest_addoption(parser: pytest.Parser) -> None:
    group = parser.getgroup("netstack")
    group.addoption(
        "--target-stack",
        choices=["linux", "windows"],
        default=None,
        help="Behavioral profile to assert stack-characteristic checks against.",
    )
    group.addoption(
        "--role",
        choices=[r.value for r in Role],
        default="client",
        help="Which side the suite plays: client (initiator) or server (responder). "
        "Tests not marked for the selected role are skipped.",
    )
    group.addoption("--dut-ip", default=None, help="DUT IP address.")
    group.addoption("--dut-iface", default=None, help="Local Ethernet interface facing the DUT.")
    group.addoption("--dut-mac", default=None, help="DUT MAC address.")
    group.addoption("--dut-port", type=int, default=80, help="Default DUT port for tests that need one.")
    group.addoption(
        "--dut-source-port",
        type=int,
        default=None,
        help="Optional fixed local source port for tests that honor it (default: per-test).",
    )
    group.addoption(
        "--payload-mode",
        choices=[m.value for m in PayloadMode],
        default="random",
    )
    group.addoption("--payload-size", type=int, default=64)
    group.addoption("--payload-text", default=None, help="Custom payload as text (payload-mode=custom).")
    group.addoption("--payload-hex", default=None, help="Custom payload as hex (payload-mode=custom).")
    group.addoption("--payload-file", default=None, help="Custom payload loaded from a file (payload-mode=custom).")
    group.addoption(
        "--live-events-log",
        default=None,
        help="Path to append live PacketEvent JSON lines to, for GUI real-time plotting.",
    )
    group.addoption("--capture-pcap", default=None, help="Path to write the full run's pcap capture to.")
    group.addoption(
        "--debug-log",
        default=None,
        help="Enable debug mode: write a tshark-style per-packet debug log to this path.",
    )
    group.addoption(
        "--allowed-targets",
        action="append",
        default=[],
        help="CIDR range(s) authorized for vuln-marked tests. May be given multiple times.",
    )
    group.addoption(
        "--confirm-vuln-tests",
        action="store_true",
        default=False,
        help="Explicit confirmation required to run vuln-marked tests.",
    )


@pytest.fixture(scope="session")
def dut_config(pytestconfig: pytest.Config) -> DUTConfig:
    target_ip = pytestconfig.getoption("--dut-ip")
    iface = pytestconfig.getoption("--dut-iface")
    target_stack = pytestconfig.getoption("--target-stack")
    missing = [
        flag
        for flag, value in (
            ("--dut-ip", target_ip),
            ("--dut-iface", iface),
            ("--target-stack", target_stack),
        )
        if not value
    ]
    if missing:
        pytest.fail(
            "This test requires a DUT target, missing: "
            f"{', '.join(missing)}. (Running tests_internal/ alone needs none of these.)"
        )
    return DUTConfig(
        interface=iface,
        target_ip=target_ip,
        target_stack=target_stack,
        target_mac=pytestconfig.getoption("--dut-mac"),
        target_port=pytestconfig.getoption("--dut-port"),
        source_port=pytestconfig.getoption("--dut-source-port"),
        allowed_targets=tuple(pytestconfig.getoption("--allowed-targets")),
        role=Role(pytestconfig.getoption("--role")),
    )


@pytest.fixture(scope="session")
def selected_role(pytestconfig: pytest.Config) -> Role:
    return Role(pytestconfig.getoption("--role"))


@pytest.fixture(scope="session")
def target_profile(dut_config: DUTConfig) -> TargetProfile:
    return get_profile(dut_config.target_stack)


@pytest.fixture(scope="session")
def confirm_vuln_tests(pytestconfig: pytest.Config) -> bool:
    return bool(pytestconfig.getoption("--confirm-vuln-tests"))


@pytest.fixture(scope="session")
def payload_settings(pytestconfig: pytest.Config) -> dict:
    from src.packet_engine.payloads import from_file, from_hex, from_text

    mode = PayloadMode(pytestconfig.getoption("--payload-mode"))
    custom = None
    if mode is PayloadMode.CUSTOM:
        if pytestconfig.getoption("--payload-text"):
            custom = from_text(pytestconfig.getoption("--payload-text"))
        elif pytestconfig.getoption("--payload-hex"):
            custom = from_hex(pytestconfig.getoption("--payload-hex"))
        elif pytestconfig.getoption("--payload-file"):
            custom = from_file(pytestconfig.getoption("--payload-file"))
        else:
            raise pytest.UsageError(
                "--payload-mode=custom requires one of --payload-text, --payload-hex, --payload-file"
            )
    return {"mode": mode, "size": pytestconfig.getoption("--payload-size"), "custom": custom}


@pytest.fixture(scope="session")
def network_interface(pytestconfig: pytest.Config, dut_config: DUTConfig):
    """Session-scoped: raw sockets are expensive to open/close, so this is
    opened once and reused across the whole run; individual tests layer
    their own sniff filters and cleanup on top. Flushes the run's pcap
    capture on session teardown.
    """
    from src.utils.permissions import require_elevation

    require_elevation()

    live_events_path = pytestconfig.getoption("--live-events-log")
    capture_path = pytestconfig.getoption("--capture-pcap")
    writer = PacketEventLogWriter(Path(live_events_path)) if live_events_path else None

    iface = NetworkInterface(
        dut_config.interface,
        capture_path=Path(capture_path) if capture_path else None,
        on_packet=writer,
        debug_logger=getattr(pytestconfig, "_netstack_debug_logger", None),
    )
    yield iface
    iface.close()
    if writer:
        writer.close()


@pytest.fixture(scope="session")
def host_platform() -> str:
    return platform.system()


# --- Debug logging (opt-in via --debug-log) --------------------------------
# The DebugLogger is created once per session in pytest_configure, stashed on
# `config`, consumed by the network_interface fixture, and its test-boundary
# lines are written by _DebugBoundaryPlugin's hooks so packet lines sit
# inside the test that produced them.


class _DebugBoundaryPlugin:
    def __init__(self, logger) -> None:
        self._logger = logger

    def pytest_runtest_logstart(self, nodeid: str, location) -> None:
        self._logger.log_event(f">>> START {nodeid}")

    def pytest_runtest_logreport(self, report) -> None:
        if report.when in ("setup", "call", "teardown"):
            self._logger.log_event(
                f"    {report.when:<8} {report.nodeid} -> {report.outcome}"
            )

    def pytest_runtest_logfinish(self, nodeid: str, location) -> None:
        self._logger.log_event(f"<<< END   {nodeid}")


def pytest_configure(config: pytest.Config) -> None:
    debug_path = config.getoption("--debug-log")
    if not debug_path:
        return
    from src.utils.debug_log import DebugLogger

    logger = DebugLogger(Path(debug_path))
    config._netstack_debug_logger = logger  # type: ignore[attr-defined]
    config.pluginmanager.register(_DebugBoundaryPlugin(logger), name="netstack_debug_boundary")


def pytest_unconfigure(config: pytest.Config) -> None:
    logger = getattr(config, "_netstack_debug_logger", None)
    if logger is not None:
        logger.close()
        config._netstack_debug_logger = None  # type: ignore[attr-defined]
