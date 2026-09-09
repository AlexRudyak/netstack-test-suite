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

from src.config import DUTConfig, ProxyLeg, Role, random_ephemeral_port
from src.packet_engine.interface import NetworkInterface
from src.packet_engine.payloads import PayloadMode
from src.proxy.config import ProxyConfig, ProxyMode
from src.reporting.collector import PacketEventLogWriter
from src.target_profiles import TargetProfile, get_profile


def selected_proxy_leg(config: pytest.Config) -> ProxyLeg | None:
    value = config.getoption("--proxy-leg")
    return ProxyLeg(value) if value else None


def effective_role(config: pytest.Config) -> Role:
    """The role the run actually plays.

    Targeting a proxy leg determines the role unambiguously — you probe a
    proxy's front as a client and observe its back as a server — so
    --proxy-leg takes precedence over --role rather than making the
    operator keep the two in sync.
    """
    leg = selected_proxy_leg(config)
    if leg is not None:
        return leg.implied_role
    return Role(config.getoption("--role"))


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Skip tests that don't apply to the selected --role, at collection
    time (before any fixture — including the privileged network_interface —
    is set up, which a function-scoped skip fixture can't guarantee).

    Role is declared per test with the `client` / `server` markers; a test
    with neither defaults to client-only. `internal` tests (tests_internal/)
    are never role-filtered.
    """
    role = effective_role(config).value
    proxy_mode = config.getoption("--proxy-mode")
    skip_marker = pytest.mark.skip
    for item in items:
        if item.get_closest_marker("internal"):
            continue

        # Proxy tests need a proxy topology (and a second app instance running
        # `proxy-serve`), so they're opt-in: skipped unless --proxy-mode is set.
        if item.get_closest_marker("proxy") is not None:
            if not proxy_mode:
                item.add_marker(
                    skip_marker(
                        reason="proxy: needs --proxy-mode and a backend instance "
                        "(`netstack-cli proxy-serve`); see docs/proxy_testing.md"
                    )
                )
            continue  # proxy tests are not role-filtered

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
    group.addoption(
        "--proxy-mode",
        choices=[m.value for m in ProxyMode],
        default=None,
        help="Enable the proxy-DUT tests and select how the client reaches the origin: "
        "transparent (inline DUT), http-connect (RFC 9110/9112), socks5 (RFC 1928). "
        "Requires a second app instance running `proxy-serve` as the backend.",
    )
    group.addoption(
        "--proxy-leg",
        choices=[leg.value for leg in ProxyLeg],
        default=None,
        help="Point the ORDINARY endpoint suites (ip/udp/icmp/tcp) at one leg of a proxy DUT: "
        "'front' probes its client-facing stack (implies --role client, and retargets to "
        "--proxy-host/--proxy-port); 'back' observes the stack it dials origins with "
        "(implies --role server; set --dut-ip to the proxy's back-side address).",
    )
    group.addoption("--proxy-host", default=None, help="Proxy DUT front address (explicit modes).")
    group.addoption("--proxy-port", type=int, default=None, help="Proxy DUT front port (explicit modes).")
    group.addoption(
        "--backend-host",
        default=None,
        help="Origin/backend address the DUT must reach — where the backend instance listens.",
    )
    group.addoption("--backend-port", type=int, default=9099, help="Backend instance listen port.")
    group.addoption("--dut-ip", default=None, help="DUT IP address.")
    group.addoption("--dut-iface", default=None, help="Local Ethernet interface facing the DUT.")
    group.addoption("--dut-mac", default=None, help="DUT MAC address.")
    group.addoption(
        "--dut-port",
        type=int,
        default=None,
        help="DUT port for tests that need one. Omitted: a random ephemeral port is "
        "chosen once for the whole session.",
    )
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
    leg = selected_proxy_leg(pytestconfig)

    # Front leg: the ordinary suites probe the proxy's client-facing stack,
    # so retarget to its front address rather than making the operator pass
    # the same host twice.
    if leg is ProxyLeg.FRONT:
        target_ip = pytestconfig.getoption("--proxy-host") or target_ip

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
    # Unspecified destination port ⇒ one random ephemeral port for the whole
    # session (this fixture is session-scoped, so it's resolved exactly once).
    target_port = pytestconfig.getoption("--dut-port")
    if leg is ProxyLeg.FRONT and target_port is None:
        # The proxy's front port is the one port we *know* is open; a random
        # ephemeral one would just measure closed-port behavior.
        target_port = pytestconfig.getoption("--proxy-port")
    if target_port is None:
        target_port = random_ephemeral_port()

    return DUTConfig(
        interface=iface,
        target_ip=target_ip,
        target_stack=target_stack,
        target_mac=pytestconfig.getoption("--dut-mac"),
        target_port=target_port,
        source_port=pytestconfig.getoption("--dut-source-port"),
        allowed_targets=tuple(pytestconfig.getoption("--allowed-targets")),
        role=effective_role(pytestconfig),
        proxy_leg=leg,
    )


@pytest.fixture(scope="session")
def selected_role(pytestconfig: pytest.Config) -> Role:
    return effective_role(pytestconfig)


@pytest.fixture(scope="session")
def proxy_config(pytestconfig: pytest.Config) -> ProxyConfig:
    """Topology for the proxy-DUT tests.

    Only reached by `proxy`-marked tests, which the collection hook already
    skips when --proxy-mode is absent.
    """
    mode = ProxyMode(pytestconfig.getoption("--proxy-mode"))
    backend_host = pytestconfig.getoption("--backend-host")
    if not backend_host:
        pytest.fail(
            "--backend-host is required for proxy tests: the origin address the DUT must "
            "reach, i.e. where the backend instance (`netstack-cli proxy-serve`) listens."
        )
    try:
        return ProxyConfig(
            mode=mode,
            backend_host=backend_host,
            backend_port=pytestconfig.getoption("--backend-port"),
            proxy_host=pytestconfig.getoption("--proxy-host"),
            proxy_port=pytestconfig.getoption("--proxy-port"),
        )
    except ValueError as exc:
        pytest.fail(str(exc))


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
