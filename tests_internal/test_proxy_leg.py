"""Unit tests for `--proxy-leg`: running the ORDINARY endpoint suites
against one leg of a proxy DUT.

The leg is a single switch that has to reach three places consistently —
the role the suite plays, the address it aims at, and (for the back leg)
the traffic inducer that keeps the proxy dialling out. These tests pin
each of those, plus the pass-through from RunRequest to the subprocess.
"""
from __future__ import annotations

import dataclasses
import json
from pathlib import Path

import pytest

from src.config import DUTConfig, ProxyLeg, Role
from src.runner import RunRequest, build_pytest_args

pytestmark = [pytest.mark.internal]


def _config(**overrides) -> DUTConfig:
    base = dict(interface="eth0", target_ip="10.0.0.5", target_stack="linux")
    base.update(overrides)
    return DUTConfig(**base)


# --- the enum's core promise ----------------------------------------------


def test_leg_implies_the_role_it_can_only_have() -> None:
    """You probe a proxy's front as a client and observe its back as a
    server — there is no other combination."""
    assert ProxyLeg.FRONT.implied_role is Role.CLIENT
    assert ProxyLeg.BACK.implied_role is Role.SERVER


def test_leg_survives_config_round_trip() -> None:
    """Through JSON, since that is what a persisted config would be."""
    encoded = json.dumps(_config(proxy_leg=ProxyLeg.BACK).to_dict())
    assert DUTConfig.from_dict(json.loads(encoded)).proxy_leg is ProxyLeg.BACK


def test_absent_leg_round_trips_as_none() -> None:
    encoded = json.dumps(_config().to_dict())
    assert DUTConfig.from_dict(json.loads(encoded)).proxy_leg is None


def test_config_round_trip_covers_every_field() -> None:
    """A field dropped from to_dict/from_dict is silent otherwise."""
    config = _config(
        target_mac="aa:bb:cc:dd:ee:ff",
        target_port=8080,
        source_port=41000,
        timeout=9.5,
        retries=7,
        role=Role.SERVER,
        proxy_leg=ProxyLeg.FRONT,
        allowed_targets=("10.0.0.0/24",),
    )
    assert set(config.to_dict()) == {f.name for f in dataclasses.fields(DUTConfig)}
    assert DUTConfig.from_dict(config.to_dict()) == config


# --- runner pass-through ---------------------------------------------------


def test_leg_and_front_address_reach_the_subprocess(tmp_path: Path) -> None:
    """A front-leg run needs the proxy address even with no proxy-marked
    tests selected — that's what the ordinary suites retarget to."""
    request = RunRequest(
        config=_config(proxy_leg=ProxyLeg.FRONT),
        proxy_host="10.0.0.5",
        proxy_port=1080,
    )
    args = build_pytest_args(request, tmp_path)
    assert "--proxy-leg=front" in args
    assert "--proxy-host=10.0.0.5" in args
    assert "--proxy-port=1080" in args
    assert not any(a.startswith("--proxy-mode") for a in args)


def test_no_leg_emits_no_leg_arg(tmp_path: Path) -> None:
    args = build_pytest_args(RunRequest(config=_config()), tmp_path)
    assert not any(a.startswith("--proxy-leg") for a in args)


# --- conftest resolution (front-leg retargeting + effective role) ----------


class _StubConfig:
    """Stands in for pytest.Config: only getoption() is exercised."""

    def __init__(self, **options) -> None:
        defaults = {
            "--role": "client",
            "--proxy-leg": None,
            "--proxy-host": None,
            "--proxy-port": None,
            "--dut-ip": "10.0.0.5",
            "--dut-iface": "eth0",
            "--target-stack": "linux",
            "--dut-mac": None,
            "--dut-port": None,
            "--dut-source-port": None,
            "--allowed-targets": [],
        }
        defaults.update(options)
        self._options = defaults

    def getoption(self, name: str):
        return self._options[name]


def test_effective_role_follows_the_leg_over_role_flag() -> None:
    from conftest import effective_role

    # Deliberately contradictory: the leg must win, not silently run the
    # wrong side of the conversation.
    config = _StubConfig(**{"--proxy-leg": "back", "--role": "client"})
    assert effective_role(config) is Role.SERVER

    config = _StubConfig(**{"--proxy-leg": "front", "--role": "server"})
    assert effective_role(config) is Role.CLIENT


def test_effective_role_falls_back_to_role_flag() -> None:
    from conftest import effective_role

    assert effective_role(_StubConfig(**{"--role": "server"})) is Role.SERVER


def test_front_leg_retargets_to_the_proxy_front_address() -> None:
    from conftest import dut_config

    config = _StubConfig(
        **{
            "--proxy-leg": "front",
            "--proxy-host": "192.0.2.7",
            "--proxy-port": 1080,
            "--dut-ip": "10.0.0.5",  # the back-side address; not what we probe
        }
    )
    result = dut_config.__wrapped__(config)
    assert result.target_ip == "192.0.2.7"
    assert result.target_port == 1080
    assert result.role is Role.CLIENT
    assert result.proxy_leg is ProxyLeg.FRONT


def test_explicit_dut_port_still_wins_on_the_front_leg() -> None:
    from conftest import dut_config

    config = _StubConfig(
        **{"--proxy-leg": "front", "--proxy-host": "192.0.2.7", "--proxy-port": 1080, "--dut-port": 8080}
    )
    assert dut_config.__wrapped__(config).target_port == 8080


def test_back_leg_keeps_the_configured_address_and_runs_as_server() -> None:
    """The back leg is a different address entirely — the operator gives it
    as --dut-ip, and nothing retargets."""
    from conftest import dut_config

    config = _StubConfig(
        **{"--proxy-leg": "back", "--proxy-host": "192.0.2.7", "--dut-ip": "198.51.100.9"}
    )
    result = dut_config.__wrapped__(config)
    assert result.target_ip == "198.51.100.9"
    assert result.role is Role.SERVER
    assert result.proxy_leg is ProxyLeg.BACK


# --- the inducer -----------------------------------------------------------


def _wait_until(predicate, timeout: float = 5.0) -> bool:
    import time

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return False


def test_inducer_counts_attempts_and_reports_unreachable_proxy() -> None:
    """A proxy that never answers is a DUT result, not an inducer crash:
    the loop keeps trying and the summary says nothing got through."""
    import socket

    from src.proxy.config import ProxyConfig, ProxyMode
    from src.proxy.inducer import TrafficInducer

    # Bind and immediately close, so the port is (almost certainly) dead.
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    dead_port = probe.getsockname()[1]
    probe.close()

    config = ProxyConfig(
        mode=ProxyMode.TRANSPARENT,
        backend_host="127.0.0.1",
        backend_port=dead_port,
        timeout=0.5,
    )
    inducer = TrafficInducer(config, interval=0.01)
    with inducer:
        assert _wait_until(lambda: inducer.attempts >= 1), "inducer never attempted a connection"
        _wait_until(lambda: inducer.last_error is not None, timeout=3.0)

    assert inducer.successes == 0
    assert inducer.last_error  # the refusal is recorded, not raised
    assert "induced 0/" in inducer.summary()


def test_inducer_drives_real_connections_through_a_stub_proxy() -> None:
    """The point of the inducer: with a working path, the origin sees the
    connections the proxy dials — which is exactly what the back-leg
    server-role tests wait for."""
    from src.proxy.backend import EchoBackend
    from src.proxy.config import ProxyConfig, ProxyMode
    from src.proxy.inducer import TrafficInducer
    from tests_internal.test_proxy_relay import StubProxy

    backend = EchoBackend("127.0.0.1", 0)
    backend.start()
    try:
        with StubProxy(ProxyMode.HTTP_CONNECT) as proxy:
            config = ProxyConfig(
                mode=ProxyMode.HTTP_CONNECT,
                backend_host="127.0.0.1",
                backend_port=backend.bound_port,
                proxy_host="127.0.0.1",
                proxy_port=proxy.port,
                timeout=2.0,
            )
            with TrafficInducer(config, interval=0.01) as inducer:
                got = _wait_until(lambda: inducer.successes >= 3)
            assert got, inducer.summary()
        # Each induced connection made the proxy dial the origin.
        assert backend.stats.tcp_connections >= 3
    finally:
        backend.stop()


def test_request_cannot_disagree_with_its_config_about_role_or_leg() -> None:
    """RunRequest reads role/proxy_leg off its config rather than copying
    them. Copies let the value reaching the pytest subprocess diverge from
    the one preflight and the vuln allow-list check saw — and role decides
    which direction traffic is sent at the DUT.
    """
    fields = {f.name for f in dataclasses.fields(RunRequest)}
    assert "role" not in fields and "proxy_leg" not in fields, (
        "RunRequest grew a role/proxy_leg field again — they belong to "
        "DUTConfig, which resolves them together (src.config.resolve_role)."
    )

    config = _config(proxy_leg=ProxyLeg.BACK, role=Role.SERVER)
    request = RunRequest(config=config)
    assert request.role is config.role
    assert request.proxy_leg == ProxyLeg.BACK.value


def test_inducer_summary_breaks_failures_down_by_type() -> None:
    """When nothing was induced, every server-role timeout in the run has
    this same root cause — so the teardown line has to say which. Keeping
    only the last error meant thousands of identical failures reported one
    string, and a transient refusal read like a permanent misconfiguration.
    """
    import socket

    from src.proxy.config import ProxyConfig, ProxyMode
    from src.proxy.inducer import TrafficInducer

    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    dead_port = probe.getsockname()[1]
    probe.close()

    config = ProxyConfig(
        mode=ProxyMode.TRANSPARENT,
        backend_host="127.0.0.1",
        backend_port=dead_port,
        timeout=0.5,
    )
    inducer = TrafficInducer(config, interval=0.01)
    with inducer:
        _wait_until(lambda: inducer.attempts >= 3, timeout=3.0)

    summary = inducer.summary()
    assert "failures:" in summary
    assert "x" in summary  # "<ExceptionName>x<count>"
    assert "last:" in summary


def test_inducer_backs_off_after_a_run_of_failures() -> None:
    """At 4Hz an unreachable backend otherwise burns a whole session of
    connect attempts against something that will never answer."""
    import src.proxy.inducer as inducer_mod
    from src.proxy.config import ProxyConfig, ProxyMode
    from src.proxy.inducer import TrafficInducer

    waits: list[float] = []

    class _AlwaysFails:
        def __init__(self, config) -> None:
            pass

        def __enter__(self):
            raise ConnectionRefusedError("nothing listening")

        def __exit__(self, *exc_info) -> None:
            pass

    monkeypatch_target = inducer_mod.ProxyClient
    inducer_mod.ProxyClient = _AlwaysFails
    try:
        config = ProxyConfig(
            mode=ProxyMode.TRANSPARENT, backend_host="127.0.0.1", backend_port=1, timeout=0.1
        )
        inducer = TrafficInducer(config, interval=0.001)
        original_wait = inducer._stop.wait

        def recording_wait(timeout=None):
            if timeout is not None:
                waits.append(timeout)
            return original_wait(timeout)

        inducer._stop.wait = recording_wait  # type: ignore[method-assign]
        with inducer:
            _wait_until(lambda: inducer.attempts >= 15, timeout=5.0)
    finally:
        inducer_mod.ProxyClient = monkeypatch_target

    assert inducer.successes == 0
    assert max(waits) > inducer.interval, "the loop never backed off"
