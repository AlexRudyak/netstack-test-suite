"""Fixtures for the proxy-DUT suite.

Every test here assumes the two-instance topology:

    [this instance: client] --front--> [ PROXY DUT ] --back--> [backend instance]

The backend instance must already be running `netstack-cli proxy-serve`
(or the GUI's Proxy Backend panel) at --backend-host:--backend-port.
"""
from __future__ import annotations

import socket

import pytest

from src.errors import ProtocolViolation, ProxyTunnelError
from src.proxy.client import ProxyClient
from src.proxy.config import ProxyConfig, ProxyMode


def _require_mode(config: ProxyConfig, mode: ProxyMode) -> ProxyConfig:
    if config.mode is not mode:
        pytest.skip(f"requires --proxy-mode={mode.value} (running {config.mode.value})")
    return config


@pytest.fixture
def http_connect_config(proxy_config: ProxyConfig) -> ProxyConfig:
    return _require_mode(proxy_config, ProxyMode.HTTP_CONNECT)


@pytest.fixture
def socks5_config(proxy_config: ProxyConfig) -> ProxyConfig:
    return _require_mode(proxy_config, ProxyMode.SOCKS5)


@pytest.fixture
def closed_origin_port() -> int:
    """A port on this host that is definitely not listening.

    Bind an ephemeral port and release it — the OS will not immediately
    reuse it, so a CONNECT to it should be refused by the origin, letting us
    check how the proxy reports an unreachable origin.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("0.0.0.0", 0))
        return probe.getsockname()[1]


@pytest.fixture
def proxy_client(proxy_config: ProxyConfig):
    """A connection to the origin through the DUT, closed on teardown.

    Establishing this fixture already exercises the DUT's *server* side (it
    accepted our connection and, for explicit modes, answered the tunnel
    handshake) and its *client* side (it dialled the backend).
    """
    client = ProxyClient(proxy_config)
    try:
        client.connect()
    except (ProxyTunnelError, ProtocolViolation) as exc:
        # The DUT answered, and what it answered was a refusal or was not
        # RFC-conformant. Caught here so the report says which of the three
        # things went wrong and carries what the DUT reported: `details` (the
        # parsed CONNECT response or SOCKS5 reply) is otherwise nowhere in
        # the output, and it is the field the refusal assertions read.
        #
        # This is still reported as an ERROR, not a FAIL: it happens in the
        # setup phase, and pytest files everything that happens there as an
        # error regardless of how it is raised. Establishing the tunnel is
        # this fixture's whole purpose, so that is the accurate bucket — the
        # tests that assert on *how* a DUT refuses build their own client.
        pytest.fail(
            f"The proxy DUT did not establish the tunnel: {exc} "
            f"(it reported: {getattr(exc, 'details', None)!r})"
        )
    except OSError as exc:  # ConnectionError is an OSError
        pytest.fail(
            f"Could not establish a tunnel through the proxy DUT at "
            f"{proxy_config.dial_target[0]}:{proxy_config.dial_target[1]} "
            f"to origin {proxy_config.backend_host}:{proxy_config.backend_port} — {exc}. "
            "Is the DUT running, and is the backend instance (`netstack-cli proxy-serve`) up?"
        )
    yield client
    client.close()
