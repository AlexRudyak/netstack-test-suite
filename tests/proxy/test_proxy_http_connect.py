"""HTTP CONNECT tunnel conformance — RFC 9110 §9.3.6, RFC 9112.

Exercises the DUT's **server** side: it must parse an authority-form
CONNECT request, establish the tunnel to the origin, and answer with a
2xx — after which it forwards octets blindly in both directions.

Only runs with --proxy-mode=http-connect.
"""
from __future__ import annotations

import dataclasses

import pytest

from src.proxy.client import ProxyClient, ProxyTunnelError

pytestmark = [pytest.mark.proxy]


def test_connect_request_establishes_tunnel_with_2xx(http_connect_config) -> None:
    """RFC 9110 §9.3.6: a 2xx response to CONNECT establishes the tunnel."""
    with ProxyClient(http_connect_config) as client:
        response = client.details.http_response
        assert response is not None, "no CONNECT response was captured"
        assert response.tunnel_established, (
            f"proxy answered CONNECT with {response.status} {response.reason} — "
            "RFC 9110 §9.3.6 requires 2xx to establish the tunnel"
        )
        # The tunnel must actually carry data once established.
        assert client.roundtrip(b"post-connect") == b"post-connect"


def test_2xx_connect_response_omits_framing_headers(http_connect_config) -> None:
    """RFC 9110 §9.3.6: a server MUST NOT send Content-Length or
    Transfer-Encoding in a 2xx response to CONNECT — the tunnel has no
    message body, and framing headers would desynchronise the stream."""
    with ProxyClient(http_connect_config) as client:
        response = client.details.http_response
        assert response is not None
        assert "content-length" not in response.headers, (
            "2xx CONNECT response carried Content-Length (forbidden by RFC 9110 §9.3.6)"
        )
        assert "transfer-encoding" not in response.headers, (
            "2xx CONNECT response carried Transfer-Encoding (forbidden by RFC 9110 §9.3.6)"
        )


def test_connect_to_unreachable_origin_is_not_reported_as_success(
    http_connect_config, closed_origin_port: int
) -> None:
    """A tunnel the proxy could not establish must not be answered 2xx.

    RFC 9110 §9.3.6: the proxy only sends 2xx once the connection to the
    request target is established; a failure is reported with an
    appropriate error status (commonly 502/504).
    """
    unreachable = dataclasses.replace(http_connect_config, backend_port=closed_origin_port)
    client = ProxyClient(unreachable)
    try:
        with pytest.raises((ProxyTunnelError, OSError)) as exc_info:
            client.connect()
    finally:
        client.close()

    if isinstance(exc_info.value, ProxyTunnelError):
        response = client.details.http_response
        assert response is not None and not response.tunnel_established
        assert response.status >= 400, (
            f"proxy reported an unreachable origin with status {response.status}; "
            "expected a 4xx/5xx error status"
        )
