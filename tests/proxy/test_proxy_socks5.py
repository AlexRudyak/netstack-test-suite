"""SOCKS5 conformance — RFC 1928.

Exercises the DUT's **server** side: version/method negotiation (§3), the
CONNECT request (§4), and the reply format and codes (§6).

Only runs with --proxy-mode=socks5.
"""
from __future__ import annotations

import dataclasses

import pytest

from src.proxy import tunnel
from src.proxy.client import ProxyClient, ProxyTunnelError

pytestmark = [pytest.mark.proxy]


def test_socks5_negotiation_and_connect_succeed(socks5_config) -> None:
    """RFC 1928 §3/§4/§6: method selection, then CONNECT answered REP=0x00."""
    with ProxyClient(socks5_config) as client:
        assert client.details.socks_method == tunnel.AUTH_NONE, (
            f"proxy selected method 0x{client.details.socks_method:02x}; "
            "expected 0x00 (NO AUTHENTICATION REQUIRED)"
        )
        reply = client.details.socks_reply
        assert reply is not None
        assert reply.succeeded, (
            f"CONNECT reply REP=0x{reply.reply_code:02x} ({reply.message}); "
            "RFC 1928 §6 requires 0x00 on success"
        )
        # The negotiated tunnel must actually relay.
        assert client.roundtrip(b"post-socks5") == b"post-socks5"


def test_socks5_never_selects_an_unoffered_method(socks5_config) -> None:
    """RFC 1928 §3: the server selects one of the METHODS the client offered
    (or 0xFF). We offer only 0x00, so anything else is non-conformant."""
    with ProxyClient(socks5_config) as client:
        assert client.details.socks_method in (tunnel.AUTH_NONE,), (
            f"proxy selected method 0x{client.details.socks_method:02x}, which the client "
            "never offered (RFC 1928 §3)"
        )


def test_socks5_connect_to_closed_origin_returns_failure_reply(
    socks5_config, closed_origin_port: int
) -> None:
    """RFC 1928 §6: an origin that refuses the connection must be reported
    with a non-zero REP (0x05 'connection refused' is the specific code),
    never as success."""
    unreachable = dataclasses.replace(socks5_config, backend_port=closed_origin_port)
    client = ProxyClient(unreachable)
    try:
        with pytest.raises((ProxyTunnelError, OSError)):
            client.connect()
    finally:
        client.close()

    reply = client.details.socks_reply
    if reply is not None:  # proxy answered rather than dropping the connection
        assert not reply.succeeded, "proxy reported REP=0x00 for an origin that is not listening"
        assert reply.reply_code in tunnel.SOCKS5_REPLY_MESSAGES, (
            f"REP=0x{reply.reply_code:02x} is not a code defined in RFC 1928 §6"
        )
