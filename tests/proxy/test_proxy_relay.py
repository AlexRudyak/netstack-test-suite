"""Proxy relay fidelity — the DUT must forward bytes unchanged, both ways.

These are the headline two-instance tests. A successful round-trip proves
the DUT did all of the following:

1. accepted our connection on its front leg  (DUT as **server**, RFC 9293 §3.5)
2. dialled the origin on its back leg        (DUT as **client**, RFC 9293 §3.5)
3. relayed client→origin bytes faithfully
4. relayed origin→client bytes faithfully

A proxy is expected to be an octet-transparent relay: the payload it
delivers must be byte-identical to what was sent (RFC 9293 §3.7 reliable,
ordered delivery on each leg; for a CONNECT tunnel RFC 9110 §9.3.6 states
the proxy blindly forwards the octet stream in both directions).
"""
from __future__ import annotations

import os

import pytest

pytestmark = [pytest.mark.proxy]


def test_proxy_relays_payload_round_trip(proxy_client) -> None:
    """End-to-end: a unique payload survives client → DUT → origin → DUT → client."""
    payload = b"netstack-proxy-" + os.urandom(16).hex().encode("ascii")
    echoed = proxy_client.roundtrip(payload)
    assert echoed == payload, (
        "Payload came back altered through the proxy — the relay is not octet-transparent.\n"
        f"  sent:     {payload!r}\n  received: {echoed!r}"
    )


def test_proxy_relay_is_eight_bit_clean(proxy_client) -> None:
    """Every octet 0x00-0xFF must survive, including NUL, CR and LF.

    A proxy that scans or rewrites the stream (e.g. treats CRLF as a header
    boundary after the tunnel is established) corrupts binary traffic; RFC
    9110 §9.3.6 requires blind forwarding once a tunnel exists.
    """
    payload = bytes(range(256)) + b"\r\n\r\nCONNECT evil:1 HTTP/1.1\r\n\r\n" + b"\x00" * 32
    assert proxy_client.roundtrip(payload) == payload


def test_proxy_relays_payload_larger_than_one_segment(proxy_client) -> None:
    """A payload well beyond one MSS must be relayed intact and in order.

    Exercises the DUT's buffering/segmentation across both legs (RFC 9293
    §3.7 — the byte stream is reassembled in order regardless of how it is
    segmented).
    """
    payload = bytes(i % 251 for i in range(128 * 1024))
    assert proxy_client.roundtrip(payload) == payload


def test_proxy_relays_successive_exchanges_on_one_connection(proxy_client) -> None:
    """Several request/response exchanges must all survive on a single
    relayed connection — the DUT must not desynchronise the stream."""
    for index in range(8):
        payload = f"exchange-{index:02d}-".encode() + os.urandom(8)
        assert proxy_client.roundtrip(payload) == payload
