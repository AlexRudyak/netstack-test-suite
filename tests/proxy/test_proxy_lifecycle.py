"""Connection lifecycle across the proxy (RFC 9293 §3.6).

A proxy bridges two independent TCP connections, so it is responsible for
propagating shutdown from one leg to the other. TCP's half-close (RFC 9293
§3.6) means a FIN closes only the sender's direction — the reverse
direction must keep working until the peer closes too. A proxy that tears
down both legs on the first FIN breaks half-duplex protocols; one that
never propagates the FIN leaks connections on the origin.
"""
from __future__ import annotations

import pytest

pytestmark = [pytest.mark.proxy]


def test_client_half_close_propagates_and_returns_eof(proxy_client) -> None:
    """Our FIN must reach the origin, whose own close must come back to us.

    RFC 9293 §3.6: after we send FIN we may still receive. The origin
    (backend instance) mirrors the shutdown, so a conformant proxy relays
    that FIN back and we observe a clean EOF rather than a hang or RST.
    """
    proxy_client.send(b"last-write")
    assert proxy_client.recv_exact(len(b"last-write")) == b"last-write"

    proxy_client.half_close()
    trailing = proxy_client.read_until_eof()
    assert trailing == b"", (
        "Expected a clean EOF after half-closing (the origin's FIN relayed back), "
        f"but received {trailing!r}. The DUT may not be propagating shutdown."
    )


def test_data_sent_before_close_is_fully_flushed(proxy_client) -> None:
    """Bytes written immediately before FIN must not be discarded.

    A proxy that closes the origin leg on FIN without flushing what it has
    already buffered silently truncates the stream.
    """
    payload = b"flush-me-" + b"z" * 4096
    proxy_client.send(payload)
    echoed = proxy_client.recv_exact(len(payload))
    assert echoed == payload

    proxy_client.half_close()
    assert proxy_client.read_until_eof() == b""
