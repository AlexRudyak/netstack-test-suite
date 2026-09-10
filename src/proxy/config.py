"""Topology and mode configuration for proxy-DUT testing.

A proxy DUT has two legs, and the suite tests both by running **two
instances**:

    [client instance] --front--> [ PROXY DUT ] --back--> [backend instance]
     drives traffic                                        echoes traffic
     (exercises the DUT's                                  (exercises the DUT's
      SERVER side)                                          CLIENT side)

The two instances need no side channel: the client sends a unique payload,
the backend echoes whatever the proxy delivers, and the client verifies the
bytes that come back. A successful round-trip proves the proxy accepted the
front connection, dialled the backend, and relayed faithfully in both
directions.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

# Where the backend instance (`netstack-cli proxy-serve`, or the GUI's Proxy
# Backend tab) listens by default. Referenced by the CLI, the GUI and the
# pytest option defaults so the two instances agree without being told twice.
DEFAULT_BACKEND_PORT = 9099


class ProxyMode(Enum):
    """How the client instance reaches the origin through the DUT.

    - TRANSPARENT: an inline/intercepting proxy. The client dials the
      origin address directly and the DUT intercepts; both legs are plain
      TCP (RFC 9293), no in-band negotiation.
    - HTTP_CONNECT: an explicit HTTP proxy. The client dials the proxy and
      requests a tunnel with CONNECT (RFC 9110 §9.3.6, RFC 9112).
    - SOCKS5: an explicit SOCKS proxy. The client dials the proxy and
      negotiates with the SOCKS5 handshake (RFC 1928).
    """

    TRANSPARENT = "transparent"
    HTTP_CONNECT = "http-connect"
    SOCKS5 = "socks5"

    @property
    def is_explicit(self) -> bool:
        """True when the mode requires an in-band handshake with the proxy
        before the tunnel carries origin bytes."""
        return self is not ProxyMode.TRANSPARENT


@dataclass(frozen=True)
class ProxyConfig:
    """Addresses for a proxy test run.

    `backend_host`/`backend_port` is the origin the DUT must reach — i.e.
    where the *backend instance* (`netstack-cli proxy-serve`) is listening.
    `proxy_host`/`proxy_port` is the DUT's front, which the client dials for
    the explicit modes; in TRANSPARENT mode the client dials the origin and
    the DUT is inline, so the front address is not used.
    """

    mode: ProxyMode
    backend_host: str
    backend_port: int
    proxy_host: str | None = None
    proxy_port: int | None = None
    timeout: float = 5.0
    # SOCKS5 username/password auth (RFC 1929); None = offer "no auth" only.
    username: str | None = None
    password: str | None = None

    def __post_init__(self) -> None:
        if self.mode.is_explicit and not (self.proxy_host and self.proxy_port):
            raise ValueError(
                f"{self.mode.value} is an explicit proxy mode and needs "
                "proxy_host and proxy_port (the DUT's front address)."
            )

    @property
    def dial_target(self) -> tuple[str, int]:
        """Where the client instance opens its TCP connection.

        Explicit proxies: the DUT's front. Transparent: the origin itself
        (the DUT intercepts in path).
        """
        if self.mode.is_explicit:
            assert self.proxy_host is not None and self.proxy_port is not None
            return self.proxy_host, self.proxy_port
        return self.backend_host, self.backend_port

    @property
    def origin(self) -> tuple[str, int]:
        """The origin the tunnel must ultimately reach."""
        return self.backend_host, self.backend_port
