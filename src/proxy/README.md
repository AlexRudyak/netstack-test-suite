# src/proxy — proxy-DUT testing

Machinery for testing a DUT that **relays** traffic instead of terminating
it. A proxy has two legs and plays a different role on each, so the suite
tests it with **two instances**: one drives traffic into the front, the
other stands in as the origin. See
[`docs/proxy_testing.md`](../../docs/proxy_testing.md).

## Modules

| Module | Responsibility |
|---|---|
| `config.py` | `ProxyMode`, `ProxyConfig` — topology and which handshake to speak |
| `tunnel.py` | RFC-exact HTTP CONNECT and SOCKS5 wire formats (pure functions) |
| `backend.py` | `EchoBackend` — the *server instance*: echoes what the proxy relays |
| `client.py` | `ProxyClient` — the *client instance*: dials through the DUT and relays |
| `inducer.py` | `TrafficInducer` — keeps a proxy's back leg busy so the server-role suites have outbound connections to observe |

## Why ordinary sockets

The DUT terminates TCP on both legs, so a raw-scapy stateful echo server
would be fighting a real stack for no benefit. Here the goal is to be a
*correct peer* (RFC 9293) and check what comes back.

Packet-level conformance of the proxy's *own* stacks is covered separately,
by `--proxy-leg`: it aims the ordinary [`tests/`](../../tests/README.md)
suites at the proxy's front (probing it as a server) or back (observing it
as a client). See [`docs/proxy_testing.md`](../../docs/proxy_testing.md).

## config.py

| Symbol | Description |
|---|---|
| `ProxyMode` | `TRANSPARENT` (inline), `HTTP_CONNECT` (RFC 9110 §9.3.6), `SOCKS5` (RFC 1928). `.is_explicit` is True for the two that need an in-band handshake. |
| `ProxyConfig` | `mode`, `backend_host/port` (the origin the DUT must reach), `proxy_host/port` (the DUT front, explicit modes), `timeout`, optional `username`/`password`. Validates that explicit modes carry a front address. |
| `.dial_target` | Where the client opens its TCP connection — the front for explicit modes, the origin for transparent. |

## tunnel.py

Pure encoders/parsers, so the wire formats are verified against the RFCs in
unit tests without a socket or a DUT.

| Symbol | RFC | Description |
|---|---|---|
| `build_http_connect_request` | RFC 9112 §3.2.3, RFC 9110 §7.2 | Authority-form `CONNECT` with the mandatory `Host` header; brackets IPv6 literals. |
| `parse_http_connect_response` / `read_http_response_head` | RFC 9110 §9.3.6 | Status/headers; any 2xx establishes the tunnel. The reader stops exactly at CRLFCRLF so it can't swallow relayed payload. |
| `build_socks5_greeting` / `parse_socks5_method_selection` | RFC 1928 §3 | `VER, NMETHODS, METHODS` and the 2-byte selection. |
| `encode_socks5_address` / `build_socks5_request` | RFC 1928 §4 | `ATYP` + address + 2-byte port; IPv4/IPv6/length-prefixed domain. |
| `read_socks5_reply` | RFC 1928 §6 | Variable-length reply; `SOCKS5_REPLY_MESSAGES` maps `REP` codes to their RFC text. |
| `build_socks5_userpass_auth` / `parse_socks5_userpass_result` | RFC 1929 §2 | Username/password subnegotiation (note: version byte `0x01`, not `0x05`). |

## backend.py

`EchoBackend(host, port, *, enable_udp=False, on_event=None)` — threaded TCP
(and optional UDP) echo server; context manager; binds port 0 for an
ephemeral port. `BackendStats` counts connections, bytes in/echoed and
records peers — the visible proof the DUT's client leg dialled out. On peer
half-close it mirrors the shutdown so a conformant proxy propagates it
(RFC 9293 §3.6).

## client.py

`ProxyClient(config)` — `connect()` dials and performs the mode's handshake;
`roundtrip(payload)` sends and reads back the same byte count;
`half_close()` / `read_until_eof()` drive the lifecycle tests.
`ProxyTunnelError` carries the DUT's own refusal text (HTTP status, or the
RFC 1928 `REP` message). `TunnelDetails` exposes the negotiated fields so
tests can assert on RFC specifics rather than just success.

## inducer.py

`TrafficInducer(config, *, interval=0.25, payload=b"netstack-induce")` —
a background thread that repeatedly opens connections through the proxy.

It exists for one asymmetry: the server-role tests wait for the DUT to
initiate. An endpoint DUT does that by itself; a **proxy only dials its
origin while a client is driving its front**. So a `--proxy-leg back` run
starts an inducer for the session (autouse fixture in
[`tests/conftest.py`](../../tests/conftest.py)) and the proxy keeps opening
outbound connections for those tests to observe.

`start()`/`stop()` or use it as a context manager. Failures are **counted,
not raised** — a proxy refusing or an unreachable origin is a DUT result
that the test's own assertions should report, not an inducer error.
`attempts`, `successes`, `last_error` and `summary()` make that visible:
`induced 0/40 connections through the proxy` tells you at a glance that
every server-role failure in the run shares one root cause.
