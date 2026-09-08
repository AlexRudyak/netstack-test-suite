# tests/proxy — proxy-DUT conformance

Tests a DUT that **relays** traffic rather than terminating it. Requires
**two instances** of the app — see
[`docs/proxy_testing.md`](../../docs/proxy_testing.md) for the full setup.

```
[this instance: client] --front--> [ PROXY DUT ] --back--> [backend instance]
```

The backend instance (`netstack-cli proxy-serve`, or the GUI's **Proxy
Backend** tab) echoes whatever the proxy relays; these tests verify the
round-trip. One successful round-trip proves the DUT accepted the front
connection (**server** side), dialled the origin (**client** side), and
relayed faithfully both ways.

## Test functions

| Test | Mode | RFC | Checks |
|---|---|---|---|
| `test_proxy_relays_payload_round_trip` | all | RFC 9293 §3.5, §3.7 | A unique payload survives client → DUT → origin → DUT → client. |
| `test_proxy_relay_is_eight_bit_clean` | all | RFC 9110 §9.3.6 | Every octet 0x00–0xFF, embedded CRLF and a fake `CONNECT` line pass through unaltered. |
| `test_proxy_relays_payload_larger_than_one_segment` | all | RFC 9293 §3.7 | 128 KiB arrives intact and in order across both legs. |
| `test_proxy_relays_successive_exchanges_on_one_connection` | all | RFC 9293 §3.7 | Repeated exchanges don't desynchronise the stream. |
| `test_client_half_close_propagates_and_returns_eof` | all | RFC 9293 §3.6 | FIN reaches the origin; the origin's close returns as a clean EOF. |
| `test_data_sent_before_close_is_fully_flushed` | all | RFC 9293 §3.6 | Bytes written just before FIN are not truncated. |
| `test_connect_request_establishes_tunnel_with_2xx` | http-connect | RFC 9110 §9.3.6, RFC 9112 §3.2.3 | Authority-form CONNECT answered 2xx, tunnel carries data. |
| `test_2xx_connect_response_omits_framing_headers` | http-connect | RFC 9110 §9.3.6 | No `Content-Length`/`Transfer-Encoding` on a 2xx CONNECT. |
| `test_connect_to_unreachable_origin_is_not_reported_as_success` | http-connect | RFC 9110 §9.3.6 | Closed origin → error status, never a false 2xx. |
| `test_socks5_negotiation_and_connect_succeed` | socks5 | RFC 1928 §3, §4, §6 | Method selection then `REP=0x00`, tunnel relays. |
| `test_socks5_never_selects_an_unoffered_method` | socks5 | RFC 1928 §3 | Server picks only from the offered methods. |
| `test_socks5_connect_to_closed_origin_returns_failure_reply` | socks5 | RFC 1928 §6 | Closed origin → non-zero, RFC-defined `REP`. |

Mode-specific tests skip automatically when `--proxy-mode` doesn't match;
the whole module skips when `--proxy-mode` is absent.

## Running

```bash
# instance 1 (server side)
netstack-cli proxy-serve --listen-host 0.0.0.0 --listen-port 9099

# instance 2 (client side)
netstack-cli run --module proxy --iface eth0 --dut-ip 10.0.0.5 --target-stack linux \
  --proxy-mode socks5 --proxy-host 10.0.0.5 --proxy-port 1080 \
  --backend-host 10.0.0.9 --backend-port 9099
```

## Why sockets here, not raw packets

A proxy *terminates* TCP on both legs, so relay conformance is about what
the DUT does with the byte stream. These tests use ordinary sockets so the
DUT faces a correct TCP peer. To exercise the proxy's front TCP stack at
the packet level, point the existing [`tests/tcp`](../tcp/README.md) suite
at the proxy's front address — no proxy options needed.
