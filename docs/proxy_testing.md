# Testing a proxy DUT (two instances)

A proxy is not an endpoint — it has **two legs**, and it plays a different
role on each:

```
 [ client instance ] --front--> [  PROXY DUT  ] --back--> [ backend instance ]
   drives traffic               server │ client            echoes traffic
   (tests the DUT's                    │                   (receives what the
    SERVER side)                       │                    DUT dials out —
                                       │                    tests its CLIENT side)
```

So testing it needs **two instances of the app**: one drives traffic into
the front, the other stands in as the origin server the proxy dials out to.

## How the two instances agree without a side channel

They don't need one — the payload *is* the rendezvous:

1. the client instance sends a unique payload through the proxy,
2. the backend instance echoes whatever the proxy delivers,
3. the client verifies the bytes that come back are identical.

A successful round-trip proves, in one shot, that the DUT accepted the
front connection (**server** side), dialled the origin (**client** side),
and relayed faithfully in **both directions**.

## 1. Start the backend instance (the "server")

On the host the proxy is configured to forward to:

```bash
netstack-cli proxy-serve --listen-host 0.0.0.0 --listen-port 9099
```

Or open the GUI and use the **Proxy Backend** tab. Either way the live
counters show connections as the proxy dials in — that's your direct
evidence the DUT's client leg works.

No elevated privileges are needed on this side: the DUT terminates TCP
here, so the backend's job is to be a correct TCP peer (RFC 9293), not to
craft packets.

## 2. Run the proxy tests from the client instance

Pick the mode that matches your DUT:

| Mode | DUT type | Handshake |
|---|---|---|
| `transparent` | inline / intercepting | none — client dials the origin, DUT is in path |
| `http-connect` | explicit HTTP proxy | `CONNECT` (RFC 9110 §9.3.6, RFC 9112 §3.2.3) |
| `socks5` | explicit SOCKS proxy | RFC 1928 greeting → CONNECT → reply |

```bash
# Explicit SOCKS5 proxy
netstack-cli run --module proxy \
  --iface eth0 --dut-ip 10.0.0.5 --target-stack linux \
  --proxy-mode socks5 --proxy-host 10.0.0.5 --proxy-port 1080 \
  --backend-host 10.0.0.9 --backend-port 9099

# Explicit HTTP proxy
netstack-cli run --module proxy ... --proxy-mode http-connect \
  --proxy-host 10.0.0.5 --proxy-port 3128 --backend-host 10.0.0.9

# Inline / transparent proxy (no front address needed)
netstack-cli run --module proxy ... --proxy-mode transparent \
  --backend-host 10.0.0.9 --backend-port 9099
```

In the GUI, set **Proxy mode**, **Proxy front** and **Proxy backend** in the
DUT configuration group, then run the `proxy` module from the test tree.

Without `--proxy-mode` the proxy tests **skip** with a message pointing
here, so they never fail a normal endpoint run.

## What gets tested

| Area | Checks | RFC |
|---|---|---|
| Relay fidelity | round-trip echo, 8-bit clean, 128 KiB multi-segment, repeated exchanges | RFC 9293 §3.5, §3.7 |
| Lifecycle | half-close propagates both ways; data flushed before close | RFC 9293 §3.6 |
| HTTP CONNECT | 2xx establishes tunnel; no `Content-Length`/`Transfer-Encoding` on 2xx; unreachable origin is not 2xx | RFC 9110 §9.3.6, RFC 9112 §3.2.3 |
| SOCKS5 | greeting/method selection, CONNECT reply `REP=0x00`, only offered methods selected, failure codes for a closed origin | RFC 1928 §3, §4, §6 |

## Also test the front leg at packet level

The relay tests use real sockets, because the DUT *terminates* TCP on both
legs. To additionally validate the proxy's front TCP stack at the packet
level, point the ordinary endpoint suites at the proxy's front address —
they need no proxy-specific options:

```bash
netstack-cli run --module tcp --iface eth0 --dut-ip <proxy-front-ip> --target-stack linux
```

That reuses the existing SYN/handshake, invalid-flag, options and
state-machine tests against the proxy's server side.

## Not yet covered

- **UDP relay** — `proxy-serve --udp` runs a UDP echo responder, but the
  SOCKS5 `UDP ASSOCIATE` flow and its per-datagram request header
  (RFC 1928 §7) are not implemented, so there is no UDP proxy test yet.
- **Proxy authentication** — the client can offer username/password
  (RFC 1929) and the code path is implemented, but there is no test that
  asserts a DUT *requires* it.
