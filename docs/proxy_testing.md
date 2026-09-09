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

## 3. Run *all* the other tests against the proxy too — `--proxy-leg`

The relay tests above use real sockets, because the DUT *terminates* TCP on
both legs, so they say nothing about how it builds and parses packets. The
ordinary IP/ICMP/UDP/TCP suites do exactly that — and a proxy has two stacks
that both deserve them.

`--proxy-leg` points the whole existing suite at one side of the proxy:

| Leg | The proxy is… | Suite runs as | Aimed at |
|---|---|---|---|
| `front` | a **server** | client (initiates) | the proxy's client-facing address |
| `back` | a **client** | server (responds) | the proxy's origin-facing address |

The leg determines the role — you probe a front as a client and observe a
back as a server — so it **overrides `--role`** rather than making you keep
the two in sync.

### Front leg — probe the proxy's client-facing stack

Retargets automatically to `--proxy-host`/`--proxy-port`, so `--dut-ip` can
stay pointed at whatever you normally use:

```bash
netstack-cli run --iface eth0 --dut-ip 10.0.0.5 --target-stack linux \
  --proxy-leg front --proxy-host 10.0.0.5 --proxy-port 1080
```

Every client-role test now applies: TTL expiry, IP options, header and
checksum validation, the three-way handshake, TCP options and MSS, invalid
flag combinations, RST handling, zero-window behavior, retransmission
timing, and the vuln-marked SYN-flood/land probes.

Note the port: on the front leg the default "random ephemeral port" would
only ever measure *closed*-port behavior, so an unset `--dut-port` falls
back to the proxy's front port, which is the one you know is open.

### Back leg — observe the stack it dials origins with

Aim `--dut-ip` at the proxy's origin-facing address:

```bash
netstack-cli run --iface eth1 --dut-ip 198.51.100.4 --target-stack linux \
  --proxy-leg back \
  --proxy-mode socks5 --proxy-host 10.0.0.5 --proxy-port 1080 \
  --backend-host 198.51.100.9 --backend-port 9099
```

There is a catch that front-leg runs don't have: **a proxy's back leg is
idle unless something is driving its front.** The server-role tests wait for
the DUT to initiate — an endpoint does that on its own, a proxy does not. So
a back-leg run starts a background *traffic inducer* for the session
(`src/proxy/inducer.py`), which keeps opening connections through the front
so the proxy keeps dialling out. That is why the back leg requires
`--proxy-mode` and `--backend-host`, and why the run refuses to start
without them — otherwise every test would simply time out with no
explanation. At the end of the run the inducer reports what it managed:

```
[proxy-leg back] induced 42/42 connections through the proxy
```

If that says `0/…`, nothing reached the origin and every server-role
failure in the run has the same root cause.

In the GUI, set **Proxy leg** in the DUT configuration group (with **Proxy
front**/**Proxy backend** filled in) and run any part of the test tree.

### Which suites are meaningful on which leg

| Suite | Front leg | Back leg |
|---|---|---|
| `ip` (TTL, options, header/checksum validation) | yes — the proxy answers as a server | partly: only what it emits outbound is observable |
| `icmp` (echo, unreachable, TTL exceeded) | yes | yes, when the DUT's origin-side stack sources ICMP |
| `udp` | only if the DUT proxies UDP | only if the DUT proxies UDP |
| `tcp/syn`, `tcp/state_machine` | yes — its listener is exercised directly | yes — its outbound handshakes are observed |
| `tcp/congestion` (window, retransmit) | yes | yes |
| `proxy` (relay/tunnel) | run with `--proxy-mode`, not a leg | same |

## Not yet covered

- **UDP relay** — `proxy-serve --udp` runs a UDP echo responder, but the
  SOCKS5 `UDP ASSOCIATE` flow and its per-datagram request header
  (RFC 1928 §7) are not implemented, so there is no UDP proxy test yet.
- **Proxy authentication** — the client can offer username/password
  (RFC 1929) and the code path is implemented, but there is no test that
  asserts a DUT *requires* it.
