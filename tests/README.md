# tests/ — automated RFC/vulnerability suite

Requires a live DUT and Ethernet interface. For framework self-validation
that runs with no DUT at all, see [`../tests_internal/`](../tests_internal/README.md).

| Module | Scope |
|---|---|
| [`ip/`](ip/README.md) | RFC 791 IP layer: header fields, checksum, TTL, fragmentation, malformed/oversized datagrams |
| [`udp/`](udp/README.md) | RFC 768 UDP layer: header fields, checksum (incl. zero-checksum), port-unreachable, payload robustness, echo server |
| [`icmp/`](icmp/README.md) | RFC 792 ICMP: echo/reply (client + server), malformed robustness |
| [`tcp/`](tcp/README.md) | RFC 9293 TCP layer, split into `syn/`, `state_machine/`, `congestion/` |

## Roles (client / server)

Every test declares which role(s) it runs in via the `client` / `server`
markers, and `--role` selects one (default `client`); non-matching tests
are skipped at collection time.

- **client** — the suite initiates (sends probes) and validates the DUT's
  *responder* behavior. The classic mode; a test with no role marker
  defaults to client.
- **server** — the suite responds and the DUT initiates, validating the
  DUT's *client* behavior (it connects to us, sends data, pings us). Built
  on [`src/packet_engine/responder.py`](../src/packet_engine/README.md#responderpy).

```bash
netstack-cli run --role client --iface eth0 --dut-ip 10.0.0.5 --target-stack linux
netstack-cli run --role server --module tcp --submodule syn --iface eth0 --dut-ip 10.0.0.5 --target-stack linux
```

Server-role tests currently cover the TCP handshake
(`tcp/syn/test_server_handshake.py`), UDP echo
(`udp/test_udp_echo_server.py`), and ICMP echo
(`icmp/test_icmp_echo.py::test_server_responds_to_dut_echo`).

## Required options

Every test here needs a DUT target, supplied via pytest CLI options
registered in the root [`conftest.py`](../conftest.py):

```bash
pytest tests/ \
  --target-stack linux \
  --dut-ip 10.0.0.5 \
  --dut-iface eth0 \
  --payload-mode random
```

`--target-stack` selects which [target profile](../src/target_profiles/)
(informational baseline for implementation-defined behavior) tests
compare stack-characteristic values against — independent of whichever
OS this suite itself is running on (see [docs/architecture.md](../docs/architecture.md)).

`vuln`-marked tests additionally require `--allowed-targets <CIDR>` and
`--confirm-vuln-tests` (see [src/utils/safety.py](../src/utils/safety.py)).

Normally you won't invoke pytest directly — use `netstack-cli run` or the
GUI, which construct this command line for you (see the root
[README.md](../README.md)).

## Shared fixtures (what a test requests)

Registered in the root [`conftest.py`](../conftest.py), the suite
[`tests/conftest.py`](conftest.py), and the TCP
[`tests/tcp/conftest.py`](tcp/conftest.py):

| Fixture | Scope | Provides |
|---|---|---|
| `dut_config` | session | `DUTConfig` — fails fast if `--dut-ip`/`--dut-iface`/`--target-stack` are missing |
| `target_profile` | session | The selected [`TargetProfile`](../src/target_profiles/README.md) |
| `network_interface` | session | Open [`NetworkInterface`](../src/packet_engine/README.md#interfacepy) (checks privileges, wires pcap + debug-log + live-event feed) |
| `payload` | function | Resolved payload bytes for the active `--payload-mode`/`--payload-size` |
| `payload_settings` | session | `{mode, size, custom}` for tests that resolve payloads themselves |
| `confirm_vuln_tests` | session | Whether `--confirm-vuln-tests` was passed |
| `local_mac` / `local_ip` | session | The interface's own MAC/IP |
| `dut_mac` | session | DUT MAC (broadcast fallback if `--dut-mac` unset) |
| `host_platform` | session | `platform.system()` of the runner host |
| `established_tcp_connection` | function | A `TCPConnection` past a completed handshake (TCP `state_machine`/`congestion` tests) |

## pytest options

`--target-stack`, `--dut-ip`, `--dut-iface`, `--dut-mac`,
`--dut-port` (omitted ⇒ one random ephemeral port for the session, chosen
once in the session-scoped `dut_config` fixture),
`--dut-source-port` (optional fixed local source port; default per-test),
`--payload-mode`, `--payload-size`, `--payload-text/-hex/-file`,
`--allowed-targets` (repeatable), `--confirm-vuln-tests`,
`--live-events-log`, `--capture-pcap`, `--debug-log`. All are optional so
`tests_internal/` runs standalone; DUT-facing tests fail fast via
`dut_config` when the required ones are absent.

## Markers

`ip`, `udp`, `tcp`, `icmp`, `syn`, `state_machine`, `congestion`, `vuln`,
`slow`, `client`, `server`, `internal` (registered in
[`pyproject.toml`](../pyproject.toml)).

Per-test descriptions and RFC mappings live in the machine-readable
catalog ([`src/catalog.py`](../src/catalog.py)), which drives the GUI's
per-test detail panel and is drift-checked against the actual test
functions by `tests_internal/test_catalog.py`.
