# tests/ip — IP (RFC 791) conformance

Tests the DUT's IP layer: header field handling, TTL, fragmentation and
reassembly, and malformed/oversized-datagram handling. Scope is strictly
L3 — no transport-layer assumptions.

## Files

| File | RFC clause(s) | What it tests |
|---|---|---|
| `test_ip_header_validation.py` | RFC 791 §3.1, RFC 792 | TTL expiry → ICMP Time Exceeded; baseline echo round-trip |
| `test_ip_fragmentation.py` | RFC 791 §3.2 | Multi-fragment reassembly; Teardrop-class overlapping fragments (`vuln`) |
| `test_ip_malformed.py` | RFC 791 §3.1 | Ping of Death (oversized reassembly, `vuln`, `slow`); invalid IHL discard |

## Test functions

| Test | Asserts |
|---|---|
| `test_ttl_expiry_generates_icmp_time_exceeded` | A TTL=1 datagram elicits ICMP Time Exceeded (type 11). |
| `test_icmp_echo_round_trip_baseline` | A well-formed echo request round-trips (type 0 reply) — sanity baseline before malformed-header tests. |
| `test_fragmented_icmp_echo_reassembles_correctly` | A payload split across multiple IP fragments is reassembled and answered. |
| `test_overlapping_fragments_teardrop_do_not_crash_dut` *(vuln)* | Overlapping-offset fragment pair doesn't crash the DUT — a plain ping still answers afterward. |
| `test_oversized_reassembled_datagram_ping_of_death` *(vuln, slow)* | Fragments summing past 65535 bytes are rejected, not fatal — liveness ping still answers. |
| `test_invalid_ihl_is_discarded` | A sub-minimum IHL packet is discarded without wedging the DUT. |
| `test_bad_ip_checksum_is_discarded` | A packet with a wrong IP header checksum is silently discarded (no reply); a good one still answers. |
| `test_ip_record_route_option_is_handled` | An echo with a Record Route IP option (larger IHL) is still processed (RFC 791 §3.1 options). |
| `test_ip_nop_option_padding_is_handled` | An echo padded with NOP IP options is processed normally. |
| `test_ip_reserved_flag_bit_is_ignored` | The reserved IP flag bit is ignored, not treated as an error (RFC 791 edge case). |

## Markers

- `ip` — applied to every test in this module.
- `vuln` — tests that send intentionally malformed/attack traffic; require `--confirm-vuln-tests` and an `--allowed-targets` CIDR match (see [src/utils/safety.py](../../src/utils/safety.py)).
- `slow` — long-running (e.g. many fragments).

## Running

```bash
netstack-cli run --module ip --iface eth0 --dut-ip 10.0.0.5 --target-stack linux
```

To include `vuln`-marked tests:

```bash
netstack-cli run --module ip --iface eth0 --dut-ip 10.0.0.5 --target-stack linux \
  --allowed-target 10.0.0.5/32 --confirm-vuln-tests
```

Or directly via pytest:

```bash
pytest tests/ip --target-stack linux --dut-ip 10.0.0.5 --dut-iface eth0
```
