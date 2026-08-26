# tests/tcp/syn — TCP connection establishment

This submodule is the structural reference implementation for the rest
of the suite — every other test module follows the same shape (builders
+ NetworkInterface + target_profile/payload fixtures, one assertion tied
to one RFC clause or vulnerability class per test).

## Files

| File | RFC clause(s) | What it tests |
|---|---|---|
| `test_three_way_handshake.py` | RFC 9293 §3.5 | SYN → SYN-ACK; full handshake reaches ESTABLISHED (no stray RST) |
| `test_syn_flood.py` | — (vulnerability) | Connection table / backlog survives a SYN flood (`vuln`, `slow`) |
| `test_sequence_prediction.py` | RFC 6528 | ISN is not fixed or linearly incrementing across samples |
| `test_invalid_syn_flags.py` | — (hardening) | SYN+FIN, SYN+RST, NULL scan, Xmas scan never establish a connection |

## Test functions

| Test | Asserts |
|---|---|
| `test_syn_elicits_syn_ack` | A SYN to an open port is answered with SYN-ACK. |
| `test_full_handshake_completes_and_ack_is_accepted` | SYN → SYN-ACK → ACK reaches ESTABLISHED (no stray RST on a follow-up segment). |
| `test_syn_flood_does_not_exhaust_connection_table` *(vuln, slow)* | After 500 half-open SYNs, a legitimate handshake still completes. |
| `test_isn_is_not_fixed_or_linearly_incrementing` | Across 20 samples, ISNs are neither constant nor constant-delta (RFC 6528). |
| `test_contradictory_flag_combination_does_not_establish_connection[...]` | Parametrized over SYN+FIN, SYN+RST, NULL, Xmas — none yields a bare SYN-ACK. |
| `test_syn_with_mss_option_is_accepted` | A SYN carrying an MSS option still gets a SYN-ACK (RFC 6691). |
| `test_syn_with_window_scale_option_is_accepted` | A SYN with a Window Scale option is accepted (RFC 7323 §2). |
| `test_syn_with_timestamp_option_is_accepted` | A SYN with a Timestamps option is accepted (RFC 7323 §3). |
| `test_syn_with_sack_permitted_option_is_accepted` | A SYN with the SACK-Permitted option is accepted (RFC 2018). |
| `test_syn_with_combined_options_is_accepted` | A realistic MSS+SACK+TS+NOP+WScale option list is parsed and establishes. |
| `test_syn_with_unknown_option_is_ignored` | An unknown option kind is skipped via its length field (still SYN-ACK) — RFC 9293 §3.1 edge case. |
| `test_dut_completes_handshake_it_initiated` *(server)* | SERVER role: the DUT connects to us; we SYN-ACK; validate the DUT completes with an ACK. |

## Markers

`tcp`, `syn`, plus `vuln`/`slow` on `test_syn_flood.py` (see [../../ip/README.md](../../ip/README.md) for the safety-gate mechanics, identical here).

## Running

```bash
netstack-cli run --module tcp --submodule syn --iface eth0 --dut-ip 10.0.0.5 --target-stack linux

# Single test:
netstack-cli run --test test_syn_elicits_syn_ack --iface eth0 --dut-ip 10.0.0.5 --target-stack linux

# Including the flood test:
netstack-cli run --module tcp --submodule syn --iface eth0 --dut-ip 10.0.0.5 --target-stack linux \
  --allowed-target 10.0.0.5/32 --confirm-vuln-tests
```
