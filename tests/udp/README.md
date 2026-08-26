# tests/udp — UDP (RFC 768) conformance

## Files

| File | RFC clause(s) | What it tests |
|---|---|---|
| `test_udp_header_validation.py` | RFC 768 | Length field correctness; checksum acceptance round-trip |
| `test_udp_port_unreachable.py` | RFC 792 | ICMP Port Unreachable for datagrams to closed ports |
| `test_udp_fuzzing.py` | — (robustness) | Survives edge-case payload sizes (0 .. 65507 bytes) without crashing |

## Test functions

| Test | Asserts |
|---|---|
| `test_udp_length_field_matches_payload` | The builder's `UDP.len` equals `8 + len(payload)` (checked after serialization — the field is computed lazily). |
| `test_udp_datagram_reaches_dut_with_correct_checksum` | A correctly-checksummed datagram produces *some* response (not silently dropped in checksum validation). |
| `test_closed_port_elicits_icmp_port_unreachable` | A datagram to a closed port elicits ICMP Destination Unreachable, code 3. |
| `test_zero_checksum_datagram_is_accepted` | A checksum=0 (checksum-disabled) datagram is still processed, per RFC 768's optional checksum. |
| `test_udp_survives_edge_case_payload_sizes[N]` *(slow)* | Parametrized over `{0,1,512,1472,65507}`; DUT stays responsive after each. |
| `test_dut_sends_udp_and_receives_echo` *(server)* | SERVER role: waits for the DUT to send a datagram, echoes it, validates the DUT initiated. |
| `test_udp_length_below_minimum_is_discarded` | A UDP length field below the 8-byte minimum is discarded without crashing (RFC 768 edge case). |
| `test_udp_source_port_zero_is_handled` | Source port 0 (valid, 'no reply port') is processed without crashing (RFC 768 edge case). |

## Markers

`udp`, plus `slow` on the fuzzing sweep (5 payload sizes × liveness check each).

## Running

```bash
netstack-cli run --module udp --iface eth0 --dut-ip 10.0.0.5 --target-stack linux
```
