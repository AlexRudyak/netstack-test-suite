# RFC coverage matrix

| RFC | Clause | Test | Notes |
|---|---|---|---|
| RFC 791 | §3.1 header fields | `tests/ip/test_ip_header_validation.py` | TTL expiry, baseline round-trip |
| RFC 791 | §3.1 IHL minimum | `tests/ip/test_ip_malformed.py::test_invalid_ihl_is_discarded` | |
| RFC 791 | §3.1 header checksum | `tests/ip/test_ip_checksum.py::test_bad_ip_checksum_is_discarded` | |
| RFC 791 | §3.1 options (Record Route, NOP) | `tests/ip/test_ip_options.py` | |
| RFC 791 | §3.1 reserved flag bit | `tests/ip/test_ip_options.py::test_ip_reserved_flag_bit_is_ignored` | edge |
| RFC 791 | §3.2 fragmentation/reassembly | `tests/ip/test_ip_fragmentation.py::test_fragmented_icmp_echo_reassembles_correctly` | |
| RFC 791 | §3.2 (vuln: Teardrop) | `tests/ip/test_ip_fragmentation.py::test_overlapping_fragments_teardrop_do_not_crash_dut` | `vuln` |
| RFC 791 | max datagram size (vuln: Ping of Death) | `tests/ip/test_ip_malformed.py::test_oversized_reassembled_datagram_ping_of_death` | `vuln`, `slow` |
| RFC 792 | ICMP Time Exceeded | `tests/ip/test_ip_header_validation.py::test_ttl_expiry_generates_icmp_time_exceeded` | |
| RFC 792 | ICMP Echo/Reply | `tests/ip/test_ip_header_validation.py::test_icmp_echo_round_trip_baseline` | |
| RFC 792 | ICMP Port Unreachable | `tests/udp/test_udp_port_unreachable.py::test_closed_port_elicits_icmp_port_unreachable` | |
| RFC 792 | ICMP Echo/Reply (client) | `tests/icmp/test_icmp_echo.py::test_echo_request_elicits_reply` | |
| RFC 792 | ICMP Echo/Reply (server) | `tests/icmp/test_icmp_echo.py::test_server_responds_to_dut_echo` | `server` |
| RFC 792 | ICMP robustness | `tests/icmp/test_icmp_errors.py::test_truncated_icmp_does_not_crash_dut` | `vuln` |
| RFC 768 | length field | `tests/udp/test_udp_header_validation.py::test_udp_length_field_matches_payload` | |
| RFC 768 | checksum | `tests/udp/test_udp_header_validation.py::test_udp_datagram_reaches_dut_with_correct_checksum` | |
| RFC 768 | zero-checksum (optional) | `tests/udp/test_udp_header_validation.py::test_zero_checksum_datagram_is_accepted` | |
| RFC 768 | UDP client (server-role) | `tests/udp/test_udp_echo_server.py::test_dut_sends_udp_and_receives_echo` | `server` |
| RFC 768 | length/source-port edge cases | `tests/udp/test_udp_edge_cases.py` | edge |
| — (robustness) | payload edge cases | `tests/udp/test_udp_fuzzing.py::test_udp_survives_edge_case_payload_sizes` | `slow` |
| RFC 9293 | §3.5 three-way handshake (client) | `tests/tcp/syn/test_three_way_handshake.py` | |
| RFC 9293 | §3.5 handshake (server-role) | `tests/tcp/syn/test_server_handshake.py::test_dut_completes_handshake_it_initiated` | `server` |
| RFC 9293/6691 | §3.1 MSS option | `tests/tcp/syn/test_tcp_options.py::test_syn_with_mss_option_is_accepted` | |
| RFC 7323 | window scale, timestamps | `tests/tcp/syn/test_tcp_options.py` | |
| RFC 2018 | SACK-permitted option | `tests/tcp/syn/test_tcp_options.py::test_syn_with_sack_permitted_option_is_accepted` | |
| RFC 9293 | §3.1 unknown option ignored | `tests/tcp/syn/test_tcp_options.py::test_syn_with_unknown_option_is_ignored` | edge |
| RFC 6528 | ISN unpredictability | `tests/tcp/syn/test_sequence_prediction.py` | |
| — (hardening) | invalid flag combos | `tests/tcp/syn/test_invalid_syn_flags.py` | SYN+FIN, SYN+RST, NULL, Xmas |
| — (vuln) | SYN flood / backlog exhaustion | `tests/tcp/syn/test_syn_flood.py` | `vuln`, `slow` |
| RFC 9293 | §3.6 FIN handling | `tests/tcp/state_machine/test_connection_termination.py` | |
| RFC 9293 | §3.5.2, §3.10.7.1 RST handling | `tests/tcp/state_machine/test_rst_handling.py` | |
| RFC 5961 | §3 out-of-window RST ignored | `tests/tcp/state_machine/test_rst_edge_cases.py::test_out_of_window_rst_is_ignored` | edge/security |
| RFC 9293 | §3.5.3 simultaneous close | `tests/tcp/state_machine/test_simultaneous_open_close.py` | representative case only |
| RFC 9293 | §3.7.1 flow control window | `tests/tcp/congestion/test_window_scaling.py` | informational, vs. `target_profile` |
| RFC 9293 | §3.8.6 zero window | `tests/tcp/congestion/test_zero_window.py` | client + server |
| RFC 1122 | §4.2.2.17 persist timer | `tests/tcp/congestion/test_zero_window.py::test_zero_window_persist_probe_from_dut` | `server`, `slow` |
| RFC 6298 | retransmission timer | `tests/tcp/congestion/test_retransmission_timeout.py` | `slow` |
| RFC 5681 | slow start | `tests/tcp/congestion/test_slow_start.py` | **skipped placeholder** — see module docstring |

This is the representative sample scaffolded per module, not exhaustive
coverage of any of these RFCs — each test file's own docstring and the
module `README.md` note where a fuller implementation would extend.
