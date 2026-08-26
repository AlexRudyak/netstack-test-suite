"""Test catalog — the single source of truth for per-test metadata.

Each `TestSpec` records what a test is responsible for, the RFC clause it
maps to, and which role(s) (client/server) it runs in. This drives:

- the GUI's per-test description panel (title + description + RFC + roles),
- the RFC coverage documentation,
- a self-validation test that catches drift between the catalog and the
  actual test functions on disk (tests_internal/test_catalog.py).

Keep an entry here whenever you add a test. The self-test will fail if a
cataloged test doesn't exist (or a test file has functions missing from
the catalog), so the two can't silently diverge.
"""
from __future__ import annotations

from dataclasses import dataclass

from src.config import Role

CLIENT = (Role.CLIENT,)
SERVER = (Role.SERVER,)
BOTH = (Role.CLIENT, Role.SERVER)


@dataclass(frozen=True)
class TestSpec:
    module: str  # "ip" | "udp" | "tcp" | "icmp"
    submodule: str | None  # e.g. "syn" | "state_machine" | "congestion"
    file: str  # file stem, e.g. "test_ip_header_validation"
    test: str  # test function name (base name, without parametrization)
    title: str
    description: str
    rfc: str
    roles: tuple[Role, ...] = CLIENT
    markers: tuple[str, ...] = ()

    @property
    def rel_path(self) -> str:
        parts = ["tests", self.module]
        if self.submodule:
            parts.append(self.submodule)
        parts.append(self.file + ".py")
        return "/".join(parts)

    @property
    def nodeid(self) -> str:
        return f"{self.rel_path}::{self.test}"

    @property
    def role_labels(self) -> str:
        return ", ".join(r.value for r in self.roles)


CATALOG: list[TestSpec] = [
    # ---- IP (RFC 791) -----------------------------------------------------
    TestSpec(
        "ip", None, "test_ip_header_validation", "test_ttl_expiry_generates_icmp_time_exceeded",
        "TTL expiry → ICMP Time Exceeded",
        "Sends a datagram with TTL=1 and expects the hop that decrements it to zero to "
        "discard it and return an ICMP Time Exceeded (type 11), rather than forwarding it.",
        "RFC 791 §3.2, RFC 792", CLIENT, ("ip",),
    ),
    TestSpec(
        "ip", None, "test_ip_header_validation", "test_icmp_echo_round_trip_baseline",
        "Baseline echo round-trip",
        "Confirms a normally-formed packet with a correct checksum round-trips (ICMP echo → "
        "reply) before the malformed-header tests run. A sanity baseline, not an RFC edge case.",
        "RFC 792", CLIENT, ("ip",),
    ),
    TestSpec(
        "ip", None, "test_ip_fragmentation", "test_fragmented_icmp_echo_reassembles_correctly",
        "Fragment reassembly",
        "Splits an oversized ICMP payload into multiple IP fragments and verifies the DUT "
        "reassembles them before ICMP processing (proven by a valid echo reply).",
        "RFC 791 §3.2", CLIENT, ("ip",),
    ),
    TestSpec(
        "ip", None, "test_ip_fragmentation", "test_overlapping_fragments_teardrop_do_not_crash_dut",
        "Teardrop (overlapping fragments)",
        "Sends two IP fragments with overlapping offsets (the Teardrop attack). A hardened "
        "stack must discard the malformed pair rather than fault; proven by a follow-up ping.",
        "— (vulnerability: Teardrop)", CLIENT, ("ip", "vuln"),
    ),
    TestSpec(
        "ip", None, "test_ip_malformed", "test_oversized_reassembled_datagram_ping_of_death",
        "Ping of Death (oversized reassembly)",
        "Sends fragments whose reassembled size exceeds the 65535-byte IP maximum and verifies "
        "the DUT rejects them instead of overflowing a buffer / crashing.",
        "RFC 791 (max datagram size) — vulnerability", CLIENT, ("ip", "vuln", "slow"),
    ),
    TestSpec(
        "ip", None, "test_ip_malformed", "test_invalid_ihl_is_discarded",
        "Invalid IHL discard",
        "Sends a packet whose IHL is below the 20-byte minimum header and verifies it's "
        "discarded without wedging the DUT.",
        "RFC 791 §3.1", CLIENT, ("ip",),
    ),
    TestSpec(
        "ip", None, "test_ip_checksum", "test_bad_ip_checksum_is_discarded",
        "Bad IP header checksum discard",
        "Sends an IP packet with a deliberately wrong header checksum and verifies the DUT "
        "silently discards it (no reply), per RFC 791's mandatory header checksum.",
        "RFC 791 §3.1 (Header Checksum)", CLIENT, ("ip",),
    ),
    TestSpec(
        "ip", None, "test_ip_options", "test_ip_record_route_option_is_handled",
        "IP Record Route option",
        "Sends an echo carrying a Record Route IP option (larger IHL) and verifies the DUT uses "
        "IHL to locate the payload and still replies — rather than assuming a 20-byte header.",
        "RFC 791 §3.1 (Options)", CLIENT, ("ip",),
    ),
    TestSpec(
        "ip", None, "test_ip_options", "test_ip_nop_option_padding_is_handled",
        "IP NOP option padding",
        "Sends an echo padded with several No-Operation IP options and verifies it's processed "
        "normally.",
        "RFC 791 §3.1 (Options)", CLIENT, ("ip",),
    ),
    TestSpec(
        "ip", None, "test_ip_options", "test_ip_reserved_flag_bit_is_ignored",
        "Reserved IP flag bit ignored",
        "Sets the reserved high-order IP flag bit and verifies the DUT ignores it (still replies) "
        "rather than dropping the datagram.",
        "RFC 791 §3.1 (Flags) — edge case", CLIENT, ("ip",),
    ),
    # ---- UDP (RFC 768) ----------------------------------------------------
    TestSpec(
        "udp", None, "test_udp_header_validation", "test_udp_length_field_matches_payload",
        "UDP length field",
        "Local check that the builder sets the UDP length to 8 (header) + payload bytes, per "
        "RFC 768's Length field definition.",
        "RFC 768", CLIENT, ("udp",),
    ),
    TestSpec(
        "udp", None, "test_udp_header_validation", "test_udp_datagram_reaches_dut_with_correct_checksum",
        "UDP checksum acceptance",
        "Sends a correctly-checksummed datagram and expects a response (e.g. ICMP port "
        "unreachable), proving it wasn't dropped during checksum validation.",
        "RFC 768 (Checksum)", CLIENT, ("udp",),
    ),
    TestSpec(
        "udp", None, "test_udp_header_validation", "test_zero_checksum_datagram_is_accepted",
        "UDP zero-checksum (optional) accepted",
        "RFC 768 allows an all-zero checksum to mean 'no checksum computed'. Sends such a "
        "datagram and verifies the DUT still accepts and processes it.",
        "RFC 768 (Checksum optional)", CLIENT, ("udp",),
    ),
    TestSpec(
        "udp", None, "test_udp_port_unreachable", "test_closed_port_elicits_icmp_port_unreachable",
        "Closed port → ICMP Port Unreachable",
        "Sends a datagram to a port with no listener and expects ICMP Destination Unreachable, "
        "code 3 (Port Unreachable).",
        "RFC 792", CLIENT, ("udp",),
    ),
    TestSpec(
        "udp", None, "test_udp_fuzzing", "test_udp_survives_edge_case_payload_sizes",
        "Payload-size robustness",
        "Sends zero-fill payloads at boundary sizes (0, 1, 512, 1472, 65507 bytes) and verifies "
        "the DUT stays responsive after each.",
        "— (robustness)", CLIENT, ("udp", "slow"),
    ),
    TestSpec(
        "udp", None, "test_udp_echo_server", "test_dut_sends_udp_and_receives_echo",
        "SERVER: echo a DUT-sent datagram",
        "The suite acts as a UDP echo server: it waits for the DUT to send a datagram to it, "
        "echoes the payload back, and validates the DUT actually initiated the transfer.",
        "RFC 768", SERVER, ("udp",),
    ),
    TestSpec(
        "udp", None, "test_udp_edge_cases", "test_udp_length_below_minimum_is_discarded",
        "UDP length below minimum discarded",
        "Sends a datagram whose length field is below the 8-byte header minimum and verifies the "
        "DUT discards it without crashing (a follow-up datagram still gets a response).",
        "RFC 768 (Length) — edge case", CLIENT, ("udp",),
    ),
    TestSpec(
        "udp", None, "test_udp_edge_cases", "test_udp_source_port_zero_is_handled",
        "UDP source port 0",
        "Sends a datagram with source port 0 (valid, meaning 'no reply port') and verifies the "
        "DUT still processes it without crashing.",
        "RFC 768 (Source Port) — edge case", CLIENT, ("udp",),
    ),
    # ---- ICMP (RFC 792) ---------------------------------------------------
    TestSpec(
        "icmp", None, "test_icmp_echo", "test_echo_request_elicits_reply",
        "CLIENT: Echo Request → Reply",
        "The suite sends an ICMP Echo Request (type 8) to the DUT and expects a matching Echo "
        "Reply (type 0) with the same id/seq and payload.",
        "RFC 792 (Echo/Echo Reply)", CLIENT, ("icmp",),
    ),
    TestSpec(
        "icmp", None, "test_icmp_echo", "test_server_responds_to_dut_echo",
        "SERVER: answer a DUT-initiated ping",
        "The suite waits for the DUT to send it an Echo Request, replies with an Echo Reply, "
        "and validates the DUT initiated the ping — exercising the DUT's ping-client path.",
        "RFC 792 (Echo/Echo Reply)", SERVER, ("icmp",),
    ),
    TestSpec(
        "icmp", None, "test_icmp_errors", "test_truncated_icmp_does_not_crash_dut",
        "Truncated ICMP robustness",
        "Sends a malformed/truncated ICMP message and verifies the DUT discards it without "
        "crashing (proven by a follow-up echo still succeeding).",
        "RFC 792 — robustness", CLIENT, ("icmp", "vuln"),
    ),
    # ---- TCP / SYN (RFC 9293) --------------------------------------------
    TestSpec(
        "tcp", "syn", "test_three_way_handshake", "test_syn_elicits_syn_ack",
        "CLIENT: SYN → SYN-ACK",
        "The suite sends a SYN to an open port and expects the DUT to answer SYN-ACK.",
        "RFC 9293 §3.5", CLIENT, ("tcp", "syn"),
    ),
    TestSpec(
        "tcp", "syn", "test_three_way_handshake", "test_full_handshake_completes_and_ack_is_accepted",
        "CLIENT: full handshake to ESTABLISHED",
        "Completes SYN → SYN-ACK → ACK and confirms the connection reaches ESTABLISHED (no "
        "stray RST on a follow-up segment).",
        "RFC 9293 §3.5", CLIENT, ("tcp", "syn"),
    ),
    TestSpec(
        "tcp", "syn", "test_server_handshake", "test_dut_completes_handshake_it_initiated",
        "SERVER: accept a DUT-initiated connection",
        "The suite listens as a TCP server: it waits for the DUT to send a SYN, replies "
        "SYN-ACK, and validates the DUT completes the handshake with a final ACK — exercising "
        "the DUT's active-open (connect) path.",
        "RFC 9293 §3.5", SERVER, ("tcp", "syn"),
    ),
    TestSpec(
        "tcp", "syn", "test_tcp_options", "test_syn_with_mss_option_is_accepted",
        "MSS option handling",
        "Sends a SYN carrying a Maximum Segment Size option and verifies the DUT still "
        "establishes the connection (SYN-ACK), i.e. it parses TCP options rather than "
        "rejecting an optioned SYN.",
        "RFC 9293 §3.1, RFC 6691 (MSS)", CLIENT, ("tcp", "syn"),
    ),
    TestSpec(
        "tcp", "syn", "test_tcp_options", "test_syn_with_window_scale_option_is_accepted",
        "Window Scale option",
        "Sends a SYN with a Window Scale option (kind 3) and verifies the DUT accepts it "
        "(SYN-ACK), enabling windows beyond 64 KiB.",
        "RFC 7323 §2", CLIENT, ("tcp", "syn"),
    ),
    TestSpec(
        "tcp", "syn", "test_tcp_options", "test_syn_with_timestamp_option_is_accepted",
        "Timestamps option",
        "Sends a SYN with a TCP Timestamps option (kind 8) and verifies the DUT accepts it.",
        "RFC 7323 §3", CLIENT, ("tcp", "syn"),
    ),
    TestSpec(
        "tcp", "syn", "test_tcp_options", "test_syn_with_sack_permitted_option_is_accepted",
        "SACK-Permitted option",
        "Sends a SYN with the SACK-Permitted option (kind 4) and verifies the DUT accepts it.",
        "RFC 2018", CLIENT, ("tcp", "syn"),
    ),
    TestSpec(
        "tcp", "syn", "test_tcp_options", "test_syn_with_combined_options_is_accepted",
        "Combined options list",
        "Sends a realistic SYN with MSS + SACK-permitted + Timestamps + NOP padding + Window "
        "Scale together and verifies the DUT parses the whole list and still establishes.",
        "RFC 9293 §3.1, RFC 7323, RFC 2018", CLIENT, ("tcp", "syn"),
    ),
    TestSpec(
        "tcp", "syn", "test_tcp_options", "test_syn_with_unknown_option_is_ignored",
        "Unknown option ignored",
        "Sends a SYN with an unrecognised option kind and verifies the DUT skips it via its "
        "length field (still SYN-ACKs) rather than rejecting the segment.",
        "RFC 9293 §3.1 — edge case", CLIENT, ("tcp", "syn"),
    ),
    TestSpec(
        "tcp", "syn", "test_syn_flood", "test_syn_flood_does_not_exhaust_connection_table",
        "SYN flood resilience",
        "Sends a burst of un-ACKed SYNs (half-open connections) then verifies a legitimate "
        "handshake still completes — i.e. the backlog / SYN-cookie handling holds up.",
        "— (vulnerability: SYN flood)", CLIENT, ("tcp", "syn", "vuln", "slow"),
    ),
    TestSpec(
        "tcp", "syn", "test_sequence_prediction", "test_isn_is_not_fixed_or_linearly_incrementing",
        "ISN unpredictability",
        "Samples several SYN-ACK ISNs and checks they are neither constant nor incrementing by "
        "a fixed delta — the naive predictable-ISN vulnerability class.",
        "RFC 6528", CLIENT, ("tcp", "syn"),
    ),
    TestSpec(
        "tcp", "syn", "test_invalid_syn_flags", "test_contradictory_flag_combination_does_not_establish_connection",
        "Invalid flag combinations",
        "Sends SYN+FIN, SYN+RST, NULL, and Xmas flag combinations and verifies none of them are "
        "treated as a valid connection request (no bare SYN-ACK).",
        "— (hardening / scan resistance)", CLIENT, ("tcp", "syn"),
    ),
    # ---- TCP / state machine ---------------------------------------------
    TestSpec(
        "tcp", "state_machine", "test_connection_termination", "test_fin_is_acknowledged",
        "FIN acknowledgement",
        "Sends a FIN on an ESTABLISHED connection and verifies the DUT ACKs it (moving toward "
        "CLOSE-WAIT).",
        "RFC 9293 §3.6", CLIENT, ("tcp", "state_machine"),
    ),
    TestSpec(
        "tcp", "state_machine", "test_rst_handling", "test_ack_to_closed_port_elicits_rst",
        "RST for closed-port segment",
        "Sends a segment to a closed port and verifies the DUT answers with RST.",
        "RFC 9293 §3.10.7.1", CLIENT, ("tcp", "state_machine"),
    ),
    TestSpec(
        "tcp", "state_machine", "test_rst_handling", "test_established_connection_accepts_valid_rst",
        "Valid RST aborts connection",
        "Sends an in-window RST on an ESTABLISHED connection and verifies it's aborted "
        "(follow-up traffic is no longer acknowledged normally).",
        "RFC 9293 §3.5.2", CLIENT, ("tcp", "state_machine"),
    ),
    TestSpec(
        "tcp", "state_machine", "test_simultaneous_open_close", "test_fin_before_peer_fin_is_still_acknowledged",
        "Simultaneous-close ordering",
        "Sends our FIN before observing the DUT's FIN and verifies it's still ACKed — the DUT "
        "doesn't require a specific close ordering.",
        "RFC 9293 §3.5.3", CLIENT, ("tcp", "state_machine"),
    ),
    TestSpec(
        "tcp", "state_machine", "test_rst_edge_cases", "test_out_of_window_rst_is_ignored",
        "Out-of-window RST ignored",
        "Sends a RST with a sequence number well outside the receive window on an ESTABLISHED "
        "connection and verifies the DUT does NOT tear the connection down — blind RST "
        "acceptance enables off-path reset attacks.",
        "RFC 5961 §3 (also RFC 9293 §3.10.7.1)", CLIENT, ("tcp", "state_machine"),
    ),
    # ---- TCP / congestion -------------------------------------------------
    TestSpec(
        "tcp", "congestion", "test_window_scaling", "test_syn_ack_window_matches_target_stack_profile",
        "Advertised window vs. profile",
        "Compares the DUT's advertised receive window against the selected target-stack "
        "profile's reference range. Informational — a mismatch flags a stack-characteristic "
        "difference, not an RFC violation.",
        "RFC 9293 §3.7.1 (informational)", CLIENT, ("tcp", "congestion"),
    ),
    TestSpec(
        "tcp", "congestion", "test_retransmission_timeout", "test_unacked_syn_ack_is_retransmitted",
        "SYN-ACK retransmission",
        "Withholds the final ACK and verifies the DUT retransmits its SYN-ACK per the RFC 6298 "
        "retransmission timer.",
        "RFC 6298", CLIENT, ("tcp", "congestion", "slow"),
    ),
    TestSpec(
        "tcp", "congestion", "test_slow_start", "test_congestion_window_grows_across_initial_round_trips",
        "Slow start (placeholder)",
        "Placeholder — genuine cwnd-growth measurement needs a DUT-side data stream this "
        "generic harness can't trigger. Skipped; see the module docstring.",
        "RFC 5681", CLIENT, ("tcp", "congestion"),
    ),
    TestSpec(
        "tcp", "congestion", "test_zero_window", "test_zero_window_advertisement_does_not_break_connection",
        "Zero window advertisement",
        "Completes a handshake, advertises a zero receive window, and verifies the DUT treats it "
        "as a legal flow-control state (no RST) — it must stop sending, not abort.",
        "RFC 9293 §3.8.6", CLIENT, ("tcp", "congestion"),
    ),
    TestSpec(
        "tcp", "congestion", "test_zero_window", "test_window_reopen_after_zero_is_accepted",
        "Window reopen after zero",
        "After advertising a zero window, sends a window update reopening it and verifies the "
        "connection stays alive (no RST) — the DUT accepts window updates.",
        "RFC 9293 §3.8.6.2", CLIENT, ("tcp", "congestion"),
    ),
    TestSpec(
        "tcp", "congestion", "test_zero_window", "test_zero_window_persist_probe_from_dut",
        "SERVER: zero-window persist probe",
        "The suite accepts the DUT's connection but advertises a zero window in its SYN-ACK; a "
        "DUT with data to send must emit a zero-window (persist) probe rather than flooding or "
        "stalling. Requires the DUT to have data queued to send.",
        "RFC 1122 §4.2.2.17", SERVER, ("tcp", "congestion", "slow"),
    ),
]


def specs_for_rel_path(rel_path: str) -> list[TestSpec]:
    """All test specs defined in the given test file (posix rel path)."""
    normalized = rel_path.replace("\\", "/")
    return [s for s in CATALOG if s.rel_path == normalized]


def find_by_nodeid(nodeid: str) -> TestSpec | None:
    normalized = nodeid.replace("\\", "/")
    for spec in CATALOG:
        if spec.nodeid == normalized or normalized.endswith(spec.nodeid):
            return spec
    return None


def find_by_test(rel_path: str, test: str) -> TestSpec | None:
    normalized = rel_path.replace("\\", "/")
    for spec in CATALOG:
        if spec.rel_path == normalized and spec.test == test:
            return spec
    return None
