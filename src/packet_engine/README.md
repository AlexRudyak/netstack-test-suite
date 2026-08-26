# src/packet_engine — packet crafting, wire I/O, capture

The lowest layer of the framework: builds L3/L4 packets, sends/receives
them over a real Ethernet interface, records the wire to pcap, generates
L7 payloads, and tracks TCP sequence state. Everything above
(`tests/`, `custom_packet/`, the CLI `record`) is a client of this
package.

**Scope is strictly L2 transport of L3/L4 packets** — no application
protocol awareness (no HTTP/DNS parsing). Payloads are opaque bytes.

## Modules

| Module | Responsibility |
|---|---|
| `builders.py` | Packet factories with RFC-sane defaults |
| `interface.py` | `NetworkInterface` — L2 send/receive/sniff + capture + hooks |
| `platform_backend.py` | Per-host-OS socket backend selection (Windows/Linux) |
| `payloads.py` | L7 payload modes: zeros / ones / random / custom |
| `recorder.py` | `PacketRecorder` — passive on-wire pcap capture |
| `sequence.py` | `TCPSequenceTracker` — local seq/ack bookkeeping |
| `preflight.py` | `run_preflight` — pre-run connectivity/privilege check |
| `responder.py` | Server-role primitives — reply to DUT-initiated traffic |

---

## builders.py

Packet factories. Each returns a Scapy `Packet`; `payload` (opaque bytes)
is attached via a `Raw()` layer only when non-empty.

| Function | Signature | Description |
|---|---|---|
| `build_ip` | `(src_ip, dst_ip, *, ttl=64, flags="", frag=0, proto=None, payload=b"") -> Packet` | Bare IP datagram — used directly by IP-layer tests (TTL, fragmentation, malformed). |
| `build_udp` | `(src_ip, dst_ip, src_port, dst_port, *, ttl=64, payload=b"") -> Packet` | IP/UDP. `UDP.len` is computed lazily by Scapy at serialization — round-trip through `bytes()` to read it. |
| `build_tcp` | `(src_ip, dst_ip, src_port, dst_port, *, flags="S", seq=None, ack=0, window=8192, ttl=64, payload=b"") -> Packet` | IP/TCP. `seq=None` lets Scapy pick a random ISN. |
| `wrap_ethernet` | `(l3_packet, src_mac, dst_mac) -> Packet` | Prefixes an `Ether` header — **required** before `sendp`/`srp1` since the suite operates at L2. |

Constants: `DEFAULT_TTL = 64`, `DEFAULT_WINDOW = 8192`.

## interface.py

`NetworkInterface` — a session-scoped wrapper around one interface. Raw
sockets are expensive to open, so construct once (the `network_interface`
fixture) and reuse. OS-agnostic: `platform_backend` handles the
Windows/Linux socket differences underneath.

Constructor: `NetworkInterface(iface, capture_path=None, on_packet=None, backend=None, debug_logger=None)`

| Method | Signature | Description |
|---|---|---|
| `send` | `(packet, *, test_nodeid=None) -> None` | `sendp` at L2; records the frame. |
| `send_receive` | `(packet, *, timeout=2.0, test_nodeid=None) -> Packet \| None` | `srp1` — send one, await one matching reply. Records both. |
| `sniff` | `(*, count=0, timeout=None, lfilter=None, test_nodeid=None) -> list[Packet]` | Passive capture with an optional predicate filter. |
| `.captured_count` | property `-> int` | Frames written to the pcap so far. |
| `close` | `() -> None` | Closes the pcap writer; also the context-manager exit. |

Every send/receive runs through a private `_record`, which (1) **streams**
the frame to a `PcapWriter` (opened lazily on the first packet when
`capture_path` is set — bounded memory, valid file even if interrupted),
(2) forwards to `debug_logger` if debug mode is on (raw packet → tshark
line), and (3) emits a `PacketEvent` to `on_packet` (the live-plot/GUI
feed). `_DEBUG_DIRECTION` maps `PacketDirection` → `TX`/`RX`.

## platform_backend.py

Selects the Scapy socket backend by **host** OS (auto-detected). Both
backends are **L2-only** — Windows L3 raw send is unreliable regardless
of Npcap, and L2 behaves identically on both hosts.

| Symbol | Signature | Description |
|---|---|---|
| `SocketBackend` | `Protocol` | `configure()` (applies `conf` settings) + `l2_socket_class()`. |
| `WindowsBackend` | dataclass | Sets `conf.use_pcap = True` (Npcap-backed L2). |
| `LinuxBackend` | dataclass | Sets `conf.use_pcap = False` (native `AF_PACKET`). |
| `get_backend` | `() -> SocketBackend` | Returns the backend for `platform.system()`; raises on anything but Windows/Linux. |

## payloads.py

L7 payload generation. One dispatcher (`resolve_payload`) serves the
automated suite, the `send` command, and the GUI panel uniformly.

| Symbol | Signature | Description |
|---|---|---|
| `PayloadMode` | `Enum` | `ZEROS`, `ONES`, `RANDOM`, `CUSTOM`. |
| `zeros` | `(size) -> bytes` | `b"\x00" * size`. |
| `ones` | `(size) -> bytes` | `b"\xff" * size` — **bit-pattern all-1s, not ASCII `'1'`**. |
| `random_bytes` | `(size) -> bytes` | `os.urandom(size)`. |
| `from_text` | `(text) -> bytes` | UTF-8 encode. |
| `from_hex` | `(hex_str) -> bytes` | Parse hex, tolerating spaces and `:` separators. |
| `from_file` | `(path) -> bytes` | Read file bytes. |
| `resolve_payload` | `(mode, size=0, custom=None) -> bytes` | Dispatch. `CUSTOM` requires `custom` (resolution of text/hex/file is the caller's job); raises `ValueError` otherwise. |

## recorder.py

`PacketRecorder` — passive on-wire capture to pcap, independent of any
test run. Distinct from `NetworkInterface`'s per-run capture: this sniffs
what genuinely crossed the wire (incl. OS retransmits, asymmetric reply
paths). Writes incrementally (`PcapWriter(sync=True)`) so a long or
interrupted capture still yields a valid file.

Constructor: `PacketRecorder(iface, output_path, *, bpf_filter=None, on_packet=None, backend=None)`

| Symbol | Signature | Description |
|---|---|---|
| `build_host_filter` | `(host_ip) -> str \| None` | `"host <ip>"` (both directions of a conversation), or `None` to capture everything. |
| `.packet_count` | property `-> int` | Thread-safe count written so far. |
| `.start` | `(*, count=0, timeout=None) -> None` | Non-blocking; starts an `AsyncSniffer`. `0`/`None` = unbounded. |
| `.join` | `() -> None` | Block until a bounded capture finishes; closes the writer. |
| `.stop` | `() -> int` | Stop an unbounded capture; returns packets written. Also the context-manager exit. |

## sequence.py

`TCPSequenceTracker` — local seq/ack bookkeeping for a hand-crafted TCP
connection (so a multi-packet test needn't recompute by hand). **Not**
RFC 6528 ISN-generation logic — that's what
`tests/tcp/syn/test_sequence_prediction.py` evaluates on the DUT.

| Method | Signature | Description |
|---|---|---|
| `new` | `classmethod () -> TCPSequenceTracker` | Fresh tracker with a random ISN. |
| `on_send` | `(payload_len, *, syn=False, fin=False) -> int` | Returns the seq used, then advances (SYN/FIN consume 1). |
| `on_receive` | `(remote_seq, payload_len, *, syn=False, fin=False) -> None` | Updates our ack to acknowledge a received segment. |

## preflight.py

Runs before a test run is launched (by the CLI `run` and the GUI Run
button) to answer "can this run work, and is the DUT there?" up front —
so a misconfiguration or unreachable DUT produces a clear message instead
of a run that silently does nothing.

| Symbol | Signature | Description |
|---|---|---|
| `PreflightResult` | dataclass | `ok` (False = hard blocker, don't run), `errors` / `warnings` / `info` lists, resolved `dut_mac`. `.render_lines()` → level-prefixed log lines. |
| `run_preflight` | `(config, *, timeout=1.5) -> PreflightResult` | Validates required config → checks privileges (`require_elevation`) → sends an ARP request to the DUT. |

Blocker vs. warning: missing config, insufficient privileges, and an
interface that can't send are **blockers** (`ok=False`). *No ARP reply* is
a **warning** (`ok=True`, run proceeds) — the DUT is a custom stack that
may deliberately not implement ARP, so refusing to test it would be wrong.

## responder.py

Server-role primitives — used when the suite plays the responder and the
**DUT initiates**. Reply *construction* is separated from sniff/send
orchestration so the wire format is unit-testable without a NIC.

| Symbol | Signature | Description |
|---|---|---|
| `build_syn_ack_reply` | `(syn, local_mac, *, server_isn=None) -> Packet` | From a SYN the DUT sent, build the server's SYN-ACK (swap endpoints, ack DUT-ISN+1). |
| `build_udp_echo_reply` | `(datagram, local_mac) -> Packet` | Echo a UDP datagram back to its sender. |
| `build_icmp_echo_reply` | `(request, local_mac) -> Packet` | Build the Echo Reply (type 0) for a received Echo Request. |
| `serve_tcp_handshake` | `(iface, local_ip, local_mac, listen_port, *, timeout, ...) -> Packet \| None` | Wait for the DUT's SYN, reply SYN-ACK, return its final ACK. |
| `serve_udp_echo` | `(iface, local_ip, local_mac, listen_port, *, timeout, ...) -> Packet \| None` | Wait for a DUT datagram, echo it, return what was received. |
| `serve_icmp_echo` | `(iface, local_ip, local_mac, *, timeout, ...) -> Packet \| None` | Wait for the DUT's Echo Request, reply, return the request. |
