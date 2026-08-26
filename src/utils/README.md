# src/utils — privileges, safety, debug log, logging

Cross-cutting helpers used across the framework.

## Modules

| Module | Responsibility |
|---|---|
| `permissions.py` | OS-branched raw-socket privilege check + remediation |
| `safety.py` | Authorization gate for `vuln`-marked tests |
| `debug_log.py` | Opt-in tshark-style per-packet debug log |
| `logging_config.py` | Shared Python logging setup |

---

## permissions.py

Raw Ethernet access needs elevation, and the mechanism differs by host OS.
No silent self-elevation is ever attempted — the requirement is surfaced.

| Symbol | Signature | Description |
|---|---|---|
| `InsufficientPrivilegesError` | `RuntimeError` | Raised by `require_elevation`. |
| `is_elevated` | `() -> bool` | Windows: `ctypes … IsUserAnAdmin()`. Linux: `geteuid()==0` **or** a `getcap` check for `cap_net_raw`+`cap_net_admin` on the interpreter. |
| `remediation_message` | `() -> str` | OS-specific fix text (Npcap non-restricted / run as Admin; or `setcap` — preferred over root for the GUI). |
| `require_elevation` | `() -> None` | Raises `InsufficientPrivilegesError(remediation_message())` if not elevated. Called by the `network_interface` fixture before opening a socket. |
| `relaunch_module_as_admin` | `(module="src.gui.app") -> ElevationResult` | Windows only: if not elevated, relaunch `python -m <module>` via a UAC prompt. Returns `ALREADY` / `RELAUNCHED` (caller should exit) / `DECLINED` (continue non-elevated) / `UNSUPPORTED` (non-Windows). Used by the GUI entry point to self-elevate. |

## safety.py

`vuln` tests fire real attack traffic (SYN flood, Ping of Death, Teardrop)
at a real MAC/IP. A misconfigured target must never become a live
incident, so authorization requires **both** an allow-list entry **and**
an explicit confirmation.

| Symbol | Signature | Description |
|---|---|---|
| `UnauthorizedTargetError` | `RuntimeError` | Raised when either condition fails. |
| `enforce_vuln_test_authorization` | `(config, *, confirmed) -> None` | Requires `config.target_in_allowed_range()` **and** `confirmed` (from `--confirm-vuln-tests` / the GUI toggle). Called at the top of every `vuln` test body. |

## debug_log.py

Opt-in per-run log (`reports/<run_id>/debug.log`) with one tshark-style
line per packet: frame number, absolute + relative timestamps, `TX`/`RX`,
L3/L4 summary (ports, TCP flags/Seq/Ack/Win/Len), the owning test, and
the Python function that initiated the packet.

| Symbol | Signature | Description |
|---|---|---|
| `format_packet_summary` | `(packet) -> str` | tshark-like L3/L4 line for TCP/UDP/ICMP/IP (e.g. `TCP a:41100 -> b:80 [SYN, ACK] Seq=… Ack=… Win=… Len=…`). |
| `resolve_caller` | `() -> str` | Walks the stack past packet-engine plumbing (`interface.py`, `debug_log.py`, `recorder.py`) to the real caller — `func@file:lineno`. |
| `DebugLogger(path)` | class | Thread-safe writer (sniffer and test threads may both write). |
| `DebugLogger.log_packet` | `(packet, direction, *, test_nodeid=None) -> None` | One frame line; increments the frame counter, flushes. |
| `DebugLogger.log_event` | `(message) -> None` | Free-form line — test setup/call/teardown boundaries, notes. |
| `DebugLogger.close` | `() -> None` | Flush and close. |

Wiring: created in the root `conftest.py`'s `pytest_configure` when
`--debug-log` is set, injected into `NetworkInterface`, and fed test
boundaries by a small pytest plugin. See [`docs/getting_started.md`](../../docs/getting_started.md#debug-logging).

## logging_config.py

| Function | Signature | Description |
|---|---|---|
| `configure_logging` | `(level=logging.INFO) -> None` | `logging.basicConfig` with a shared format/timestamp. Called by both CLI and GUI entry points. |
