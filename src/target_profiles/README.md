# src/target_profiles — DUT behavioral baselines

Describes what an OS stack the **DUT** is expected to behave like — an
explicit user choice (`--target-stack linux|windows`), **independent of
which OS the suite itself runs on** (that's `packet_engine/platform_backend.py`).

RFCs leave much of TCP/IP implementation-defined (default TTL, window
size, fragment reassembly timeout, retry counts). Hardcoding one OS's
numbers as "correct" would false-fail an equally compliant DUT that
behaves like the other OS — so those values live here, tagged by
confidence, and are only asserted for tests explicitly fingerprinting the
DUT against its claimed stack.

## Modules

| Module | Responsibility |
|---|---|
| `base.py` | `Confidence`, `RangeField`, `TargetProfile` types |
| `linux_profile.py` | `LINUX_PROFILE` reference values |
| `windows_profile.py` | `WINDOWS_PROFILE` reference values |
| `registry.py` | Name → profile lookup |

## base.py

| Symbol | Description |
|---|---|
| `Confidence` | `STRICT` (RFC-mandated; assert directly, not via profile) vs. `INFORMATIONAL` (implementation characteristic; a mismatch is *not* an RFC violation). |
| `RangeField(low, high, confidence=INFORMATIONAL)` | Inclusive numeric range. `.contains(value) -> bool`. |
| `TargetProfile` | Frozen dataclass: `name`, `source` (citation), and four `RangeField`s: `default_ttl`, `tcp_initial_window`, `frag_reassembly_timeout_s`, `syn_ack_retries`. |

## Reference values

| Field | `LINUX_PROFILE` | `WINDOWS_PROFILE` |
|---|---|---|
| `default_ttl` | 60–64 | 125–128 |
| `tcp_initial_window` | 14600–65535 | 8192–65535 |
| `frag_reassembly_timeout_s` | 25–35 | 45–75 |
| `syn_ack_retries` | 4–6 | 2–3 |

All are `INFORMATIONAL`. See each module's `source` field for the
provenance (sysctl defaults, registry defaults, kernel behavior).

## registry.py

| Function | Signature | Description |
|---|---|---|
| `get_profile` | `(name) -> TargetProfile` | Case-insensitive lookup; raises `ValueError` listing valid names on miss. |
| `list_profiles` | `() -> list[str]` | Sorted profile names. |

## Adding a profile

1. Create `<name>_profile.py` defining a `TargetProfile`.
2. Register it in `registry._PROFILES`.
3. Add the choice to `--target-stack` in the root `conftest.py`, the CLI,
   and the GUI selector.
4. Extend the reference table above.
