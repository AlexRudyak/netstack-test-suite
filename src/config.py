"""Run configuration: DUT target, interface, and safety allow-list.

This is the single object threaded through the CLI, the GUI, and every pytest
fixture that needs to know what it's allowed to talk to. It is intentionally
separate from `target_profiles/` (target_profiles.py) held: this describes
*where* to send traffic and how far the operator has authorized it to go;
`target_profiles/` describes the *behavioral baseline* to assert against.
"""
from __future__ import annotations

import ipaddress
import secrets
from dataclasses import asdict, dataclass, field, fields
from enum import Enum
from typing import ClassVar, Literal

from src.errors import ConfigurationError

# The profile names src/target_profiles/ ships. Kept as a Literal for type
# checking; `target_profiles.list_profiles()` is the runtime source both
# front ends build their choice lists from, so the two can't drift.
TargetStackName = Literal["linux", "windows"]

# IANA dynamic/ephemeral range — used when no destination port is configured.
EPHEMERAL_PORT_RANGE = (49152, 65535)


def random_ephemeral_port() -> int:
    """A random port in the IANA dynamic range, chosen once per session when
    the destination port is left unspecified."""
    lo, hi = EPHEMERAL_PORT_RANGE
    return lo + secrets.randbelow(hi - lo + 1)


class Role(Enum):
    """Which side of a conversation the *test suite* plays.

    - CLIENT: the suite initiates (sends SYNs/probes) and validates the
      DUT's *responder* behavior. This is the classic mode.
    - SERVER: the suite listens and responds to traffic the DUT initiates,
      validating the DUT's *client/initiator* behavior (e.g. the DUT opens
      a connection to us, sends data, pings us).

    A test declares which role(s) it applies to via the `client` / `server`
    pytest markers; the selected `--role` skips the tests that don't match.
    """

    CLIENT = "client"
    SERVER = "server"


class ProxyLeg(Enum):
    """Which leg of a proxy DUT the ordinary endpoint suites point at.

    A proxy has two stacks, and each is a legitimate target for the normal
    IP/ICMP/UDP/TCP tests — they just probe it from opposite directions:

    - FRONT: the client-facing side, where the proxy acts as a **server**.
      The suite probes it exactly as it would any endpoint, so it implies
      `Role.CLIENT`.
    - BACK: the origin-facing side, where the proxy acts as a **client**.
      The suite observes and responds to the connections the proxy dials
      out, so it implies `Role.SERVER`. The proxy only dials out when
      traffic flows through it, so back-leg runs need traffic induced
      through the front (see `src/proxy/inducer.py`).
    """

    FRONT = "front"
    BACK = "back"

    @property
    def implied_role(self) -> Role:
        return Role.CLIENT if self is ProxyLeg.FRONT else Role.SERVER


# --- The proxy-leg rule, stated once ---------------------------------------
# A leg decides which side the suite plays and, for the front, which address
# and port it probes. All three front ends (the CLI, the GUI, and the pytest
# subprocess via conftest.py) route through these three functions, so a run
# configured one way can never be aimed somewhere else by another.


def resolve_role(leg: ProxyLeg | None, configured: Role) -> Role:
    """The role the run actually plays.

    A leg determines the role unambiguously — you probe a proxy's front as a
    client and observe its back as a server — so it wins over whatever role
    was configured, rather than making the operator keep the two in sync.
    """
    return leg.implied_role if leg is not None else configured


def resolve_leg_target(
    leg: ProxyLeg | None,
    *,
    target_ip: str,
    target_port: int | None,
    proxy_host: str | None,
    proxy_port: int | None,
) -> tuple[str, int | None]:
    """Where a leg-targeted run actually sends traffic.

    FRONT probes the proxy's client-facing stack, so it retargets to the
    front address, and — unless a port was given explicitly — to the front
    port: that is the one port known to be open, where a random ephemeral
    one would only measure closed-port behaviour. BACK and endpoint runs
    keep the configured addressing.

    A `None` port is returned unchanged so each caller can apply its own
    fallback (a fresh random port for the CLI and pytest, a session-stable
    one for the GUI).
    """
    if leg is not ProxyLeg.FRONT:
        return target_ip, target_port
    return (
        proxy_host or target_ip,
        target_port if target_port is not None else proxy_port,
    )


def back_leg_requirement_error(
    leg: ProxyLeg | None,
    *,
    proxy_mode: object,
    backend_host: object,
    mode_label: str = "--proxy-mode",
    host_label: str = "--backend-host",
) -> str | None:
    """Why a back-leg run can't start, or None when it can.

    A proxy's back leg carries nothing unless a client is driving traffic
    through its front, so a back-leg run has to be able to induce that
    traffic itself (see `src/proxy/inducer.py`).

    The rule and its rationale live here; the two labels let each front end
    name its own controls (CLI flags, or the GUI's field names) so the
    message tells the operator what to actually go and set.
    """
    if leg is not ProxyLeg.BACK or (proxy_mode and backend_host):
        return None
    return (
        f"A back proxy leg needs {mode_label} and {host_label}: a proxy's back leg is "
        "idle unless traffic is driven through its front, so the run has to induce it. "
        "See docs/proxy_testing.md."
    )


@dataclass(frozen=True)
class DUTConfig:
    """Everything required to address the device under test."""

    interface: str
    target_ip: str
    target_stack: TargetStackName
    target_mac: str | None = None
    # DUT port the port-specific tests target. None ⇒ a single random
    # ephemeral port is chosen once and used for the whole session (both
    # front ends resolve it before building this config, so by the time a
    # test sees it, it is always a concrete int).
    target_port: int | None = None
    # Optional fixed local source port. None ⇒ each test picks its own
    # (the historical behavior: per-test counters / hardcoded ports).
    source_port: int | None = None
    timeout: float = 2.0
    # There is deliberately no `retries` field. A conformance suite that
    # silently retries hides the defect it exists to find: a DUT that answers
    # the second probe but not the first has a bug, and a retry would report
    # it as a pass. The tests that legitimately repeat (the congestion and
    # flood suites) loop explicitly, where the count is part of the
    # assertion. One was declared here for a long time and never read by any
    # production code, which told every reader of this object the opposite.
    role: Role = Role.CLIENT
    # Set when the target is one leg of a proxy DUT rather than an endpoint.
    # Purely descriptive here — the addressing is already resolved into
    # target_ip/target_port — but carried so tests, logs and reports can say
    # which side of the proxy a result refers to.
    proxy_leg: ProxyLeg | None = None

    # CIDR ranges this run is authorized to send traffic to. Enforced by
    # src/utils/safety.py before any `vuln`-marked test executes.
    allowed_targets: tuple[str, ...] = field(default_factory=tuple)

    # Fields a run cannot proceed without, paired with the flag an operator
    # sets them by. Checked in two places — the preflight check and the
    # pytest `dut_config` fixture — which report it differently but must
    # agree on what "required" means.
    REQUIRED_FIELDS: ClassVar[tuple[tuple[str, str, str], ...]] = (
        ("target_ip", "--dut-ip", "Target IP"),
        ("interface", "--dut-iface", "Interface"),
        ("target_stack", "--target-stack", "Target stack"),
    )

    def missing_required(self, *, as_flags: bool = True) -> list[str]:
        """The required fields that are unset, named either by the CLI flag
        that sets them (`as_flags`) or by their human label."""
        return [
            flag if as_flags else label
            for attr, flag, label in self.REQUIRED_FIELDS
            if not getattr(self, attr)
        ]

    def target_in_allowed_range(self) -> bool:
        """Whether the target falls inside any authorized CIDR.

        Both parses raise ConfigurationError rather than the bare ValueError
        ipaddress produces. `--dut-ip` and `--allowed-target` are free text,
        so a typo is ordinary operator input — and the only caller is the
        vuln safety gate, where an unhandled ValueError made every
        `vuln`-marked test ERROR with a message about network syntax instead
        of naming the flag to fix. It fails closed either way; this decides
        what the operator is told.
        """
        if not self.allowed_targets:
            return False
        try:
            addr = ipaddress.ip_address(self.target_ip)
        except ValueError as exc:
            raise ConfigurationError(
                f"Target {self.target_ip!r} is not an IP address, so it cannot be "
                "checked against the vuln-test allow-list."
            ) from exc
        for cidr in self.allowed_targets:
            try:
                network = ipaddress.ip_network(cidr, strict=False)
            except ValueError as exc:
                raise ConfigurationError(
                    f"Allowed target {cidr!r} is not a valid CIDR range: {exc}"
                ) from exc
            if addr in network:
                return True
        return False

    # --- serialization ------------------------------------------------------
    # Derived from `fields()` rather than written out field-by-field: the
    # field list used to be stated three times (here, to_file, from_file)
    # and the two serializers silently dropped anything added to only one.
    #
    # These are plain DTO methods — no path, no file. The pair that took a
    # `path` (defaulting to ~/.netstack_test_suite/config.json) made a
    # frozen value object know where it lives, and had no production caller:
    # neither front end offers save/load. If config persistence ships, the
    # caller owns the path and writes `json.dumps(config.to_dict())`.

    def to_dict(self) -> dict:
        data = asdict(self)
        data["allowed_targets"] = list(self.allowed_targets)
        data["role"] = self.role.value
        data["proxy_leg"] = self.proxy_leg.value if self.proxy_leg else None
        return data

    @classmethod
    def from_dict(cls, data: dict) -> "DUTConfig":
        known = {f.name for f in fields(cls)} - {"allowed_targets", "role", "proxy_leg"}
        return cls(
            **{k: v for k, v in data.items() if k in known},
            allowed_targets=tuple(data.get("allowed_targets", ())),
            role=Role(data.get("role", "client")),
            proxy_leg=ProxyLeg(data["proxy_leg"]) if data.get("proxy_leg") else None,
        )
