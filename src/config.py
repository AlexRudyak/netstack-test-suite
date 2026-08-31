"""Run configuration: DUT target, interface, and safety allow-list.

This is the single object threaded through the CLI, the GUI, and every pytest
fixture that needs to know what it's allowed to talk to. It is intentionally
separate from `target_profiles/` (target_profiles.py) held: this describes
*where* to send traffic and how far the operator has authorized it to go;
`target_profiles/` describes the *behavioral baseline* to assert against.
"""
from __future__ import annotations

import ipaddress
import json
import secrets
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Literal

TargetStackName = Literal["linux", "windows"]

DEFAULT_CONFIG_PATH = Path.home() / ".netstack_test_suite" / "config.json"

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
    retries: int = 2
    role: Role = Role.CLIENT

    # CIDR ranges this run is authorized to send traffic to. Enforced by
    # src/utils/safety.py before any `vuln`-marked test executes.
    allowed_targets: tuple[str, ...] = field(default_factory=tuple)

    def target_in_allowed_range(self) -> bool:
        if not self.allowed_targets:
            return False
        addr = ipaddress.ip_address(self.target_ip)
        return any(
            addr in ipaddress.ip_network(cidr, strict=False)
            for cidr in self.allowed_targets
        )

    @classmethod
    def from_file(cls, path: Path = DEFAULT_CONFIG_PATH) -> "DUTConfig":
        data = json.loads(path.read_text(encoding="utf-8"))
        return cls(
            interface=data["interface"],
            target_ip=data["target_ip"],
            target_stack=data["target_stack"],
            target_mac=data.get("target_mac"),
            target_port=data.get("target_port"),
            source_port=data.get("source_port"),
            timeout=data.get("timeout", 2.0),
            retries=data.get("retries", 2),
            allowed_targets=tuple(data.get("allowed_targets", [])),
            role=Role(data.get("role", "client")),
        )

    def to_file(self, path: Path = DEFAULT_CONFIG_PATH) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(
                {
                    "interface": self.interface,
                    "target_ip": self.target_ip,
                    "target_stack": self.target_stack,
                    "target_mac": self.target_mac,
                    "target_port": self.target_port,
                    "source_port": self.source_port,
                    "timeout": self.timeout,
                    "retries": self.retries,
                    "allowed_targets": list(self.allowed_targets),
                    "role": self.role.value,
                },
                indent=2,
            ),
            encoding="utf-8",
        )
