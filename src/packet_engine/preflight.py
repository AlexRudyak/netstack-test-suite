"""Preflight connectivity check, run before a test run is launched.

Answers "can this run possibly work, and is the DUT there?" up front and
reports it — so a misconfiguration (blank target, missing privileges,
wrong interface) or an unreachable DUT produces a clear message instead
of a run that silently does nothing.

Distinguishes hard blockers from warnings:

- **Blockers** (`ok=False`) — the run cannot proceed: missing required
  config, insufficient privileges, or the interface can't send at all.
- **Warnings** (`ok=True`) — worth telling the user but not fatal. Most
  importantly, *no ARP reply* is a warning, not a blocker: the DUT is a
  custom stack that may deliberately not implement ARP, so we surface the
  fact and let the run proceed rather than refusing to test it.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from src.config import DUTConfig
from src.utils.permissions import InsufficientPrivilegesError, require_elevation


@dataclass
class PreflightResult:
    ok: bool
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    info: list[str] = field(default_factory=list)
    dut_mac: str | None = None  # resolved via ARP, if the DUT answered

    def render_lines(self) -> list[str]:
        """Flat, level-prefixed lines for a log/console."""
        lines = [f"[ok]   {m}" for m in self.info]
        lines += [f"[warn] {m}" for m in self.warnings]
        lines += [f"[FAIL] {m}" for m in self.errors]
        return lines


def run_preflight(config: DUTConfig, *, timeout: float = 1.5) -> PreflightResult:
    """Validate config + privileges, then probe the DUT with an ARP request."""
    missing = [
        name
        for name, value in (
            ("Target IP", config.target_ip),
            ("Interface", config.interface),
            ("Target stack", config.target_stack),
        )
        if not value
    ]
    if missing:
        return PreflightResult(
            ok=False,
            errors=[f"Missing required configuration: {', '.join(missing)}."],
        )

    try:
        require_elevation()
    except InsufficientPrivilegesError as exc:
        return PreflightResult(
            ok=False,
            errors=["Insufficient privileges to open a raw socket.", str(exc)],
        )

    info = [
        f"Privileges OK. Interface: {config.interface}, target stack: {config.target_stack}."
    ]

    try:
        from scapy.layers.l2 import ARP, Ether
        from scapy.sendrecv import srp1

        reply = srp1(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=config.target_ip),
            iface=config.interface,
            timeout=timeout,
            verbose=False,
        )
    except Exception as exc:  # interface missing / driver / permission at send time
        return PreflightResult(
            ok=False,
            errors=[
                f"Could not send on interface {config.interface!r}: {exc}",
                "Check the interface name and that Npcap (Windows) / capabilities (Linux) are set up.",
            ],
            info=info,
        )

    if reply is None:
        return PreflightResult(
            ok=True,
            info=info,
            warnings=[
                f"No ARP reply from {config.target_ip} on {config.interface} within {timeout}s.",
                "The DUT may not implement ARP, or may be unreachable at layer 2. "
                "Proceeding — tests that expect a reply may time out.",
            ],
        )

    mac = reply[ARP].hwsrc
    info.append(
        f"DUT {config.target_ip} responded to ARP (MAC {mac}). Layer-2 reachability confirmed."
    )
    return PreflightResult(ok=True, info=info, dut_mac=mac)
