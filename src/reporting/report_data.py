"""Shared enrichment for the HTML and PDF reports.

Turns a raw TestRunResult into the structures both report generators
render, so they stay consistent: the failures-first "findings" list (each
joined to its catalog description + RFC clause), the full test catalog
grouped for the appendix, and the RFC reading list.

The reports are meant to hand to a developer fixing the DUT's stack, so
the emphasis is: *what broke, which RFC it maps to, and what to read next.*
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from src import catalog
from src.catalog import TestSpec
from src.reporting.models import TestEvent, TestOutcome, TestRunResult

# Titles for the RFCs the suite references — the developer's reading list.
RFC_TITLES: dict[str, str] = {
    "RFC 768": "User Datagram Protocol (UDP)",
    "RFC 791": "Internet Protocol (IP)",
    "RFC 792": "Internet Control Message Protocol (ICMP)",
    "RFC 1122": "Requirements for Internet Hosts — Communication Layers",
    "RFC 2018": "TCP Selective Acknowledgment (SACK) Options",
    "RFC 5681": "TCP Congestion Control",
    "RFC 5961": "Improving TCP's Robustness to Blind In-Window Attacks",
    "RFC 6298": "Computing TCP's Retransmission Timer",
    "RFC 6528": "Defending against Sequence Number Attacks",
    "RFC 6691": "TCP Options and Maximum Segment Size (MSS)",
    "RFC 7323": "TCP Extensions for High Performance",
    "RFC 9293": "Transmission Control Protocol (TCP)",
}

_SEVERITY = {TestOutcome.ERROR: 0, TestOutcome.FAILED: 1}


@dataclass
class Finding:
    """A failed or errored test, joined to its catalog metadata."""

    event: TestEvent
    spec: TestSpec | None

    @property
    def rfc(self) -> str:
        return self.spec.rfc if self.spec else "—"

    @property
    def description(self) -> str:
        return self.spec.description if self.spec else "(no catalog description)"

    @property
    def title(self) -> str:
        return self.spec.title if self.spec else self.event.nodeid.rsplit("::", 1)[-1]


def build_findings(result: TestRunResult) -> list[Finding]:
    """Failed/errored tests, errors first, each joined to its catalog spec."""
    problems = [t for t in result.tests if t.outcome in (TestOutcome.FAILED, TestOutcome.ERROR)]
    problems.sort(key=lambda t: (_SEVERITY.get(t.outcome, 9), t.nodeid))
    return [Finding(t, catalog.find_by_nodeid(t.nodeid)) for t in problems]


def catalog_by_group() -> list[tuple[str, list[TestSpec]]]:
    """The full catalog grouped by module[/submodule], for the appendix."""
    groups: dict[str, list[TestSpec]] = {}
    for spec in catalog.CATALOG:
        key = spec.module if not spec.submodule else f"{spec.module}/{spec.submodule}"
        groups.setdefault(key, []).append(spec)
    return sorted(groups.items())


def referenced_rfcs() -> list[tuple[str, str]]:
    """Distinct RFCs the suite references, as (label, title), sorted by number."""
    numbers: set[int] = set()
    for spec in catalog.CATALOG:
        numbers.update(int(n) for n in re.findall(r"RFC\s*(\d+)", spec.rfc))
    out = []
    for n in sorted(numbers):
        label = f"RFC {n}"
        out.append((label, RFC_TITLES.get(label, "")))
    return out


def reproduction_command(result: TestRunResult) -> str:
    """An approximate CLI command to reproduce this run against the DUT."""
    return (
        "netstack-cli run "
        f"--iface <iface> --dut-ip {result.target_ip} "
        f"--target-stack {result.target_stack} --role client"
    )
