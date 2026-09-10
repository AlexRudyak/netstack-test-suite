"""Canonical result models.

Everything that produces or consumes test-run data — the pytest
`--report-log` parser, the packet capture layer, the GUI's live view, and
the PDF/JSON report generator — normalizes to these shapes. One source of
truth avoids each consumer re-deriving its own notion of "what happened."
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field, fields
from datetime import datetime
from enum import Enum
from typing import Any, ClassVar

# These classes are named Test* for clarity (they mirror pytest's own
# vocabulary), not because pytest should collect them as test classes —
# __test__ = False opts each one out of collection.


class PacketDirection(Enum):
    SENT = "sent"
    RECEIVED = "received"


@dataclass
class PacketEvent:
    timestamp: float  # time.time() at capture
    direction: PacketDirection
    summary: str  # Scapy .summary() string
    size_bytes: int
    test_nodeid: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["direction"] = self.direction.value
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PacketEvent":
        return cls(**{**data, "direction": PacketDirection(data["direction"])})


class TestOutcome(Enum):
    __test__ = False
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"
    ERROR = "error"


# How each outcome is *presented* lives in reporting/palette.py, not here:
# this module is imported by the runner, the collector, the packet
# interface and every GUI panel, none of which render a report.


@dataclass
class TestEvent:
    __test__: ClassVar[bool] = False

    nodeid: str
    outcome: TestOutcome
    duration_s: float
    markers: list[str] = field(default_factory=list)
    message: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["outcome"] = self.outcome.value
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TestEvent":
        known = {f.name for f in fields(cls)}
        return cls(**{**{k: v for k, v in data.items() if k in known},
                      "outcome": TestOutcome(data["outcome"])})

    def summary_line(self, label_width: int = 7) -> str:
        """One console/log line for this test. Shared by the CLI's progress
        output and the GUI log panel so a run reads the same in both."""
        line = f"[{self.outcome.value.upper():{label_width}}] {self.nodeid} ({self.duration_s:.3f}s)"
        return f"{line} — {self.message}" if self.message else line


# Serialization is derived from `fields()` rather than written out
# field-by-field: the field list used to be stated three times (the
# dataclass body, to_dict, from_dict), and a field added to one but not the
# others was dropped in silence — never persisted, or written and then
# discarded on reload. These two tables name the only fields that are not
# plain JSON scalars, so a new scalar field needs no serializer edit.
_DATETIME_FIELDS = ("started_at", "finished_at")
_NESTED_FIELDS: dict[str, type] = {"tests": TestEvent, "packet_events": PacketEvent}


@dataclass
class TestRunResult:
    __test__: ClassVar[bool] = False

    run_id: str
    started_at: datetime
    finished_at: datetime | None
    target_ip: str
    target_stack: str  # target_profiles name active for this run ("linux" | "windows")
    host_platform: str  # platform.system() of the machine that executed the suite
    payload_mode: str = "random"
    role: str = "client"  # which side the suite played ("client" | "server")
    # Set when target_ip was one leg of a proxy DUT ("front" | "back") rather
    # than an endpoint — without it a report reads as if a plain host was
    # tested, and the reader can't tell which of the proxy's two stacks the
    # findings belong to.
    proxy_leg: str | None = None
    tests: list[TestEvent] = field(default_factory=list)
    packet_events: list[PacketEvent] = field(default_factory=list)
    # pytest's process exit code (0=all passed, 1=some failed, 2-5=collection/
    # usage/internal error, None while still running). Distinguishes "0 tests
    # ran because a collection error aborted the run" from "0 tests selected".
    pytest_returncode: int | None = None

    @property
    def role_description(self) -> str:
        """How the run was positioned, in the terms a developer fixing the
        DUT needs: which side the suite played, and — for a proxy — which of
        the DUT's two stacks the findings belong to."""
        if self.proxy_leg == "front":
            return (
                "client — probing the FRONT leg of a proxy DUT: the stack it serves "
                "its own clients with"
            )
        if self.proxy_leg == "back":
            return (
                "server — observing the BACK leg of a proxy DUT: the stack it dials "
                "origin servers with (traffic induced through the front)"
            )
        if self.role == "server":
            return "server — the suite responded; the DUT initiated (validates its client path)"
        return "client — the suite initiated (validates the DUT's responder)"

    @property
    def errored(self) -> bool:
        """True when pytest itself failed to run the tests (not a test
        assertion failure) — collection error, usage error, no tests."""
        return self.pytest_returncode is not None and self.pytest_returncode >= 2

    @property
    def passed(self) -> int:
        return sum(1 for t in self.tests if t.outcome is TestOutcome.PASSED)

    @property
    def failed(self) -> int:
        return sum(1 for t in self.tests if t.outcome is TestOutcome.FAILED)

    @property
    def errors(self) -> int:
        """Tests that errored (fixture/setup/teardown failure) rather than
        failing an assertion — distinct from `failed`."""
        return sum(1 for t in self.tests if t.outcome is TestOutcome.ERROR)

    @property
    def skipped(self) -> int:
        return sum(1 for t in self.tests if t.outcome is TestOutcome.SKIPPED)

    @property
    def total(self) -> int:
        return len(self.tests)

    @property
    def counts_summary(self) -> str:
        """The one-line tally every front end prints at the end of a run."""
        return (
            f"{self.passed} passed, {self.failed} failed, {self.errors} errored, "
            f"{self.skipped} skipped, {self.total} total"
        )

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for f in fields(self):
            value = getattr(self, f.name)
            if f.name in _DATETIME_FIELDS:
                out[f.name] = value.isoformat() if value else None
            elif f.name in _NESTED_FIELDS:
                out[f.name] = [item.to_dict() for item in value]
            else:
                out[f.name] = value
        return out

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TestRunResult":
        kwargs: dict[str, Any] = {}
        for f in fields(cls):
            if f.name in _DATETIME_FIELDS:
                raw = data.get(f.name)
                kwargs[f.name] = datetime.fromisoformat(raw) if raw else None
            elif f.name in _NESTED_FIELDS:
                kwargs[f.name] = [
                    _NESTED_FIELDS[f.name].from_dict(d) for d in data.get(f.name, [])
                ]
            elif f.name in data:
                # Absent keys fall through to the dataclass default, which
                # is what lets an older results.json still load.
                kwargs[f.name] = data[f.name]
        return cls(**kwargs)
