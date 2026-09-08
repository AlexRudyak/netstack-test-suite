"""Canonical result models.

Everything that produces or consumes test-run data — the pytest
`--report-log` parser, the packet capture layer, the GUI's live view, and
the PDF/JSON report generator — normalizes to these shapes. One source of
truth avoids each consumer re-deriving its own notion of "what happened."
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
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


class TestOutcome(Enum):
    __test__ = False
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"
    ERROR = "error"


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

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "target_ip": self.target_ip,
            "target_stack": self.target_stack,
            "host_platform": self.host_platform,
            "payload_mode": self.payload_mode,
            "role": self.role,
            "proxy_leg": self.proxy_leg,
            "pytest_returncode": self.pytest_returncode,
            "tests": [t.to_dict() for t in self.tests],
            "packet_events": [p.to_dict() for p in self.packet_events],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TestRunResult":
        return cls(
            run_id=data["run_id"],
            started_at=datetime.fromisoformat(data["started_at"]),
            finished_at=datetime.fromisoformat(data["finished_at"]) if data.get("finished_at") else None,
            target_ip=data["target_ip"],
            target_stack=data["target_stack"],
            host_platform=data["host_platform"],
            payload_mode=data.get("payload_mode", "random"),
            role=data.get("role", "client"),
            proxy_leg=data.get("proxy_leg"),
            pytest_returncode=data.get("pytest_returncode"),
            tests=[
                TestEvent(
                    nodeid=t["nodeid"],
                    outcome=TestOutcome(t["outcome"]),
                    duration_s=t["duration_s"],
                    markers=t.get("markers", []),
                    message=t.get("message"),
                )
                for t in data.get("tests", [])
            ],
            packet_events=[
                PacketEvent(
                    timestamp=p["timestamp"],
                    direction=PacketDirection(p["direction"]),
                    summary=p["summary"],
                    size_bytes=p["size_bytes"],
                    test_nodeid=p.get("test_nodeid"),
                )
                for p in data.get("packet_events", [])
            ],
        )
