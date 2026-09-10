"""tests_internal has no DUT-facing fixtures — that's the point: nothing
here should need a DUT, a real interface, or elevated privileges. Tests
that need to fake network I/O do so with monkeypatch directly against
src.packet_engine.interface's module-level Scapy function references.

What does live here is `make_run_result`: seven near-identical
`TestRunResult(...)` builders had accumulated across these modules (two of
them under the same name, `_sample_result`, with different bodies), so a
reader couldn't tell which shape a given test asserted against.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import pytest

from src.reporting.models import TestRunResult


def make_run_result(**overrides: Any) -> TestRunResult:
    """A minimal valid run result.

    Pass overrides for whatever the test is actually about (`tests=`,
    `pytest_returncode=`, `proxy_leg=` …); everything else gets a stable,
    obviously-fake default so the fixed values never read as meaningful.
    """
    now = datetime.now(timezone.utc)
    defaults: dict[str, Any] = {
        "run_id": "r1",
        "started_at": now,
        "finished_at": now,
        "target_ip": "10.0.0.5",
        "target_stack": "linux",
        "host_platform": "TestOS",
    }
    return TestRunResult(**{**defaults, **overrides})


@pytest.fixture
def run_result() -> TestRunResult:
    """A bare run result with no tests recorded."""
    return make_run_result()
