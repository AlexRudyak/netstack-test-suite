"""Guards against the duplication patterns removed in the audit.

Each of these was a real, repeated pattern across the DUT-facing suite that
nothing checked, so it drifted. These tests are cheap and specific: they
fail loudly if the pattern reappears, and each names the shared thing to use
instead. See audits/code-duplication-audit.md.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from src import paths
from src.runner import KNOWN_MARKERS

pytestmark = [pytest.mark.internal]


def _suite_files() -> list[Path]:
    """Every DUT-facing test module (not conftest — the fixtures live there)."""
    return sorted(paths.tests_root().rglob("test_*.py"))


def test_no_hand_typed_test_nodeids() -> None:
    """Packet attribution must come from the `nodeid` fixture.

    A literal `test_nodeid="test_..."` goes stale silently on rename, which
    is exactly what had happened in tests/tcp/congestion/test_zero_window.py
    (four tests all reporting a name no test had).
    """
    offenders = [
        f"{path.relative_to(paths.project_root()).as_posix()}:{i}"
        for path in _suite_files()
        for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
        if re.search(r'test_nodeid\s*=\s*["\']', line)
    ]
    assert not offenders, (
        "Hand-typed test_nodeid literals found — request the `nodeid` fixture "
        "(tests/conftest.py) instead:\n  " + "\n  ".join(offenders)
    )


def test_no_locally_redefined_tcp_flags() -> None:
    """TCP flag bits come from src/utils/tcp_flags.py.

    Thirteen modules used to declare `SYN = 0x02` and friends independently;
    a single wrong digit in one copy would have made a test silently assert
    the wrong thing with nothing to cross-check it.
    """
    pattern = re.compile(r"^\s*(FIN|SYN|RST|PSH|ACK|URG|ECE|CWR|SYN_ACK|MAX_SEQ)\s*=\s*0?x?[0-9A-Fa-f]", re.M)
    offenders = [
        path.relative_to(paths.project_root()).as_posix()
        for path in _suite_files()
        if pattern.search(path.read_text(encoding="utf-8"))
    ]
    assert not offenders, (
        "TCP flag constants redefined locally — import them from "
        f"src.utils.tcp_flags instead: {offenders}"
    )


def test_no_hardcoded_source_ports() -> None:
    """Source ports come from the `source_port` / `source_ports` fixtures.

    Hardcoded ports collided with each other and with the SYN-flood sweep
    (42000-46999), risking a DUT-held TIME_WAIT entry corrupting the next
    test's handshake.
    """
    pattern = re.compile(r"\b(?:sport|src_port)\s*=\s*\d{4,5}\b")
    offenders = [
        f"{path.relative_to(paths.project_root()).as_posix()}:{i}"
        for path in _suite_files()
        for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
        if pattern.search(line)
    ]
    assert not offenders, (
        "Hardcoded source ports found — request the `source_port` (one) or "
        "`source_ports` (several) fixture instead:\n  " + "\n  ".join(offenders)
    )


def test_known_markers_match_pyproject() -> None:
    """runner.KNOWN_MARKERS is read from pyproject.toml, not retyped.

    It filters the report-log keywords, so a marker registered in
    pyproject.toml but missing from that set would be silently dropped from
    every generated report.
    """
    declared = re.findall(
        r'^\s*"([a-z_]+):', (paths.project_root() / "pyproject.toml").read_text(encoding="utf-8"), re.M
    )
    assert declared, "no markers parsed out of pyproject.toml — the format changed"
    assert KNOWN_MARKERS == set(declared)
