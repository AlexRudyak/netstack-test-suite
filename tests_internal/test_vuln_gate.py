"""Guards the `vuln` safety gate against the failure mode it already had.

`vuln`-marked tests fire real attack patterns at a real MAC/IP, so
`src/utils/safety.py` requires both an allow-list entry and an explicit
confirmation flag. Enforcement used to be a hand-written
`enforce_vuln_test_authorization(...)` line at the top of each such test —
which three of the four `vuln`-marked tests had and the fourth did not.
A missing call is invisible: it looks exactly like a test that has no gate
to begin with.

Enforcement now lives in the root conftest's autouse
`enforce_vuln_authorization` fixture, keyed on the marker. These tests
check the two halves of that: the fixture gates on the marker and nothing
else, and no test module has drifted back to calling the gate by hand.

The marker/call census is done over the AST, so this needs no DUT, no
Scapy and no interface.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

from src import paths
from src.config import DUTConfig
from src.utils.safety import UnauthorizedTargetError

pytestmark = [pytest.mark.internal]


class _StubRequest:
    """The slice of `pytest.FixtureRequest` the gate fixture reads."""

    def __init__(self, *, marked: bool, config: DUTConfig, confirmed: bool) -> None:
        self._marked = marked
        self._values = {"dut_config": config, "confirm_vuln_tests": confirmed}
        self.node = self

    def get_closest_marker(self, name: str) -> object | None:
        return object() if (name == "vuln" and self._marked) else None

    def getfixturevalue(self, name: str) -> object:
        return self._values[name]


def _fixture_definition():
    import conftest

    return conftest.enforce_vuln_authorization


def _gate():
    """The autouse fixture's underlying function, unwrapped from pytest.

    pytest 9 wraps a fixture in a `FixtureFunctionDefinition` exposing
    `_get_wrapped_function()`; pytest 8 (which pyproject still allows)
    leaves the plain function with a `__wrapped__` attribute.
    """
    definition = _fixture_definition()
    getter = getattr(definition, "_get_wrapped_function", None)
    return getter() if getter is not None else definition.__wrapped__


def _authorized_config() -> DUTConfig:
    return DUTConfig(
        interface="eth0",
        target_ip="10.0.0.5",
        target_stack="linux",
        allowed_targets=("10.0.0.0/24",),
    )


def _unauthorized_config() -> DUTConfig:
    return DUTConfig(interface="eth0", target_ip="10.0.0.5", target_stack="linux")


def test_the_gate_fixture_is_autouse() -> None:
    """Autouse is the whole point: a new vuln test must be covered without
    its author remembering anything."""
    definition = _fixture_definition()
    # pytest 9 names it `_fixture_function_marker`; pytest 8 attaches
    # `_pytestfixturefunction` to the function itself.
    marker = getattr(definition, "_fixture_function_marker", None) or getattr(
        definition, "_pytestfixturefunction"
    )
    assert marker.autouse is True


def test_an_unmarked_test_is_not_gated() -> None:
    """The gate must be a no-op for the ~300 tests that aren't vuln-marked —
    including every test that has no DUT config at all."""
    request = _StubRequest(marked=False, config=_unauthorized_config(), confirmed=False)
    _gate()(request)  # no exception, and no fixture lookup


def test_a_marked_test_outside_the_allow_list_is_refused() -> None:
    request = _StubRequest(marked=True, config=_unauthorized_config(), confirmed=True)
    with pytest.raises(UnauthorizedTargetError, match="allowed_targets"):
        _gate()(request)


def test_a_marked_test_without_confirmation_is_refused() -> None:
    request = _StubRequest(marked=True, config=_authorized_config(), confirmed=False)
    with pytest.raises(UnauthorizedTargetError, match="explicit confirmation"):
        _gate()(request)


def test_a_marked_test_that_is_allowed_and_confirmed_proceeds() -> None:
    request = _StubRequest(marked=True, config=_authorized_config(), confirmed=True)
    _gate()(request)


def _test_modules() -> list[Path]:
    return sorted(paths.tests_root().rglob("test_*.py"))


def test_no_test_module_calls_the_gate_by_hand() -> None:
    """Two enforcement paths would be worse than one.

    A hand-written call is now redundant with the autouse fixture, and its
    presence in some modules but not others is exactly what made the gap
    invisible last time — a reader can't tell an intentionally ungated test
    from a forgotten line.
    """
    offenders = []
    for path in _test_modules():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id == "enforce_vuln_test_authorization":
                    offenders.append(f"{path.name}:{node.lineno}")
    assert not offenders, (
        "These call the vuln gate by hand; the autouse fixture in the root "
        f"conftest.py already gates every `vuln`-marked test: {offenders}"
    )
