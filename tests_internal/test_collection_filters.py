"""Unit tests for src/collection_policy.py, applied by the root conftest's
pytest_collection_modifyitems hook.

`skip_reason` gates which tests run for a given --role and proxy topology.
It is safety-relevant (a role-mismatched test that silently runs sends the
wrong traffic at the DUT) and previously had no direct test — it was only
exercised end-to-end, where a wrong verdict looks like an ordinary skip.
"""
from __future__ import annotations

import pytest

from src.collection_policy import PROXY_SKIP_REASON, applicable_roles, skip_reason

pytestmark = [pytest.mark.internal]


class _Item:
    """The slice of pytest.Item that skip_reason actually uses."""

    def __init__(self, *markers: str) -> None:
        self._markers = set(markers)

    def get_closest_marker(self, name: str) -> object | None:
        return object() if name in self._markers else None


# --- applicable_roles -------------------------------------------------------


def test_no_role_marker_defaults_to_client_only() -> None:
    assert applicable_roles(_Item()) == {"client"}


def test_role_markers_are_read_from_the_item() -> None:
    assert applicable_roles(_Item("client")) == {"client"}
    assert applicable_roles(_Item("server")) == {"server"}
    assert applicable_roles(_Item("client", "server")) == {"client", "server"}


# --- the role gate ----------------------------------------------------------


def test_matching_role_runs() -> None:
    assert skip_reason(_Item("client"), role="client", proxy_mode=None) is None
    assert skip_reason(_Item("server"), role="server", proxy_mode=None) is None
    assert skip_reason(_Item("client", "server"), role="server", proxy_mode=None) is None


def test_mismatched_role_is_skipped_with_an_explanatory_reason() -> None:
    reason = skip_reason(_Item("server"), role="client", proxy_mode=None)
    assert reason is not None
    assert "server" in reason and "client" in reason


def test_unmarked_test_is_skipped_when_running_as_server() -> None:
    """The client-only default is what makes an unmarked test safe to add."""
    assert skip_reason(_Item(), role="server", proxy_mode=None) is not None
    assert skip_reason(_Item(), role="client", proxy_mode=None) is None


# --- the proxy gate ---------------------------------------------------------


def test_proxy_tests_are_opt_in() -> None:
    assert skip_reason(_Item("proxy"), role="client", proxy_mode=None) == PROXY_SKIP_REASON
    assert skip_reason(_Item("proxy"), role="client", proxy_mode="socks5") is None


def test_proxy_tests_are_never_role_filtered() -> None:
    """The topology decides whether a proxy test applies, not --role. This is
    the load-bearing `continue` the original loop expressed as control flow."""
    assert skip_reason(_Item("proxy", "client"), role="server", proxy_mode="socks5") is None
    assert skip_reason(_Item("proxy", "server"), role="client", proxy_mode="socks5") is None


# --- the internal exemption -------------------------------------------------


def test_internal_tests_are_never_filtered() -> None:
    assert skip_reason(_Item("internal"), role="server", proxy_mode=None) is None
    assert skip_reason(_Item("internal", "client"), role="server", proxy_mode=None) is None
