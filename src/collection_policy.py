"""Which tests apply to a given role and topology.

The root conftest's `pytest_collection_modifyitems` applies this at
collection time (before any fixture — including the privileged
network_interface — is set up, which a function-scoped skip fixture can't
guarantee). The policy itself lives here rather than in conftest.py for two
reasons: it is safety-relevant (a role-mismatched test that runs anyway
sends the wrong traffic at the DUT), so it deserves direct unit tests; and
`conftest` is an ambiguous module name — `tests/conftest.py` shadows the
root one, so a test module importing it by name gets the wrong file.

Nothing here imports pytest. The functions need only an object with
`get_closest_marker(name)`, so they can be tested with a stub item.
"""
from __future__ import annotations

from typing import Protocol


class MarkedItem(Protocol):
    """The slice of `pytest.Item` this policy reads."""

    def get_closest_marker(self, name: str) -> object | None: ...


PROXY_SKIP_REASON = (
    "proxy: needs --proxy-mode and a backend instance "
    "(`netstack-cli proxy-serve`); see docs/proxy_testing.md"
)


def applicable_roles(item: MarkedItem) -> set[str]:
    """The roles a test declares. Neither marker ⇒ client-only (the default).

    The client-only default is what makes an unmarked test safe to add: it
    runs in the direction the suite has always defaulted to, rather than
    silently applying to both.
    """
    declared = {name for name in ("client", "server") if item.get_closest_marker(name)}
    return declared or {"client"}


def skip_reason(item: MarkedItem, *, role: str, proxy_mode: str | None) -> str | None:
    """The one reason this item should be skipped, or None to run it.

    Two independent gates, in order of precedence:

    1. `internal` (tests_internal/) is never filtered — it needs no DUT.
    2. `proxy` tests are opt-in on --proxy-mode, and are deliberately NOT
       role-filtered: the topology, not the --role selector, decides whether
       they apply.
    3. Everything else must declare the running role via `client`/`server`.
    """
    if item.get_closest_marker("internal"):
        return None

    if item.get_closest_marker("proxy") is not None:
        return None if proxy_mode else PROXY_SKIP_REASON

    applicable = applicable_roles(item)
    if role in applicable:
        return None
    return f"role: applies to {sorted(applicable)}, running as {role}"
