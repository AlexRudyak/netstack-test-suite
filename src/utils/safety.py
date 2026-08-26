"""Safety gate for `vuln`-marked tests.

`vuln` tests fire real attack patterns (SYN flood, Ping of Death,
Teardrop) at a real MAC/IP over real Ethernet, and the GUI makes running
one a single click away. A misconfigured target should never turn into a
live incident — so these tests require BOTH an explicit allow-list entry
AND an explicit confirmation flag, checked before the test body runs.
"""
from __future__ import annotations

from src.config import DUTConfig


class UnauthorizedTargetError(RuntimeError):
    pass


def enforce_vuln_test_authorization(config: DUTConfig, *, confirmed: bool) -> None:
    if not config.target_in_allowed_range():
        raise UnauthorizedTargetError(
            f"Target {config.target_ip} is not within any of this run's "
            f"allowed_targets ranges {config.allowed_targets!r}. Add it to "
            "the DUTConfig allow-list before running vuln-marked tests."
        )
    if not confirmed:
        raise UnauthorizedTargetError(
            "vuln-marked tests require explicit confirmation "
            "(--confirm-vuln-tests on the CLI, or the confirmation toggle "
            "in the GUI) in addition to being in the allow-list."
        )
