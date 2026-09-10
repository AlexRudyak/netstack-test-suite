"""The one base every deliberate failure in this package derives from.

Before this module there were three custom exceptions — `ProxyTunnelError`,
`InsufficientPrivilegesError`, `UnauthorizedTargetError` — in three packages,
each subclassing `RuntimeError` directly and sharing no base. So no caller
could express the distinction an entry point actually needs to make:

    "this run cannot proceed and we know why"  → render it as a message
    "something in here is broken"              → keep the traceback

Without that split, an error boundary has to catch `Exception`, which
swallows genuine bugs into a one-line message. `NetstackError` is what makes
the boundary in `src/cli/main.py` narrow enough to be safe.

`exit_code` rides on the exception because the CLI's exit status is part of
its contract with a script: the code belongs with the failure that decides
it, not in a mapping the boundary has to maintain separately.
"""
from __future__ import annotations


class NetstackError(Exception):
    """Base for every error this package raises on purpose."""

    exit_code: int = 1


class ConfigurationError(NetstackError):
    """Invalid or missing run configuration.

    A bad `--payload-hex`, an unreadable `--payload-file`, a malformed CIDR
    in the vuln allow-list: the operator asked for something the run can't
    act on. Exits 2 to match the preflight failure path in `cli.main.run`,
    which already means "the run never started".
    """

    exit_code = 2


class InsufficientPrivilegesError(NetstackError):
    """Raw Ethernet access is unavailable on this host.

    Carries the OS-specific remediation text from
    `src.utils.permissions.remediation_message`.
    """

    exit_code = 2


class UnsupportedHostError(NetstackError):
    """No socket backend or privilege check exists for this host OS."""

    exit_code = 2


class UnauthorizedTargetError(NetstackError):
    """The target is outside what this run was authorized to send at.

    Its own exit code, distinct from a configuration error: a script driving
    the suite should be able to tell "you pointed me somewhere I'm not
    allowed to touch" from "your flags don't parse".
    """

    exit_code = 3


class CaptureError(NetstackError):
    """A packet capture could not be started, or failed while running."""


class ProxyTunnelError(NetstackError):
    """The DUT refused or mishandled the tunnel-establishment handshake.

    `details` carries whatever the DUT managed to report before the failure
    (an HTTP error response, a non-zero SOCKS5 reply), or None when it said
    nothing. The conformance tests assert on it: "refused with a defined
    error code" is a pass, "reported success" is not.
    """

    def __init__(self, message: str, details: object = None) -> None:
        super().__init__(message)
        self.details = details
