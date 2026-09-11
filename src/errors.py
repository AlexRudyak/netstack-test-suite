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

    def render(self, *, prefix: str = "Error") -> str:
        """The one user-facing rendering, shared by every boundary.

        Six surfaces had each invented their own — `Error: {exc}`,
        `[FAIL] {msg}`, `Failed to start: {exc}` — so the same
        ConfigurationError read differently depending on which one caught
        it, and only two of the six named the type. The type is the part
        that tells the operator what kind of thing went wrong:
        ConfigurationError and UnauthorizedTargetError call for quite
        different reactions.
        """
        return f"{prefix}: [{type(self).__name__}] {self}"


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


class RunArtifactError(NetstackError):
    """A run's directory or results file could not be written.

    The pcap and the debug log flush per frame, so the *evidence* of a run
    survives a full disk or a read-only reports/ — it is the verdict and the
    machine-readable record that do not, and results.json is the only thing
    `reporting.collector.load_run_result` can read back.

    Raised rather than left as a bare OSError so both entry points can tell
    the operator which file, and say that the rest of the run is still on
    disk: in the GUI these writes happen inside Qt slots, where an unhandled
    exception reaches sys.excepthook and ends the process.
    """


class ProtocolViolation(NetstackError, ValueError):
    """The peer's bytes do not conform to the protocol's RFC.

    Every parse failure in src/proxy/tunnel.py describes something the *DUT*
    sent — a test result — but they were raised as bare ValueErrors, which a
    caller cannot tell apart from a ValueError raised by a bug in our own
    encoder. tests/proxy/ could not assert "the DUT violated RFC 1928" as
    distinct from "our parser crashed".

    Subclasses ValueError as well, so the handlers that already catch
    ValueError around those calls keep working unchanged.
    """


class PeerClosedEarly(ProtocolViolation, ConnectionError):
    """The DUT closed the connection part-way through a protocol message.

    "The proxy hung up before finishing its SOCKS5 reply" is an observation
    about the DUT, exactly like a malformed reply is — but it was raised as
    a builtin ConnectionError, the type the OS uses for a local socket
    problem, so tests/proxy/ could not claim it as a verdict and
    ProxyClient could not classify it.

    Subclasses ConnectionError as well, so the handlers that already catch
    that (the proxy fixtures, ProxyClient.connect's cleanup) keep working
    unchanged.
    """


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
