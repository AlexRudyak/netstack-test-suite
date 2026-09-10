"""Options declared once, registered on both CLI surfaces.

The suite exposes the same run configuration twice: as `netstack-cli run`
flags (click) and as pytest options (conftest.py's `pytest_addoption`),
bridged by `src/runner.build_pytest_args`. Declaring each option in both
places meant the help text was copy-pasted and the two could silently
disagree about a default.

Each option is described once here as data, and each surface renders it in
its own idiom.

Deliberately NOT shared, because the two surfaces genuinely differ:

- `--dut-ip`, `--target-stack` — required on the CLI (a run can't proceed
  without them), optional for pytest so `tests_internal/` runs standalone.
- `--iface` (CLI) vs `--dut-iface` (pytest) — different flag names.
- `--allowed-target` (click `multiple=True`) vs `--allowed-targets`
  (pytest `action="append"`) — different names and different mechanisms.
- `--report`, `--skip-preflight` (CLI only); `--live-events-log`,
  `--capture-pcap`, `--debug-log`, `--payload-text/-hex/-file`,
  `--confirm-vuln-tests` (pytest only, or flag-shaped).

Those stay declared where they belong rather than being forced through a
shared abstraction that would have to special-case each one.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SharedOption:
    """One option, in the terms both surfaces need.

    `name` is the flag as both surfaces spell it. `choices` and `type` are
    mutually exclusive: click wraps choices in `click.Choice`, pytest passes
    them as `choices=`.
    """

    name: str
    help: str
    type: type | None = None
    default: object = None
    choices: tuple[str, ...] | None = None

    @property
    def dest(self) -> str:
        """The attribute name pytest derives from the flag."""
        return self.name.lstrip("-").replace("-", "_")


def shared_options(*, role_choices: tuple[str, ...], payload_modes: tuple[str, ...],
                   proxy_modes: tuple[str, ...], proxy_legs: tuple[str, ...],
                   backend_port: int) -> tuple[SharedOption, ...]:
    """Build the shared option list.

    Takes the enumerations as arguments rather than importing them, so this
    module stays free of the config/proxy imports and can be read as the
    declaration it is.
    """
    return (
        SharedOption(
            "--role",
            "Which side the suite plays: client (initiator) or server (responder). "
            "Tests not marked for the selected role are skipped.",
            choices=role_choices,
            default="client",
        ),
        SharedOption("--dut-mac", "DUT MAC address."),
        SharedOption(
            "--dut-port",
            "DUT port that port-specific tests target. Omit it and a random ephemeral "
            "port is chosen once for the whole run.",
            type=int,
        ),
        SharedOption(
            "--dut-source-port",
            "Optional fixed local source port for tests that honor it (default: per-test).",
            type=int,
        ),
        SharedOption(
            "--payload-mode",
            "L7 payload content for tests that carry one.",
            choices=payload_modes,
            default="random",
        ),
        SharedOption("--payload-size", "L7 payload size in bytes.", type=int, default=64),
        SharedOption(
            "--proxy-mode",
            "Enable the proxy-DUT tests and select how the client reaches the origin: "
            "transparent (inline DUT), http-connect (RFC 9110/9112), socks5 (RFC 1928). "
            "Requires a second app instance running `proxy-serve` as the backend.",
            choices=proxy_modes,
        ),
        SharedOption(
            "--proxy-leg",
            "Point the ORDINARY endpoint suites (ip/udp/icmp/tcp) at one leg of a proxy DUT: "
            "'front' probes its client-facing stack (implies --role client, and retargets to "
            "--proxy-host/--proxy-port); 'back' observes the stack it dials origins with "
            "(implies --role server, and needs --proxy-mode + --backend-host so traffic can "
            "be induced through the front).",
            choices=proxy_legs,
        ),
        SharedOption("--proxy-host", "Proxy DUT front address (explicit modes)."),
        SharedOption("--proxy-port", "Proxy DUT front port (explicit modes).", type=int),
        SharedOption(
            "--backend-host",
            "Origin/backend address the DUT must reach — where the backend instance "
            "(`netstack-cli proxy-serve`) listens.",
        ),
        SharedOption(
            "--backend-port", "Backend instance listen port.", type=int, default=backend_port
        ),
    )


def register_pytest_options(group, options: tuple[SharedOption, ...]) -> None:
    """Add every shared option to a pytest option group."""
    for opt in options:
        kwargs: dict = {"default": opt.default, "help": opt.help}
        if opt.choices:
            kwargs["choices"] = list(opt.choices)
        elif opt.type is not None:
            kwargs["type"] = opt.type
        group.addoption(opt.name, **kwargs)


def click_options(options: tuple[SharedOption, ...]):
    """Decorator adding every shared option to a click command.

    Applied in reverse so the rendered `--help` lists them in declaration
    order (click stacks decorators bottom-up).
    """
    import click

    def decorate(fn):
        for opt in reversed(options):
            kwargs: dict = {"default": opt.default, "help": opt.help}
            kwargs["type"] = click.Choice(list(opt.choices)) if opt.choices else opt.type
            fn = click.option(opt.name, **kwargs)(fn)
        return fn

    return decorate
