"""CLI entry point (`netstack-cli`).

`run` drives the automated suite via src/runner.py; `send` drives the
ad-hoc custom-packet feature via src/custom_packet; `record` drives the
passive on-wire pcap recorder via src/packet_engine/recorder.py. All are
thin wrappers — no logic lives here that the GUI can't reach through the
same underlying modules (src/runner.py is the shared orchestration layer
both front ends use).
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

import click

from src.catalog import CATALOG
from src.cli.options import click_options as shared_click_options
from src.cli.options import shared_options
from src.config import (
    DUTConfig,
    ProxyLeg,
    Role,
    back_leg_requirement_error,
    random_ephemeral_port,
    resolve_leg_target,
    resolve_role,
)
from src.custom_packet.builder import CustomPacketSpec
from src.custom_packet.sender import send_custom_packet
from src.packet_engine.payloads import PayloadMode, resolve_custom_source
from src.packet_engine.preflight import run_preflight
from src.packet_engine.recorder import PacketRecorder, build_host_filter
from src.proxy.backend import EchoBackend
from src.proxy.config import DEFAULT_BACKEND_PORT, ProxyMode
from src.reporting import formats
from src.run_artifacts import RunArtifacts
from src.runner import RunRequest, run_tests
from src.target_profiles import list_profiles
from src.utils.logging_config import configure_logging


# Derived from the catalog (which tests_internal AST-checks against the real
# test tree), so a new test module can't leave the CLI rejecting it.
TEST_MODULES = sorted({spec.module for spec in CATALOG})
TEST_SUBMODULES = sorted({spec.submodule for spec in CATALOG if spec.submodule})

# The options this command shares with the pytest surface in conftest.py —
# declared once in src/cli/options.py.
SHARED_OPTIONS = shared_options(
    role_choices=tuple(r.value for r in Role),
    payload_modes=tuple(m.value for m in PayloadMode),
    proxy_modes=tuple(m.value for m in ProxyMode),
    proxy_legs=tuple(leg.value for leg in ProxyLeg),
    backend_port=DEFAULT_BACKEND_PORT,
)


@click.group()
def cli() -> None:
    """Network Stack Test Suite — RFC conformance & vulnerability testing over Ethernet."""
    configure_logging()


def _resolve_topology(
    proxy_leg: str | None,
    configured_role: str,
    *,
    dut_ip: str,
    dut_port: int | None,
    proxy_mode: str | None,
    proxy_host: str | None,
    proxy_port: int | None,
    backend_host: str | None,
) -> tuple[ProxyLeg | None, Role, str, int]:
    """Leg → role → retarget → validate, echoing what it decided.

    Returns the resolved (leg, role, target ip, target port). Raises
    click.UsageError when the selected leg's requirements aren't met. The
    GUI's counterpart is MainWindow._current_dut_config, which applies the
    same rules from src.config against widget state.
    """
    leg = ProxyLeg(proxy_leg) if proxy_leg else None
    role = resolve_role(leg, Role(configured_role))
    if leg is not None:
        click.echo(f"Proxy leg '{leg.value}' selected — running as {role.value}.")

    dut_ip, dut_port = resolve_leg_target(
        leg,
        target_ip=dut_ip,
        target_port=dut_port,
        proxy_host=proxy_host,
        proxy_port=proxy_port,
    )
    blocked = back_leg_requirement_error(leg, proxy_mode=proxy_mode, backend_host=backend_host)
    if blocked:
        raise click.UsageError(blocked)

    # No --dut-port ⇒ pick one random ephemeral port and use it for the run.
    if dut_port is None:
        dut_port = random_ephemeral_port()
        click.echo(f"No --dut-port given — using random destination port {dut_port} for this run.")
    return leg, role, dut_ip, dut_port


def _emit_results(result, run_dir: Path, *, report: str, debug: bool) -> int:
    """Print the run's outcome, write the report, and return the exit code."""
    artifacts = RunArtifacts(run_dir)
    if result.errored:
        # pytest itself failed to run the tests (collection/usage error,
        # no tests). Don't masquerade as a clean pass — point at the log.
        click.echo(
            f"\npytest exited with code {result.pytest_returncode} "
            f"(collection/usage error or no tests). See {artifacts.pytest_output}",
            err=True,
        )
        return result.pytest_returncode or 2

    click.echo(f"\n{result.counts_summary}")
    if result.total == 0:
        click.echo(
            "No tests ran. Check your --module/--submodule/--test selection and "
            f"the target configuration. Raw output: {artifacts.pytest_output}",
            err=True,
        )

    if debug:
        click.echo(f"Debug log: {artifacts.debug_log}")
    fmt = formats.BY_KEY.get(report)
    if fmt is not None:
        click.echo(f"{fmt.label} report: {fmt.generate(result, artifacts.report(fmt.key))}")

    return 1 if (result.failed or result.errors) else 0


@cli.command()
@click.option("--module", type=click.Choice(TEST_MODULES), default=None)
@click.option("--submodule", type=click.Choice(TEST_SUBMODULES), default=None)
@click.option("--test", "test_name", default=None, help="Substring match against test node IDs (-k).")
@click.option("--marker", "markers", multiple=True, help="Extra pytest marker expression term(s).")
@click.option("--iface", required=True, help="Local Ethernet interface facing the DUT.")
@click.option("--dut-ip", required=True)
@click.option("--target-stack", type=click.Choice(list_profiles()), required=True)
@shared_click_options(SHARED_OPTIONS)
@click.option("--allowed-target", "allowed_targets", multiple=True, help="CIDR authorized for vuln-marked tests.")
@click.option("--confirm-vuln-tests", is_flag=True, default=False)
@click.option(
    "--debug",
    is_flag=True,
    default=False,
    help="Write a tshark-style per-packet debug log to reports/<run_id>/debug.log.",
)
@click.option("--report", type=click.Choice(formats.CLI_CHOICES), default="pdf")
@click.option(
    "--skip-preflight",
    is_flag=True,
    default=False,
    help="Skip the pre-run connectivity check (config, privileges, ARP probe of the DUT).",
)
def run(
    module: str | None,
    submodule: str | None,
    test_name: str | None,
    markers: tuple[str, ...],
    iface: str,
    dut_ip: str,
    dut_mac: str | None,
    dut_port: int,
    dut_source_port: int | None,
    target_stack: str,
    role: str,
    payload_mode: str,
    payload_size: int,
    allowed_targets: tuple[str, ...],
    confirm_vuln_tests: bool,
    debug: bool,
    proxy_mode: str | None,
    proxy_leg: str | None,
    proxy_host: str | None,
    proxy_port: int | None,
    backend_host: str | None,
    backend_port: int,
    report: str,
    skip_preflight: bool,
) -> None:
    """Run the automated suite, or a module/submodule/test slice of it.

    Examples:
      netstack-cli run --iface eth0 --dut-ip 10.0.0.5 --target-stack linux
      netstack-cli run --module tcp --submodule syn --iface eth0 --dut-ip 10.0.0.5 --target-stack windows
      netstack-cli run --test test_three_way_handshake --iface eth0 --dut-ip 10.0.0.5 --target-stack linux
    """
    leg, resolved_role, dut_ip, dut_port = _resolve_topology(
        proxy_leg,
        role,
        dut_ip=dut_ip,
        dut_port=dut_port,
        proxy_mode=proxy_mode,
        proxy_host=proxy_host,
        proxy_port=proxy_port,
        backend_host=backend_host,
    )

    config = DUTConfig(
        interface=iface,
        target_ip=dut_ip,
        target_stack=target_stack,
        target_mac=dut_mac,
        target_port=dut_port,
        source_port=dut_source_port,
        allowed_targets=tuple(allowed_targets),
        role=resolved_role,
        proxy_leg=leg,
    )

    if not skip_preflight:
        click.echo("Preflight connectivity check…")
        pre = run_preflight(config)
        for line in pre.render_lines():
            click.echo("  " + line)
        if not pre.ok:
            click.echo("Preflight failed — aborting before running any tests.", err=True)
            sys.exit(2)

    request = RunRequest(
        config=config,
        module=module,
        submodule=submodule,
        test_name=test_name,
        markers=tuple(markers),
        payload_mode=PayloadMode(payload_mode),
        payload_size=payload_size,
        confirm_vuln_tests=confirm_vuln_tests,
        debug=debug,
        # role/proxy_leg are read off `config` (which _resolve_topology
        # already settled) — RunRequest deliberately has no copies.
        proxy_mode=proxy_mode,
        proxy_host=proxy_host,
        proxy_port=proxy_port,
        backend_host=backend_host,
        backend_port=backend_port,
    )

    def on_test_event(event) -> None:
        click.echo(event.summary_line())

    result = run_tests(request, on_test_event=on_test_event)

    run_dir = Path("reports") / result.run_id
    sys.exit(_emit_results(result, run_dir, report=report, debug=debug))


@cli.command()
@click.option("--proto", type=click.Choice(["tcp", "udp"]), required=True)
@click.option("--iface", required=True)
@click.option("--src-ip", required=True)
@click.option("--dst-ip", required=True)
@click.option("--src-port", type=int, required=True)
@click.option("--dst-port", type=int, required=True)
@click.option("--src-mac", required=True)
@click.option("--dst-mac", required=True)
@click.option("--ttl", type=int, default=64)
@click.option("--tcp-flags", default="S")
@click.option("--payload-mode", type=click.Choice([m.value for m in PayloadMode]), default="random")
@click.option("--payload-size", type=int, default=64)
@click.option("--payload", "payload_text", default=None, help="Custom payload as text.")
@click.option("--payload-hex", default=None, help="Custom payload as hex.")
@click.option("--payload-file", default=None, help="Custom payload loaded from a file.")
@click.option("--timeout", type=float, default=2.0)
@click.option("--capture", "capture_path", default=None, type=click.Path())
def send(
    proto: str,
    iface: str,
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    src_mac: str,
    dst_mac: str,
    ttl: int,
    tcp_flags: str,
    payload_mode: str,
    payload_size: int,
    payload_text: str | None,
    payload_hex: str | None,
    payload_file: str | None,
    timeout: float,
    capture_path: str | None,
) -> None:
    """Send one ad-hoc packet with a custom/raw L7 payload and print the response."""
    mode = PayloadMode(payload_mode)
    custom = None
    if mode is PayloadMode.CUSTOM:
        custom = resolve_custom_source(text=payload_text, hex_str=payload_hex, file=payload_file)
        if custom is None:
            raise click.UsageError(
                "--payload-mode=custom requires --payload, --payload-hex, or --payload-file"
            )

    spec = CustomPacketSpec(
        proto=proto,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        src_mac=src_mac,
        dst_mac=dst_mac,
        ttl=ttl,
        tcp_flags=tcp_flags,
        payload_mode=mode,
        payload_size=payload_size,
        custom_payload=custom,
    )
    reply = send_custom_packet(
        spec, iface, timeout=timeout, capture_path=Path(capture_path) if capture_path else None
    )
    if reply is None:
        click.echo("No reply received within timeout.")
    else:
        click.echo(reply.summary())


@cli.command()
@click.option("--iface", required=True, help="Local Ethernet interface to record from.")
@click.option("--out", "output", required=True, type=click.Path(), help="Output .pcap file path.")
@click.option(
    "--dut-ip",
    default=None,
    help="Restrict capture to the conversation with this host (the app's traffic to it "
    "and the associated transmission back). Omit to capture everything the interface sees.",
)
@click.option(
    "--filter",
    "bpf_filter",
    default=None,
    help="Explicit BPF filter, overriding the --dut-ip-derived one (e.g. 'tcp port 80').",
)
@click.option("--count", type=int, default=0, help="Stop after N packets (0 = unbounded, until Ctrl+C).")
@click.option("--duration", type=float, default=None, help="Stop after this many seconds (default: until Ctrl+C).")
def record(
    iface: str,
    output: str,
    dut_ip: str | None,
    bpf_filter: str | None,
    count: int,
    duration: float | None,
) -> None:
    """Record all packets leaving the app and the transmission associated
    with it to a .pcap file (passive on-wire capture).

    Runs until Ctrl+C unless --count or --duration bounds it. Writes
    incrementally, so the file stays valid even if interrupted.

    Examples:
      netstack-cli record --iface eth0 --out capture.pcap --dut-ip 10.0.0.5
      netstack-cli record --iface eth0 --out capture.pcap --duration 30
      netstack-cli record --iface eth0 --out capture.pcap --filter "tcp port 80"
    """
    effective_filter = bpf_filter if bpf_filter is not None else build_host_filter(dut_ip)
    output_path = Path(output)

    recorder = PacketRecorder(
        iface,
        output_path,
        bpf_filter=effective_filter,
        on_packet=lambda pkt: click.echo(pkt.summary()),
    )

    click.echo(
        f"Recording on {iface} -> {output_path}"
        + (f" (filter: {effective_filter})" if effective_filter else " (no filter)")
    )
    recorder.start(count=count, timeout=duration)

    try:
        if count or duration:
            recorder.join()  # bounded: block until the sniffer stops itself
        else:
            click.echo("Press Ctrl+C to stop.")
            while True:
                time.sleep(0.5)
    except KeyboardInterrupt:
        click.echo("\nStopping…")
    finally:
        written = recorder.stop()
        click.echo(f"Wrote {written} packet(s) to {output_path}")


@cli.command("proxy-serve")
@click.option("--listen-host", default="0.0.0.0", help="Address to listen on (the origin the DUT dials).")
@click.option(
    "--listen-port", type=int, default=DEFAULT_BACKEND_PORT, help="Port to listen on."
)
@click.option("--udp/--no-udp", default=False, help="Also run a UDP echo responder on the same port.")
def proxy_serve(listen_host: str, listen_port: int, udp: bool) -> None:
    """Run the backend (origin) instance for proxy-DUT testing.

    This is the **server instance** of the two-instance proxy setup: it
    stands in as the origin server that the proxy DUT dials out to, and
    echoes everything the proxy relays. The client instance then verifies
    the round-trip, which proves both of the DUT's legs work.

    Start this first, then run the proxy tests from the other instance:

      netstack-cli proxy-serve --listen-host 0.0.0.0 --listen-port 9099

      netstack-cli run --module proxy --iface eth0 --dut-ip 10.0.0.5 \\
        --target-stack linux --proxy-mode socks5 \\
        --proxy-host 10.0.0.5 --proxy-port 1080 \\
        --backend-host 10.0.0.9 --backend-port 9099

    Runs until Ctrl+C. No elevated privileges required — this side uses
    ordinary sockets, because the DUT terminates TCP on this leg.
    """
    backend = EchoBackend(listen_host, listen_port, enable_udp=udp, on_event=click.echo)
    backend.start()
    click.echo("Waiting for the proxy DUT to connect. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        click.echo("\nStopping…")
    finally:
        stats = backend.stats
        backend.stop()
        click.echo(stats.summary())
        if not stats.tcp_connections and not stats.udp_datagrams:
            click.echo(
                "No connections were received — the DUT never dialled this backend. "
                "Check the proxy's upstream/origin configuration and routing.",
                err=True,
            )


if __name__ == "__main__":
    cli()
