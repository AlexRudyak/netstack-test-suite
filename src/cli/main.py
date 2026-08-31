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

from src.config import DUTConfig, Role, random_ephemeral_port
from src.custom_packet.builder import CustomPacketSpec
from src.custom_packet.sender import send_custom_packet
from src.packet_engine.payloads import PayloadMode, from_file, from_hex, from_text
from src.packet_engine.preflight import run_preflight
from src.packet_engine.recorder import PacketRecorder, build_host_filter
from src.reporting.html_report import generate_html_report
from src.reporting.pdf_report import generate_pdf_report
from src.runner import RunRequest, run_tests
from src.utils.logging_config import configure_logging


@click.group()
def cli() -> None:
    """Network Stack Test Suite — RFC conformance & vulnerability testing over Ethernet."""
    configure_logging()


@cli.command()
@click.option("--module", type=click.Choice(["ip", "udp", "tcp"]), default=None)
@click.option("--submodule", type=click.Choice(["syn", "state_machine", "congestion"]), default=None)
@click.option("--test", "test_name", default=None, help="Substring match against test node IDs (-k).")
@click.option("--marker", "markers", multiple=True, help="Extra pytest marker expression term(s).")
@click.option("--iface", required=True, help="Local Ethernet interface facing the DUT.")
@click.option("--dut-ip", required=True)
@click.option("--dut-mac", default=None)
@click.option(
    "--dut-port",
    type=int,
    default=None,
    help="DUT port that port-specific tests target. Omit it and a random ephemeral "
    "port is chosen once for the whole run.",
)
@click.option(
    "--dut-source-port",
    type=int,
    default=None,
    help="Optional fixed local source port for tests that honor it (default: per-test).",
)
@click.option("--target-stack", type=click.Choice(["linux", "windows"]), required=True)
@click.option(
    "--role",
    type=click.Choice([r.value for r in Role]),
    default="client",
    help="client = suite initiates (validates DUT responder); server = suite responds (validates DUT client).",
)
@click.option("--payload-mode", type=click.Choice([m.value for m in PayloadMode]), default="random")
@click.option("--payload-size", type=int, default=64)
@click.option("--allowed-target", "allowed_targets", multiple=True, help="CIDR authorized for vuln-marked tests.")
@click.option("--confirm-vuln-tests", is_flag=True, default=False)
@click.option(
    "--debug",
    is_flag=True,
    default=False,
    help="Write a tshark-style per-packet debug log to reports/<run_id>/debug.log.",
)
@click.option("--report", type=click.Choice(["pdf", "html", "none"]), default="pdf")
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
    report: str,
    skip_preflight: bool,
) -> None:
    """Run the automated suite, or a module/submodule/test slice of it.

    Examples:
      netstack-cli run --iface eth0 --dut-ip 10.0.0.5 --target-stack linux
      netstack-cli run --module tcp --submodule syn --iface eth0 --dut-ip 10.0.0.5 --target-stack windows
      netstack-cli run --test test_three_way_handshake --iface eth0 --dut-ip 10.0.0.5 --target-stack linux
    """
    # No --dut-port ⇒ pick one random ephemeral port and use it for the run.
    if dut_port is None:
        dut_port = random_ephemeral_port()
        click.echo(f"No --dut-port given — using random destination port {dut_port} for this run.")

    config = DUTConfig(
        interface=iface,
        target_ip=dut_ip,
        target_stack=target_stack,
        target_mac=dut_mac,
        target_port=dut_port,
        source_port=dut_source_port,
        allowed_targets=tuple(allowed_targets),
        role=Role(role),
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
        role=Role(role),
    )

    def on_test_event(event) -> None:
        line = f"[{event.outcome.value.upper():7}] {event.nodeid} ({event.duration_s:.3f}s)"
        if event.message:
            line += f" — {event.message}"
        click.echo(line)

    result = run_tests(request, on_test_event=on_test_event)

    run_dir = Path("reports") / result.run_id

    if result.errored:
        # pytest itself failed to run the tests (collection/usage error,
        # no tests). Don't masquerade as a clean pass — point at the log.
        click.echo(
            f"\npytest exited with code {result.pytest_returncode} "
            f"(collection/usage error or no tests). See {run_dir / 'pytest_output.log'}",
            err=True,
        )
        sys.exit(result.pytest_returncode or 2)

    click.echo(
        f"\n{result.passed} passed, {result.failed} failed, "
        f"{result.errors} errored, {result.skipped} skipped, {result.total} total"
    )
    if result.total == 0:
        click.echo(
            "No tests ran. Check your --module/--submodule/--test selection and "
            f"the target configuration. Raw output: {run_dir / 'pytest_output.log'}",
            err=True,
        )

    if debug:
        click.echo(f"Debug log: {run_dir / 'debug.log'}")
    if report == "pdf":
        path = generate_pdf_report(result, run_dir / "report.pdf")
        click.echo(f"PDF report: {path}")
    elif report == "html":
        path = generate_html_report(result, run_dir / "report.html")
        click.echo(f"HTML report: {path}")

    sys.exit(1 if (result.failed or result.errors) else 0)


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
        if payload_text is not None:
            custom = from_text(payload_text)
        elif payload_hex is not None:
            custom = from_hex(payload_hex)
        elif payload_file is not None:
            custom = from_file(payload_file)
        else:
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


if __name__ == "__main__":
    cli()
