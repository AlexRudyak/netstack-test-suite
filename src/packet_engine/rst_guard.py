"""Windows-only: stops the host's own TCP/IP stack from seeing (and
resetting) traffic that belongs to this suite's faked TCP connections.

Every test crafts and sends TCP segments with Scapy over a raw L2 socket
(platform_backend.py), bypassing Winsock entirely. The DUT's replies still
arrive addressed to the host's real IP, so Windows' own tcpip.sys sees them
too — and since no Winsock socket is bound to that port, RFC 793 has
Windows answer with its own RST. That RST races the test framework's own
protocol logic and can reach the DUT first, tearing connections down for
reasons that have nothing to do with the DUT under test.

A Windows Firewall block rule is not a reliable fix here: WFP's inbound
filtering did not intercept this traffic in practice (confirmed via empty
`LogBlocked` output) on at least one virtual-switch/bridged host topology,
so tcpip.sys still saw the segment and generated the RST regardless of the
rule. WinDivert intercepts at the NDIS layer, below both tcpip.sys and WFP,
so a packet captured here never reaches the OS stack at all — while Npcap's
independent adapter tap (which Scapy's send/receive/sniff use) is
unaffected, since it observes the wire separately.
"""
from __future__ import annotations

import logging
import platform
import threading

from src.config import EPHEMERAL_PORT_RANGE

log = logging.getLogger(__name__)


class HostRstGuard:
    """Diverts (and drops) inbound TCP segments addressed to `local_ip`
    within the suite's ephemeral source-port range, for as long as it's
    running. Windows-only; construct via `start_for_host()`."""

    def __init__(self, local_ip: str) -> None:
        port_low, port_high = EPHEMERAL_PORT_RANGE
        self._filter = (
            f"tcp and ip.DstAddr == {local_ip} "
            f"and tcp.DstPort >= {port_low} and tcp.DstPort <= {port_high}"
        )
        self._handle = None
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        import pydivert

        self._handle = pydivert.WinDivert(self._filter, layer=pydivert.Layer.NETWORK)
        self._handle.open()
        self._thread = threading.Thread(target=self._run, name="rst-guard", daemon=True)
        self._thread.start()
        log.info("Host RST guard active: %s", self._filter)

    def _run(self) -> None:
        # `recv()` removes each matching packet from the OS's own processing
        # pipeline; never calling `send()` on it means it's dropped rather
        # than reinjected. `handle.close()` unblocks a pending recv() with an
        # OSError, which is this loop's normal exit.
        while True:
            try:
                self._handle.recv()
            except OSError:
                return

    def stop(self) -> None:
        if self._handle is not None:
            self._handle.close()
        if self._thread is not None:
            self._thread.join(timeout=2)


def start_for_host(local_ip: str) -> HostRstGuard | None:
    """Starts a guard for `local_ip` on Windows; a no-op (returns None) on
    every other host OS, where this interference doesn't occur the same
    way (platform_backend.py)."""
    if platform.system() != "Windows":
        return None

    guard = HostRstGuard(local_ip)
    guard.start()
    return guard
