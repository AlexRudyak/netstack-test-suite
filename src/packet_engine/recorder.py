"""Passive on-wire packet recorder → .pcap.

Distinct from `NetworkInterface`'s per-run capture (which records the
packets the suite *programmatically* built and sent/received): this
recorder sniffs the actual Ethernet interface and writes what genuinely
crossed the wire — the app's outbound frames *and* the associated
inbound transmission (replies, retransmits, RSTs, ICMP errors). What's
on the wire is the ground truth; the programmatic capture can't see, for
example, a retransmit the OS did on the app's behalf or an asymmetric
reply path.

Runs independently of any test run: start it, exercise the DUT however
you like (a `send`, a GUI session, a manual poke), stop it. Writing is
incremental via PcapWriter so a long capture survives an abrupt exit and
lands on disk as packets are seen, not buffered until the end.

Scope stays L3/L4: the default BPF filter narrows to the conversation
with a given host, so the file captures the app's traffic and its
associated transmission rather than everything on the segment.
"""
from __future__ import annotations

import threading
from collections.abc import Callable
from pathlib import Path

from scapy.packet import Packet
from scapy.sendrecv import AsyncSniffer
from scapy.utils import PcapWriter

from src.errors import CaptureError
from src.packet_engine.pcap import open_pcap
from src.packet_engine.platform_backend import SocketBackend, get_backend

RecorderCallback = Callable[[Packet], None]


def build_host_filter(host_ip: str | None) -> str | None:
    """BPF filter capturing both directions of a conversation with one
    host — i.e. the app's outbound packets to it and the associated
    inbound transmission from it. None means capture everything the
    interface sees (still L2-filtered by the OS to this NIC)."""
    if not host_ip:
        return None
    return f"host {host_ip}"


class PacketRecorder:
    """Sniffs an interface and streams matching packets to a .pcap file.

    Thread-safe start/stop around Scapy's AsyncSniffer so a caller (the
    CLI `record` command, or a future GUI toggle) can run it in the
    background and stop it on Ctrl+C / a button without blocking.
    """

    def __init__(
        self,
        iface: str,
        output_path: Path,
        *,
        bpf_filter: str | None = None,
        on_packet: RecorderCallback | None = None,
        backend: SocketBackend | None = None,
    ) -> None:
        self.iface = iface
        self.output_path = output_path
        self.bpf_filter = bpf_filter
        # A list for the same reason as NetworkInterface's: one callback
        # meant a second consumer had to displace the first.
        self._sinks: list[RecorderCallback] = [on_packet] if on_packet is not None else []
        self._backend = backend or get_backend()
        self._backend.configure()

        self._lock = threading.Lock()
        self._packet_count = 0
        self._writer: PcapWriter | None = None
        self._sniffer: AsyncSniffer | None = None

    @property
    def packet_count(self) -> int:
        with self._lock:
            return self._packet_count

    def subscribe(self, sink: RecorderCallback) -> None:
        """Add a sink called from the sniffer thread for every matching
        frame. Sinks run in subscription order; a sink that blocks holds up
        the capture, so keep them cheap."""
        self._sinks.append(sink)

    def _handle(self, packet: Packet) -> None:
        # Called from the sniffer thread for every matching frame.
        assert self._writer is not None
        self._writer.write(packet)  # incremental flush to disk
        with self._lock:
            self._packet_count += 1
        for sink in self._sinks:
            sink(packet)

    def start(self, *, count: int = 0, timeout: float | None = None) -> None:
        """Begin recording. Non-blocking — returns immediately while the
        sniffer runs in its own thread. `count`/`timeout` (0/None =
        unbounded) let the sniffer stop itself; otherwise call stop()."""
        self._writer = open_pcap(self.output_path)
        self._sniffer = AsyncSniffer(
            iface=self.iface,
            filter=self.bpf_filter,
            prn=self._handle,
            store=False,  # never accumulate in RAM; the file is the record
            count=count,
            timeout=timeout,
        )
        self._sniffer.start()

    def join(self) -> None:
        """Block until a count/timeout-bounded capture finishes on its own."""
        try:
            if self._sniffer is not None:
                self._sniffer.join()
        except Exception as exc:
            raise self._capture_error(exc) from exc
        finally:
            self._close_writer()

    def stop(self) -> int:
        """Stop an unbounded capture. Returns the number of packets written.

        Scapy sets AsyncSniffer.running *before* it opens the socket, so a
        capture that never started (bad interface, invalid BPF filter) leaves
        a dead thread with the exception stored on the sniffer — which
        `stop()` and `join()` then re-raise. Callers put this in a `finally:`
        (see cli.main.record), where an escaping exception skips the writer
        close, suppresses the "wrote N packets" line, and replaces a clean
        Ctrl+C exit with a raw traceback.

        So the failure is translated into a CaptureError the entry-point
        boundary can render, and the writer is closed either way.
        """
        try:
            if self._sniffer is not None and self._sniffer.running:
                self._sniffer.stop()
        except Exception as exc:
            raise self._capture_error(exc) from exc
        finally:
            self._close_writer()
        return self.packet_count

    def _capture_error(self, exc: Exception) -> CaptureError:
        return CaptureError(
            f"Capture on interface {self.iface!r} failed: {exc}. Check the interface "
            f"name and the BPF filter ({self.bpf_filter!r})."
        )

    def _close_writer(self) -> None:
        if self._writer is not None:
            self._writer.close()
            self._writer = None

    def __enter__(self) -> "PacketRecorder":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.stop()
