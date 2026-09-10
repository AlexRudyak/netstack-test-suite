"""Per-host-OS socket backend selection.

This is orthogonal to `src/target_profiles/` — that module describes what
OS stack the *DUT* is expected to behave like (a user choice); this module
describes what OS the test suite itself is *running on* (an environment
fact, auto-detected). All four combinations of {host, target} are valid.

Both backends operate at L2 (Ethernet) exclusively:
- Windows: L3 raw send is unreliable regardless of Npcap; Npcap-backed L2
  sockets are the one consistently working path.
- Linux: native AF_PACKET L2 sockets work with no extra driver and are
  more efficient than routing through libpcap.

Standardizing on L2-only isn't a Windows workaround — it's the strategy
that behaves identically on both host platforms.
"""
from __future__ import annotations

import platform
from dataclasses import dataclass
from typing import Protocol

SUPPORTED_HOSTS = ("Windows", "Linux")


def unsupported_host_message(system: str) -> str:
    """One wording for the host-OS check, shared with src/utils/permissions.py."""
    return (
        f"Unsupported host platform: {system!r}. This suite supports running on "
        f"{' and '.join(SUPPORTED_HOSTS)} hosts."
    )


class SocketBackend(Protocol):
    host_name: str

    def configure(self) -> None:
        """Apply Scapy `conf` settings appropriate for this host OS.

        This is the whole backend contract: once `conf` is configured,
        interface.py uses Scapy's standard sendp/srp1/sniff, which pick
        the right L2 socket class themselves — so the backend never needs
        to hand out a socket class of its own.
        """
        ...


@dataclass(frozen=True)
class ScapyConfBackend:
    """One backend, parameterised by the single setting that differs.

    Two classes stood here whose `configure()` bodies differed only in the
    boolean they assigned. The seam itself stays — `NetworkInterface` and
    `PacketRecorder` both accept a `backend=`, and the self-tests pass a
    stub through it — but the seam is the Protocol, not the class count.
    """

    host_name: str
    use_pcap: bool

    def configure(self) -> None:
        from scapy.config import conf

        conf.use_pcap = self.use_pcap


# Scapy's `conf` is process-global, so `configure()` is a last-writer-wins
# assignment. Nothing in the app holds two backends at once (each front end
# runs one host OS), but that is why these are frozen singletons rather
# than freshly constructed per call — there is only ever one right answer
# per host.
_BACKENDS: dict[str, SocketBackend] = {
    # Windows: force Npcap-backed L2 sockets.
    "Windows": ScapyConfBackend("Windows", use_pcap=True),
    # Linux: native AF_PACKET, no libpcap dependency required.
    "Linux": ScapyConfBackend("Linux", use_pcap=False),
}


def get_backend() -> SocketBackend:
    system = platform.system()
    try:
        return _BACKENDS[system]
    except KeyError:
        raise RuntimeError(unsupported_host_message(system)) from None
