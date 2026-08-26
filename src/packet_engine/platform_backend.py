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


@dataclass
class WindowsBackend:
    host_name: str = "Windows"

    def configure(self) -> None:
        from scapy.config import conf

        conf.use_pcap = True  # force Npcap-backed L2 sockets


@dataclass
class LinuxBackend:
    host_name: str = "Linux"

    def configure(self) -> None:
        from scapy.config import conf

        conf.use_pcap = False  # native AF_PACKET, no libpcap dependency required


def get_backend() -> SocketBackend:
    system = platform.system()
    if system == "Windows":
        return WindowsBackend()
    if system == "Linux":
        return LinuxBackend()
    raise RuntimeError(
        f"Unsupported host platform: {system!r}. "
        "This suite supports running on Windows and Linux hosts."
    )
