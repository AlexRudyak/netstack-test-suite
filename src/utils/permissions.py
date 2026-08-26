"""Privilege checks with OS-specific remediation guidance.

Windows needs Administrator (or Npcap installed with non-restricted
access). Linux needs root, or — preferred, since this suite ships a GUI
and running Qt apps as root causes its own problems — CAP_NET_RAW /
CAP_NET_ADMIN granted to the interpreter via setcap.
"""
from __future__ import annotations

import os
import platform
import subprocess
import sys


class InsufficientPrivilegesError(RuntimeError):
    pass


def is_elevated() -> bool:
    system = platform.system()
    if system == "Windows":
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        except Exception:
            return False
    if system == "Linux":
        if os.geteuid() == 0:
            return True
        return _has_linux_capabilities()
    raise RuntimeError(f"Unsupported host platform: {system!r}")


def _has_linux_capabilities() -> bool:
    """Best-effort check for CAP_NET_RAW/CAP_NET_ADMIN via getcap on the interpreter."""
    interpreter = os.path.realpath(sys.executable)
    try:
        result = subprocess.run(
            ["getcap", interpreter], capture_output=True, text=True, timeout=5
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False
    return "cap_net_raw" in result.stdout and "cap_net_admin" in result.stdout


def remediation_message() -> str:
    system = platform.system()
    if system == "Windows":
        return (
            "Raw Ethernet access requires Administrator privileges, or Npcap "
            "installed with 'Restrict Npcap driver's access to Administrators "
            "only' UNCHECKED during setup. Re-run as Administrator, or "
            "reinstall Npcap with that option disabled."
        )
    if system == "Linux":
        interpreter = os.path.realpath(sys.executable)
        return (
            "Raw Ethernet access requires root, or (recommended — running "
            "the GUI as root is discouraged) grant capabilities once to the "
            f"interpreter:\n  sudo setcap cap_net_raw,cap_net_admin+eip {interpreter}"
        )
    return f"Unsupported host platform: {system!r}"


def require_elevation() -> None:
    if not is_elevated():
        raise InsufficientPrivilegesError(remediation_message())


class ElevationResult:
    """Outcome of an auto-elevation attempt."""

    ALREADY = "already_elevated"  # running with sufficient privileges
    RELAUNCHED = "relaunched"  # an elevated copy was started; caller should exit
    DECLINED = "declined"  # UAC prompt was declined/failed; continue non-elevated
    UNSUPPORTED = "unsupported"  # not Windows; can't silently self-elevate


def relaunch_module_as_admin(module: str = "src.gui.app") -> str:
    """On Windows, relaunch the current process elevated via UAC (the
    standard pattern for tools that need raw-socket access, like packet
    capture apps).

    Returns an `ElevationResult`:
    - ALREADY   — already elevated, nothing to do.
    - RELAUNCHED — an elevated instance was started; the caller MUST exit so
      only the elevated copy runs.
    - DECLINED  — the user dismissed the UAC prompt (or it failed); the
      caller should continue non-elevated (a preflight check will then
      surface the privilege message).
    - UNSUPPORTED — not Windows; auto-elevation isn't attempted (Linux uses
      root or a one-time `setcap`; see `remediation_message`).

    Re-invokes `python -m <module>` so it works whether launched as the
    console script or via `-m`. The elevated instance re-enters this
    function, finds itself elevated, and returns ALREADY (no relaunch loop).
    """
    if platform.system() != "Windows":
        return ElevationResult.UNSUPPORTED
    if is_elevated():
        return ElevationResult.ALREADY

    # Frozen build: sys.executable IS the app exe, so relaunch it directly.
    # Source: relaunch `python -m <module>`. (The packaged exe also carries a
    # UAC manifest, so it's usually already elevated and returns ALREADY.)
    if getattr(sys, "frozen", False):
        params = subprocess.list2cmdline(sys.argv[1:])
    else:
        params = subprocess.list2cmdline(["-m", module, *sys.argv[1:]])
    rc = _shell_execute_runas(sys.executable, params, os.getcwd())
    return ElevationResult.RELAUNCHED if rc > 32 else ElevationResult.DECLINED


def _shell_execute_runas(program: str, params: str, directory: str) -> int:
    """Trigger a UAC-elevated relaunch. Returns ShellExecuteW's HINSTANCE
    result (> 32 on success). Isolated so the decision logic above stays
    unit-testable without actually elevating."""
    import ctypes

    return int(
        ctypes.windll.shell32.ShellExecuteW(  # type: ignore[attr-defined]
            None, "runas", program, params, directory, 1  # verb runas, SW_SHOWNORMAL
        )
    )
