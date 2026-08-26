"""Application-layer (L7) payload generation for crafted packets.

Payload content is deliberately pluggable rather than hardcoded per test:
the same four modes are offered uniformly to the automated suite (via the
--payload-mode/--payload-size pytest options), the CLI `send` subcommand,
and the GUI's custom packet panel.

This module only produces *bytes* to ride inside a Raw() layer on top of an
IP/TCP/UDP packet built by builders.py — it has no L7 protocol awareness
(no HTTP/DNS parsing), keeping the suite's scope at L3/L4 as intended.
"""
from __future__ import annotations

import os
from enum import Enum
from pathlib import Path


class PayloadMode(Enum):
    ZEROS = "zeros"
    ONES = "ones"
    RANDOM = "random"
    CUSTOM = "custom"


def zeros(size: int) -> bytes:
    return b"\x00" * size


def ones(size: int) -> bytes:
    """Bit-pattern all-1s (0xFF fill), not the ASCII character '1'."""
    return b"\xff" * size


def random_bytes(size: int) -> bytes:
    return os.urandom(size)


def from_text(text: str) -> bytes:
    return text.encode("utf-8")


def from_hex(hex_str: str) -> bytes:
    return bytes.fromhex(hex_str.replace(" ", "").replace(":", ""))


def from_file(path: str | Path) -> bytes:
    return Path(path).read_bytes()


def resolve_payload(
    mode: PayloadMode,
    size: int = 0,
    custom: bytes | None = None,
) -> bytes:
    """Single dispatcher used by every payload-consuming caller.

    For ZEROS/ONES/RANDOM, `size` is required. For CUSTOM, `custom` bytes
    must already be resolved by the caller (from text/hex/file — that
    resolution is a CLI/GUI input-parsing concern, not this function's).
    """
    if mode is PayloadMode.ZEROS:
        return zeros(size)
    if mode is PayloadMode.ONES:
        return ones(size)
    if mode is PayloadMode.RANDOM:
        return random_bytes(size)
    if mode is PayloadMode.CUSTOM:
        if custom is None:
            raise ValueError("PayloadMode.CUSTOM requires `custom` bytes")
        return custom
    raise ValueError(f"Unhandled PayloadMode: {mode!r}")
