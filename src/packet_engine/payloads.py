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
from collections.abc import Callable
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


def resolve_custom_source(
    *,
    text: str | None = None,
    hex_str: str | None = None,
    file: str | Path | None = None,
) -> bytes | None:
    """Resolve CUSTOM payload bytes from the first source that is set.

    Precedence is text > hex > file, matching every front end (CLI `send`,
    the pytest `payload_settings` fixture, and the GUI's custom packet
    panel). Returns None when no source is given, so each caller raises its
    own idiomatic "custom mode needs a source" error (click.UsageError /
    pytest.UsageError / ValueError) rather than this module inventing a
    shared exception type they'd all have to catch and translate.
    """
    if text:
        return from_text(text)
    if hex_str:
        return from_hex(hex_str)
    if file:
        return from_file(file)
    return None


# The size-driven modes, as a table. The three generators already share a
# one-argument signature, so the branch structure they used to sit behind
# was pure ceremony: a new mode meant editing the enum *and* the chain.
#
# CUSTOM is deliberately absent — its bytes come from the caller, not from
# a generator over `size`.
_GENERATORS: dict[PayloadMode, Callable[[int], bytes]] = {
    PayloadMode.ZEROS: zeros,
    PayloadMode.ONES: ones,
    PayloadMode.RANDOM: random_bytes,
}


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
    if mode is PayloadMode.CUSTOM:
        if custom is None:
            raise ValueError("PayloadMode.CUSTOM requires `custom` bytes")
        return custom
    try:
        return _GENERATORS[mode](size)
    except KeyError:
        raise ValueError(f"Unhandled PayloadMode: {mode!r}") from None
