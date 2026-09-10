"""Unit tests for src/packet_engine/payloads.py: generation, encoding
round-trips, and attach-point correctness across builders."""
from __future__ import annotations

import pytest

from src.packet_engine.builders import build_ip
from src.packet_engine.payloads import (
    PayloadMode,
    from_file,
    from_hex,
    from_text,
    ones,
    random_bytes,
    resolve_custom_source,
    resolve_payload,
    zeros,
)

pytestmark = [pytest.mark.internal]


def test_zeros_produces_correct_length_and_content() -> None:
    data = zeros(10)
    assert len(data) == 10
    assert data == b"\x00" * 10


def test_ones_is_bit_pattern_0xff_not_ascii_one() -> None:
    data = ones(4)
    assert data == b"\xff\xff\xff\xff"
    assert data != b"1111"


def test_random_bytes_has_correct_length() -> None:
    assert len(random_bytes(32)) == 32


def test_from_text_encodes_utf8() -> None:
    assert from_text("hello") == b"hello"


def test_from_hex_parses_with_and_without_separators() -> None:
    assert from_hex("deadbeef") == b"\xde\xad\xbe\xef"
    assert from_hex("de:ad:be:ef") == b"\xde\xad\xbe\xef"
    assert from_hex("de ad be ef") == b"\xde\xad\xbe\xef"


def test_from_file_reads_bytes(tmp_path) -> None:
    path = tmp_path / "payload.bin"
    path.write_bytes(b"\x01\x02\x03")
    assert from_file(path) == b"\x01\x02\x03"


@pytest.mark.parametrize(
    "mode,expected",
    [(PayloadMode.ZEROS, b"\x00" * 5), (PayloadMode.ONES, b"\xff" * 5)],
)
def test_resolve_payload_generated_modes(mode: PayloadMode, expected: bytes) -> None:
    assert resolve_payload(mode, size=5) == expected


def test_resolve_payload_random_has_correct_size() -> None:
    assert len(resolve_payload(PayloadMode.RANDOM, size=16)) == 16


def test_resolve_payload_custom_returns_given_bytes() -> None:
    assert resolve_payload(PayloadMode.CUSTOM, custom=b"xyz") == b"xyz"


def test_resolve_payload_custom_without_bytes_raises() -> None:
    with pytest.raises(ValueError):
        resolve_payload(PayloadMode.CUSTOM)


def test_payload_attaches_at_correct_offset_across_builders() -> None:
    payload = b"PAYLOAD"
    pkt = build_ip("10.0.0.1", "10.0.0.2", payload=payload)
    assert bytes(pkt).endswith(payload)


# --- resolve_custom_source: the text > hex > file precedence rule ----------
# Shared by CLI `send`, the payload_settings fixture and the GUI panel, all
# three of which previously implemented it separately.


def test_custom_source_precedence_is_text_then_hex_then_file(tmp_path) -> None:
    path = tmp_path / "payload.bin"
    path.write_bytes(b"FROMFILE")

    assert resolve_custom_source(text="hi", hex_str="4142", file=path) == b"hi"
    assert resolve_custom_source(hex_str="4142", file=path) == b"AB"
    assert resolve_custom_source(file=path) == b"FROMFILE"


def test_custom_source_returns_none_when_no_source_given() -> None:
    """None, not an exception — each front end raises its own error type."""
    assert resolve_custom_source() is None
    assert resolve_custom_source(text="", hex_str="", file="") is None
