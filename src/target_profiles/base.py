"""Target stack behavioral profiles (RFC-defined vs. implementation-defined).

RFCs leave plenty of TCP/IP behavior implementation-defined (default TTL,
default window size, fragment reassembly timeout, retry counts). A test that
hardcodes one OS's numbers as "correct" will false-fail against an equally
RFC-compliant DUT that simply behaves like the other OS.

Every field on a TargetProfile is tagged with a Confidence:

- STRICT: the RFC actually mandates this behavior. It doesn't vary by target
  stack. It's included on the profile for convenience only — tests SHOULD
  assert it directly, not via profile comparison, since it must hold
  regardless of which profile is selected.
- INFORMATIONAL: an implementation characteristic, not an RFC requirement.
  Only use these for tests that are explicitly fingerprinting/comparing the
  DUT against a claimed target stack — never treat a mismatch here as an RFC
  violation.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Confidence(Enum):
    STRICT = "strict"
    INFORMATIONAL = "informational"


@dataclass(frozen=True)
class RangeField:
    """An inclusive numeric range with a confidence tag."""

    low: float
    high: float
    confidence: Confidence = Confidence.INFORMATIONAL

    def contains(self, value: float) -> bool:
        return self.low <= value <= self.high

    def __str__(self) -> str:  # pragma: no cover - cosmetic
        return f"[{self.low}, {self.high}] ({self.confidence.value})"


@dataclass(frozen=True)
class TargetProfile:
    """Reference behavioral values for a DUT claiming to be this stack."""

    name: str
    source: str  # citation/notes on where these reference numbers came from

    default_ttl: RangeField
    tcp_initial_window: RangeField
    frag_reassembly_timeout_s: RangeField
    syn_ack_retries: RangeField
