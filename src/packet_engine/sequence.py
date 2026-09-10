"""TCP sequence/ack number tracking for one logical connection under test."""
from __future__ import annotations

import random
from dataclasses import dataclass

from src.utils.tcp_flags import MAX_SEQ, seq32

__all__ = ["MAX_SEQ", "TCPSequenceTracker"]


@dataclass
class TCPSequenceTracker:
    """Tracks local seq/ack for a hand-crafted TCP connection.

    Not RFC 6528 ISN-generation logic itself (that's what
    tests/tcp/syn/test_sequence_prediction.py evaluates on the DUT) —
    this is just local bookkeeping so a test can build the next segment
    in a multi-packet exchange without recomputing seq/ack by hand.
    """

    seq: int
    ack: int = 0

    @classmethod
    def new(cls) -> "TCPSequenceTracker":
        return cls(seq=random.randint(0, MAX_SEQ))

    def on_send(self, payload_len: int, *, syn: bool = False, fin: bool = False) -> int:
        """Returns the seq number used for the segment just sent, then advances."""
        sent_seq = self.seq
        self.seq = seq32(self.seq + payload_len + (1 if syn or fin else 0))
        return sent_seq

    def on_receive(self, remote_seq: int, payload_len: int, *, syn: bool = False, fin: bool = False) -> None:
        """Updates our ack to acknowledge a received segment."""
        self.ack = seq32(remote_seq + payload_len + (1 if syn or fin else 0))
