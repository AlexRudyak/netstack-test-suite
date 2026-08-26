"""Live metrics buffer: accumulates PacketEvents, hands out plot snapshots.

Packet events can arrive far faster than any UI can render (a SYN flood
test emits thousands of events in milliseconds). This buffer decouples
ingestion (cheap, thread-safe append from NetworkInterface's callback,
possibly from a background/subprocess-reading thread) from rendering
(pulled on a timer by the plot widget) — see realtime_plotter.py.

Cumulative series are maintained *incrementally* on each `add()` rather
than recomputed from scratch in `snapshot()`. The plot pulls a snapshot
~25x/second; recomputing five cumulative arrays over the whole history on
every tick was O(n) per tick (O(n·ticks) overall) and dominated cost on
large captures. `add()` is now O(1) amortized and `snapshot()` is a plain
copy. `max_points` bounds memory (and the drawn point count) by dropping
the oldest samples — a rolling window, which is what a live view wants.
"""
from __future__ import annotations

import threading
from collections import deque
from dataclasses import dataclass

from src.reporting.models import PacketDirection, PacketEvent


@dataclass
class MetricsSnapshot:
    elapsed_s: list[float]
    sent_cumulative: list[int]
    received_cumulative: list[int]
    bytes_sent_cumulative: list[int]
    bytes_received_cumulative: list[int]


class MetricsBuffer:
    """Thread-safe accumulator fed by NetworkInterface's on_packet callback."""

    def __init__(self, max_points: int = 100_000) -> None:
        self._lock = threading.Lock()
        self._start_time: float | None = None
        self._sent = self._received = 0
        self._bytes_sent = self._bytes_received = 0
        # Parallel rolling windows; bounded so a long capture can't grow
        # memory (or the plotted point count) without limit.
        self._elapsed: deque[float] = deque(maxlen=max_points)
        self._sent_cum: deque[int] = deque(maxlen=max_points)
        self._recv_cum: deque[int] = deque(maxlen=max_points)
        self._bytes_sent_cum: deque[int] = deque(maxlen=max_points)
        self._bytes_recv_cum: deque[int] = deque(maxlen=max_points)

    def add(self, event: PacketEvent) -> None:
        with self._lock:
            if self._start_time is None:
                self._start_time = event.timestamp
            if event.direction is PacketDirection.SENT:
                self._sent += 1
                self._bytes_sent += event.size_bytes
            else:
                self._received += 1
                self._bytes_received += event.size_bytes
            self._elapsed.append(event.timestamp - self._start_time)
            self._sent_cum.append(self._sent)
            self._recv_cum.append(self._received)
            self._bytes_sent_cum.append(self._bytes_sent)
            self._bytes_recv_cum.append(self._bytes_received)

    def snapshot(self) -> MetricsSnapshot:
        with self._lock:
            return MetricsSnapshot(
                list(self._elapsed),
                list(self._sent_cum),
                list(self._recv_cum),
                list(self._bytes_sent_cum),
                list(self._bytes_recv_cum),
            )

    def clear(self) -> None:
        with self._lock:
            self._start_time = None
            self._sent = self._received = 0
            self._bytes_sent = self._bytes_received = 0
            for d in (
                self._elapsed,
                self._sent_cum,
                self._recv_cum,
                self._bytes_sent_cum,
                self._bytes_recv_cum,
            ):
                d.clear()
