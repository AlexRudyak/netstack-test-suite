"""Traffic inducer — makes a proxy's back leg emit traffic to observe.

The ordinary server-role tests wait for the DUT to initiate a connection.
An endpoint DUT does that on its own; a **proxy** only dials its origin
when a client drives traffic through the front. So when the endpoint
suites are pointed at a proxy's back leg (`--proxy-leg back`), something
has to keep opening connections through the front.

This does exactly that, in the background, for the duration of a test: it
repeatedly connects through the proxy and round-trips a small payload, so
the proxy keeps dialling the backend and the server-role responders have
something real to observe.

Failures are counted rather than raised — the proxy refusing or the origin
being unavailable is a *test result*, not an inducer error, and the test's
own assertions should report it.
"""
from __future__ import annotations

import threading

from src.proxy.client import ProxyClient
from src.proxy.config import ProxyConfig

DEFAULT_INTERVAL_S = 0.25
DEFAULT_PAYLOAD = b"netstack-induce"

# Consecutive failures after which the loop starts backing off, and the
# ceiling it backs off to. Ten at the default interval is ~2.5s of trying
# before conceding that the far side is not merely busy.
_BACKOFF_AFTER_FAILURES = 10
_MAX_BACKOFF_S = 5.0


class TrafficInducer:
    """Repeatedly drives connections through the proxy in a background thread."""

    def __init__(
        self,
        config: ProxyConfig,
        *,
        interval: float = DEFAULT_INTERVAL_S,
        payload: bytes = DEFAULT_PAYLOAD,
    ) -> None:
        self.config = config
        self.interval = interval
        self.payload = payload
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._attempts = 0
        self._successes = 0
        self._last_error: str | None = None
        # Tallied by exception type. Keeping only the last error meant a run
        # that failed identically thousands of times reported one string, and
        # a transient refusal looked the same as a permanent misconfiguration.
        self._error_counts: dict[str, int] = {}

    @property
    def attempts(self) -> int:
        with self._lock:
            return self._attempts

    @property
    def successes(self) -> int:
        with self._lock:
            return self._successes

    @property
    def last_error(self) -> str | None:
        with self._lock:
            return self._last_error

    def start(self) -> "TrafficInducer":
        if self._thread is not None:
            return self
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="proxy-traffic-inducer", daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=max(2.0, self.config.timeout))
            self._thread = None

    def __enter__(self) -> "TrafficInducer":
        return self.start()

    def __exit__(self, *exc_info: object) -> None:
        self.stop()

    def _loop(self) -> None:
        consecutive_failures = 0
        while not self._stop.is_set():
            with self._lock:
                self._attempts += 1
            try:
                with ProxyClient(self.config) as client:
                    client.roundtrip(self.payload)
            except Exception as exc:  # refusal/timeout is a DUT result, not our error
                consecutive_failures += 1
                with self._lock:
                    self._last_error = f"{type(exc).__name__}: {exc}"
                    name = type(exc).__name__
                    self._error_counts[name] = self._error_counts.get(name, 0) + 1
                # Back off once it is plainly not transient. The handler
                # cannot tell a refusal from an unresolvable backend host, and
                # at 4Hz the latter burns a whole session's worth of connect
                # attempts against something that will never answer.
                if consecutive_failures >= _BACKOFF_AFTER_FAILURES:
                    self._stop.wait(min(self.interval * consecutive_failures, _MAX_BACKOFF_S))
            else:
                consecutive_failures = 0
                with self._lock:
                    self._successes += 1
            self._stop.wait(self.interval)

    def summary(self) -> str:
        """One line at teardown. When nothing was induced, every server-role
        timeout in the run has this same root cause — so the breakdown by
        exception type is what tells the operator which one."""
        with self._lock:
            text = f"induced {self._successes}/{self._attempts} connections through the proxy"
            if self._error_counts:
                breakdown = ", ".join(
                    f"{name}x{count}" for name, count in sorted(self._error_counts.items())
                )
                text += f" (failures: {breakdown}; last: {self._last_error})"
            return text
