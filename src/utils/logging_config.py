"""Central logging configuration, shared by the CLI and GUI entry points."""
from __future__ import annotations

import logging
import sys
from pathlib import Path

LOG_FORMAT = "%(asctime)s %(levelname)-8s %(name)s: %(message)s"
TIME_FORMAT = "%H:%M:%S"


def configure_logging(level: int = logging.INFO, *, log_file: Path | None = None) -> None:
    """Console logging, plus an optional durable file.

    The file matters for the GUI. Its log panel is cleared at the start of
    every run and capped at 10,000 blocks, so without one the only record of
    a failed run is destroyed by starting the next one — and the GUI has no
    terminal to fall back on.

    `force=True` so a second call actually reconfigures: basicConfig is a
    no-op once the root logger has handlers, which would silently ignore a
    later --verbose.
    """
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stdout)]
    failure: OSError | None = None
    if log_file is not None:
        try:
            log_file.parent.mkdir(parents=True, exist_ok=True)
            handlers.append(logging.FileHandler(log_file, encoding="utf-8"))
        except OSError as exc:
            # An unwritable log destination must not stop the app starting;
            # the console handler still carries everything. Reported below
            # rather than here, because there is nowhere to report it to
            # until basicConfig has installed that handler.
            failure = exc
    logging.basicConfig(
        level=level,
        format=LOG_FORMAT,
        datefmt=TIME_FORMAT,
        handlers=handlers,
        force=True,
    )
    if failure is not None:
        logging.getLogger(__name__).warning(
            "Could not open the log file %s: %s. Logging to the console only — "
            "the GUI's log panel is cleared at the start of every run, so a "
            "failed run will leave no durable record.",
            log_file,
            failure,
        )
