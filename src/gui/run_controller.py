"""Drives a test run via QProcess so the Qt event loop is never blocked.

Uses src/runner.py's `build_pytest_args` so a GUI-triggered run is
byte-for-byte the same pytest invocation the CLI would produce, and
reuses its `drain_test_events`/`drain_packet_events` file-tailing
helpers (polled here on a QTimer instead of runner.py's blocking loop)
so the two front ends never drift into parsing results differently.
"""
from __future__ import annotations

import json
import platform
from datetime import datetime, timezone
from pathlib import Path

from PySide6.QtCore import QObject, QProcess, QTimer, Signal

from src import paths
from src.reporting.models import TestRunResult
from src.runner import RunRequest, build_pytest_args, drain_packet_events, drain_test_events, new_run_dir

POLL_INTERVAL_MS = 200


class RunController(QObject):
    test_event = Signal(object)  # emits TestEvent
    packet_event = Signal(object)  # emits PacketEvent
    output_line = Signal(str)
    finished = Signal(object)  # emits the completed TestRunResult

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._process: QProcess | None = None
        self._timer = QTimer(self)
        self._timer.setInterval(POLL_INTERVAL_MS)
        self._timer.timeout.connect(self._poll)
        self._result: TestRunResult | None = None
        self._run_dir: Path | None = None
        self._report_offset = 0
        self._events_offset = 0

    def start(self, request: RunRequest) -> None:
        run_id, run_dir = new_run_dir()
        self._run_dir = run_dir
        self._report_offset = 0
        self._events_offset = 0
        self._result = TestRunResult(
            run_id=run_id,
            started_at=datetime.now(timezone.utc),
            finished_at=None,
            target_ip=request.config.target_ip,
            target_stack=request.config.target_stack,
            host_platform=platform.system(),
            payload_mode=request.payload_mode.value,
        )

        args = build_pytest_args(request, run_dir)
        self._process = QProcess(self)
        # Relative test paths resolve against the project root in both source
        # and frozen builds (matches src/runner.stream_run).
        self._process.setWorkingDirectory(str(paths.project_root()))
        self._process.setProcessChannelMode(QProcess.ProcessChannelMode.MergedChannels)
        self._process.readyReadStandardOutput.connect(self._on_output)
        self._process.finished.connect(self._on_finished)
        self._process.start(args[0], args[1:])
        self._timer.start()

    def stop(self) -> None:
        if self._process is not None and self._process.state() != QProcess.ProcessState.NotRunning:
            self._process.kill()

    def _on_output(self) -> None:
        assert self._process is not None
        data = bytes(self._process.readAllStandardOutput()).decode("utf-8", errors="replace")
        for line in data.splitlines():
            self.output_line.emit(line)

    def _poll(self) -> None:
        self._drain()

    def _drain(self) -> None:
        assert self._run_dir is not None and self._result is not None
        self._report_offset = drain_test_events(
            self._run_dir / "report_log.jsonl",
            self._report_offset,
            self._result,
            lambda event: self.test_event.emit(event),
        )
        self._events_offset = drain_packet_events(
            self._run_dir / "packet_events.jsonl",
            self._events_offset,
            self._result,
            lambda event: self.packet_event.emit(event),
        )

    def _on_finished(self, exit_code: int, exit_status: QProcess.ExitStatus) -> None:
        self._timer.stop()
        self._drain()
        assert self._result is not None and self._run_dir is not None
        self._result.pytest_returncode = exit_code
        self._result.finished_at = datetime.now(timezone.utc)
        (self._run_dir / "results.json").write_text(
            json.dumps(self._result.to_dict(), indent=2), encoding="utf-8"
        )
        self.finished.emit(self._result)
