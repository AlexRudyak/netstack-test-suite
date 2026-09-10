"""Drives a test run via QProcess so the Qt event loop is never blocked.

Uses src/runner.py's `build_pytest_args` so a GUI-triggered run is
byte-for-byte the same pytest invocation the CLI would produce, and
reuses its `drain_test_events`/`drain_packet_events` file-tailing
helpers (polled here on a QTimer instead of runner.py's blocking loop)
so the two front ends never drift into parsing results differently.
"""
from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QObject, QProcess, QTimer, Signal

from src import paths
from src.reporting.models import TestRunResult
from src.run_artifacts import RunArtifacts
from src.runner import (
    RunRequest,
    build_pytest_args,
    drain_packet_events,
    drain_test_events,
    finalize_run,
    new_run_dir,
    new_run_result,
)

POLL_INTERVAL_MS = 200


class RunController(QObject):
    test_event = Signal(object)  # emits TestEvent
    packet_event = Signal(object)  # emits PacketEvent
    output_line = Signal(str)
    finished = Signal(object)  # emits the completed TestRunResult
    failed = Signal(str)  # emits why the runner could not be started

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
        self._result = new_run_result(run_id, request)

        args = build_pytest_args(request, run_dir)
        self._process = QProcess(self)
        # Relative test paths resolve against the project root in both source
        # and frozen builds (matches src/runner.stream_run).
        self._process.setWorkingDirectory(str(paths.project_root()))
        self._process.setProcessChannelMode(QProcess.ProcessChannelMode.MergedChannels)
        self._process.readyReadStandardOutput.connect(self._on_output)
        self._process.finished.connect(self._on_finished)
        self._process.errorOccurred.connect(self._on_error)
        # Start polling *before* launching: QProcess.start emits
        # errorOccurred synchronously on FailedToStart, so a timer started
        # afterwards would outlive the handler that stops it.
        self._timer.start()
        self._process.start(args[0], args[1:])

    def stop(self) -> None:
        if self._process is not None and self._process.state() != QProcess.ProcessState.NotRunning:
            self._process.kill()
        else:
            # Nothing is running to deliver `finished`, so the poll timer
            # would otherwise keep tailing files that will never grow.
            self._timer.stop()

    def _on_error(self, error: QProcess.ProcessError) -> None:
        """A QProcess that never starts never emits `finished`.

        Without this the run's QTimer polls a report log that will never be
        created, `finalize_run` is never called, and the Log tab shows
        "Starting run…" and then nothing at all — for a missing interpreter,
        a frozen build whose sys.executable moved, or an unreadable working
        directory.

        Crashed/Timedout still deliver `finished`, so only FailedToStart is
        handled here; anything else would double-report the run.
        """
        if error is not QProcess.ProcessError.FailedToStart:
            return
        self._timer.stop()
        reason = self._process.errorString() if self._process is not None else "unknown error"
        self.failed.emit(f"Could not start the test runner: {reason}")
        if self._result is not None and self._run_dir is not None:
            # No return code: the process never ran, so there is none to
            # report. finalize_run still writes results.json, which keeps a
            # failed launch visible in the reports directory.
            self.finished.emit(finalize_run(self._result, self._run_dir, None))

    def _on_output(self) -> None:
        assert self._process is not None
        data = bytes(self._process.readAllStandardOutput()).decode("utf-8", errors="replace")
        for line in data.splitlines():
            self.output_line.emit(line)

    def _poll(self) -> None:
        self._drain()

    def _drain(self) -> None:
        assert self._run_dir is not None and self._result is not None
        artifacts = RunArtifacts(self._run_dir)
        self._report_offset = drain_test_events(
            artifacts.report_log,
            self._report_offset,
            self._result,
            lambda event: self.test_event.emit(event),
        )
        self._events_offset = drain_packet_events(
            artifacts.packet_events,
            self._events_offset,
            self._result,
            lambda event: self.packet_event.emit(event),
        )

    def _on_finished(self, exit_code: int, exit_status: QProcess.ExitStatus) -> None:
        self._timer.stop()
        self._drain()
        assert self._result is not None and self._run_dir is not None
        self.finished.emit(finalize_run(self._result, self._run_dir, exit_code))
