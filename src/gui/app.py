"""GUI entry point (`netstack-gui`) and the frozen exe's entry point.

Two responsibilities before the window opens:

1. **Frozen pytest worker.** A packaged `.exe` has no `python -m pytest`,
   so the runner re-invokes the exe with a sentinel first argument; when we
   see it, we run `pytest.main()` and exit instead of opening the GUI.
2. **Self-elevation.** The suite needs Administrator for raw sockets, so on
   Windows the GUI relaunches itself elevated via UAC (the packaged exe
   also carries a UAC manifest), rather than requiring an admin shell.
"""
from __future__ import annotations

import logging
import sys

from src.paths import PYTEST_SENTINEL


def main() -> None:
    # Frozen worker mode — must run before importing Qt (this process is a
    # short-lived pytest subprocess re-invoked by the runner, not a GUI).
    if len(sys.argv) > 1 and sys.argv[1] == PYTEST_SENTINEL:
        import pytest

        raise SystemExit(pytest.main(sys.argv[2:]))

    from PySide6.QtWidgets import QApplication

    from src.gui.main_window import MainWindow
    from src.utils.logging_config import configure_logging
    from src.utils.permissions import ElevationResult, relaunch_module_as_admin

    log = logging.getLogger(__name__)
    configure_logging()

    # Self-elevate on Windows before opening the window. If an elevated copy
    # is launched, exit so only it runs. If UAC is declined, continue
    # non-elevated — the preflight check will then explain the privilege
    # requirement when a run is attempted.
    outcome = relaunch_module_as_admin("src.gui.app")
    if outcome == ElevationResult.RELAUNCHED:
        log.info("Relaunching elevated via UAC; exiting non-elevated instance.")
        return
    if outcome == ElevationResult.DECLINED:
        log.warning(
            "Elevation was declined — running without Administrator. "
            "Test runs will report the privilege requirement until you re-launch elevated."
        )

    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
