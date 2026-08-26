"""Path resolution that works both from source and from a frozen
(PyInstaller) build.

A frozen `.exe` has no `python -m pytest`, and its bundled data lives in a
temp extraction dir, not the current working directory. Everything that
needs to locate the test tree, the project root, or a writable output
directory goes through here so the same code runs in both modes.
"""
from __future__ import annotations

import sys
from pathlib import Path

# The runner re-invokes the frozen exe with this as argv[1] to run pytest
# as a subprocess (see src/gui/app.py and src/runner.py). Kept here — a
# dependency-free module — so the entry point can check it before importing
# anything heavy.
PYTEST_SENTINEL = "--__run_pytest__"


def is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def project_root() -> Path:
    """Directory containing tests/, conftest.py and pyproject.toml.

    Frozen: PyInstaller's extraction dir (`sys._MEIPASS`), where those files
    are bundled as data. Source: the repo root (parent of this `src/`),
    independent of the current working directory.
    """
    if is_frozen():
        return Path(getattr(sys, "_MEIPASS"))
    return Path(__file__).resolve().parents[1]


def tests_root() -> Path:
    return project_root() / "tests"


def reports_base() -> Path:
    """Writable base for run artifacts (reports/, pcaps, logs).

    Frozen: the directory the exe lives in (`sys.executable`'s folder) — so
    artifacts land next to the app, not in a temp folder. Note this is NOT
    the same as `project_root()`, which for a one-file build is the
    read-only temp extraction dir (`sys._MEIPASS`) where the bundled tests
    live. Source: the repo root, so artifacts land in `reports/`.
    """
    if is_frozen():
        return Path(sys.executable).resolve().parent
    return project_root()
