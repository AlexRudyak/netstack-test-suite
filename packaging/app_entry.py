"""PyInstaller entry point for the packaged app.

Thin wrapper around src.gui.app.main so the whole thing is driven by one
`main()` (which also handles the frozen pytest-worker sentinel and UAC
self-elevation).
"""
from src.gui.app import main

if __name__ == "__main__":
    main()
