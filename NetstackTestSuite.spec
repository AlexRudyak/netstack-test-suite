# PyInstaller spec — builds NetstackTestSuite.exe (single-file, UAC admin).
#
# Build:  python -m PyInstaller NetstackTestSuite.spec --noconfirm
# Output: dist/NetstackTestSuite.exe
#
# The exe is BOTH the GUI and the pytest worker: the runner re-invokes it
# with a sentinel arg to run tests (a frozen exe has no `python -m pytest`),
# so pytest, its plugins, and the tests/ tree must all be bundled.
import os

from PyInstaller.utils.hooks import collect_submodules, collect_data_files

project_root = os.path.abspath(".")

# The suite runs pytest against these on disk, and the GUI reads tests/ to
# populate the tree — bundle them as data at the extraction root.
datas = [
    ("tests", "tests"),  # the DUT test suite the app runs (tests_internal is dev-only, not shipped)
    ("conftest.py", "."),
    ("pyproject.toml", "."),
]
# Config/data files pytest and its reportlog plugin ship.
datas += collect_data_files("pytest")
datas += collect_data_files("_pytest")

# pytest and scapy import plugins/layers dynamically — collect them so the
# frozen build can find them.
hiddenimports = []
hiddenimports += collect_submodules("_pytest")
hiddenimports += collect_submodules("pytest_reportlog")
hiddenimports += collect_submodules("scapy")
# The GUI import graph doesn't reach every src module (responder, recorder,
# cli, custom_packet…) but the bundled tests import them at runtime, so
# collect the whole package.
hiddenimports += collect_submodules("src")
hiddenimports += ["pytest", "pluggy", "conftest"]

a = Analysis(
    ["packaging/app_entry.py"],
    pathex=[project_root],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=["tkinter"],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="NetstackTestSuite",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,        # windowed GUI (no console)
    uac_admin=True,       # request Administrator via UAC on launch
    disable_windowed_traceback=False,
)
