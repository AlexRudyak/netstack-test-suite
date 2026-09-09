# PyInstaller spec — builds the single-file NetstackTestSuite app.
#
# Build:  python -m PyInstaller NetstackTestSuite.spec --noconfirm
# Output: dist/NetstackTestSuite.exe   (Windows)
#         dist/NetstackTestSuite       (Linux — a self-contained ELF binary)
#
# One spec, both platforms: the only differences are Windows-only options
# (the UAC admin manifest), guarded by sys.platform below. On Linux there
# is no UAC — raw sockets need root, or grant the binary the capability once
# with:  sudo setcap cap_net_raw,cap_net_admin+eip ./NetstackTestSuite
#
# The app is BOTH the GUI and the pytest worker: the runner re-invokes it
# with a sentinel arg to run tests (a frozen build has no `python -m pytest`),
# so pytest, its plugins, and the tests/ tree must all be bundled.
import os
import sys

from PyInstaller.utils.hooks import collect_submodules, collect_data_files

project_root = os.path.abspath(".")
is_windows = sys.platform == "win32"

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

exe_kwargs = dict(
    name="NetstackTestSuite",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,  # windowed GUI (no console)
    disable_windowed_traceback=False,
)
if is_windows:
    exe_kwargs["uac_admin"] = True  # request Administrator via UAC on launch

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    **exe_kwargs,
)
