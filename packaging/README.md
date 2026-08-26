# packaging — building the Windows executable

Turns the app into a single, double-clickable Windows `.exe` that runs as
Administrator (needed for raw sockets), with no Python install required on
the target machine.

## Build

```powershell
powershell -ExecutionPolicy Bypass -File packaging\build.ps1
```

Or directly:

```bash
python -m PyInstaller NetstackTestSuite.spec --noconfirm
```

Output:

| File | What it is |
|---|---|
| `dist\NetstackTestSuite.exe` | The app. **Double-click to run** — it self-elevates via UAC. No install step needed. |
| `dist\NetstackTestSuite-Setup.exe` | A proper installer (Start Menu + optional desktop shortcut), built **only if Inno Setup is installed** (see below). |

## How it works

The exe is **both the GUI and the pytest worker**. The app runs tests by
launching a subprocess — but a frozen exe has no `python -m pytest`, so the
runner re-invokes the exe itself with a sentinel argument
(`--__run_pytest__`); [`src/gui/app.py`](../src/gui/app.py) routes that to
`pytest.main()`. The `tests/` tree, `conftest.py`, `pyproject.toml`, and
all of `src` (plus scapy, pytest, and the report-log plugin) are bundled
by [`NetstackTestSuite.spec`](../NetstackTestSuite.spec). Run artifacts
(reports, `.pcap` captures, debug logs) are written to a `reports\` folder
**next to the exe** — not the read-only temp dir the bundle extracts to.
See [`src/paths.py`](../src/paths.py) (`reports_base` vs. `project_root`).

A frozen build loses pytest's entry-point plugin discovery, so the runner
force-loads the report-log plugin with `-p pytest_reportlog.plugin`.

## Requirements on the target machine

- **Npcap** (https://npcap.com) — the exe bundles scapy but *not* the Npcap
  driver, which raw packet capture needs. Install it with "Restrict …to
  Administrators only" **unchecked**. (Most machines that have run the app
  from source already have it.)
- Nothing else — Python and all libraries are inside the exe.

## Building the installer (optional)

The single exe already satisfies "double-click and run". For a formal
installer with Start Menu shortcuts, install
[Inno Setup 6](https://jrsoftware.org/isdl.php), then re-run
`packaging\build.ps1` (it detects `ISCC.exe` and compiles
[`installer.iss`](installer.iss)), or compile directly:

```
"C:\Program Files (x86)\Inno Setup 6\ISCC.exe" packaging\installer.iss
```

## Notes

- The single-file exe extracts to a temp dir on each launch, so first start
  takes a few seconds. For faster startup, switch the spec to a one-dir
  build (`COLLECT`) — it produces a folder instead of one file.
- `tests_internal/` (the framework's own dev self-tests) is intentionally
  **not** bundled — it depends on dev-only packages and isn't part of the
  shipped product.
