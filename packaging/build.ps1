# Build NetstackTestSuite.exe (and, if Inno Setup is present, the installer).
#
#   powershell -ExecutionPolicy Bypass -File packaging\build.ps1
#
# Produces:
#   dist\NetstackTestSuite.exe            — the app (double-click to run, self-elevates)
#   dist\NetstackTestSuite-Setup.exe      — installer (only if Inno Setup's ISCC is found)
#
# Run from the repo root, with the project's virtualenv active or on PATH.

$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

$python = if (Test-Path ".venv\Scripts\python.exe") { ".venv\Scripts\python.exe" } else { "python" }

Write-Host "==> Ensuring PyInstaller is installed" -ForegroundColor Cyan
& $python -m pip install --quiet pyinstaller

Write-Host "==> Building NetstackTestSuite.exe" -ForegroundColor Cyan
& $python -m PyInstaller NetstackTestSuite.spec --noconfirm --distpath dist --workpath build
if (-not (Test-Path "dist\NetstackTestSuite.exe")) { throw "Build failed: dist\NetstackTestSuite.exe not found" }
Write-Host "    dist\NetstackTestSuite.exe" -ForegroundColor Green

# Optional installer via Inno Setup, if available.
$iscc = @(
    "C:\Program Files (x86)\Inno Setup 6\ISCC.exe",
    "C:\Program Files\Inno Setup 6\ISCC.exe"
) | Where-Object { Test-Path $_ } | Select-Object -First 1

if ($iscc) {
    Write-Host "==> Building installer with Inno Setup" -ForegroundColor Cyan
    & $iscc "packaging\installer.iss"
    Write-Host "    dist\NetstackTestSuite-Setup.exe" -ForegroundColor Green
} else {
    Write-Host "Inno Setup (ISCC.exe) not found — skipping installer." -ForegroundColor Yellow
    Write-Host "The exe in dist\ is standalone: double-click to run (no install needed)." -ForegroundColor Yellow
    Write-Host "To build the installer, install Inno Setup from https://jrsoftware.org/isdl.php and re-run." -ForegroundColor Yellow
}
