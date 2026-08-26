; Inno Setup script — builds a double-click installer for NetstackTestSuite.
;
; Requires Inno Setup 6 (https://jrsoftware.org/isdl.php). Build the exe
; first (packaging\build.ps1 or the PyInstaller spec), then compile this:
;   "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" packaging\installer.iss
;
; Produces dist\NetstackTestSuite-Setup.exe — the user double-clicks it to
; install (Start Menu + optional desktop shortcut), then runs the app.

#define AppName "Netstack Test Suite"
#define AppVersion "0.1.0"
#define AppExe "NetstackTestSuite.exe"

[Setup]
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher=Netstack Test Suite
DefaultDirName={autopf}\NetstackTestSuite
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
OutputDir=..\dist
OutputBaseFilename=NetstackTestSuite-Setup
Compression=lzma2
SolidCompression=yes
; The app self-elevates at runtime; install per-machine so it lands in
; Program Files (requires admin to install).
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible
WizardStyle=modern

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional icons:"

[Files]
Source: "..\dist\{#AppExe}"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExe}"
Name: "{group}\Uninstall {#AppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#AppExe}"; Description: "Launch {#AppName}"; Flags: nowait postinstall skipifsilent

[Messages]
; Reminder shown at the end of setup — the app needs Npcap for raw packet access.
FinishedLabel=Setup is complete.%n%nNote: raw packet capture requires Npcap (https://npcap.com). If tests can't open the interface, install Npcap and try again.
