; Inno Setup script: per-user install (no administrator rights needed), Start menu + optional desktop shortcut.
[Setup]
AppName=Ultrimater
AppVersion=0.1.0
AppPublisher=Ultrimater Team
DefaultDirName={autopf}\Ultrimater
DefaultGroupName=Ultrimater
PrivilegesRequired=lowest
OutputBaseFilename=Ultrimater-Setup-0.1.0
SetupIconFile=..\assets\ultrimater.ico
UninstallDisplayIcon={app}\Ultrimater.exe
Compression=lzma2
SolidCompression=yes
WizardStyle=modern

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; Flags: unchecked
Name: "autostart"; Description: "Start Ultrimater when I sign in to Windows"; Flags: unchecked

[Registry]
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "Ultrimater"; ValueData: """{app}\Ultrimater.exe"""; Flags: uninsdeletevalue; Tasks: autostart

[Files]
Source: "..\dist\Ultrimater\*"; DestDir: "{app}"; Flags: recursesubdirs ignoreversion

[Icons]
Name: "{group}\Ultrimater"; Filename: "{app}\Ultrimater.exe"
Name: "{autodesktop}\Ultrimater"; Filename: "{app}\Ultrimater.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\Ultrimater.exe"; Description: "Launch Ultrimater"; Flags: nowait postinstall skipifsilent
; User data (findings, vault, audit log) lives in %LOCALAPPDATA%\Ultrimater and is intentionally NOT removed on uninstall.
