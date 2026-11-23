; Inno Setup script: per-user install (no administrator rights needed), Start menu + optional desktop shortcut.
[Setup]
AppName=Panzeron
AppVersion=0.1.0
AppPublisher=Panzeron Team
DefaultDirName={autopf}\Panzeron
DefaultGroupName=Panzeron
PrivilegesRequired=lowest
OutputBaseFilename=Panzeron-Setup-0.1.0
SetupIconFile=..\assets\panzeron.ico
UninstallDisplayIcon={app}\Panzeron.exe
Compression=lzma2
SolidCompression=yes
WizardStyle=modern

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; Flags: unchecked
Name: "autostart"; Description: "Start Panzeron when I sign in to Windows"; Flags: unchecked

[Registry]
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "Panzeron"; ValueData: """{app}\Panzeron.exe"""; Flags: uninsdeletevalue; Tasks: autostart

[Files]
Source: "..\dist\Panzeron\*"; DestDir: "{app}"; Flags: recursesubdirs ignoreversion

[Icons]
Name: "{group}\Panzeron"; Filename: "{app}\Panzeron.exe"
Name: "{autodesktop}\Panzeron"; Filename: "{app}\Panzeron.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\Panzeron.exe"; Description: "Launch Panzeron"; Flags: nowait postinstall skipifsilent
; User data (findings, vault, audit log) lives in %LOCALAPPDATA%\Panzeron and is intentionally NOT removed on uninstall.
