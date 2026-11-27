; Inno Setup script for Panzeron.
;
; HOW TO USE
;   1. Build the program first:  double-click build_windows.bat in the project folder (it creates dist\Panzeron\Panzeron.exe).
;      build_windows.bat then compiles THIS script for you if Inno Setup is installed.
;   2. Or compile it yourself: open this file in "Inno Setup Compiler" (https://jrsoftware.org/isinfo.php) and press Compile (F9),
;      or run:  iscc installer\panzeron.iss
;   3. The finished installer is installer\Output\Panzeron-Setup-0.1.0.exe. Give that single file to anyone; they double-click it.
;
; WHAT THE INSTALLER DOES
;   * Installs Panzeron into a folder the user chooses (any drive). Default: per-user (no administrator needed);
;     the first page offers "install for all users" to put it in Program Files instead.
;   * Optional component: the complete project (source code, tests, docs and build scripts) next to the program.
;   * Optional tasks: desktop shortcut, and start Panzeron in the system tray when signing in to Windows.
;   * Closes a running Panzeron (even one sitting in the tray) before installing, upgrading or uninstalling.
;   * Uninstall removes the program. Your data (findings, quarantine vault, settings) is kept unless you choose to delete it.

#define MyAppName "Panzeron"
#define MyAppVersion "0.1.0"
#define MyAppExe "Panzeron.exe"

#if !FileExists(SourcePath + "..\dist\Panzeron\Panzeron.exe")
  #error "dist\Panzeron\Panzeron.exe was not found. Run build_windows.bat first: it builds the program and then compiles this installer."
#endif

[Setup]
; A fixed id: later versions of Panzeron upgrade this install in place.
AppId={{B7C3D2A0-5F1E-4C6B-9A8E-3D2F1C0B7A19}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher=Panzeron
DefaultDirName={autopf}\Panzeron
DefaultGroupName=Panzeron
DisableProgramGroupPage=yes
DisableDirPage=no
UsePreviousAppDir=yes
ArchitecturesInstallIn64BitMode=x64
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
; Panzeron creates this mutex while it runs (panzeron/tray.py); Setup waits for it to be gone.
AppMutex=Panzeron-Instance
SetupIconFile=..\assets\panzeron.ico
UninstallDisplayIcon={app}\{#MyAppExe}
UninstallDisplayName={#MyAppName}
OutputDir=Output
OutputBaseFilename=Panzeron-Setup-{#MyAppVersion}
Compression=lzma2/ultra
SolidCompression=yes
WizardStyle=modern

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Types]
Name: "full"; Description: "Full installation (program and the complete project)"
Name: "compact"; Description: "Program only"
Name: "custom"; Description: "Custom"; Flags: iscustom

[Components]
Name: "app"; Description: "Panzeron (the program)"; Types: full compact custom; Flags: fixed
Name: "source"; Description: "The complete project: source code, tests, documentation and build scripts"; Types: full

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Shortcuts:"
Name: "startup"; Description: "Start Panzeron in the system &tray when I sign in to Windows"; GroupDescription: "Protection:"; Flags: unchecked

[Files]
Source: "..\dist\Panzeron\*"; DestDir: "{app}"; Components: app; Flags: recursesubdirs createallsubdirs ignoreversion
Source: "..\*"; DestDir: "{app}\project"; Components: source; Excludes: ".git,dist,build,Output,__pycache__,*.pyc,*.spec"; Flags: recursesubdirs createallsubdirs ignoreversion

[Icons]
Name: "{autoprograms}\Panzeron"; Filename: "{app}\{#MyAppExe}"; Comment: "Protect the person"
Name: "{autoprograms}\Panzeron project folder"; Filename: "{app}\project"; Components: source
Name: "{autodesktop}\Panzeron"; Filename: "{app}\{#MyAppExe}"; Tasks: desktopicon

[Registry]
; Same entry the app's own "Start with Windows" switch writes, so the two always agree. --background = straight to the tray, no window.
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "Panzeron"; ValueData: """{app}\{#MyAppExe}"" --background"; Flags: uninsdeletevalue; Tasks: startup

[InstallDelete]
; Clean up the shortcuts of the old name (Ultrimater). The user's data is moved by the app on first start, never deleted.
Type: files; Name: "{autodesktop}\Ultrimater.lnk"
Type: filesandordirs; Name: "{autoprograms}\Ultrimater"

[Run]
Filename: "{app}\{#MyAppExe}"; Description: "Start Panzeron now"; Flags: nowait postinstall skipifsilent

[Code]
// Ask a running Panzeron (including one hiding in the tray) to quit, so its files can be replaced or removed.
procedure QuitRunningPanzeron(AppDir: String);
var
  ResultCode: Integer;
  Exe: String;
begin
  Exe := AppDir + '\{#MyAppExe}';
  if FileExists(Exe) then
  begin
    Exec(Exe, '--quit', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Sleep(1500);
  end;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  QuitRunningPanzeron(ExpandConstant('{app}'));
  Result := '';
end;

function InitializeUninstall(): Boolean;
begin
  QuitRunningPanzeron(ExpandConstant('{app}'));
  Result := True;
end;

// Uninstall never deletes personal data silently: it asks, and the default answer is No.
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  DataDir: String;
begin
  if CurUninstallStep = usPostUninstall then
  begin
    DataDir := ExpandConstant('{localappdata}\Panzeron');
    if (not UninstallSilent) and DirExists(DataDir) then
      if MsgBox('Also delete your Panzeron data (findings, quarantine vault, settings, audit log)?' + #13#10 + #13#10 +
                'Choose No to keep it for a future install.', mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES then
        DelTree(DataDir, True, True, True);
  end;
end;
