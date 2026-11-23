# Creates "Ultrimater" shortcuts (Desktop + Start menu) with the Ultrimater icon. Launches without a console window.
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$pyw = (Get-Command pythonw.exe -ErrorAction SilentlyContinue).Source
if (-not $pyw) {
  $py = (Get-Command python.exe -ErrorAction SilentlyContinue).Source
  if ($py) { $pyw = $py -replace 'python\.exe$', 'pythonw.exe' }
}
if (-not $pyw -or -not (Test-Path $pyw)) { Write-Host "Python 3.11+ was not found. Install it from python.org (tick 'Add to PATH') and run this again."; exit 1 }
$ws = New-Object -ComObject WScript.Shell
$targets = @([Environment]::GetFolderPath('Desktop'), (Join-Path ([Environment]::GetFolderPath('Programs')) ''))
foreach ($dir in $targets) {
  $lnk = $ws.CreateShortcut((Join-Path $dir "Ultrimater.lnk"))
  $lnk.TargetPath = $pyw
  $lnk.Arguments = "`"$root\Ultrimater.pyw`""
  $lnk.WorkingDirectory = $root
  $lnk.IconLocation = "$root\assets\ultrimater.ico,0"
  $lnk.Description = "Ultrimater: protect the device, the identity, the person"
  $lnk.Save()
}
Write-Host "Done. Look for 'Ultrimater' on your Desktop and in the Start menu."
# Windows caches shortcut icons; ask the shell to refresh so the dragon shows immediately (harmless if unavailable).
try { & ie4uinit.exe -show 2>$null } catch { }
try { Add-Type -Namespace U -Name S -MemberDefinition '[System.Runtime.InteropServices.DllImport("shell32.dll")] public static extern void SHChangeNotify(int e, int f, System.IntPtr a, System.IntPtr b);'; [U.S]::SHChangeNotify(0x08000000, 0, [IntPtr]::Zero, [IntPtr]::Zero) } catch { }
