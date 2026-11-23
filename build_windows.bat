@echo off
REM Builds Ultrimater.exe (a normal Windows desktop application), a portable zip, and, if Inno Setup is installed, the Setup installer.
REM Double-click this file on Windows. It needs Python 3.11+ (https://www.python.org/downloads/, tick "Add python.exe to PATH").
setlocal
cd /d "%~dp0"
set "PY="
where python >nul 2>nul && set "PY=python"
if not defined PY ( where py >nul 2>nul && set "PY=py -3" )
if not defined PY (
  echo Python 3.11 or newer was not found. Install it from https://www.python.org/downloads/ and tick "Add python.exe to PATH", then run this again.
  goto :fail
)
%PY% -m pip install --upgrade pip pyinstaller pillow pytesseract pymupdf || goto :fail
%PY% -m PyInstaller --noconfirm --clean --windowed --name Ultrimater --icon assets\ultrimater.ico ^
  --collect-submodules ultrimater --add-data "ultrimater\web;ultrimater\web" ultrimater_app.py || goto :fail
%PY% scripts\make_manifest.py dist\Ultrimater || goto :fail
powershell -NoProfile -Command "Compress-Archive -Path 'dist\Ultrimater' -DestinationPath 'dist\Ultrimater-portable-0.1.0.zip' -Force" || goto :fail
echo.
echo Built:    dist\Ultrimater\Ultrimater.exe
echo Portable: dist\Ultrimater-portable-0.1.0.zip  (unzip anywhere, run Ultrimater.exe)
where iscc >nul 2>nul
if %errorlevel%==0 (
  iscc installer\ultrimater.iss || goto :fail
  echo Installer: installer\Output\Ultrimater-Setup-0.1.0.exe
  start "" "installer\Output"
) else (
  echo Inno Setup not found; skipping the installer. Get it from https://jrsoftware.org/isinfo.php to also create Setup.exe
  start "" "dist\Ultrimater"
)
pause
exit /b 0
:fail
echo.
echo BUILD FAILED. Scroll up for the first error.
pause
exit /b 1
