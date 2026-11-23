@echo off
REM Builds Panzeron.exe (a normal Windows desktop application), a portable zip, and, if Inno Setup is installed, the Setup installer.
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
%PY% -m PyInstaller --noconfirm --clean --windowed --name Panzeron --icon assets\panzeron.ico ^
  --collect-submodules panzeron --add-data "panzeron\web;panzeron\web" panzeron_app.py || goto :fail
%PY% scripts\make_manifest.py dist\Panzeron || goto :fail
powershell -NoProfile -Command "Compress-Archive -Path 'dist\Panzeron' -DestinationPath 'dist\Panzeron-portable-0.1.0.zip' -Force" || goto :fail
echo.
echo Built:    dist\Panzeron\Panzeron.exe
echo Portable: dist\Panzeron-portable-0.1.0.zip  (unzip anywhere, run Panzeron.exe)
where iscc >nul 2>nul
if %errorlevel%==0 (
  iscc installer\panzeron.iss || goto :fail
  echo Installer: installer\Output\Panzeron-Setup-0.1.0.exe
  start "" "installer\Output"
) else (
  echo Inno Setup not found; skipping the installer. Get it from https://jrsoftware.org/isinfo.php to also create Setup.exe
  start "" "dist\Panzeron"
)
pause
exit /b 0
:fail
echo.
echo BUILD FAILED. Scroll up for the first error.
pause
exit /b 1
