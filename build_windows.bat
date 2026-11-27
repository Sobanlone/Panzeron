@echo off
REM Builds Panzeron.exe (a normal Windows desktop application), a portable zip, and, if Inno Setup is installed, the Setup installer.
REM Double-click this file on Windows. It needs Python 3.11+ (https://www.python.org/downloads/, tick "Add python.exe to PATH").
REM
REM The build happens in %LOCALAPPDATA%\Panzeron-build, OUTSIDE your project folder. Cloud-sync folders (OneDrive, Dropbox) lock files while they
REM sync, which makes PyInstaller fail with "Access is denied" when it cleans up. Only the finished program is copied back into dist\Panzeron.
setlocal
cd /d "%~dp0"
set "HERE=%~dp0"
set "WORK=%LOCALAPPDATA%\Panzeron-build"

set "PY="
where python >nul 2>nul && set "PY=python"
if not defined PY ( where py >nul 2>nul && set "PY=py -3" )
if not defined PY (
  echo Python 3.11 or newer was not found. Install it from https://www.python.org/downloads/ and tick "Add python.exe to PATH", then run this again.
  goto :fail
)

echo [1/6] Stopping any running Panzeron (a copy in the tray would lock its own files)...
taskkill /im Panzeron.exe /f >nul 2>nul

echo [2/6] Preparing a clean build folder: %WORK%
if exist "%WORK%" rmdir /s /q "%WORK%" >nul 2>nul
if exist "%WORK%" (
  echo Could not clear %WORK%. Close any window or program using it, then run this again.
  goto :fail
)
mkdir "%WORK%" || goto :fail

echo [3/6] Installing build tools...
%PY% -m pip install --upgrade pip pyinstaller pillow pytesseract pymupdf || goto :fail

echo [4/6] Building Panzeron.exe (this takes a few minutes)...
%PY% -m PyInstaller --noconfirm --clean --windowed --name Panzeron --icon "%HERE%assets\panzeron.ico" ^
  --workpath "%WORK%\work" --distpath "%WORK%\dist" --specpath "%WORK%" ^
  --collect-submodules panzeron --add-data "%HERE%panzeron\web;panzeron\web" --add-data "%HERE%assets\panzeron.ico;assets" "%HERE%panzeron_app.py" || goto :fail

echo [5/6] Copying the finished program into dist\Panzeron ...
if exist "dist\Panzeron" rmdir /s /q "dist\Panzeron" >nul 2>nul
robocopy "%WORK%\dist\Panzeron" "dist\Panzeron" /E /NFL /NDL /NJH /NJS /NP >nul
if %errorlevel% geq 8 (
  echo Could not copy the program into dist\Panzeron. If your project folder is in OneDrive, pause OneDrive sync or move the project out of it, then run this again.
  goto :fail
)
%PY% scripts\make_manifest.py dist\Panzeron || goto :fail
powershell -NoProfile -Command "Compress-Archive -Path 'dist\Panzeron' -DestinationPath 'dist\Panzeron-portable-0.1.0.zip' -Force" || goto :fail

echo [6/6] Building the installer...
echo.
echo Built:    dist\Panzeron\Panzeron.exe
echo Portable: dist\Panzeron-portable-0.1.0.zip  (unzip anywhere, run Panzeron.exe)
where iscc >nul 2>nul
if %errorlevel%==0 (
  iscc installer\panzeron.iss || goto :fail
  echo Installer: installer\Output\Panzeron-Setup-0.1.0.exe
  start "" "installer\Output"
) else (
  echo Inno Setup not found; skipping the installer. Get it from https://jrsoftware.org/isinfo.php, then open installer\panzeron.iss and press Compile.
  start "" "dist\Panzeron"
)
pause
exit /b 0

:fail
echo.
echo BUILD FAILED. Scroll up for the first error.
echo If it says "Access is denied": your project folder is probably inside OneDrive. Pause OneDrive sync, or move the folder to a plain location such as C:\Panzeron, and run this again.
pause
exit /b 1
