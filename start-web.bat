@echo off
REM Starts CipherVault in your default browser at http://localhost:5173
REM
REM Serving over http rather than opening index.html directly gives the page a
REM real, stable origin. Firebase Auth and localStorage both depend on that,
REM and "file://" origins are treated inconsistently between browsers.
REM
REM Keep this window open while you use CipherVault. Close it to stop.

cd /d "%~dp0"

where node >nul 2>nul
if errorlevel 1 (
  echo.
  echo Node.js was not found on your PATH.
  echo Install it from https://nodejs.org and run this again.
  echo.
  pause
  exit /b 1
)

echo Starting CipherVault on http://localhost:5173
echo Close this window when you are done.
echo.

start "" "http://localhost:5173"
node _devserver.js web
