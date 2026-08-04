@echo off
REM =====================================================================
REM  Opens Firefox with the CipherVault extension already loaded.
REM
REM  A normally-launched Firefox can only keep UNSIGNED add-ons if they
REM  were signed by Mozilla - that is why the "Load Temporary Add-on"
REM  version disappears on restart. There is no script that can inject a
REM  temp add-on into an ordinary Firefox window; Mozilla blocks exactly
REM  that for security.
REM
REM  What DOES work: this launches Firefox through Mozilla's own web-ext
REM  tool, which loads the extension for that session. So this .bat
REM  becomes "the way you open Firefox when you want CipherVault".
REM
REM  It uses a dedicated CipherVault profile (kept between runs via
REM  --keep-profile-changes) so it does not touch your main Firefox
REM  profile. Sign in once and it is remembered in that profile.
REM
REM  Needs Node.js. web-ext is fetched on first run via npx.
REM  For a permanent install in your MAIN Firefox, get the extension
REM  signed on addons.mozilla.org (unlisted) - see README.
REM =====================================================================

cd /d "%~dp0"

where node >nul 2>nul
if errorlevel 1 (
  echo Node.js was not found. Install it from https://nodejs.org then run this again.
  pause
  exit /b 1
)

echo Launching Firefox with CipherVault loaded...
echo Keep this window open while you use it; close it to quit Firefox.
echo.

REM --keep-profile-changes: remember the sign-in between launches.
REM --profile-create-if-missing: make the dedicated profile on first run.
npx --yes web-ext run ^
  --source-dir="%~dp0." ^
  --firefox-profile="%~dp0.firefox-profile" ^
  --profile-create-if-missing ^
  --keep-profile-changes

pause
