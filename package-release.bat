@echo off
setlocal EnableExtensions
pushd "%~dp0" >nul

set "RELEASE_DIR=%CD%\release"
if not exist "%RELEASE_DIR%" mkdir "%RELEASE_DIR%" >nul 2>nul

call :zipRuntime win-x64
if errorlevel 1 goto :fail
call :zipRuntime win-x86
if errorlevel 1 goto :fail
call :zipRuntime win-arm64
if errorlevel 1 goto :fail

echo.
echo SUCCESS: Release zips created in:
echo   %RELEASE_DIR%
echo.
echo Each zip contains one self-contained EXE.
echo.
pause
popd >nul
exit /b 0

:zipRuntime
set "RID=%~1"
set "EXE=%RELEASE_DIR%\GamerIntegrity-%RID%.exe"
set "ZIP=%RELEASE_DIR%\GamerIntegrity-%RID%.zip"

if not exist "%EXE%" (
    echo ERROR: Missing release EXE for %RID%.
    echo Run publish-%RID%.bat first, or run publish-all-windows.bat.
    exit /b 1
)

if exist "%ZIP%" del /f /q "%ZIP%" >nul 2>nul
powershell -NoProfile -ExecutionPolicy Bypass -Command "Compress-Archive -Path '%EXE%' -DestinationPath '%ZIP%' -Force"
if errorlevel 1 (
    echo ERROR: Failed to create %ZIP%.
    exit /b 1
)

echo Created %ZIP%
exit /b 0

:fail
echo.
echo ERROR: Release zip packaging failed.
echo.
pause
popd >nul
exit /b 1
