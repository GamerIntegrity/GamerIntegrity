@echo off
setlocal EnableExtensions
pushd "%~dp0" >nul

call "%~dp0publish-runtime.bat" win-x64
if errorlevel 1 goto :fail

call "%~dp0publish-runtime.bat" win-x86
if errorlevel 1 goto :fail

call "%~dp0publish-runtime.bat" win-arm64
if errorlevel 1 goto :fail

echo.
echo SUCCESS: All self-contained single-EXE Windows releases were created.
echo   release\GamerIntegrity-win-x64.exe
echo   release\GamerIntegrity-win-x86.exe
echo   release\GamerIntegrity-win-arm64.exe
echo.
echo Optional: run package-release.bat to create clean release zips.
echo.
pause
popd >nul
exit /b 0

:fail
echo.
echo ERROR: One of the Windows publishes failed. Review the matching publish-*.log file.
echo.
pause
popd >nul
exit /b 1
