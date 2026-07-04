@echo off
setlocal EnableExtensions EnableDelayedExpansion
pushd "%~dp0" >nul

set "PROJECT=GamerIntegrity.csproj"
set "CONFIGURATION=Release"
set "TFM=net10.0-windows"
set "LOGFILE=%CD%\build.log"

if not exist "%PROJECT%" (
    echo ERROR: %PROJECT% was not found in this folder.
    echo Extract the whole zip first, then run build.bat from the extracted folder.
    goto :fail
)

echo ============================================================
echo GamerIntegrity build
echo Target: Windows 10 / Windows 11
echo Project: %PROJECT%
echo Config:  %CONFIGURATION%
echo Log:     %LOGFILE%
echo ============================================================
echo.

where dotnet >nul 2>nul
if errorlevel 1 (
    echo ERROR: dotnet.exe was not found.
    echo.
    echo Open this in Visual Studio 2026 with the .NET desktop development workload,
    echo or install the .NET 10 SDK, then run this script again.
    goto :fail
)

if exist "%LOGFILE%" del /f /q "%LOGFILE%" >nul 2>nul

echo Restoring packages...
dotnet restore "%PROJECT%" > "%LOGFILE%" 2>&1
if errorlevel 1 (
    echo ERROR: restore failed. Review:
    echo   %LOGFILE%
    goto :fail
)

echo Building AnyCPU project...
dotnet build "%PROJECT%" -c %CONFIGURATION% --no-restore >> "%LOGFILE%" 2>&1
if errorlevel 1 (
    echo ERROR: build failed. Review:
    echo   %LOGFILE%
    goto :fail
)

echo.
echo SUCCESS: Build complete.
echo Output:
echo   %CD%\bin\%CONFIGURATION%\%TFM%\GamerIntegrity.exe
echo.
echo IMPORTANT: build.bat is only for developer compile checks.
echo For public releases, use publish-win-x64.bat, publish-win-x86.bat, or publish-win-arm64.bat.
echo Those publish self-contained single EXEs so the target PC does not need a separate .NET install.
echo After publishing, package them with package-release.bat if zips are needed.
echo.
echo Log:
echo   %LOGFILE%
goto :done

:fail
echo.
echo Build did not complete.
echo.
pause
popd >nul
exit /b 1

:done
echo.
pause
popd >nul
exit /b 0
