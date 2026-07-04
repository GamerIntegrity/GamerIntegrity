@echo off
setlocal EnableExtensions
pushd "%~dp0" >nul

set "RID=%~1"
set "PROJECT=GamerIntegrity.csproj"
set "CONFIGURATION=Release"

if "%RID%"=="" (
    echo ERROR: Missing runtime id. Use win-x64, win-x86, or win-arm64.
    popd >nul
    exit /b 1
)

if /I not "%RID%"=="win-x64" if /I not "%RID%"=="win-x86" if /I not "%RID%"=="win-arm64" (
    echo ERROR: Unsupported runtime id: %RID%
    echo Use win-x64, win-x86, or win-arm64.
    popd >nul
    exit /b 1
)

set "PUBLISH_DIR=%CD%\publish\%RID%"
set "RELEASE_DIR=%CD%\release"
set "LOGFILE=%CD%\publish-%RID%.log"
set "EXE_NAME=GamerIntegrity-%RID%.exe"

if not exist "%PROJECT%" (
    echo ERROR: %PROJECT% was not found in this folder.
    popd >nul
    exit /b 1
)

where dotnet >nul 2>nul
if errorlevel 1 (
    echo ERROR: dotnet.exe was not found.
    echo Install the .NET SDK or open this project in Visual Studio with .NET desktop development.
    popd >nul
    exit /b 1
)

if exist "%LOGFILE%" del /f /q "%LOGFILE%" >nul 2>nul
if exist "%PUBLISH_DIR%" rmdir /s /q "%PUBLISH_DIR%" >nul 2>nul
if not exist "%RELEASE_DIR%" mkdir "%RELEASE_DIR%" >nul 2>nul

rem Release builds are self-contained single EXEs.
rem The target PC should not need the .NET Desktop Runtime installed.
echo ============================================================
echo Publishing GamerIntegrity release
echo Runtime: %RID%
echo Output:  %PUBLISH_DIR%
echo Release: %RELEASE_DIR%\%EXE_NAME%
echo Log:     %LOGFILE%
echo Mode:    self-contained single EXE, not trimmed
echo ============================================================
echo.

dotnet publish "%PROJECT%" ^
  -c %CONFIGURATION% ^
  -r %RID% ^
  --self-contained true ^
  -p:SelfContained=true ^
  -p:PublishSelfContained=true ^
  -p:UseAppHost=true ^
  -p:PublishSingleFile=true ^
  -p:PublishTrimmed=false ^
  -p:IncludeNativeLibrariesForSelfExtract=true ^
  -p:EnableCompressionInSingleFile=true ^
  -p:DebugType=None ^
  -p:DebugSymbols=false ^
  -o "%PUBLISH_DIR%" > "%LOGFILE%" 2>&1

if errorlevel 1 (
    echo ERROR: publish failed. Review:
    echo   %LOGFILE%
    popd >nul
    exit /b 1
)

if not exist "%PUBLISH_DIR%\GamerIntegrity.exe" (
    echo ERROR: publish finished, but GamerIntegrity.exe was not found.
    echo Review:
    echo   %LOGFILE%
    popd >nul
    exit /b 1
)

rem Single-file sanity checks. These DLLs should NOT be next to the EXE in the publish folder.
if exist "%PUBLISH_DIR%\coreclr.dll" (
    echo ERROR: coreclr.dll was found beside the EXE. This is not a single-EXE release.
    echo Review:
    echo   %LOGFILE%
    popd >nul
    exit /b 1
)

if exist "%PUBLISH_DIR%\hostfxr.dll" (
    echo ERROR: hostfxr.dll was found beside the EXE. This is not a single-EXE release.
    echo Review:
    echo   %LOGFILE%
    popd >nul
    exit /b 1
)

if exist "%PUBLISH_DIR%\hostpolicy.dll" (
    echo ERROR: hostpolicy.dll was found beside the EXE. This is not a single-EXE release.
    echo Review:
    echo   %LOGFILE%
    popd >nul
    exit /b 1
)

if exist "%PUBLISH_DIR%\PresentationFramework.dll" (
    echo ERROR: PresentationFramework.dll was found beside the EXE. This is not a single-EXE release.
    echo Review:
    echo   %LOGFILE%
    popd >nul
    exit /b 1
)

copy /y "%PUBLISH_DIR%\GamerIntegrity.exe" "%RELEASE_DIR%\%EXE_NAME%" >nul
if errorlevel 1 (
    echo ERROR: Failed to copy release EXE.
    popd >nul
    exit /b 1
)

echo SUCCESS: Self-contained single-EXE release complete.
echo Release EXE:
echo   %RELEASE_DIR%\%EXE_NAME%
echo.
popd >nul
exit /b 0
