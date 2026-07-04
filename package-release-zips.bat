@echo off
rem Backward-compatible wrapper. New script name: package-release.bat
call "%~dp0package-release.bat"
exit /b %ERRORLEVEL%
