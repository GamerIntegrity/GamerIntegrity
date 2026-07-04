@echo off
setlocal EnableExtensions
call "%~dp0publish-runtime.bat" win-arm64
exit /b %ERRORLEVEL%
