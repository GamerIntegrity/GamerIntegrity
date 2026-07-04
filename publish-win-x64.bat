@echo off
setlocal EnableExtensions
call "%~dp0publish-runtime.bat" win-x64
exit /b %ERRORLEVEL%
