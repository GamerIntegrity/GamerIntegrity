@echo off
setlocal EnableExtensions
call "%~dp0publish-runtime.bat" win-x86
exit /b %ERRORLEVEL%
