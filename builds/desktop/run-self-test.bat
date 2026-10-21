@echo off
chcp 65001 >nul
"%~dp0aegis-desktop.exe" --self-test
pause
