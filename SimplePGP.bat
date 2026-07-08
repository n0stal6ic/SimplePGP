@echo off
start "" pythonw "%~dp0simplepgp.py"
if errorlevel 1 python "%~dp0simplepgp.py"