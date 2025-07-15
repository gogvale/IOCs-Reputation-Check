@echo off
REM Get the directory where this script is located
cd /d %~dp0

REM Install pipenv environment
pipenv install

pause
