@echo off
REM Get the directory where this script is located
cd /d %~dp0

REM Run the Streamlit app using pipenv
pipenv run streamlit run ioc_reputation_checker.py

pause
