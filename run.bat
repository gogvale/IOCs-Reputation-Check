@echo off
REM Get the directory where this script is located
cd /d %~dp0

REM Run the Streamlit app using pipenv
python3 -m pipenv run streamlit run ioc_reputation_checker.py

pause
