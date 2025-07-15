#!/bin/zsh

# Get the directory where this script is located
DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

pipenv run streamlit run ioc_reputation_checker.py
