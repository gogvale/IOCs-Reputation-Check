# Gemini Project Context: IOC Reputation Checker

## Project Overview

This project is a web-based utility designed to check the reputation of Indicators of Compromise (IOCs) by querying the VirusTotal API. It is built in Python using the Streamlit framework for its user interface.

The application allows users to upload a file (CSV or Excel) containing IOCs (such as hashes, domains, IPs, or URLs). It then processes these IOCs in parallel using multithreading, retrieves the latest detection data from VirusTotal, and displays the results.

A local SQLite database is used as a cache to store results from previous scans, preventing re-scanning of known IOCs and updating when they are seen again.

The primary technologies used are:
- **Language:** Python 3.13
- **Framework:** Streamlit
- **Dependencies:** `pandas`, `requests`, `streamlit`, `pipenv`
- **Database:** SQLite

## Building and Running

### 1. Setup

**Configuration:**
Before the first run, you must create a `settings.yaml` file in the root directory. You can do this by copying the `settings.yaml.example` file:
```bash
cp settings.yaml.example settings.yaml
```
Then, edit `settings.yaml` to add your VirusTotal API key(s).

**Database Initialization:**
A SQLite database file is expected at `db/db.sqlite3`. If it does not exist, it will be created on the first run, but the schema must be initialized. You can create the `IoC` table using the provided SQL script:
```bash
mkdir -p db
sqlite3 db/db.sqlite3 < db/create_db.sql
```

**Install Dependencies:**
The project uses `pipenv` to manage dependencies. To install them, run the setup script:
```bash
./setup.command
```
Or, directly using `pipenv`:
```bash
pipenv install
```

### 2. Running the Application

To launch the Streamlit web interface, run the `run.command` script:
```bash
./run.command
```
Or, directly using `pipenv`:
```bash
pipenv run streamlit run ioc_reputation_checker.py
```
This will start a local web server and open the application in your browser.

## Development Conventions

*   **Dependency Management:** Dependencies are managed via `Pipfile` and `Pipfile.lock`. Any new packages should be added using `pipenv install <package>`.
*   **Configuration:** All configuration is handled through the `settings.yaml` file. No secrets or keys should be hardcoded in the source code.
*   **User Interface:** The UI is built with Streamlit. Changes to the front-end are made directly in `ioc_reputation_checker.py`.
*   **Error Handling:** The application includes retry logic with exponential backoff for API requests to handle transient network errors.
*   **File Handling:** The application is designed to read `.csv` and `.xlsx` files, and includes error handling for different file encodings.
