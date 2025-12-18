# IOC Reputation Checker

## About

The **IOC Reputation Checker** is a web-based utility designed to automate the process of checking the reputation of Indicators of Compromise (IOCs) using the VirusTotal API. It is built with Python and Streamlit, providing an interactive user interface for cybersecurity professionals.

Users can upload a CSV or Excel file containing IOCs (hashes, domains, IPs, URLs). The application processes these IOCs concurrently, fetches the latest data from VirusTotal, and provides downloadable reports of the results.

## Features

- **Web-Based UI**: An easy-to-use interface built with Streamlit for file uploads and interaction.
- **VirusTotal Integration**: Leverages the VirusTotal API for comprehensive reputation data.
- **Multiple API Key Support**: Cycles through a list of API keys provided in the UI to maximize request throughput.
- **Concurrent Processing**: Utilizes multi-threading to handle large volumes of IOCs efficiently.
- **Local Caching**: Uses a SQLite database to cache previous results, avoiding redundant scans.
- **Flexible Input**: Supports both CSV and Excel (`.xlsx`) files as input.
- **Downloadable Reports**: Provides results in both CSV and Excel formats.

## How to Use

### 1. Prerequisites

- Python 3.13 (as specified in `Pipfile`)
- `pipenv`

### 2. Setup

**a. Clone the Repository**
```bash
git clone <repository-url>
cd IOCs-Reputation-Check
```

**b. Configure Settings**
The application requires a `settings.yaml` file for basic configuration. Copy the example file:

```bash
cp settings.yaml.example settings.yaml
```
*Note: While you can add API keys to this file, the application's UI will prompt you to enter them at runtime.*

**c. Install Dependencies**
This project uses `pipenv` to manage dependencies. Run the setup script to install them:

```bash
./setup.command
```
(On Windows, you can run `pipenv install` directly).

**d. Initialize the Database**
Create the SQLite database and its schema using the provided SQL file:

```bash
mkdir -p db
sqlite3 db/db.sqlite3 < db/create_db.sql
```

### 3. Running the Application

Launch the Streamlit web application by running the `run.command` script:

```bash
./run.command
```
Or, you can run it directly with `pipenv`:
```bash
pipenv run streamlit run ioc_reputation_checker.py
```
This will start the application in your web browser.

### 4. Using the App

1.  Open the application in your browser.
2.  Enter one or more VirusTotal API keys in the text input field (one per line).
3.  Use the slider to select the number of threads for processing.
4.  Upload your CSV or Excel file containing the IOCs.
5.  Click "Run Reputation Check".
6.  Once the process is complete, download your results using the provided buttons.