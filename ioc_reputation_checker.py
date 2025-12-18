import pandas as pd
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from tqdm import tqdm
from datetime import datetime
import itertools
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
import base64
import yaml
import sqlite3
import os
import streamlit as st
import time
import io


# Constants
with open('settings.yaml', 'r', encoding='utf-8') as file:
    VirusTotal = yaml.safe_load(file)['VirusTotal']
    # VT_API_KEYS = VirusTotal['API_KEYS']
    VT_URLS = VirusTotal['URLS']
    MAX_REQUESTS_PER_MINUTE = VirusTotal['REQ_PER_MIN']
    VT_MIN_DETECTION = VirusTotal['MIN_DETECTION']
MAX_CHARS = 255


# Thread-safe iterators for API keys
vt_api_key_lock = threading.Lock()
# vt_api_key_cycle = itertools.cycle(VT_API_KEYS)

def format_date(datetime):
    return datetime.strftime("%Y-%m-%d %H:%M:%S")

def open_db_connection(filepath="db/db.sqlite3"):
    conn = sqlite3.connect(filepath, timeout=30)
    conn.execute("PRAGMA journal_mode=WAL;")
    cursor = conn.cursor()
    return conn, cursor

def get_db_positives(conn):
    query = f"SELECT * FROM IoC WHERE vt_detections >= {VT_MIN_DETECTION}"
    db_iocs = pd.read_sql_query(query, conn)
    return db_iocs

def upsert_db_results(df, cursor, conn):
    # Get current timestamp in the desired format
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Prepare data for insertion
    records = [
        (row['ioc'], row['iocType'], row['vt_detections'], now, now, now)
        for _, row in df.iterrows()
    ]

    # Insert with conflict handling (replace 'ioc' with your unique constraint column)
    insert_query = """
    INSERT INTO IoC (ioc, ioc_type, vt_detections, created_at, updated_at, last_seen)
    VALUES (?, ?, ?, ?, ?, ?)
    ON CONFLICT(ioc) DO UPDATE SET
        updated_at = excluded.updated_at,
        vt_detections = excluded.vt_detections,
        last_seen = excluded.last_seen
    """

    cursor.executemany(insert_query, records)
    conn.commit()


def update_as_seen(df, cursor, conn):
    now = format_date(datetime.now())
    records = [(now, row['ioc']) for _, row in df.iterrows()]

    update_query = """
    UPDATE IoC
    SET last_seen = ?
    WHERE ioc = ?
    """

    cursor.executemany(update_query, records)
    conn.commit()


def close_db_connection(conn):
    conn.close()


def get_session_with_retries(retries=5, backoff_factor=1, status_forcelist=(500, 502, 503, 504), session=None):
    """
    Creates a requests.Session object with a retry mechanism.

    This function configures a session to automatically retry requests that fail
    due to transient errors, such as network issues or temporary server problems.
    It uses an exponential backoff strategy to avoid overwhelming the server.

    Args:
        retries (int): The total number of retry attempts.
        backoff_factor (float): A factor to calculate the delay between retries.
                                The delay will be {backoff factor} * (2 ** ({number of total retries} - 1)).
        status_forcelist (tuple): A set of HTTP status codes that should force a retry.
        session (requests.Session, optional): An existing session to which the retry
                                              logic will be added. If None, a new
                                              session is created.

    Returns:
        requests.Session: A session object with the retry mechanism configured.
    """
    session = session or requests.Session()
    retry = Retry(
        total=retries,
        read=retries,
        connect=retries,
        backoff_factor=backoff_factor,
        status_forcelist=status_forcelist,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session

session = get_session_with_retries()


def get_vt_report(ioc, ioc_type):
    with vt_api_key_lock:
        api_key = next(vt_api_key_cycle)

    headers = {
        "x-apikey": api_key
    }
    if ioc_type == 'url':
        encoded_ioc = base64.urlsafe_b64encode(ioc.encode()).decode().rstrip("=")
        url = VT_URLS[ioc_type] + encoded_ioc
    else:
        url = VT_URLS[ioc_type] + ioc

    response = session.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        return None


def process_ioc(ioc, iocType):
    report = get_vt_report(ioc, iocType)
    vt_detections = (
        report.get('data', {})
              .get('attributes', {})
              .get('last_analysis_stats', {})
              .get('malicious', 0)
        if report else -1
    )
    datetime_string = format_date(datetime.now())
    return vt_detections, datetime_string

def main(num_threads, df):
    conn, cursor = open_db_connection()
    db_iocs = get_db_positives(conn)

    subset = df[~df['ioc'].isin(db_iocs['ioc'])]
    seen_iocs = db_iocs[db_iocs['ioc'].isin(df['ioc'])]

    update_as_seen(seen_iocs, cursor, conn)

    ioc_list = [(index, row['ioc'], row['iocType']) for index, row in subset.iterrows()]

    def process_ioc_thread(index, ioc, ioc_type):
        return index, *process_ioc(ioc, ioc_type)

    # Initialize vt_detections column as numeric, fill with -1 as default for unprocessed
    df['vt_detections'] = -1

    progress_bar = st.progress(0)
    status_text = st.empty()

    results = []  # <-- Initialize this before loop!

    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = {executor.submit(process_ioc_thread, index, ioc, ioc_type): index for index, ioc, ioc_type in ioc_list}

        total = len(futures)
        completed = 0

        for future in as_completed(futures):
            index, vt_detections, updated_at = future.result()
            df.loc[index, 'vt_detections'] = vt_detections

            completed += 1
            progress = int(completed / total * 100)
            progress_bar.progress(progress)
            status_text.text(f"Processed {completed} / {total}")

    # Filter with numeric comparison after ensuring dtype is int
    df['vt_detections'] = pd.to_numeric(df['vt_detections'], errors='coerce').fillna(-1).astype(int)
    df[f">{MAX_CHARS} chars"] = df['ioc'].str.len() > MAX_CHARS
    filtered_df = df[df['vt_detections'] >= VT_MIN_DETECTION]
    current_datetime = datetime.now().strftime("%Y%m%d_%H%M%S")
    # Prepare in-memory Excel
    excel_buf = io.BytesIO()
    with pd.ExcelWriter(excel_buf, engine="xlsxwriter") as writer:
        filtered_df.to_excel(writer, index=False, sheet_name="Results")
    excel_buf.seek(0)

    # Prepare CSV bytes
    csv_bytes = filtered_df.to_csv(index=False).encode('utf-8')

    # Streamlit download buttons (no server-side file persistence)
    st.download_button(
        label="⬇️ Download results (Excel)",
        data=excel_buf,
        file_name=f"weekly_report_{current_datetime}.xlsx",
        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        key="dl_xlsx",
    )

    st.download_button(
        label="⬇️ Download results (CSV)",
        data=csv_bytes,
        file_name=f"weekly_report_{current_datetime}.csv",
        mime="text/csv",
        key="dl_csv",
    )
    upsert_db_results(filtered_df, cursor, conn)
    close_db_connection(conn)

    st.success("Process complete! Your downloads are ready below.")

if __name__ == "__main__":
    st.title("🔍 IoC Reputation Checker (VirusTotal)")
    api_keys_input = st.text_input("Enter VirusTotal API Key", type="password")
    threads = st.slider("Select Number of Threads", 1, 200, 4)
    uploaded_file = st.file_uploader("Upload Excel File", type=["xlsx","csv"])

    if st.button("Run Reputation Check"):
        global VT_API_KEYS, vt_api_key_cycle  # <-- Moved here
        if not uploaded_file or not api_keys_input.strip():
            st.error("Please provide both API keys and an Excel file.")
        else:
            df = pd.read_excel(uploaded_file)

            # Override global VT_API_KEYS
            VT_API_KEYS = [key.strip() for key in api_keys_input.strip().splitlines()]
            vt_api_key_cycle = itertools.cycle(VT_API_KEYS)

            main(threads, df)
