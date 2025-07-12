import pandas as pd
import requests
from tqdm import tqdm
from datetime import datetime
import itertools
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
import base64
import yaml
import sqlite3
import json

# Constants
with open('settings.yaml', 'r', encoding='utf-8') as file:
    VirusTotal = yaml.safe_load(file)['VirusTotal']
    VT_API_KEYS = VirusTotal['API_KEYS']
    VT_URLS = VirusTotal['URLS']
    MAX_REQUESTS_PER_MINUTE = VirusTotal['REQ_PER_MIN']


# Thread-safe iterators for API keys
vt_api_key_lock = threading.Lock()
vt_api_key_cycle = itertools.cycle(VT_API_KEYS)

def format_date(datetime):
    return datetime.strftime("%Y-%m-%d %H:%M:%S")

def open_db_connection(filepath="db/db.sqlite3"):
    conn = sqlite3.connect(filepath, timeout=30)
    conn.execute("PRAGMA journal_mode=WAL;")
    cursor = conn.cursor()
    return conn, cursor

def get_db_positives(conn):
    query = "SELECT ic.* FROM IoC AS ic WHERE vt_detections >= 10"
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

    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error {response.status_code}: {response.text}")  # Debug statement
        return None


def process_ioc(ioc, iocType):
    report = get_vt_report(ioc, iocType)
    vt_detections = (
        report.get('data', {})
            .get('attributes', {})
            .get('last_analysis_stats', {})
            .get('malicious', None)
    )
    datetime_string = format_date(datetime.now())
    return vt_detections, datetime_string

def main(num_threads, input_file):
    try:
        df = pd.read_excel(input_file)
    except FileNotFoundError:
        print(f"Error: The file {input_file} does not exist.")
        exit()

    conn, cursor = open_db_connection()
    db_iocs = get_db_positives(conn)

    subset = df[~df['ioc'].isin(db_iocs['ioc'])]
    seen_iocs = db_iocs[db_iocs['ioc'].isin(df['ioc'])]

    update_as_seen(seen_iocs, cursor, conn)


    # Create a list of (index, ioc, iocType)
    ioc_list = [(index, row['ioc'], row['iocType']) for index, row in subset.iterrows()]

    # Define wrapper for threading
    def process_ioc_thread(index, ioc, ioc_type):
        return index, *process_ioc(ioc, ioc_type)

    # Run multithreaded processing
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = {executor.submit(process_ioc_thread, index, ioc, ioc_type): index for index, ioc, ioc_type in ioc_list}
        for future in tqdm(as_completed(futures), total=len(futures)):
            index, vt_detections, updated_at = future.result()
            df.loc[index, 'vt_detections'] = vt_detections


    # Generate output file name with current date and timestamp
    current_datetime = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = f"output_{current_datetime}.xlsx"

    # Write output to Excel
    filtered_df = df[df['vt_detections'] >= 10]
    filtered_df.to_excel(output_file, index=False)

    upsert_db_results(filtered_df, cursor, conn)
    close_db_connection(conn)


if __name__ == "__main__":
    # print(json.dumps(get_vt_report('681a1b5fe10eeaae001df553ba590843','hash')))
    
    parser = argparse.ArgumentParser(description='VirusTotal IOC Checker')
    parser.add_argument('--threads', type=int, default=4, help='Number of threads to use')
    parser.add_argument('--file', default="input2.xlsx", help='Filename')
    args = parser.parse_args()
    num_threads = args.threads
    filename = args.file

    # Ensure the number of threads does not exceed the API key limits
    max_possible_threads = len(VT_API_KEYS) * (MAX_REQUESTS_PER_MINUTE // 60)
    if num_threads > MAX_REQUESTS_PER_MINUTE:
        print(
            f"Warning: Number of threads exceeds the limit based on API keys and rate limit. Using {max_possible_threads} threads instead.")
        num_threads = max_possible_threads

    main(num_threads, filename)
