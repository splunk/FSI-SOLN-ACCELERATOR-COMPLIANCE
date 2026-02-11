import argparse
import datetime
import json
import random
import uuid
import math
import time # For epoch time conversion and potential sleep for retries
from typing import Any, Dict

import pytz # For timezone handling
import requests # For Splunk HEC
import urllib3
from faker import Faker
try:
    import pandas as pd  # Optional dependency for CSV output
except ImportError:  # We'll fall back to csv module if missing
    pd = None
import csv

# --- Disable insecure request warnings for self-signed certs (if applicable) ---
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- Configuration ---
NUM_EVENTS_TOTAL = 1000  # Number of KYC events to generate
DEFAULT_CSV_FILENAME = "kyc_events.csv"  # Default CSV output if none specified

# Target "local" timezone for business hours definition
TARGET_LOCAL_TIMEZONE = "America/New_York"

# Data Drift Thresholds (as a percentage of total events processed)
DOC_TYPE_DRIFT_THRESHOLDS = {
    "passport": 0.15,
    "national_id": 0.30,
    "utility_bill": 0.50,
    "bank_statement": 0.70,
    "residence_permit": 0.85,
}
NATIONALITY_FORMAT_DRIFT_THRESHOLD = 0.25
EMAIL_FORMAT_DRIFT_THRESHOLD = 0.45
PHONE_FORMAT_DRIFT_THRESHOLD = 0.65

# --- Splunk HEC Configuration ---
# !!! WARNING: Do NOT hardcode sensitive tokens in production scripts.
# Use environment variables or a secure config management system.
SPLUNK_HEC_URL = "YOUR_SPLUNK_HEC_URL"  # e.g., "https://splunk.example.com:8088/services/collector"
SPLUNK_HEC_TOKEN = "YOUR_SPLUNK_HEC_TOKEN"
SPLUNK_HEC_SOURCE = "kyc_simulator"
SPLUNK_HEC_SOURCETYPE = "kyc:synthetic:event"
SPLUNK_HEC_INDEX = "sample_kyc" # Or your preferred index
SPLUNK_HEC_VERIFY_SSL = False  # Set to False if using self-signed certs (not recommended for prod)
SPLUNK_HEC_BATCH_SIZE = 100 # Number of events to send in one HEC request
SPLUNK_HEC_TIMEOUT = 30 # Timeout in seconds for HEC requests

# --- Initialize Faker ---
fake = Faker()

# --- Constants for realistic choices (same as before) ---
KYC_EVENT_TYPES = [
    "kyc_application_submitted", "document_uploaded",
    "identity_verification_pending", "address_verification_pending",
    "background_check_initiated", "kyc_review_required",
    "kyc_approved", "kyc_rejected",
    "profile_update_requested", "account_flagged",
]
BASE_DOCUMENT_TYPE = "driver_license"
DRIFTING_DOCUMENT_TYPES = [
    "passport", "national_id", "utility_bill",
    "bank_statement", "residence_permit",
]
DOCUMENT_STATUSES = [
    "uploaded", "verified", "rejected", "expired",
    "pending_review", "missing_information", "illegible",
]

# --- Timestamp Generation Logic (same as before) ---
def generate_event_timestamps(
    num_events, current_utc_time, local_tz_name
):
    if num_events == 0:
        return []
    num_weeks_backfill = math.ceil(num_events / 1000.0)
    end_datetime_utc = current_utc_time
    start_datetime_utc = end_datetime_utc - datetime.timedelta(
        weeks=num_weeks_backfill
    )
    target_tz = pytz.timezone(local_tz_name)
    potential_slots = []
    current_hour_start_utc = start_datetime_utc.replace(
        minute=0, second=0, microsecond=0
    )
    while current_hour_start_utc < end_datetime_utc:
        local_dt_for_hour = current_hour_start_utc.astimezone(target_tz)
        day_of_week = local_dt_for_hour.weekday()
        local_hour = local_dt_for_hour.hour
        is_valid_slot_for_event = False
        weight = 0
        if 0 <= day_of_week <= 4:
            if 8 <= local_hour < 19:
                is_valid_slot_for_event = True
                weight = 80
        elif day_of_week == 5:
            if 8 <= local_hour < 14:
                is_valid_slot_for_event = True
                weight = 15
        elif day_of_week == 6:
            if 10 <= local_hour < 13:
                is_valid_slot_for_event = True
                weight = 5
        if is_valid_slot_for_event:
            for _ in range(5):
                rand_minute, rand_second, rand_microsecond = (
                    random.randint(0, 59),
                    random.randint(0, 59),
                    random.randint(0, 999999),
                )
                event_local_dt = local_dt_for_hour.replace(
                    minute=rand_minute,
                    second=rand_second,
                    microsecond=rand_microsecond,
                )
                event_utc_dt = event_local_dt.astimezone(
                    datetime.timezone.utc
                )
                if start_datetime_utc <= event_utc_dt <= end_datetime_utc:
                    potential_slots.append(
                        {"timestamp": event_utc_dt, "weight": weight}
                    )
        current_hour_start_utc += datetime.timedelta(hours=1)

    if not potential_slots:
        print(
            "Warning: No valid business hour slots found. "
            "Generating evenly spread UTC timestamps.",
            file=sys.stderr
        )
        time_delta_per_event = (
            end_datetime_utc - start_datetime_utc
        ) / num_events
        return sorted(
            [
                start_datetime_utc + time_delta_per_event * i
                for i in range(num_events)
            ]
        )
    population = [slot["timestamp"] for slot in potential_slots]
    weights = [slot["weight"] for slot in potential_slots]
    chosen_timestamps = random.choices(
        population, weights=weights, k=num_events
    )
    return sorted(chosen_timestamps)

# --- Core Event Generation (same as before) ---
def generate_base_event(timestamp_utc):
    event_type = random.choice(KYC_EVENT_TYPES)
    status_map = {
        "kyc_application_submitted": "received_for_processing",
        "document_uploaded": "upload_successful",
        "identity_verification_pending": "verification_initiated",
        "address_verification_pending": "verification_initiated",
        "background_check_initiated": "check_started",
        "kyc_review_required": "escalated_for_review",
        "kyc_approved": "decision_approved",
        "kyc_rejected": "decision_rejected",
        "profile_update_requested": "update_request_logged",
        "account_flagged": "account_status_flagged",
    }
    event_status = status_map.get(event_type, "processed_unknown_status")
    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": timestamp_utc.isoformat().replace("+00:00", "Z"),
        "user_id": f"user_{random.randint(10000, 99999)}",
        "event_type": event_type,
        "event_status": event_status,
        "source_ip": fake.ipv4(),
        "device_id": fake.sha256()[:32],
        "session_id": fake.uuid4(),
    }

# --- Modular Feature Functions (with Drift - same as before) ---
def add_pii_data(event_data, progress_percentage):
    country_name_val = fake.country()
    country_code_val = fake.country_code()
    nationality_display = (
        country_name_val
        if progress_percentage < NATIONALITY_FORMAT_DRIFT_THRESHOLD
        else country_code_val
    )
    raw_email = fake.unique.email()
    email_display = (
        raw_email.lower()
        if progress_percentage < EMAIL_FORMAT_DRIFT_THRESHOLD
        else raw_email.upper()
    )
    base_phone_digits = "".join(filter(str.isdigit, fake.phone_number()))
    if len(base_phone_digits) > 10:
        formatted_phone = f"{base_phone_digits[:3]}-{base_phone_digits[3:6]}-{base_phone_digits[6:10]}"
    else:
        formatted_phone = fake.phone_number()
    phone_display = (
        formatted_phone.replace("-", ".")
        if progress_percentage >= PHONE_FORMAT_DRIFT_THRESHOLD
        else formatted_phone
    )
    event_data["pii"] = {
        "full_name": fake.name(),
        "date_of_birth": fake.date_of_birth(
            minimum_age=18, maximum_age=90
        ).isoformat(),
        "nationality": nationality_display,
        "_internal_nationality_code": country_code_val,
        "email": email_display,
        "phone_number": phone_display,
    }

def add_address_data(event_data):
    event_data["address"] = {
        "street_address": fake.street_address(),
        "city": fake.city(),
        "state_province": fake.state_abbr(),
        "postal_code": fake.postcode(),
        "country_code": fake.country_code(),
    }

def add_document_data(event_data, progress_percentage):
    available_doc_types = [BASE_DOCUMENT_TYPE]
    for doc_type, threshold in DOC_TYPE_DRIFT_THRESHOLDS.items():
        if progress_percentage >= threshold:
            available_doc_types.append(doc_type)
    num_documents = random.randint(1, 2)
    documents = []
    main_event_type = event_data.get("event_type")
    for _ in range(num_documents):
        doc_type = random.choice(available_doc_types)
        issue_date = fake.date_between(start_date="-5y", end_date="today")
        expiry_date_iso = None
        if doc_type not in ["utility_bill", "bank_statement"]:
            expiry_years = random.randint(1, 10)
            expiry_date = issue_date + datetime.timedelta(
                days=expiry_years * 365 + random.randint(0, 30)
            )
            expiry_date_iso = expiry_date.isoformat()
        else:
            issue_date = fake.date_between(start_date="-90d", end_date="today")
        doc_status = random.choice(DOCUMENT_STATUSES)
        if main_event_type == "document_uploaded":
            doc_status = random.choice(["uploaded", "pending_review"])
        elif main_event_type == "kyc_approved":
            doc_status = "verified"
        elif main_event_type == "kyc_rejected" and _ == 0:
            if doc_status in ["verified", "uploaded", "pending_review"]:
                doc_status = random.choice(
                    ["rejected", "expired", "illegible"]
                )
        doc_issuing_country = fake.country_code()
        if doc_type in ["utility_bill", "bank_statement"]:
            if "address" in event_data and event_data["address"].get("country_code"):
                doc_issuing_country = event_data["address"]["country_code"]
        elif "pii" in event_data and event_data["pii"].get("_internal_nationality_code"):
            doc_issuing_country = event_data["pii"]["_internal_nationality_code"]
        documents.append({
            "document_type": doc_type,
            "document_id": fake.bothify(text="??########??").upper(),
            "document_issue_date": issue_date.isoformat(),
            "document_expiry_date": expiry_date_iso,
            "document_status": doc_status,
            "issuing_country": doc_issuing_country,
            "file_hash_sha256": fake.sha256(),
        })
    event_data["documents"] = documents

# --- Splunk HEC Sending Function ---
def send_events_to_splunk_hec(
    events_batch, url, token, source, sourcetype, index, verify_ssl, timeout
):
    """Sends a batch of events to Splunk HEC."""
    if not events_batch:
        return True # Nothing to send

    headers = {"Authorization": f"Splunk {token}"}
    # Each event in the batch needs to be a JSON object, newline separated
    payload_items = []
    for event_data in events_batch:
        # Convert ISO timestamp from event to epoch for HEC 'time' field
        try:
            # Assuming event_data["timestamp"] is like "2024-05-27T15:30:00Z"
            dt_object = datetime.datetime.fromisoformat(
                event_data["timestamp"].replace("Z", "+00:00")
            )
            epoch_time = dt_object.timestamp()
        except (ValueError, KeyError) as e:
            print(f"Error converting timestamp for HEC: {e}. Using current time.", file=sys.stderr)
            epoch_time = time.time() # Fallback

        hec_event = {
            "time": epoch_time,
            "source": source,
            "sourcetype": sourcetype,
            "index": index,
            "event": event_data, # The actual generated event
        }
        payload_items.append(json.dumps(hec_event))

    payload = "\n".join(payload_items)

    try:
        response = requests.post(
            url,
            data=payload.encode('utf-8'), # Ensure payload is bytes
            headers=headers,
            verify=verify_ssl,
            timeout=timeout,
        )
        response.raise_for_status()  # Raises an exception for bad status codes (4xx or 5xx)
        # print(f"Successfully sent batch of {len(events_batch)} events to Splunk HEC.", file=sys.stderr)
        return True
    except requests.exceptions.RequestException as e:
        print(f"Error sending batch to Splunk HEC: {e}", file=sys.stderr)
        if hasattr(e, 'response') and e.response is not None:
            try:
                print(f"Splunk HEC Response: {e.response.json()}", file=sys.stderr)
            except json.JSONDecodeError:
                print(f"Splunk HEC Response (raw): {e.response.text}", file=sys.stderr)
        return False

# --- Main Execution ---
def main():
    parser = argparse.ArgumentParser(
        description="Generate synthetic KYC event data and optionally send to Splunk HEC."
    )
    parser.add_argument(
        "--send-to-splunk",
        action="store_true",
        help="Enable sending data to Splunk HEC.",
    )
    parser.add_argument(
        "--splunk-url",
        type=str,
        default=SPLUNK_HEC_URL,
        help=f"Splunk HEC URL (default: {SPLUNK_HEC_URL})",
    )
    parser.add_argument(
        "--splunk-token",
        type=str,
        default=SPLUNK_HEC_TOKEN,
        help="Splunk HEC Token (default: [sensitive - check script])",
    )
    parser.add_argument(
        "--splunk-index",
        type=str,
        default=SPLUNK_HEC_INDEX,
        help=f"Splunk Index (default: {SPLUNK_HEC_INDEX})",
    )
    parser.add_argument(
        "--splunk-source",
        type=str,
        default=SPLUNK_HEC_SOURCE,
        help=f"Splunk Source (default: {SPLUNK_HEC_SOURCE})",
    )
    parser.add_argument(
        "--splunk-sourcetype",
        type=str,
        default=SPLUNK_HEC_SOURCETYPE,
        help=f"Splunk Sourcetype (default: {SPLUNK_HEC_SOURCETYPE})",
    )
    parser.add_argument(
        "--num-events",
        type=int,
        default=NUM_EVENTS_TOTAL,
        help=f"Number of events to generate (default: {NUM_EVENTS_TOTAL})",
    )
    parser.add_argument(
        "--output-file",
        type=str,
        default=None,
        help="Optional: File path to save JSON output (e.g., kyc_events.json). If not provided, prints to stdout.",
    )
    parser.add_argument(
        "--output-csv",
        type=str,
        default=None,
        help="Optional: File path to save flattened CSV output (e.g., kyc_events.csv). Nested objects are flattened; documents stored as JSON string.",
    )


    args = parser.parse_args()
    # Provide default CSV if no outputs and not sending to Splunk (parity with other simulators)
    if (not args.send_to_splunk) and (not args.output_file) and (not args.output_csv):
        args.output_csv = DEFAULT_CSV_FILENAME
        print(f"No explicit output specified. Defaulting to save to CSV: {args.output_csv}", file=sys.stderr)

    # Update config from args
    current_num_events = args.num_events
    hec_url = args.splunk_url
    hec_token = args.splunk_token
    hec_index = args.splunk_index
    hec_source = args.splunk_source
    hec_sourcetype = args.splunk_sourcetype


    if args.send_to_splunk:
        if "YOUR_SPLUNK_HEC_URL" in hec_url or "YOUR_SPLUNK_HEC_TOKEN" in hec_token:
            print(
                "ERROR: Splunk HEC URL or Token is not configured. "
                "Please update SPLUNK_HEC_URL and SPLUNK_HEC_TOKEN in the script "
                "or provide them via command-line arguments.",
                file=sys.stderr
            )
            sys.exit(1)
        print(f"Splunk HEC sending enabled: URL={hec_url}, Index={hec_index}", file=sys.stderr)


    print(
        f"Generating {current_num_events} KYC events...", file=sys.stderr
    )
    current_time_utc = datetime.datetime.now(datetime.timezone.utc)

    print("Generating timestamps...", file=sys.stderr)
    event_timestamps = generate_event_timestamps(
        current_num_events, current_time_utc, TARGET_LOCAL_TIMEZONE
    )

    all_generated_events = [] # For local saving if requested (JSON or CSV)
    splunk_batch = []
    total_sent_to_splunk = 0
    total_failed_splunk = 0

    print("Generating event data...", file=sys.stderr)
    for i, timestamp in enumerate(event_timestamps):
        if (i + 1) % (current_num_events // 20 or 1) == 0:
            print(f"  Processed {i+1}/{current_num_events} events...", file=sys.stderr)

        if i > 0 and i % 1000 == 0:
            fake.unique.clear()

        progress = (
            (i + 1) / current_num_events if current_num_events > 0 else 0
        )

        event = generate_base_event(timestamp)
        add_pii_data(event, progress)
        add_address_data(event)
        add_document_data(event, progress)

        if args.output_file or args.output_csv or not args.send_to_splunk:  # Ensure events retained when CSV requested
            all_generated_events.append(event)

        if args.send_to_splunk:
            splunk_batch.append(event)
            if len(splunk_batch) >= SPLUNK_HEC_BATCH_SIZE:
                print(f"  Sending batch of {len(splunk_batch)} events to Splunk HEC...", file=sys.stderr)
                if send_events_to_splunk_hec(
                    splunk_batch, hec_url, hec_token,
                    hec_source, hec_sourcetype, hec_index,
                    SPLUNK_HEC_VERIFY_SSL, SPLUNK_HEC_TIMEOUT
                ):
                    total_sent_to_splunk += len(splunk_batch)
                else:
                    total_failed_splunk += len(splunk_batch)
                splunk_batch = [] # Reset batch

    # Send any remaining events in the batch
    if args.send_to_splunk and splunk_batch:
        print(f"  Sending final batch of {len(splunk_batch)} events to Splunk HEC...", file=sys.stderr)
        if send_events_to_splunk_hec(
            splunk_batch, hec_url, hec_token,
            hec_source, hec_sourcetype, hec_index,
            SPLUNK_HEC_VERIFY_SSL, SPLUNK_HEC_TIMEOUT
        ):
            total_sent_to_splunk += len(splunk_batch)
        else:
            total_failed_splunk += len(splunk_batch)

    if args.send_to_splunk:
        print(f"\nSplunk HEC Summary for KYC Simulator:", file=sys.stderr)
        print(f"  Successfully sent: {total_sent_to_splunk} events", file=sys.stderr)
        print(f"  Failed to send:    {total_failed_splunk} events", file=sys.stderr)


    # JSON/JSONL output handling
    if args.output_file:
        print(f"\nSaving {len(all_generated_events)} events to {args.output_file}...", file=sys.stderr)
        try:
            if args.output_file.lower().endswith('.jsonl'):
                with open(args.output_file, 'w', encoding='utf-8') as f:
                    for event in all_generated_events:
                        f.write(json.dumps(event, ensure_ascii=False) + '\n')
                print(f"Successfully saved events to {args.output_file} (JSONL format)", file=sys.stderr)
            else:
                with open(args.output_file, 'w', encoding='utf-8') as f:
                    json.dump(all_generated_events, f, indent=2, ensure_ascii=False)
                print(f"Successfully saved events to {args.output_file} (JSON array)", file=sys.stderr)
        except Exception as e:
            print(f"Error writing JSON/JSONL file {args.output_file}: {e}", file=sys.stderr)

    # CSV output handling (flatten nested structures)
    if args.output_csv:
        print(f"\nWriting raw events to CSV ({len(all_generated_events)} events)...", file=sys.stderr)
        try:
            if pd is not None:
                # pandas will auto-expand top-level keys; nested dict/list become string reps
                df = pd.DataFrame(all_generated_events)
                df.to_csv(args.output_csv, index=False)
            else:
                print("pandas not available; using csv module; nested structures stringified via json.", file=sys.stderr)
                # Collect union of scalar top-level keys (include nested containers as JSON strings)
                all_keys = set()
                serializable_rows = []
                for ev in all_generated_events:
                    row = {}
                    for k, v in ev.items():
                        if isinstance(v, (dict, list)):
                            try:
                                row[k] = json.dumps(v, ensure_ascii=False)
                            except Exception:
                                row[k] = str(v)
                        else:
                            row[k] = v
                    all_keys.update(row.keys())
                    serializable_rows.append(row)
                fieldnames = sorted(all_keys)
                with open(args.output_csv, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.DictWriter(f, fieldnames=fieldnames)
                    writer.writeheader()
                    writer.writerows(serializable_rows)
            print(f"Successfully saved CSV to {args.output_csv}", file=sys.stderr)
        except Exception as e:
            print(f"Error writing CSV file {args.output_csv}: {e}", file=sys.stderr)

    # If no outputs requested and not sending, print JSON to stdout
    if not args.send_to_splunk and not args.output_file and not args.output_csv:
        print(json.dumps(all_generated_events, indent=2, ensure_ascii=False))

    print(f"\nScript finished. Generated {len(event_timestamps)} events in total.", file=sys.stderr)


if __name__ == "__main__":
    import sys # For stderr and exit
    # Ensure Faker, pytz, requests are installed:
    # pip install Faker pytz requests
    main()
