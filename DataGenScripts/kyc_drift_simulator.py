# kyc_data_schema_drift.py
import argparse
import datetime
import json
import random
import sys
import time
import uuid
import math
import warnings # For suppressing urllib3 warnings

import pandas as pd
import pytz
import requests
from faker import Faker

# Initialize Faker
fake = Faker()
Faker.seed(42) # Seed Faker globally
random.seed(42)

# --- Configuration ---
DEFAULT_NUM_EVENTS = 1000
DEFAULT_CSV_FILENAME = "kyc_schema_drift_raw_logs.csv"
TARGET_LOCAL_TIMEZONE = "America/New_York" # For timestamp generation logic

# --- Splunk HEC Configuration for RAW DRIFT DATA ---
SPLUNK_HEC_URL_DEFAULT = "YOUR_SPLUNK_HEC_URL/services/collector" # Batch endpoint
SPLUNK_HEC_TOKEN_DEFAULT = "YOUR_HEC_TOKEN_FOR_RAW_DATA"
SPLUNK_RAW_INDEX_DEFAULT = "drift_raw_data" # Common index
SPLUNK_KYC_RAW_SOURCETYPE_DEFAULT = "kyc_drift_raw" # Specific sourcetype
SPLUNK_HEC_SOURCE_DEFAULT = "kyc_drift_generator"
SPLUNK_HEC_VERIFY_SSL_DEFAULT = False
SPLUNK_HEC_BATCH_SIZE_DEFAULT = 100
SPLUNK_HEC_TIMEOUT_DEFAULT = 30

# --- Existing Format/Content Drift Thresholds (from original KYC script) ---
# These will continue to operate based on progress_percentage for their specific effects
DOC_TYPE_DRIFT_THRESHOLDS = { "passport": 0.15, "national_id": 0.30, "utility_bill": 0.50, "bank_statement": 0.70, "residence_permit": 0.85 }
NATIONALITY_FORMAT_DRIFT_THRESHOLD = 0.25
EMAIL_FORMAT_DRIFT_THRESHOLD = 0.45
PHONE_FORMAT_DRIFT_THRESHOLD = 0.65

# --- Schema Drift Percentage Thresholds ---
DRIFT_ADD_COMMON_KYC_START_PCT = 0.25
DRIFT_REMOVE_SESSION_ADD_PII_START_PCT = 0.50
DRIFT_RENAME_IP_ADD_DOC_START_PCT = 0.75

# --- Constants for realistic choices (from original KYC script) ---
KYC_EVENT_TYPES = [ "kyc_application_submitted", "document_uploaded", "identity_verification_pending", "address_verification_pending", "background_check_initiated", "kyc_review_required", "kyc_approved", "kyc_rejected", "profile_update_requested", "account_flagged", ]
BASE_DOCUMENT_TYPE = "driver_license"
DRIFTING_DOCUMENT_TYPES = [ "passport", "national_id", "utility_bill", "bank_statement", "residence_permit", ]
DOCUMENT_STATUSES = [ "uploaded", "verified", "rejected", "expired", "pending_review", "missing_information", "illegible", ]
CHANNEL_OF_INTERACTION_CHOICES = ["WebApp_Desktop", "WebApp_Mobile", "MobileApp_iOS", "MobileApp_Android", "API_Integration", "Internal_Ops_Tool", "In_Person_Branch"]
EMPLOYMENT_STATUS_CHOICES = ["Employed", "Self-Employed", "Unemployed", "Student", "Retired", "Homemaker", "Other"]
DOC_VERIFICATION_METHODS = ["Automated_AI_Scan", "Manual_Review_Level1", "Manual_Review_Level2", "ThirdParty_Verification_Service", "Database_Crosscheck"]


# --- Timestamp Generation Logic (from original KYC script) ---
def generate_event_timestamps(num_events, current_utc_time, local_tz_name):
    if num_events == 0: return []
    num_weeks_backfill = math.ceil(num_events / 1000.0)
    end_datetime_utc = current_utc_time
    start_datetime_utc = end_datetime_utc - datetime.timedelta(weeks=num_weeks_backfill)
    target_tz = pytz.timezone(local_tz_name)
    potential_slots = []
    current_hour_start_utc = start_datetime_utc.replace(minute=0, second=0, microsecond=0)
    while current_hour_start_utc < end_datetime_utc:
        local_dt_for_hour = current_hour_start_utc.astimezone(target_tz)
        day_of_week, local_hour = local_dt_for_hour.weekday(), local_dt_for_hour.hour
        is_valid, weight = False, 0
        if 0 <= day_of_week <= 4 and 8 <= local_hour < 19: is_valid, weight = True, 80
        elif day_of_week == 5 and 8 <= local_hour < 14: is_valid, weight = True, 15
        elif day_of_week == 6 and 10 <= local_hour < 13: is_valid, weight = True, 5
        if is_valid:
            for _ in range(5):
                event_local_dt = local_dt_for_hour.replace(minute=random.randint(0,59), second=random.randint(0,59), microsecond=random.randint(0,999999))
                event_utc_dt = event_local_dt.astimezone(datetime.timezone.utc)
                if start_datetime_utc <= event_utc_dt <= end_datetime_utc:
                    potential_slots.append({"timestamp": event_utc_dt, "weight": weight})
        current_hour_start_utc += datetime.timedelta(hours=1)
    if not potential_slots:
        print("Warning: No valid business hour slots. Generating evenly spread UTC timestamps.", file=sys.stderr)
        delta = (end_datetime_utc - start_datetime_utc) / num_events
        return sorted([start_datetime_utc + delta * i for i in range(num_events)])
    return sorted(random.choices([s["timestamp"] for s in potential_slots], weights=[s["weight"] for s in potential_slots], k=num_events))


# --- Modular Feature Functions (incorporating original format/content drift) ---
# These will be called by the main event generator. Schema drift will be applied *after* these.
def generate_base_event_fields(timestamp_utc): # Generates only the initial common fields
    event_type = random.choice(KYC_EVENT_TYPES)
    status_map = { "kyc_application_submitted": "received_for_processing", "document_uploaded": "upload_successful", "identity_verification_pending": "verification_initiated", "address_verification_pending": "verification_initiated", "background_check_initiated": "check_started", "kyc_review_required": "escalated_for_review", "kyc_approved": "decision_approved", "kyc_rejected": "decision_rejected", "profile_update_requested": "update_request_logged", "account_flagged": "account_status_flagged", }
    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": timestamp_utc.isoformat().replace("+00:00", "Z"),
        "user_id": f"user_{random.randint(10000, 99999)}",
        "event_type": event_type,
        "event_status": status_map.get(event_type, "processed_unknown_status"),
        # source_ip, device_id, session_id will be added/drifted in the main generator
    }

def get_pii_data(progress_percentage): # Changed to return data, not modify in place
    country_name_val, country_code_val = fake.country(), fake.country_code()
    nationality_display = country_name_val if progress_percentage < NATIONALITY_FORMAT_DRIFT_THRESHOLD else country_code_val
    raw_email = fake.unique.email()
    email_display = raw_email.lower() if progress_percentage < EMAIL_FORMAT_DRIFT_THRESHOLD else raw_email.upper()
    base_phone_digits = "".join(filter(str.isdigit, fake.phone_number()))
    formatted_phone = f"{base_phone_digits[:3]}-{base_phone_digits[3:6]}-{base_phone_digits[6:10]}" if len(base_phone_digits) > 10 else fake.phone_number()
    phone_display = formatted_phone.replace("-", ".") if progress_percentage >= PHONE_FORMAT_DRIFT_THRESHOLD else formatted_phone
    return {
        "full_name": fake.name(), "date_of_birth": fake.date_of_birth(minimum_age=18, maximum_age=90).isoformat(),
        "nationality": nationality_display, "_internal_nationality_code": country_code_val,
        "email": email_display, "phone_number": phone_display,
    }

def get_address_data(): # Changed to return data
    return {
        "street_address": fake.street_address(), "city": fake.city(), "state_province": fake.state_abbr(),
        "postal_code": fake.postcode(), "country_code": fake.country_code(),
    }

def get_document_data(main_event_type, progress_percentage, pii_data_for_country_ref=None, address_data_for_country_ref=None): # Changed to return data
    available_doc_types = [BASE_DOCUMENT_TYPE]
    for doc_type, threshold in DOC_TYPE_DRIFT_THRESHOLDS.items():
        if progress_percentage >= threshold: available_doc_types.append(doc_type)
    
    documents = []
    for _ in range(random.randint(1, 2)):
        doc_type = random.choice(available_doc_types)
        issue_date = fake.date_between(start_date="-5y", end_date="today")
        expiry_date_iso = None
        if doc_type not in ["utility_bill", "bank_statement"]:
            expiry_date = issue_date + datetime.timedelta(days=random.randint(1,10)*365 + random.randint(0,30))
            expiry_date_iso = expiry_date.isoformat()
        else: issue_date = fake.date_between(start_date="-90d", end_date="today")
        
        doc_status = random.choice(DOCUMENT_STATUSES)
        if main_event_type == "document_uploaded": doc_status = random.choice(["uploaded", "pending_review"])
        elif main_event_type == "kyc_approved": doc_status = "verified"
        elif main_event_type == "kyc_rejected" and not documents: # if first doc for rejected event
            if doc_status in ["verified", "uploaded", "pending_review"]: doc_status = random.choice(["rejected", "expired", "illegible"])

        doc_issuing_country = fake.country_code() # Default
        if doc_type in ["utility_bill", "bank_statement"] and address_data_for_country_ref:
            doc_issuing_country = address_data_for_country_ref.get("country_code", doc_issuing_country)
        elif pii_data_for_country_ref: # For ID/Passport, try to use PII nationality
            doc_issuing_country = pii_data_for_country_ref.get("_internal_nationality_code", doc_issuing_country)

        documents.append({
            "document_type": doc_type, "document_id": fake.bothify(text="??########??").upper(),
            "document_issue_date": issue_date.isoformat(), "document_expiry_date": expiry_date_iso,
            "document_status": doc_status, "issuing_country": doc_issuing_country,
            "file_hash_sha256": fake.sha256(),
        })
    return documents


# --- Value Schema Drift Threshold (same as field drift) ---
DRIFT_VALUE_SCHEMA_START_PCT = DRIFT_RENAME_IP_ADD_DOC_START_PCT  # 0.75

def drift_underscore_fields(val, progress_pct, drift_start_pct=DRIFT_VALUE_SCHEMA_START_PCT):
    """Change underscores to dashes, dots, or spaces."""
    if progress_pct < drift_start_pct or not isinstance(val, str):
        return val
    if "_" in val:
        drift_type = random.choice(["-", ".", " "])
        return val.replace("_", drift_type)
    return val

# --- Main Event Generation Function with Targeted Value Drift ---
def generate_kyc_event_with_drift(event_number, total_events, timestamp_utc):
    """
    Generates a single KYC event with a clean, refactored approach to schema
    and value drift.
    """
    current_progress_pct = event_number / total_events

    # 1. --- Generate all potential data points as clean, local variables/blocks ---
    base_event_data = generate_base_event_fields(timestamp_utc)
    base_source_ip_value = fake.ipv4()
    base_device_id_value = fake.sha256()[:32]
    base_session_id_value = str(uuid.uuid4())

    pii_block = (
        get_pii_data(current_progress_pct) if random.random() < 0.8 else None
    )
    address_block = get_address_data() if random.random() < 0.7 else None
    documents_block = (
        get_document_data(
            base_event_data["event_type"],
            current_progress_pct,
            pii_block,
            address_block,
        )
        if random.random() < 0.6
        else None
    )

    # 2. --- Assemble the event with its final STRUCTURE, using clean data ---
    event = base_event_data
    event["device_id"] = base_device_id_value

    # Add/rename IP field
    if current_progress_pct < DRIFT_RENAME_IP_ADD_DOC_START_PCT:
        event["source_ip"] = base_source_ip_value
    else:
        event["client_ip_address"] = base_source_ip_value

    # Add/remove session_id
    if current_progress_pct < DRIFT_REMOVE_SESSION_ADD_PII_START_PCT:
        event["session_id"] = base_session_id_value

    # Add common KYC fields
    if current_progress_pct >= DRIFT_ADD_COMMON_KYC_START_PCT:
        event["risk_score_provisional"] = random.randint(0, 100)
        event["channel_of_interaction"] = random.choice(
            CHANNEL_OF_INTERACTION_CHOICES
        )

    # Add employment_status to PII block
    if current_progress_pct >= DRIFT_REMOVE_SESSION_ADD_PII_START_PCT:
        if pii_block:
            pii_block["employment_status"] = random.choice(
                EMPLOYMENT_STATUS_CHOICES
            )

    # Add verification_method to documents block
    if current_progress_pct >= DRIFT_RENAME_IP_ADD_DOC_START_PCT:
        if documents_block:
            for doc in documents_block:
                doc["document_verification_method"] = random.choice(
                    DOC_VERIFICATION_METHODS
                )

    # Add the complete blocks to the event
    if pii_block:
        event["pii"] = pii_block
    if address_block:
        event["address"] = address_block
    if documents_block:
        event["documents"] = documents_block

    # 3. --- Apply VALUE drift to the fully constructed event object ---
    if current_progress_pct >= DRIFT_VALUE_SCHEMA_START_PCT:
        # Drift top-level fields
        if "event_type" in event:
            event["event_type"] = drift_underscore_fields(
                event["event_type"], current_progress_pct
            )
        if "channel_of_interaction" in event:
            event["channel_of_interaction"] = drift_underscore_fields(
                event["channel_of_interaction"], current_progress_pct
            )

        # Drift nested fields in the documents block
        if "documents" in event and event["documents"]:
            for doc in event["documents"]:
                if "document_type" in doc:
                    doc["document_type"] = drift_underscore_fields(
                        doc["document_type"], current_progress_pct
                    )
                if "document_verification_method" in doc:
                    doc["document_verification_method"] = drift_underscore_fields(
                        doc["document_verification_method"], current_progress_pct
                    )

    return event

# --- Splunk HEC Sending Function (Batching, same as before) ---
def send_events_to_splunk_hec(
    events_batch, url, token, source, sourcetype, index, verify_ssl, timeout
):
    if not events_batch: return True
    headers = {"Authorization": f"Splunk {token}"}
    payload_items = []
    for event_data in events_batch:
        try:
            dt_object = datetime.datetime.fromisoformat(event_data["timestamp"].replace("Z", "+00:00"))
            epoch_time = dt_object.timestamp()
        except (ValueError, KeyError) as e:
            print(f"Error converting timestamp for HEC: {e}. Using current time. Event: {event_data.get('event_id', 'N/A')}", file=sys.stderr)
            epoch_time = time.time()
        hec_event = {
            "time": epoch_time, "source": source, "sourcetype": sourcetype,
            "index": index, "host": event_data.get("user_id", source), # Using user_id as host for KYC
            "event": event_data,
        }
        payload_items.append(json.dumps(hec_event))
    payload = "\n".join(payload_items)
    try:
        response = requests.post(
            url, data=payload.encode("utf-8"), headers=headers,
            verify=verify_ssl, timeout=timeout,
        )
        response.raise_for_status()
        return True
    except requests.exceptions.RequestException as e:
        print(f"Error sending batch to Splunk HEC: {e}", file=sys.stderr)
        if hasattr(e, "response") and e.response is not None:
            try: print(f"Splunk HEC Response: {e.response.json()}", file=sys.stderr)
            except json.JSONDecodeError: print(f"Splunk HEC Response (raw): {e.response.text}", file=sys.stderr)
        return False

def main():
    parser = argparse.ArgumentParser(
        description="Generate KYC logs with schema drift, send to Splunk HEC or save to CSV."
    )
    parser.add_argument("--num-events", type=int, default=DEFAULT_NUM_EVENTS, help=f"Number of events to generate (default: {DEFAULT_NUM_EVENTS}).")
    parser.add_argument("--output-csv", type=str, default=None, help=f"Filename to save logs as CSV. If not provided and --send-to-splunk is absent, defaults to '{DEFAULT_CSV_FILENAME}'.")
    parser.add_argument("--send-to-splunk", action="store_true", help="Enable sending data to Splunk HEC.")
    parser.add_argument("--events-per-hour", type=int, default=1000, help="Number of events to generate per hour of backfill (default: 1000).")
    
    hec_group = parser.add_argument_group('Splunk HEC Options (for RAW data)')
    hec_group.add_argument("--splunk-url", type=str, default=SPLUNK_HEC_URL_DEFAULT)
    hec_group.add_argument("--splunk-token", type=str, default=SPLUNK_HEC_TOKEN_DEFAULT)
    hec_group.add_argument("--splunk-index", type=str, default=SPLUNK_RAW_INDEX_DEFAULT, help="Target Splunk Index for RAW drift data.")
    hec_group.add_argument("--splunk-source", type=str, default=SPLUNK_HEC_SOURCE_DEFAULT)
    hec_group.add_argument("--splunk-sourcetype", type=str, default=SPLUNK_KYC_RAW_SOURCETYPE_DEFAULT, help="Target Splunk Sourcetype for KYC RAW drift data.")
    hec_group.add_argument("--splunk-batch-size", type=int, default=SPLUNK_HEC_BATCH_SIZE_DEFAULT)
    hec_group.add_argument("--splunk-disable-ssl-verify", action="store_false", dest="splunk_verify_ssl")
    parser.set_defaults(splunk_verify_ssl=SPLUNK_HEC_VERIFY_SSL_DEFAULT)

    args = parser.parse_args()

    csv_output_file = args.output_csv
    if not args.output_csv and not args.send_to_splunk:
        csv_output_file = DEFAULT_CSV_FILENAME
        print(f"No explicit output specified. Defaulting to save to CSV: {csv_output_file}", file=sys.stderr)

    if args.send_to_splunk:
        if "YOUR_SPLUNK_HEC_URL" in args.splunk_url or "YOUR_SPLUNK_HEC_TOKEN" in args.splunk_token:
            print("ERROR: Splunk HEC URL or Token for raw data is not configured.", file=sys.stderr)
            sys.exit(1)
        print(f"Splunk HEC sending for KYC raw data enabled: URL={args.splunk_url}, Index={args.splunk_index}, Sourcetype={args.splunk_sourcetype}", file=sys.stderr)
        if not args.splunk_verify_ssl:
            print("SSL verification for HEC is DISABLED.", file=sys.stderr)
            try:
                import urllib3
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
                warnings.filterwarnings('ignore', category=urllib3.exceptions.NotOpenSSLWarning)
            except Exception: pass

    print(f"Generating {args.num_events} KYC log records with schema drift...", file=sys.stderr)
    
    schema_drift_points_events = {
        "Add Common Fields (risk_score_provisional, channel_of_interaction)": int(DRIFT_ADD_COMMON_KYC_START_PCT * args.num_events),
        "Remove session_id & Add employment_status to PII": int(DRIFT_REMOVE_SESSION_ADD_PII_START_PCT * args.num_events),
        "Rename source_ip & Add doc_verification_method to Docs": int(DRIFT_RENAME_IP_ADD_DOC_START_PCT * args.num_events),
    }
    print(f"KYC Schema drift points (approx event number): {schema_drift_points_events}", file=sys.stderr)

    current_time_utc = datetime.datetime.now(datetime.timezone.utc)

    # Calculate total backfill hours based on user input
    EVENTS_PER_HOUR = args.events_per_hour
    total_backfill_hours = args.num_events / EVENTS_PER_HOUR
    print(f"Backfill window: {total_backfill_hours:.2f} hours ({args.num_events} events at {EVENTS_PER_HOUR} per hour)", file=sys.stderr)

    # Generate evenly spaced timestamps over the backfill window
    start_datetime_utc = current_time_utc - datetime.timedelta(hours=total_backfill_hours)
    delta = (current_time_utc - start_datetime_utc) / args.num_events
    all_timestamps = [start_datetime_utc + i * delta for i in range(args.num_events)]

    log_data_list, splunk_batch = [], []
    total_sent_to_splunk, total_failed_splunk = 0, 0

    for i in range(args.num_events):
        event_number = i + 1

        # Use the pre-generated timestamp for this event
        current_time_for_event = all_timestamps[i]

        if event_number % (args.num_events // 20 or 1) == 0:
            print(f"  Generated {event_number}/{args.num_events} logs (Progress: { (event_number/args.num_events)*100:.1f} %)...", file=sys.stderr)

        if i > 0 and i % 1000 == 0:
            fake.unique.clear() # For unique email generation

        log_entry = generate_kyc_event_with_drift(event_number, args.num_events, current_time_for_event)
        log_data_list.append(log_entry)

        if args.send_to_splunk:
            splunk_batch.append(log_entry)
            if len(splunk_batch) >= args.splunk_batch_size:
                if send_events_to_splunk_hec(
                    splunk_batch, args.splunk_url, args.splunk_token, args.splunk_source,
                    args.splunk_sourcetype, args.splunk_index, args.splunk_verify_ssl, SPLUNK_HEC_TIMEOUT_DEFAULT
                ): total_sent_to_splunk += len(splunk_batch)
                else: total_failed_splunk += len(splunk_batch)
                splunk_batch = []

    if args.send_to_splunk and splunk_batch:
        if send_events_to_splunk_hec(
            splunk_batch, args.splunk_url, args.splunk_token, args.splunk_source,
            args.splunk_sourcetype, args.splunk_index, args.splunk_verify_ssl, SPLUNK_HEC_TIMEOUT_DEFAULT
        ): total_sent_to_splunk += len(splunk_batch)
        else: total_failed_splunk += len(splunk_batch)

    if args.send_to_splunk:
        print("\nSplunk HEC Sending Summary (KYC Raw Data):", file=sys.stderr)
        print(f"  Successfully sent: {total_sent_to_splunk} logs", file=sys.stderr)
        print(f"  Failed to send:    {total_failed_splunk} logs", file=sys.stderr)

    if csv_output_file:
        print(f"\nSaving {len(log_data_list)} KYC raw log records to {csv_output_file}...", file=sys.stderr)
        df = pd.DataFrame(log_data_list)
        df.to_csv(csv_output_file, index=False)
        print(f"Successfully saved KYC raw logs to {csv_output_file}", file=sys.stderr)

    print(f"\nScript finished. Generated {args.num_events} total KYC raw logs with schema drift.", file=sys.stderr)

if __name__ == "__main__":
    main()