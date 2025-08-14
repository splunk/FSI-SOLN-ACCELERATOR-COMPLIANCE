# pci_data_schema_drift.py
import argparse
import json
import random
import sys
import time
import uuid # For transaction_id if we re-add it or similar
from datetime import datetime, timedelta, timezone

import pandas as pd
import requests
from faker import Faker
import warnings # For suppressing urllib3 warnings

# Initialize Faker
fake = Faker("en_US")
Faker.seed(42) # Seed Faker globally if desired, or per instance
random.seed(42)


# --- Splunk HEC Configuration for RAW DRIFT DATA ---
SPLUNK_HEC_URL_DEFAULT = "YOUR_SPLUNK_HEC_URL/services/collector" # Batch endpoint
SPLUNK_HEC_TOKEN_DEFAULT = "YOUR_HEC_TOKEN_FOR_RAW_DATA"
SPLUNK_RAW_INDEX_DEFAULT = "drift_raw_data" # Common index for all raw drift sources
SPLUNK_PCI_RAW_SOURCETYPE_DEFAULT = "pci_drift_raw" # Specific sourcetype for this script
SPLUNK_HEC_SOURCE_DEFAULT = "pci_drift_generator"
SPLUNK_HEC_VERIFY_SSL_DEFAULT = False
SPLUNK_HEC_BATCH_SIZE_DEFAULT = 100 # Changed from single event to batch
SPLUNK_HEC_TIMEOUT_DEFAULT = 30
DEFAULT_CSV_FILENAME = "pci_schema_drift_raw_logs.csv"

# --- Default Data Generation Parameters ---
NUM_EVENTS_DEFAULT = 1000
DELAY_SECONDS_DEFAULT = 0.05 # Only used if sending to HEC

# --- Schema Drift Percentage Thresholds ---
DRIFT_ADD_FIELDS_START_PCT = 0.30
DRIFT_REMOVE_PIN_START_PCT = 0.60
DRIFT_RENAME_IP_ADD_RECURRING_START_PCT = 0.80
DRIFT_VALUE_DRIFT_START_PCT = 0.50  # Start at 50% instead of 68%

# --- Existing Data Format Drift Manager (for PAN and Expiry Date) ---
class DataDriftManager:
    def __init__(self, field_name, initial_format_func, drift_points_pct):
        self.field_name = field_name
        self.initial_format_func = initial_format_func
        # Store drift points as a sorted list of (percentage, function) tuples
        self.drift_points_pct = sorted(
            drift_points_pct.items(), key=lambda item: item[0]
        )
        self.last_logged_stage = -1

    def get_formatted_value(self, progress_pct, raw_value):
        chosen_format_func = self.initial_format_func
        current_stage = -1

        # Find the correct format based on the current progress percentage
        for idx, (trigger_pct, func) in enumerate(self.drift_points_pct):
            if progress_pct >= trigger_pct:
                chosen_format_func = func
                current_stage = idx
            else:
                break  # Since points are sorted

        # Log the drift change only once when a new stage is entered
        if current_stage > self.last_logged_stage:
            print(
                f"--- Format Drift: {self.field_name} to '{chosen_format_func.__name__}' at {progress_pct:.1%} progress ---",
                file=sys.stderr,
            )
            self.last_logged_stage = current_stage

        return chosen_format_func(raw_value)

def format_pan_no_separator(pan): return pan.replace(".", "").replace("-", "")
def format_pan_dotted(pan):
    pan_cleaned = pan.replace(".", "").replace("-", "")
    return f"{pan_cleaned[0:4]}.{pan_cleaned[4:8]}.{pan_cleaned[8:12]}.{pan_cleaned[12:16]}"
def format_pan_hyphenated(pan):
    pan_cleaned = pan.replace(".", "").replace("-", "")
    if pan_cleaned.startswith("34") or pan_cleaned.startswith("37"):
        return f"{pan_cleaned[0:4]}-{pan_cleaned[4:10]}-{pan_cleaned[10:]}"
    return f"{pan_cleaned[0:4]}-{pan_cleaned[4:8]}-{pan_cleaned[8:12]}-{pan_cleaned[12:16]}"

pan_drift_manager = DataDriftManager(
    "account_number_full (format)",
    initial_format_func=format_pan_no_separator,
    drift_points_pct={ 
        0.30: format_pan_dotted,
        0.60: format_pan_hyphenated
    }
)

def format_exp_slash(exp_date): return exp_date.replace(".", "/").replace("-", "/")
def format_exp_dot(exp_date): return exp_date.replace("/", ".").replace("-", ".")
def format_exp_hyphen(exp_date): return exp_date.replace("/", "-").replace(".", "-")

exp_date_drift_manager = DataDriftManager(
    "expiration_date (format)",
    initial_format_func=format_exp_slash,
    drift_points_pct={ 
        0.30: format_exp_dot,
        0.60: format_exp_hyphen
    }
)

# --- Helper Function for Schema Value Drift ---
def drift_string_pattern(val, progress_pct, drift_start_pct=0.80):
    """Apply schema value drift: dots/spaces/dashes, extra spaces, mixed case, remove spaces."""
    if progress_pct < drift_start_pct or not isinstance(val, str):
        return val  # No drift

    drifted = val

    # 1. Randomly replace spaces/dashes with dots and vice versa
    if " " in drifted and random.random() < 0.5:
        drifted = drifted.replace(" ", ".")
    elif "-" in drifted and random.random() < 0.5:
        drifted = drifted.replace("-", ".")
    elif "." in drifted and random.random() < 0.5:
        drifted = drifted.replace(".", "-")
    elif "." in drifted and random.random() < 0.5:
        drifted = drifted.replace(".", " ")

    # 2. Randomly add extra spaces
    if " " in drifted and random.random() < 0.3:
        drifted = drifted.replace(" ", "  ")  # double spaces

    # 3. Randomly mix letter cases
    if random.random() < 0.5:
        drifted = ''.join(
            c.upper() if random.random() < 0.5 else c.lower() for c in drifted
        )

    # 4. Randomly remove spaces
    if " " in drifted and random.random() < 0.2:
        drifted = drifted.replace(" ", "")

    return drifted

def drift_amount(val, progress_pct, drift_start_pct=DRIFT_RENAME_IP_ADD_RECURRING_START_PCT):
    """Change decimal point to comma for amount after drift threshold."""
    if progress_pct < drift_start_pct:
        return val
    # Only apply if it's a float or string representing a float
    try:
        val_str = f"{float(val):.2f}"
        return val_str.replace('.', ',')
    except Exception:
        return val

def drift_category(val, progress_pct, drift_start_pct=DRIFT_VALUE_DRIFT_START_PCT):
    """For 'Utility Bill', randomly remove or add a space after drift threshold."""
    if progress_pct < drift_start_pct or not isinstance(val, str):
        return val
    
    # Fix: Check for "Utility Bill" properly
    if "Utility" in val and "Bill" in val:
        if " " in val and random.random() < 0.7:  # Increase probability
            return val.replace(" ", "")  # "UtilityBill"
        elif random.random() < 0.3:
            return val.replace(" ", "  ")  # "Utility  Bill"
    return val

def drift_device_info(val, progress_pct, drift_start_pct=DRIFT_VALUE_DRIFT_START_PCT):
    """Change underscores to dashes, dots, spaces, double underscores, or remove them after drift threshold."""
    if progress_pct < drift_start_pct or not isinstance(val, str):
        return val
    
    if "_" in val:
        drift_type = random.choice(["-", ".", " ", "__", "remove"])
        if drift_type == "remove":
            return val.replace("_", "")
        elif drift_type == "__":
            return val.replace("_", "__")
        else:
            return val.replace("_", drift_type)
    else:
        # Add drift even if no underscores - randomly add separators
        if random.random() < 0.3:
            # Insert random separators in camelCase or compound words
            if any(c.isupper() for c in val[1:]):  # Has uppercase letters
                import re
                # Insert separator before uppercase letters
                separator = random.choice(["_", "-", ".", " "])
                return re.sub(r'([a-z])([A-Z])', r'\1' + separator + r'\2', val).lower()
    return val

# --- PCI Data Generators ---
def generate_full_pan_raw(card_type=None):
    return fake.credit_card_number(card_type=card_type or random.choice(["visa", "mastercard", "amex", "discover"]))
def generate_cvv(): return "".join(random.choices("0123456789", k=random.choice([3, 4])))
def generate_pin_raw(): return "".join(random.choices("0123456789", k=4)) # Raw PIN
def generate_expiration_date_raw():
    month = random.randint(1, 12)
    year = random.randint(datetime.now().year % 100, (datetime.now().year % 100) + 5)
    return f"{month:02d}/{year:02d}"
def generate_track_data(pan_value, expiration_date_value): # Expects already formatted PAN/Exp for consistency
    cleaned_pan = pan_value.replace(".", "").replace("-", "") # Ensure clean for track
    exp_parts = expiration_date_value.replace("/", "").replace(".", "").replace("-", "")
    exp_yy, exp_mm = exp_parts[2:4], exp_parts[0:2]
    service_code = str(random.randint(200, 220))
    discretionary_data = "".join(random.choices("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ", k=random.randint(10, 20)))
    return f";{cleaned_pan}={exp_yy}{exp_mm}{service_code}{discretionary_data}?"

def generate_pci_event_with_schema_drift(
    event_number, total_events, current_datetime
):
    """Generates a single PCI event with both format and schema drift."""
    current_progress_pct = event_number / total_events

    card_type = random.choice(["visa", "mastercard", "amex", "discover"])
    pan_raw_unformatted = generate_full_pan_raw(card_type=card_type)
    exp_date_raw_unformatted = generate_expiration_date_raw()

    # Apply format drift using the new percentage-based managers
    pan_formatted = pan_drift_manager.get_formatted_value(
        current_progress_pct, pan_raw_unformatted
    )
    expiration_date_formatted = exp_date_drift_manager.get_formatted_value(
        current_progress_pct, exp_date_raw_unformatted
    )

    # Base values for fields that might drift in schema
    raw_cvv = generate_cvv()
    raw_pin = generate_pin_raw()
    raw_src_ip = fake.ipv4_public()

    # Initialize event with fields always present or baseline
    event = {
        "event_type": "transaction_log_raw_drift",
        "transaction_id": str(uuid.uuid4()),
        "timestamp": current_datetime.isoformat().replace("+00:00", "Z"),
        "amount": round(random.uniform(10.00, 5000.00), 2),
        "currency": "USD",
        "card_type": card_type,
        "status": random.choice(
            ["approved", "denied", "pending", "fraud_alert"]
        ),
        "channel": random.choice(["online", "POS", "mobile", "ATM"]),
        "vendor": fake.company(),
        "category": fake.word(
            ext_word_list=[
                "Retail",
                "Travel",
                "Food",
                "Entertainment",
                "Services",
                "Utility Bill",
            ]
        ),
        "customer_name": fake.name(),
        "city": fake.city(),
        "country": "United States",
        "device_info": random.choice(
            [
                "desktop_browser",
                "mobile_android_app",
                "mobile_ios_app",
                "POS_terminal",
                "ATM_machine",
            ]
        ),
        "transaction_class": "domestic",
        "account_number_full": pan_formatted,
        "expiration_date": expiration_date_formatted,
        "cvv": raw_cvv,
    }

    # --- Apply Structural Schema Drift based on current_progress_pct ---
    if current_progress_pct < DRIFT_RENAME_IP_ADD_RECURRING_START_PCT:
        event["src_ip"] = raw_src_ip
    if current_progress_pct < DRIFT_REMOVE_PIN_START_PCT:
        event["pin"] = raw_pin
    if current_progress_pct >= DRIFT_ADD_FIELDS_START_PCT:
        event["merchant_risk_score"] = random.randint(1, 100)
        event["transaction_origin_system"] = random.choice(
            [
                "WebPortal_v2.1",
                "MobileApp_iOS_3.2",
                "POS_System_X100",
                "PaymentAPI_v3",
            ]
        )
    if current_progress_pct >= DRIFT_RENAME_IP_ADD_RECURRING_START_PCT:
        event["client_ip_address"] = raw_src_ip
        event["is_recurring_payment"] = random.choice([True, False])

    event["track_data"] = generate_track_data(
        pan_formatted, expiration_date_formatted
    )

    message_parts = [
        f"Raw PCI data. Account ending {pan_raw_unformatted[-4:]}."
    ]
    if "account_number_full" in event:
        message_parts.append(f"PAN: {event['account_number_full']}")
    if "expiration_date" in event:
        message_parts.append(f"Exp: {event['expiration_date']}")
    if "cvv" in event:
        message_parts.append(f"CVV: {event['cvv']}")
    if "pin" in event:
        message_parts.append(f"PIN: {event['pin']}")
    event["message"] = " ".join(message_parts)

    # --- Apply targeted schema value drift ---
    # This outer check now correctly controls all value drift
    if current_progress_pct >= DRIFT_VALUE_DRIFT_START_PCT:
        # [FIX] Pass the controlling start_pct explicitly to each function
        event["amount"] = drift_amount(
            event["amount"],
            current_progress_pct,
            drift_start_pct=DRIFT_VALUE_DRIFT_START_PCT,
        )
        event["category"] = drift_category(
            event["category"],
            current_progress_pct,
            drift_start_pct=DRIFT_VALUE_DRIFT_START_PCT,
        )
        event["device_info"] = drift_device_info(
            event["device_info"],
            current_progress_pct,
            drift_start_pct=DRIFT_VALUE_DRIFT_START_PCT,
        )

    return event

def validate_timestamp_distribution(events_sample, num_events):
    """Validate that timestamps are properly distributed"""
    if not events_sample:
        return
    
    timestamps = []
    for event in events_sample[:100]:  # Check first 100 events
        try:
            ts = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
            timestamps.append(ts)
        except:
            continue
    
    if len(timestamps) > 1:
        timestamps.sort()
        time_spans = [(ts.hour, len([t for t in timestamps if t.hour == ts.hour])) 
                     for ts in timestamps]
        unique_hours = list(set([ts.hour for ts in timestamps]))
        
        print(f"Timestamp distribution validation:", file=sys.stderr)
        print(f"  Events span {len(unique_hours)} different hours", file=sys.stderr)
        print(f"  Hour distribution: {dict(set(time_spans))}", file=sys.stderr)
        print(f"  Time range: {timestamps[0].strftime('%Y-%m-%d %H:%M:%S')} to {timestamps[-1].strftime('%Y-%m-%d %H:%M:%S')}", file=sys.stderr)

# --- Splunk HEC Sending Function (Batching) ---
def send_events_to_splunk_hec(
    events_batch, url, token, source, sourcetype, index, verify_ssl, timeout
):
    if not events_batch: return True
    headers = {"Authorization": f"Splunk {token}"}
    payload_items = []
    for event_data in events_batch:
        try:
            dt_object = datetime.fromisoformat(event_data["timestamp"].replace("Z", "+00:00"))
            epoch_time = dt_object.timestamp()
        except (ValueError, KeyError) as e:
            print(f"Error converting timestamp for HEC: {e}. Using current time.", file=sys.stderr)
            epoch_time = time.time()
        hec_event = {
            "time": epoch_time, "source": source, "sourcetype": sourcetype,
            "index": index, "host": event_data.get("vendor", source), # Using vendor as host for PCI
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
        description="Generate PCI-compliant logs with schema & format drift, send to Splunk HEC or save to CSV."
    )
    parser.add_argument("--num-events", type=int, default=NUM_EVENTS_DEFAULT, help=f"Number of events to generate (default: {NUM_EVENTS_DEFAULT}).")
    parser.add_argument("--output-csv", type=str, default=None, help=f"Filename to save logs as CSV. If not provided and --send-to-splunk is absent, defaults to '{DEFAULT_CSV_FILENAME}'.")
    parser.add_argument("--send-to-splunk", action="store_true", help="Enable sending data to Splunk HEC.")
    
    hec_group = parser.add_argument_group('Splunk HEC Options (for RAW data)')
    hec_group.add_argument("--splunk-url", type=str, default=SPLUNK_HEC_URL_DEFAULT)
    hec_group.add_argument("--splunk-token", type=str, default=SPLUNK_HEC_TOKEN_DEFAULT)
    hec_group.add_argument("--splunk-index", type=str, default=SPLUNK_RAW_INDEX_DEFAULT, help="Target Splunk Index for RAW drift data.")
    hec_group.add_argument("--splunk-source", type=str, default=SPLUNK_HEC_SOURCE_DEFAULT)
    hec_group.add_argument("--splunk-sourcetype", type=str, default=SPLUNK_PCI_RAW_SOURCETYPE_DEFAULT, help="Target Splunk Sourcetype for PCI RAW drift data.")
    hec_group.add_argument("--splunk-batch-size", type=int, default=SPLUNK_HEC_BATCH_SIZE_DEFAULT)
    hec_group.add_argument("--splunk-disable-ssl-verify", action="store_false", dest="splunk_verify_ssl")
    parser.set_defaults(splunk_verify_ssl=SPLUNK_HEC_VERIFY_SSL_DEFAULT)

    gen_group = parser.add_argument_group('Data Generation Options')
    gen_group.add_argument("--delay-seconds", type=float, default=DELAY_SECONDS_DEFAULT, help="Delay between sending events (if HEC enabled).")
    gen_group.add_argument("--events-per-hour", type=int, default=1000, help="Number of events to generate per hour of backfill (default: 1000).")

    args = parser.parse_args()

    csv_output_file = args.output_csv
    if not args.output_csv and not args.send_to_splunk:
        csv_output_file = DEFAULT_CSV_FILENAME
        print(f"No explicit output specified. Defaulting to save to CSV: {csv_output_file}", file=sys.stderr)

    if args.send_to_splunk:
        if "YOUR_SPLUNK_HEC_URL" in args.splunk_url or "YOUR_HEC_TOKEN" in args.splunk_token: # Check for placeholder token too
            print("ERROR: Splunk HEC URL or Token for raw data is not configured.", file=sys.stderr)
            sys.exit(1)
        print(f"Splunk HEC sending for PCI raw data enabled: URL={args.splunk_url}, Index={args.splunk_index}, Sourcetype={args.splunk_sourcetype}", file=sys.stderr)
        if not args.splunk_verify_ssl:
            print("SSL verification for HEC is DISABLED.", file=sys.stderr)
            try:
                import urllib3
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
                warnings.filterwarnings('ignore', category=urllib3.exceptions.NotOpenSSLWarning)
            except Exception: pass

    print(f"Generating {args.num_events} PCI-compliant log records with schema & format drift...", file=sys.stderr)
    
    # For more visible drift changes with smaller num_events, print drift points
    schema_drift_points_events = {
        "Add Fields (merchant_risk_score, transaction_origin_system)": int(DRIFT_ADD_FIELDS_START_PCT * args.num_events),
        "Remove Field (pin)": int(DRIFT_REMOVE_PIN_START_PCT * args.num_events),
        "Rename Field (src_ip to client_ip_address) & Add (is_recurring_payment)": int(DRIFT_RENAME_IP_ADD_RECURRING_START_PCT * args.num_events),
    }
    print(f"Schema drift points (approx event number): {schema_drift_points_events}", file=sys.stderr)
    # Also log format drift points for clarity (these are fixed counts from DataDriftManager)
    print(f"PAN Format drift points (fixed event counts): {dict(pan_drift_manager.drift_points_pct)}", file=sys.stderr)
    print(f"Expiry Format drift points (fixed event counts): {dict(exp_date_drift_manager.drift_points_pct)}", file=sys.stderr)

    start_time_utc = datetime.now(timezone.utc)
    EVENTS_PER_HOUR = args.events_per_hour
    total_backfill_hours = args.num_events / EVENTS_PER_HOUR
    blocks = args.num_events // 100
    if blocks == 0:
        blocks = 1
    time_offset_per_100_events = timedelta(hours=total_backfill_hours / blocks)
    print(f"Backfill window: {total_backfill_hours:.2f} hours ({args.num_events} events at {EVENTS_PER_HOUR} per hour)", file=sys.stderr)

    log_data_list, splunk_batch = [], []
    total_sent_to_splunk, total_failed_splunk = 0, 0

    for i in range(args.num_events):
        event_number = i + 1 # 1-based event number for drift logic
        
        # Calculate which time block this event belongs to
        block_number = i // 100
        base_time_shift = block_number * time_offset_per_100_events
        base_time_for_block = start_time_utc - base_time_shift

        # Ensure each event gets a unique SECOND-level timestamp
        max_seconds_in_block = int(time_offset_per_100_events.total_seconds() * 0.8)
        
        if max_seconds_in_block > 100:
            event_position_in_block = i % 100
            seconds_step = max_seconds_in_block // 100
            base_seconds_offset = event_position_in_block * seconds_step
            random_additional_seconds = random.randint(0, min(60, seconds_step))
            total_seconds_offset = base_seconds_offset + random_additional_seconds
        else:
            total_seconds_offset = (i % 3600) + random.randint(0, 300)
        
        current_time_for_event = base_time_for_block - timedelta(seconds=total_seconds_offset)

        # Debug output for first few events to verify distribution
        if i < 5 or (i + 1) % 100 == 1:  # First event of each block
            print(f"Event {i+1}: Block {block_number}, Time: {current_time_for_event.strftime('%Y-%m-%d %H:%M:%S')}, "
                  f"Offset: {total_seconds_offset}s", file=sys.stderr)
        
        if event_number % (args.num_events // 20 or 1) == 0:
            print(f"  Generated {event_number}/{args.num_events} logs (Progress: { (event_number/args.num_events)*100:.1f} %)...", file=sys.stderr)
        
        log_entry = generate_pci_event_with_schema_drift(event_number, args.num_events, current_time_for_event)
        log_data_list.append(log_entry)

        if args.send_to_splunk:
            splunk_batch.append(log_entry)
            if len(splunk_batch) >= args.splunk_batch_size:
                # print(f"  Sending batch of {len(splunk_batch)} PCI raw logs to Splunk HEC...", file=sys.stderr)
                if send_events_to_splunk_hec(
                    splunk_batch, args.splunk_url, args.splunk_token, args.splunk_source,
                    args.splunk_sourcetype, args.splunk_index, args.splunk_verify_ssl, SPLUNK_HEC_TIMEOUT_DEFAULT
                ): total_sent_to_splunk += len(splunk_batch)
                else: total_failed_splunk += len(splunk_batch)
                splunk_batch = []
            # Delay only if sending to HEC
            if args.delay_seconds > 0 and len(splunk_batch) == 0 : # Delay after a batch is sent or if batch size is 1
                 time.sleep(args.delay_seconds)

    if args.send_to_splunk and splunk_batch:
        print(f"  Sending final batch of {len(splunk_batch)} PCI raw logs to Splunk HEC...", file=sys.stderr)
        if send_events_to_splunk_hec(
            splunk_batch, args.splunk_url, args.splunk_token, args.splunk_source,
            args.splunk_sourcetype, args.splunk_index, args.splunk_verify_ssl, SPLUNK_HEC_TIMEOUT_DEFAULT
        ): total_sent_to_splunk += len(splunk_batch)
        else: total_failed_splunk += len(splunk_batch)

    # Add timestamp validation after event generation
    if log_data_list:
        validate_timestamp_distribution(log_data_list, args.num_events)

    if args.send_to_splunk:
        print("\nSplunk HEC Sending Summary (PCI Raw Data):", file=sys.stderr)
        print(f"  Successfully sent: {total_sent_to_splunk} logs", file=sys.stderr)
        print(f"  Failed to send:    {total_failed_splunk} logs", file=sys.stderr)

    if csv_output_file:
        print(f"\nSaving {len(log_data_list)} PCI raw log records to {csv_output_file}...", file=sys.stderr)
        df = pd.DataFrame(log_data_list)
        df.to_csv(csv_output_file, index=False)
        print(f"Successfully saved PCI raw logs to {csv_output_file}", file=sys.stderr)

    print(f"\nScript finished. Generated {args.num_events} total PCI raw logs with schema & format drift.", file=sys.stderr)

if __name__ == "__main__":
    main()