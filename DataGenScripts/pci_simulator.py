import argparse
import json
import random
import sys
import time
from datetime import datetime, timedelta, timezone

import pandas as pd # Added for CSV output
import requests
from faker import Faker

# --- Default Splunk HEC Configuration (can be overridden by flags) ---
SPLUNK_HEC_URL_DEFAULT = "https://localhost:8088/services/collector/event"
SPLUNK_HEC_TOKEN_DEFAULT = "YOUR_HEC_TOKEN"  # Placeholder - MUST be configured
SPLUNK_INDEX_DEFAULT = "sample_pci"
SPLUNK_SOURCETYPE_DEFAULT = "pci:synthetic:event"
SPLUNK_HEC_SOURCE_DEFAULT = "pci_simulator"
SPLUNK_VERIFY_SSL_DEFAULT = False

# --- Default Data Generation Parameters (can be overridden by flags) ---
NUM_EVENTS_DEFAULT = 1000
DELAY_SECONDS_DEFAULT = 0.00
HOURS_BACKFILL_PER_100_DEFAULT = 1
DEFAULT_CSV_FILENAME = "pci_synthetic_logs.csv"

fake = Faker("en_US")


# --- Data Drift Manager (same as before) ---
class DataDriftManager:
    def __init__(self, field_name, initial_format_func, drift_points):
        self.field_name = field_name
        self.current_format_func = initial_format_func
        self.drift_points = sorted(
            drift_points.items(), key=lambda item: item[0]
        )
        self.next_drift_idx = 0

    def get_formatted_value(self, current_event_count, raw_value):
        if (
            self.next_drift_idx < len(self.drift_points)
            and current_event_count >= self.drift_points[self.next_drift_idx][0]
        ):
            self.current_format_func = self.drift_points[self.next_drift_idx][1]
            print(
                f"--- Data Drift: {self.field_name} format changing at event {current_event_count} ---",
                file=sys.stderr,
            )
            self.next_drift_idx += 1
        return self.current_format_func(raw_value)

def format_pan_no_separator(pan):
    return pan.replace(".", "").replace("-", "")
def format_pan_dotted(pan):
    pan_cleaned = pan.replace(".", "").replace("-", "")
    return f"{pan_cleaned[0:4]}.{pan_cleaned[4:8]}.{pan_cleaned[8:12]}.{pan_cleaned[12:16]}"
def format_pan_hyphenated(pan):
    pan_cleaned = pan.replace(".", "").replace("-", "")
    if pan_cleaned.startswith("34") or pan_cleaned.startswith("37"):
        return f"{pan_cleaned[0:4]}-{pan_cleaned[4:10]}-{pan_cleaned[10:]}"
    return f"{pan_cleaned[0:4]}-{pan_cleaned[4:8]}-{pan_cleaned[8:12]}-{pan_cleaned[12:16]}"
pan_drift_manager = DataDriftManager(
    "account_number_full",
    initial_format_func=format_pan_no_separator,
    drift_points={300: format_pan_dotted, 600: format_pan_hyphenated},
)
def format_exp_slash(exp_date):
    return exp_date.replace(".", "/").replace("-", "/")
def format_exp_dot(exp_date):
    return exp_date.replace("/", ".").replace("-", ".")
def format_exp_hyphen(exp_date):
    return exp_date.replace("/", "-").replace(".", "-")
exp_date_drift_manager = DataDriftManager(
    "expiration_date",
    initial_format_func=format_exp_slash,
    drift_points={300: format_exp_dot, 600: format_exp_hyphen},
)

# --- PCI Data Generators (same as before) ---
def generate_full_pan_raw(card_type=None):
    return fake.credit_card_number(
        card_type=card_type
        or random.choice(["visa", "mastercard", "amex", "discover"])
    )
def generate_cvv():
    return "".join(random.choices("0123456789", k=random.choice([3, 4])))
def generate_pin():
    return "".join(random.choices("0123456789", k=4))
def generate_expiration_date_raw():
    month = random.randint(1, 12)
    year = random.randint(
        datetime.now().year % 100, (datetime.now().year % 100) + 5
    )
    return f"{month:02d}/{year:02d}"
def generate_track_data(pan_value, expiration_date_value):
    cleaned_pan = pan_value.replace(".", "").replace("-", "")
    exp_parts = (
        expiration_date_value.replace("/", "")
        .replace(".", "")
        .replace("-", "")
    )
    exp_yy = exp_parts[2:4]
    exp_mm = exp_parts[0:2]
    service_code = str(random.randint(200, 220))
    discretionary_data = "".join(
        random.choices(
            "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ", k=random.randint(10, 20)
        )
    )
    return f";{cleaned_pan}={exp_yy}{exp_mm}{service_code}{discretionary_data}?"
def generate_pci_event_for_processing(event_count, current_datetime):
    service_code = str(random.randint(200, 299))
    card_type = random.choice(["visa", "mastercard", "amex", "discover"])
    pan_raw = generate_full_pan_raw(card_type=card_type)
    exp_date_raw = generate_expiration_date_raw()
    pan_formatted = pan_drift_manager.get_formatted_value(event_count, pan_raw)
    expiration_date_formatted = exp_date_drift_manager.get_formatted_value(
        event_count, exp_date_raw
    )
    cvv = generate_cvv()
    pin = generate_pin()
    track = generate_track_data(pan_formatted, expiration_date_formatted)
    event_data = {
        "event_type": "transaction_log_raw",
        "transaction_id": str(fake.uuid4()),
        "timestamp": current_datetime.isoformat(),
        "amount": round(random.uniform(10.00, 5000.00), 2),
        "currency": "USD",
        "card_type": card_type,
        "status": random.choice(["approved", "denied", "pending", "fraud_alert"]),
        "channel": random.choice(["online", "POS", "mobile", "ATM"]),
        "vendor": fake.company(),
        "category": fake.word(
            ext_word_list=[
                "Retail", "Travel", "Food", "Entertainment", "Services", "Utility Bill",
            ]
        ),
        "src_ip": fake.ipv4_public(),
        "cardholder_name": fake.name(),
        "city": fake.city(),
        "country": "United States",
        "device_info": random.choice([
            "desktop_browser", "mobile_android_app", "mobile_ios_app",
            "POS_terminal", "ATM_machine",
        ]),
        "transaction_class": "domestic",
        "account_number_full": pan_formatted,
        "pan": pan_raw,
        "expiry_date": expiration_date_formatted,
        "cvv": cvv,
        "pin": pin,
        "service_code": service_code,
        "track1_data": track,
        "message": f"Raw payment data received for account ending {pan_raw[-4:]}. "
                   f"Full PAN: {pan_formatted}, Exp: {expiration_date_formatted}, "
                   f"CVV: {cvv}, PIN: {pin}, Track: {track}. "
                   f"Timestamp: {current_datetime.isoformat()}.",
    }
    return event_data

# --- HEC Sender (same as before) ---
def send_to_splunk_hec(event, hec_url, hec_token, hec_index, hec_sourcetype, hec_source, verify_ssl):
    headers = {
        "Authorization": f"Splunk {hec_token}",
        "Content-Type": "application/json",
    }
    try:
        dt_object = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
        epoch_time = dt_object.timestamp()
    except (ValueError, KeyError) as e:
        print(f"Error converting event timestamp for HEC: {e}. Using current ingest time.", file=sys.stderr)
        epoch_time = time.time()
    hec_payload = {
        "time": epoch_time,
        "event": event,
        "sourcetype": hec_sourcetype,
        "index": hec_index,
        "source": hec_source,
    }
    try:
        response = requests.post(
            hec_url, headers=headers, json=hec_payload, verify=verify_ssl
        )
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"Error sending event to Splunk HEC: {e}", file=sys.stderr)
        if hasattr(e, "response") and e.response is not None:
            print(f"Response Status: {e.response.status_code}", file=sys.stderr)
            print(f"Response Text: {e.response.text}", file=sys.stderr)
        print("Continuing...", file=sys.stderr)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Generate synthetic PCI transaction data with drift and optionally send to Splunk HEC or save to CSV."
    )
    # Output Arguments
    parser.add_argument(
        "--send-to-splunk",
        action="store_true",
        help="Enable sending data to Splunk HEC.",
    )
    parser.add_argument(
        "--output-csv",
        type=str,
        default=None,
        help=f"Filename to save logs as CSV (e.g., pci_logs.csv). If not provided and --send-to-splunk is also absent, defaults to '{DEFAULT_CSV_FILENAME}'.",
    )

    # HEC Arguments (only relevant if --send-to-splunk is used)
    hec_group = parser.add_argument_group('Splunk HEC Options (if --send-to-splunk is used)')
    hec_group.add_argument("--splunk-url", default=SPLUNK_HEC_URL_DEFAULT, help="Splunk HEC URL.")
    hec_group.add_argument("--splunk-token", default=SPLUNK_HEC_TOKEN_DEFAULT, help="Splunk HEC Token.")
    hec_group.add_argument("--splunk-index", default=SPLUNK_INDEX_DEFAULT, help="Splunk Index.")
    hec_group.add_argument("--splunk-sourcetype", default=SPLUNK_SOURCETYPE_DEFAULT, help="Splunk Sourcetype.")
    hec_group.add_argument("--splunk-source", default=SPLUNK_HEC_SOURCE_DEFAULT, help="Splunk Source value for HEC events.")
    hec_group.add_argument(
        "--splunk-disable-ssl-verify",
        action="store_false",
        dest="splunk_verify_ssl",
        help="Disable SSL verification for Splunk HEC (use for self-signed certs).",
    )
    parser.set_defaults(splunk_verify_ssl=SPLUNK_VERIFY_SSL_DEFAULT)


    # Data Generation Arguments
    gen_group = parser.add_argument_group('Data Generation Options')
    gen_group.add_argument("--num-events", type=int, default=NUM_EVENTS_DEFAULT, help="Number of events to generate.")
    gen_group.add_argument("--delay-seconds", type=float, default=DELAY_SECONDS_DEFAULT, help="Delay in seconds between sending events (if sending to HEC).")
    gen_group.add_argument("--hours-backfill-per-100", type=int, default=HOURS_BACKFILL_PER_100_DEFAULT, help="Hours to backfill timestamp for every 100 events.")

    args = parser.parse_args()

    # Determine if any output action is requested
    if not args.send_to_splunk and not args.output_csv:
        args.output_csv = DEFAULT_CSV_FILENAME # Default to CSV if no other action
        print(f"No explicit output specified. Defaulting to save to CSV: {args.output_csv}", file=sys.stderr)


    if args.send_to_splunk and args.splunk_token == "YOUR_HEC_TOKEN":
        print("ERROR: --send-to-splunk is enabled, but SPLUNK_HEC_TOKEN is not configured. Please set it via --splunk-token or update the script default.", file=sys.stderr)
        sys.exit(1)

    if args.send_to_splunk:
        print(f"Splunk HEC sending enabled: URL={args.splunk_url}", file=sys.stderr)
        if not args.splunk_verify_ssl:
            print("SSL verification for HEC is DISABLED.", file=sys.stderr)
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    print(f"Generating {args.num_events} raw PCI events...", file=sys.stderr)

    all_generated_events = [] # Store all events for potential CSV output
    start_time_utc = datetime.now(timezone.utc)
    time_offset_per_100_events = timedelta(hours=args.hours_backfill_per_100)

    for i in range(args.num_events):
        time_shift = (i // 100) * time_offset_per_100_events
        current_time_for_event = start_time_utc - time_shift

        event = generate_pci_event_for_processing(i + 1, current_time_for_event)
        all_generated_events.append(event)

        if args.send_to_splunk:
            send_to_splunk_hec(
                event,
                args.splunk_url,
                args.splunk_token,
                args.splunk_index,
                args.splunk_sourcetype,
                args.splunk_source,
                args.splunk_verify_ssl,
            )
            if args.delay_seconds > 0:
                time.sleep(args.delay_seconds)

        if (i + 1) % 100 == 0:
            progress_message = f"Generated {i + 1}/{args.num_events} events."
            if args.send_to_splunk:
                progress_message += f" Current HEC timestamp bucket: {current_time_for_event.isoformat()}."
            print(progress_message, file=sys.stderr)


    if args.output_csv:
        print(f"\nSaving {len(all_generated_events)} events to {args.output_csv}...", file=sys.stderr)
        df = pd.DataFrame(all_generated_events)
        try:
            df.to_csv(args.output_csv, index=False)
            print(f"Successfully saved events to {args.output_csv}", file=sys.stderr)
        except Exception as e:
            print(f"Error saving CSV to {args.output_csv}: {e}", file=sys.stderr)


    print(f"\nFinished generating {args.num_events} events.", file=sys.stderr)
    if args.send_to_splunk:
        print("Please check your Splunk instance for the ingested data.", file=sys.stderr)