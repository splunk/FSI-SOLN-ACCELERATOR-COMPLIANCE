# synthetic_dora_logs_schema_drift.py
import argparse
import datetime
import json
import random
import sys
import time
import uuid
import warnings # For suppressing urllib3 warnings

import pandas as pd
import requests
from faker import Faker

# Initialize Faker and set seed for reproducibility
fake = Faker()
Faker.seed(42)
random.seed(42)

# --- Configuration ---
DEFAULT_NUM_EVENTS = 1000

# --- DORA-specific components and events (can be expanded) ---
SYSTEM_COMPONENTS = [
    "payment_gateway", "transaction_db", "auth_service", "fraud_detection",
    "api_gateway", "settlement_engine", "user_management_portal",
    "risk_assessment_module", "incident_response_platform", "backup_restore_system",
    "regulatory_reporting_engine", "customer_communication_platform"
]
SECURITY_EVENTS = [
    "Failed login attempt", "Firewall policy violation", "New admin user provisioned",
    "Database schema alteration", "Anomalous network traffic pattern", "SSL TLS certificate rotated",
    "Unusual API endpoint access", "Privilege escalation detected", "Potential data exfiltration activity",
    "Malware signature updated on endpoint", "Security control misconfiguration alert"
]
INCIDENT_TYPES = [
    "Unauthorized_system_access", "Critical_service_outage", "Data_integrity_compromised",
    "Configuration_drift_causing_instability", "Resource_exhaustion_leading_to_failure",
    "Sustained_DDoS_attack", "Exploitation_of_critical_vulnerability",
    "Major_third_party_service_disruption", "Confirmed_data_breach",
    "System_misconfiguration_exploited"
]
THREAT_ACTOR_GROUPS = ["APT_Alpha", "FIN_Beta", "CyberCrime_Gamma", "Hacktivist_Delta", "Unknown_Actor", "Insider_Accidental", "Insider_Malicious"]
DATA_SENSITIVITY_RATINGS = ["Highly_Confidential", "Confidential", "Internal_Use_Only", "Public_Data_Reference"]

# --- Splunk HEC Configuration for RAW DRIFT DATA ---
SPLUNK_HEC_URL_DEFAULT = "YOUR_SPLUNK_HEC_URL/services/collector" # Batch endpoint
SPLUNK_HEC_TOKEN_DEFAULT = "YOUR_HEC_TOKEN_FOR_RAW_DATA"
SPLUNK_RAW_INDEX_DEFAULT = "drift_raw_data" # Common index for all raw drift sources
SPLUNK_DORA_RAW_SOURCETYPE_DEFAULT = "dora_drift_raw" # Specific sourcetype for this script
SPLUNK_HEC_SOURCE_DEFAULT = "dora_drift_generator"
SPLUNK_HEC_VERIFY_SSL_DEFAULT = False # Often False for local dev
SPLUNK_HEC_BATCH_SIZE_DEFAULT = 100
SPLUNK_HEC_TIMEOUT_DEFAULT = 30
DEFAULT_CSV_FILENAME = "dora_schema_drift_raw_logs.csv"

# --- Schema Drift Percentage Thresholds ---
DRIFT_ADD_FIELDS_START_PCT = 0.25  # Start adding new fields at 25% of events
DRIFT_REMOVE_FIELDS_START_PCT = 0.50 # Start removing fields at 50%
DRIFT_RENAME_ADD_START_PCT = 0.75 # Start renaming/adding other fields at 75%


# --- Value Schema Drift Threshold (same as field drift) ---
DRIFT_VALUE_SCHEMA_START_PCT = 0.50  # Start at 50% instead of 75%

def drift_underscore_fields(val, progress_pct, drift_start_pct=DRIFT_VALUE_SCHEMA_START_PCT):
    """Change underscore for dots, spaces, or double underscore."""
    if progress_pct < drift_start_pct or not isinstance(val, str):
        return val
    if "_" in val:  # Remove the random.random() < 0.8 condition
        drift_type = random.choice(["dot", "space", "double_underscore"])
        if drift_type == "dot":
            return val.replace("_", ".")
        elif drift_type == "space":
            return val.replace("_", " ")
        elif drift_type == "double_underscore":
            return val.replace("_", "__")
    return val

def drift_space_fields(val, progress_pct, drift_start_pct=DRIFT_VALUE_SCHEMA_START_PCT):
    """Remove spaces or add double space."""
    if progress_pct < drift_start_pct or not isinstance(val, str):
        return val
    if " " in val:  # Remove the random.random() < 0.8 condition
        if random.random() < 0.5:
            return val.replace(" ", "")
        else:
            return val.replace(" ", "  ")
    return val

# --- Update event generation to apply targeted value drift ---
def generate_dora_event_with_drift(event_number, total_events, timestamp_dt=None):
    """
    Generates a single DORA-compliant log entry with a clean, refactored
    approach to schema and value drift.
    """
    current_progress_pct = event_number / total_events

    if timestamp_dt is None:
        timestamp_dt = datetime.datetime.now(
            datetime.timezone.utc
        ) - datetime.timedelta(
            days=random.randint(0, 30),
            hours=random.randint(0, 23),
            minutes=random.randint(0, 59),
            seconds=random.randint(0, 59),
        )

    # 1. --- Generate all potential data points as clean, local variables ---
    log_level = random.choices(
        ["INFO", "WARNING", "ERROR", "CRITICAL"], weights=[60, 20, 15, 5]
    )[0]
    component = random.choice(SYSTEM_COMPONENTS)
    user_id = str(fake.unique.uuid4()) if random.random() > 0.3 else "SYSTEM"
    base_ip_value = fake.ipv4() if user_id != "SYSTEM" else "N/A"
    source_hostname = f"srv-{component.replace('_', '-')}-{random.randint(1,5)}.prod.example.com"
    event_category = (
        "ICT_Operational_Event"
        if log_level in ["INFO", "WARNING"]
        else "ICT_Security_Incident"
    )

    # Variables for fields that may or may not be present
    threat_actor = random.choice(THREAT_ACTOR_GROUPS)
    data_sens = random.choice(DATA_SENSITIVITY_RATINGS)
    incident_type = random.choice(INCIDENT_TYPES)
    security_event = random.choice(SECURITY_EVENTS)

    # 2. --- Apply value drift to the local variables if past the threshold ---
    if current_progress_pct >= DRIFT_VALUE_SCHEMA_START_PCT:
        component = drift_underscore_fields(component, current_progress_pct)
        threat_actor = drift_underscore_fields(threat_actor, current_progress_pct)
        data_sens = drift_underscore_fields(data_sens, current_progress_pct)
        incident_type = drift_underscore_fields(
            incident_type, current_progress_pct
        )
        security_event = drift_space_fields(security_event, current_progress_pct)

    # 3. --- Construct the final event dictionary using the (now drifted) variables ---
    event = {
        "timestamp": timestamp_dt.isoformat().replace("+00:00", "Z"),
        "log_level": log_level,
        "component": component,  # Use the potentially drifted value
        "user_id": user_id,
        "source_hostname": source_hostname,
        "dora_compliance_tag": "DORA_v1.1_drift_log",
        "event_category": event_category,
    }

    # --- Apply Structural Schema Drift (Adding/Removing/Renaming fields) ---
    # This logic now uses the final, potentially drifted variables.
    if current_progress_pct < DRIFT_RENAME_ADD_START_PCT:
        event["ip_address"] = base_ip_value

    if current_progress_pct < DRIFT_REMOVE_FIELDS_START_PCT:
        if random.random() > 0.4:
            event["transaction_id"] = str(uuid.uuid4())
        if user_id != "SYSTEM":
            event["session_id"] = str(uuid.uuid4())

    if current_progress_pct >= DRIFT_ADD_FIELDS_START_PCT:
        if event["event_category"] == "ICT_Security_Incident":
            event["threat_actor_group"] = threat_actor
        if log_level in ["ERROR", "CRITICAL"]:
            event["impact_assessment_notes"] = fake.sentence(
                nb_words=random.randint(8, 15)
            )

    if current_progress_pct >= DRIFT_RENAME_ADD_START_PCT:
        event["source_ip_address"] = base_ip_value
        event["data_sensitivity_rating"] = data_sens

    # --- Construct the 'description' field LAST, using the final drifted values ---
    current_ip_for_desc = event.get("source_ip_address", event.get("ip_address", "N/A"))

    if log_level in ["ERROR", "CRITICAL"]:
        event[
            "description"
        ] = f"{incident_type} in {component}. Investigation ID: {uuid.uuid4()}. Source IP: {current_ip_for_desc}"
    elif "auth" in component or "security" in component or event_category == "ICT_Security_Incident":
        event[
            "description"
        ] = f"{security_event} on {component} by user {user_id} from {current_ip_for_desc}."
    elif log_level == "INFO":
        event[
            "description"
        ] = f"Operation {fake.word()}_{fake.word()} completed successfully on {component}. Initiated by {user_id}."
    else:  # WARNING
        event[
            "description"
        ] = f"Performance degradation detected in {component}. Metric: {fake.word()}_latency, Value: {random.randint(100,1000)}ms. Source IP involved: {current_ip_for_desc}"

    return event

# --- Splunk HEC Sending Function (Batching) ---
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
            print(f"Error converting timestamp for HEC: {e}. Using current time.", file=sys.stderr)
            epoch_time = time.time()
        hec_event = {
            "time": epoch_time, "source": source, "sourcetype": sourcetype,
            "index": index, "host": event_data.get("source_hostname", source),
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
        description="Generate DORA-compliant logs with schema drift, send to Splunk HEC or save to CSV."
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
    hec_group.add_argument("--splunk-sourcetype", type=str, default=SPLUNK_DORA_RAW_SOURCETYPE_DEFAULT, help="Target Splunk Sourcetype for DORA RAW drift data.")
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
        print(f"Splunk HEC sending for DORA raw data enabled: URL={args.splunk_url}, Index={args.splunk_index}, Sourcetype={args.splunk_sourcetype}", file=sys.stderr)
        if not args.splunk_verify_ssl:
            print("SSL verification for HEC is DISABLED.", file=sys.stderr)
            try:
                import urllib3
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
                warnings.filterwarnings('ignore', category=urllib3.exceptions.NotOpenSSLWarning)
            except Exception: pass # Ignore if modules or specific exceptions aren't there

    print(f"Generating {args.num_events} DORA-compliant log records with schema drift...", file=sys.stderr)
    log_data_list, splunk_batch = [], []
    total_sent_to_splunk, total_failed_splunk = 0, 0

    # For more visible drift changes with smaller num_events, print drift points
    drift_points_events = {
        "Add Fields Start": int(DRIFT_ADD_FIELDS_START_PCT * args.num_events),
        "Remove Fields Start": int(DRIFT_REMOVE_FIELDS_START_PCT * args.num_events),
        "Rename/Add Fields Start": int(DRIFT_RENAME_ADD_START_PCT * args.num_events),
    }
    print(f"Schema drift points (approx event number): {drift_points_events}", file=sys.stderr)

    # Calculate backfill window and time offsets
    start_time_utc = datetime.datetime.now(datetime.timezone.utc)
    EVENTS_PER_HOUR = args.events_per_hour
    total_backfill_hours = args.num_events / EVENTS_PER_HOUR
    blocks = args.num_events // 100
    if blocks == 0:
        blocks = 1
    time_offset_per_100_events = datetime.timedelta(hours=total_backfill_hours / blocks)
    print(f"Backfill window: {total_backfill_hours:.2f} hours ({args.num_events} events at {EVENTS_PER_HOUR} per hour)", file=sys.stderr)

    for i in range(args.num_events):
        event_number = i + 1 

        block_number = i // 100
        base_time_shift = block_number * time_offset_per_100_events
        base_time_for_block = start_time_utc - base_time_shift

        max_seconds_in_block = int(time_offset_per_100_events.total_seconds() * 0.8)

        if max_seconds_in_block > 100:
            event_position_in_block = i % 100
            seconds_step = max_seconds_in_block // 100
            base_seconds_offset = event_position_in_block * seconds_step
            
            random_additional_seconds = random.randint(0, min(60, seconds_step))
            total_seconds_offset = base_seconds_offset + random_additional_seconds
        else:
            total_seconds_offset = (i % 3600) + random.randint(0, 300)

        current_time_for_event = base_time_for_block - datetime.timedelta(seconds=total_seconds_offset)

        # Debug output for first few events of each block
        if i < 5 or i % 100 == 0:
            print(f"Event {i+1}: Block {block_number}, Time: {current_time_for_event.strftime('%Y-%m-%d %H:%M:%S')}, "
                f"Offset: {total_seconds_offset}s", file=sys.stderr)

        if event_number % (args.num_events // 20 or 1) == 0:
            print(f"  Generated {event_number}/{args.num_events} logs (Progress: { (event_number/args.num_events)*100:.1f} %)...", file=sys.stderr)
        
        if i > 0 and i % 5000 == 0: 
            fake.unique.clear()

        log_entry = generate_dora_event_with_drift(event_number, args.num_events, timestamp_dt=current_time_for_event)
        log_data_list.append(log_entry)

        # **Add HEC batching logic here**
        if args.send_to_splunk:
            splunk_batch.append(log_entry)
            if len(splunk_batch) >= args.splunk_batch_size:
                if send_events_to_splunk_hec(
                    splunk_batch, args.splunk_url, args.splunk_token, args.splunk_source,
                    args.splunk_sourcetype, args.splunk_index, args.splunk_verify_ssl, SPLUNK_HEC_TIMEOUT_DEFAULT
                ): 
                    total_sent_to_splunk += len(splunk_batch)
                else: 
                    total_failed_splunk += len(splunk_batch)
                splunk_batch = []

    # **Send final batch if there are remaining events**
    if args.send_to_splunk and splunk_batch:
        print(f"  Sending final batch of {len(splunk_batch)} DORA raw logs to Splunk HEC...", file=sys.stderr)
        if send_events_to_splunk_hec(
            splunk_batch, args.splunk_url, args.splunk_token, args.splunk_source,
            args.splunk_sourcetype, args.splunk_index, args.splunk_verify_ssl, SPLUNK_HEC_TIMEOUT_DEFAULT
        ): 
            total_sent_to_splunk += len(splunk_batch)
        else: 
            total_failed_splunk += len(splunk_batch)

    if args.send_to_splunk:
        print("\nSplunk HEC Sending Summary (DORA Raw Data):", file=sys.stderr)
        print(f"  Successfully sent: {total_sent_to_splunk} logs", file=sys.stderr)
        print(f"  Failed to send:    {total_failed_splunk} logs", file=sys.stderr)

    if csv_output_file:
        print(f"\nSaving {len(log_data_list)} DORA raw log records to {csv_output_file}...", file=sys.stderr)
        df = pd.DataFrame(log_data_list)
        df.to_csv(csv_output_file, index=False)
        print(f"Successfully saved DORA raw logs to {csv_output_file}", file=sys.stderr)

    print(f"\nScript finished. Generated {args.num_events} total DORA raw logs with schema drift.", file=sys.stderr)

if __name__ == "__main__":
    main()