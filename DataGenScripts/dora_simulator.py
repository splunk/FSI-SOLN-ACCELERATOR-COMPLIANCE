# synthetic_dora_logs_hec.py
import argparse
import datetime
import json
import random
import sys
import time # For epoch time and potential sleep
import uuid

import pandas as pd
import requests # For Splunk HEC
from faker import Faker

# Initialize Faker and set seed for reproducibility
fake = Faker()
Faker.seed(42)
random.seed(42)

# --- Configuration ---
DEFAULT_NUM_EVENTS = 1000 # Changed from DEFAULT_NUM_LOGS

# DORA-specific components and events
SYSTEM_COMPONENTS = [
    "payment_gateway",
    "transaction_db",
    "auth_service",
    "fraud_detection",
    "api_gateway",
    "settlement_engine",
    "user_management_portal",
    "risk_assessment_module",
    "incident_response_platform",
    "backup_restore_system",
]

SECURITY_EVENTS = [
    "Failed login attempt",
    "Firewall policy changed",
    "New admin user created",
    "Database schema modified",
    "Unusual network traffic detected",
    "Certificate rotated",
    "Anomalous API usage",
    "Privilege escalation attempt",
    "Data exfiltration detected",
    "Malware signature updated",
]

INCIDENT_TYPES = [
    "Unauthorized access",
    "Service outage",
    "Data corruption",
    "Configuration drift",
    "Resource exhaustion",
    "DDoS attack mitigated",
    "Critical vulnerability patched",
    "Third-party service disruption",
    "Data breach contained",
    "System misconfiguration identified",
]

# --- Splunk HEC Configuration ---
# !!! WARNING: Do NOT hardcode sensitive tokens in production scripts.
SPLUNK_HEC_URL_DEFAULT = "YOUR_SPLUNK_HEC_URL"  # e.g., "https://splunk.example.com:8088/services/collector"
SPLUNK_HEC_TOKEN_DEFAULT = "YOUR_SPLUNK_HEC_TOKEN"
SPLUNK_HEC_SOURCE_DEFAULT = "dora_simulator"
SPLUNK_HEC_SOURCETYPE_DEFAULT = "dora:synthetic:event"
SPLUNK_HEC_INDEX_DEFAULT = "sample_dora"
SPLUNK_HEC_VERIFY_SSL_DEFAULT = False
SPLUNK_HEC_BATCH_SIZE_DEFAULT = 100
SPLUNK_HEC_TIMEOUT_DEFAULT = 30


def generate_log_entry():
    """Generate a single DORA-compliant log entry"""
    timestamp_dt = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(
        days=random.randint(0, 30),
        hours=random.randint(0, 23),
        minutes=random.randint(0, 59),
        seconds=random.randint(0, 59),
    )

    log_level = random.choices(
        ["INFO", "WARNING", "ERROR", "CRITICAL"], weights=[60, 20, 15, 5]
    )[0]

    component = random.choice(SYSTEM_COMPONENTS)
    user_id = (
        str(fake.unique.uuid4())
        if random.random() > 0.3
        else "SYSTEM"
    )
    ip_address = fake.ipv4() if user_id != "SYSTEM" else "N/A"
    source_hostname = f"srv-{component.replace('_', '-')}-{random.randint(1,5)}.prod.example.com"

    # DORA-specific event patterns
    if log_level in ["ERROR", "CRITICAL"]:
        description = f"{random.choice(INCIDENT_TYPES)} in {component}. Investigation ID: {uuid.uuid4()}"
        event_type = "incident"
        severity_level = log_level
        impacted_services = [component, random.choice(SYSTEM_COMPONENTS)]
        num_clients_affected = random.randint(1, 10000)
        data_loss_details = random.choice([
            "No data loss",
            "Partial data loss",
            "Full data loss",
            "Data integrity at risk"
        ])
        incident_description = description
        dora_incident_classification = random.choice([
            "Operational Disruption",
            "Security Breach",
            "Data Loss",
            "Third-Party Failure"
        ])
        is_reportable_dora_incident = random.choice([True, False])
    elif "auth" in component or "security" in component:
        description = f"{random.choice(SECURITY_EVENTS)} on {component} by user {user_id} from {ip_address}."
        event_type = "security_event"
        severity_level = log_level
        impacted_services = [component]
        num_clients_affected = random.randint(0, 100)
        data_loss_details = "No data loss"
        incident_description = description
        dora_incident_classification = "Security Event"
        is_reportable_dora_incident = False
    elif log_level == "INFO":
        description = f"Operation {fake.word()}_{fake.word()} completed successfully on {component}."
        event_type = "operational_event"
        severity_level = log_level
        impacted_services = [component]
        num_clients_affected = 0
        data_loss_details = "No data loss"
        incident_description = description
        dora_incident_classification = "Operational Event"
        is_reportable_dora_incident = False
    else:  # WARNING
        description = f"Performance degradation detected in {component}. Metric: {fake.word()}_latency, Value: {random.randint(100,1000)}ms."
        event_type = "performance_warning"
        severity_level = log_level
        impacted_services = [component]
        num_clients_affected = random.randint(0, 500)
        data_loss_details = "No data loss"
        incident_description = description
        dora_incident_classification = "Performance Warning"
        is_reportable_dora_incident = False

    event_timestamp = timestamp_dt.isoformat().replace("+00:00", "Z")
    ict_system_id = f"ICT-{random.randint(1000,9999)}"

    event = {
        "timestamp": event_timestamp,
        "event_timestamp": event_timestamp,
        "log_level": log_level,
        "severity_level": severity_level,
        "component": component,
        "ict_system_id": ict_system_id,
        "event_type": event_type,
        "description": description,
        "user_id": user_id,
        "ip_address": ip_address,
        "source_hostname": source_hostname,
        "transaction_id": str(uuid.uuid4()) if random.random() > 0.5 else None,
        "session_id": str(uuid.uuid4()) if user_id != "SYSTEM" else None,
        "dora_compliance_tag": "DORA_v1.0_log",
        "event_category": "ICT_Operational_Event" if log_level in ["INFO", "WARNING"] else "ICT_Security_Incident",
        "impacted_services": impacted_services,
        "num_clients_affected": num_clients_affected,
        "data_loss_details": data_loss_details,
        "incident_description": incident_description,
        "dora_incident_classification": dora_incident_classification,
        "is_reportable_dora_incident": is_reportable_dora_incident,
    }
    # Add _raw field as a JSON string of the event
    event["_raw"] = json.dumps(event)

    return event

# --- Splunk HEC Sending Function ---
def send_events_to_splunk_hec(
    events_batch, url, token, source, sourcetype, index, verify_ssl, timeout
):
    """Sends a batch of events to Splunk HEC."""
    if not events_batch:
        return True

    headers = {"Authorization": f"Splunk {token}"}
    payload_items = []
    for event_data in events_batch:
        try:
            dt_object = datetime.datetime.fromisoformat(
                event_data["timestamp"].replace("Z", "+00:00")
            )
            epoch_time = dt_object.timestamp()
        except (ValueError, KeyError) as e:
            print(f"Error converting timestamp for HEC: {e}. Using current time.", file=sys.stderr)
            epoch_time = time.time()

        hec_event = {
            "time": epoch_time,
            "source": source,
            "sourcetype": sourcetype,
            "index": index,
            "host": event_data.get("source_hostname", source),
            "event": event_data,
        }
        payload_items.append(json.dumps(hec_event))

    payload = "\n".join(payload_items)

    try:
        response = requests.post(
            url,
            data=payload.encode("utf-8"),
            headers=headers,
            verify=verify_ssl,
            timeout=timeout,
        )
        response.raise_for_status()
        return True
    except requests.exceptions.RequestException as e:
        print(f"Error sending batch to Splunk HEC: {e}", file=sys.stderr)
        if hasattr(e, "response") and e.response is not None:
            try:
                print(f"Splunk HEC Response: {e.response.json()}", file=sys.stderr)
            except json.JSONDecodeError:
                print(f"Splunk HEC Response (raw): {e.response.text}", file=sys.stderr)
        return False

def main():
    parser = argparse.ArgumentParser(
        description="Generate synthetic DORA-compliant log data and optionally send to Splunk HEC or save to CSV."
    )
    parser.add_argument(
        "--num-events", # Changed from --num-logs
        type=int,
        default=DEFAULT_NUM_EVENTS, # Changed from DEFAULT_NUM_LOGS
        help=f"Number of log entries (events) to generate (default: {DEFAULT_NUM_EVENTS}).", # Updated help
    )
    parser.add_argument(
        "--output-csv",
        type=str,
        default=None,
        help="Filename to save logs as CSV (e.g., dora_logs.csv). If not provided, CSV is not saved unless --send-to-splunk is also absent.",
    )
    parser.add_argument(
        "--send-to-splunk",
        action="store_true",
        help="Enable sending data to Splunk HEC.",
    )
    # HEC arguments group
    hec_group = parser.add_argument_group('Splunk HEC Options (if --send-to-splunk is used)')
    hec_group.add_argument("--splunk-url", type=str, default=SPLUNK_HEC_URL_DEFAULT)
    hec_group.add_argument("--splunk-token", type=str, default=SPLUNK_HEC_TOKEN_DEFAULT)
    hec_group.add_argument("--splunk-index", type=str, default=SPLUNK_HEC_INDEX_DEFAULT)
    hec_group.add_argument("--splunk-source", type=str, default=SPLUNK_HEC_SOURCE_DEFAULT)
    hec_group.add_argument("--splunk-sourcetype", type=str, default=SPLUNK_HEC_SOURCETYPE_DEFAULT)
    hec_group.add_argument("--splunk-batch-size", type=int, default=SPLUNK_HEC_BATCH_SIZE_DEFAULT)
    hec_group.add_argument(
        "--splunk-disable-ssl-verify",
        action="store_false",
        dest="splunk_verify_ssl",
        help="Disable SSL verification for Splunk HEC (use for self-signed certs).",
    )
    parser.set_defaults(splunk_verify_ssl=SPLUNK_HEC_VERIFY_SSL_DEFAULT)


    args = parser.parse_args()

    if args.send_to_splunk:
        if "YOUR_SPLUNK_HEC_URL" in args.splunk_url or "YOUR_SPLUNK_HEC_TOKEN" in args.splunk_token:
            print(
                "ERROR: Splunk HEC URL or Token is not configured. "
                "Update defaults in the script or provide via command-line.",
                file=sys.stderr,
            )
            sys.exit(1)
        print(
            f"Splunk HEC sending enabled: URL={args.splunk_url}, Index={args.splunk_index}",
            file=sys.stderr,
        )
        if not args.splunk_verify_ssl: # Moved this check here for clarity
            print("SSL verification for HEC is DISABLED.", file=sys.stderr)
            # Consider suppressing urllib3 warnings if SSL verify is False
            import urllib3
            try:
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
                # Also attempt to suppress NotOpenSSLWarning if it's a concern and verify is False
                warnings.filterwarnings('ignore', category=urllib3.exceptions.NotOpenSSLWarning)
            except Exception: # Broad except if urllib3 or warnings module is different than expected
                pass


    csv_output_file = args.output_csv
    if not args.output_csv and not args.send_to_splunk:
        csv_output_file = "dora_compliant_logs.csv"
        print(f"No explicit output specified. Saving to {csv_output_file}", file=sys.stderr)


    print(f"Generating {args.num_events} DORA-compliant log records...", file=sys.stderr) # Uses args.num_events
    log_data_list = []
    splunk_batch = []
    total_sent_to_splunk = 0
    total_failed_splunk = 0

    for i in range(args.num_events): # Uses args.num_events
        if (i + 1) % (args.num_events // 10 or 1) == 0: # Uses args.num_events
            print(f"  Generated {i+1}/{args.num_events} logs...", file=sys.stderr) # Uses args.num_events
        
        if i > 0 and i % 5000 == 0:
            fake.unique.clear()

        log_entry = generate_log_entry()
        log_data_list.append(log_entry)

        if args.send_to_splunk:
            splunk_batch.append(log_entry)
            if len(splunk_batch) >= args.splunk_batch_size:
                print(f"  Sending batch of {len(splunk_batch)} logs to Splunk HEC...", file=sys.stderr)
                if send_events_to_splunk_hec(
                    splunk_batch,
                    args.splunk_url,
                    args.splunk_token,
                    args.splunk_source,
                    args.splunk_sourcetype,
                    args.splunk_index,
                    args.splunk_verify_ssl,
                    SPLUNK_HEC_TIMEOUT_DEFAULT,
                ):
                    total_sent_to_splunk += len(splunk_batch)
                else:
                    total_failed_splunk += len(splunk_batch)
                splunk_batch = []

    if args.send_to_splunk and splunk_batch:
        print(f"  Sending final batch of {len(splunk_batch)} logs to Splunk HEC...", file=sys.stderr)
        if send_events_to_splunk_hec(
            splunk_batch,
            args.splunk_url,
            args.splunk_token,
            args.splunk_source,
            args.splunk_sourcetype,
            args.splunk_index,
            args.splunk_verify_ssl,
            SPLUNK_HEC_TIMEOUT_DEFAULT,
        ):
            total_sent_to_splunk += len(splunk_batch)
        else:
            total_failed_splunk += len(splunk_batch)

    if args.send_to_splunk:
        print("\nSplunk HEC Sending DORA Summary:", file=sys.stderr)
        print(f"  Successfully sent: {total_sent_to_splunk} logs", file=sys.stderr)
        print(f"  Failed to send:    {total_failed_splunk} logs", file=sys.stderr)

    if csv_output_file:
        print(f"\nSaving {len(log_data_list)} log records to {csv_output_file}...", file=sys.stderr)
        df = pd.DataFrame(log_data_list)
        df.to_csv(csv_output_file, index=False)
        print(f"Successfully saved logs to {csv_output_file}", file=sys.stderr)

    print(f"\nScript finished. Generated {args.num_events} total logs.", file=sys.stderr) # Uses args.num_events

if __name__ == "__main__":
    # Added import for warnings module here to be used in main
    import warnings
    main()