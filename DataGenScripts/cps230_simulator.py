import argparse
import datetime
import json
import random
import sys
import time
import uuid

import pandas as pd
import pytz # For timezone handling if needed, though we'll stick to UTC
import requests
from faker import Faker

# Initialize Faker
fake = Faker()

# --- Configuration ---
DEFAULT_NUM_EVENTS = 500
DEFAULT_CSV_FILENAME = "cps230_synthetic_events.csv"
HOURS_BACKFILL_PER_100_EVENTS = 1.0  # Match PCI and RMiT simulators: 1 hour per 100 events

# --- Splunk HEC Configuration (Defaults, can be overridden) ---
SPLUNK_HEC_URL_DEFAULT = "YOUR_SPLUNK_HEC_URL"  # e.g., "https://splunk.example.com:8088/services/collector"
SPLUNK_HEC_TOKEN_DEFAULT = "YOUR_SPLUNK_HEC_TOKEN"
SPLUNK_HEC_INDEX_DEFAULT = "sample_cps"
SPLUNK_HEC_SOURCETYPE_DEFAULT = "cps230:synthetic:event"
SPLUNK_HEC_SOURCE_DEFAULT = "cps_simulator"
SPLUNK_HEC_VERIFY_SSL_DEFAULT = False
SPLUNK_HEC_BATCH_SIZE_DEFAULT = 100

# --- CPS 230 Specific Data Elements ---
ENTITY_IDS = [f"ENTITY_{str(uuid.uuid4())[:4].upper()}" for _ in range(5)] # Simulating a few regulated entities
CRITICAL_OPERATIONS = [
    "Payments Processing", "Customer Account Management", "Regulatory Reporting",
    "Insurance Claims Processing", "Superannuation Fund Administration", "Online Banking Services",
    "Trade Settlement", "Liquidity Management"
]
INCIDENT_SEVERITY_LEVELS = ["Low", "Medium", "High", "Critical"]
INCIDENT_STATUSES = ["Reported", "Investigating", "Contained", "Remediating", "Resolved", "Closed", "Post-Incident Review"]
CONTROL_TYPES = ["Preventive", "Detective", "Corrective", "Directive"]
ASSESSMENT_OUTCOMES = ["Effective", "Partially Effective", "Ineffective", "Requires Improvement"]
BCP_SCENARIOS = [
    "Cyber Attack (Ransomware)", "Data Centre Outage", "Pandemic Event",
    "Natural Disaster (Flood/Fire)", "Key Supplier Failure", "Utility Disruption (Power/Network)"
]
BCP_TEST_OUTCOMES = ["Successful", "Successful with Observations", "Partially Successful", "Unsuccessful"]
CHANGE_TYPES = ["System Upgrade", "New Application Deployment", "Process Re-engineering", "Infrastructure Change", "Security Patch"]
CHANGE_STATUSES = ["Planned", "In Progress", "Completed", "Failed", "Rolled Back"]
RISK_LEVELS = ["Low", "Medium", "High", "Very High"]
THIRD_PARTY_RISK_TYPES = ["Data Security", "Service Availability", "Compliance Risk", "Financial Stability", "Concentration Risk"]

# --- Event Type Generation Weights ---
EVENT_TYPE_WEIGHTS = {
    "operational_incident": 30,
    "control_assessment": 20,
    "third_party_risk_event": 15,
    "bcp_event": 10,
    "change_management_event": 20,
    "data_management_alert": 5,
}

# --- Helper Functions for Event Details ---
def generate_operational_incident_details():
    critical_op = random.choice(CRITICAL_OPERATIONS)
    severity = random.choice(INCIDENT_SEVERITY_LEVELS)
    status = random.choice(INCIDENT_STATUSES)
    description = f"{severity} incident impacting {critical_op}: {fake.sentence(nb_words=10)}"
    resolution_time_hours = None
    if status in ["Resolved", "Closed"]:
        resolution_time_hours = round(random.uniform(0.5, 72), 1)
        if severity == "Critical":
            resolution_time_hours = round(random.uniform(0.5, 12), 1) # Shorter for critical

    return {
        "incident_id": f"INC-{str(uuid.uuid4())[:8].upper()}",
        "severity": severity,
        "status": status,
        "description": description,
        "impacted_operation": critical_op,
        "detection_method": random.choice(["Monitoring Alert", "User Reported", "Internal Audit", "System Log"]),
        "resolution_time_hours": resolution_time_hours,
        "root_cause_category": random.choice(["Technology Failure", "Process Failure", "Human Error", "External Event", "Third-Party Issue"]) if status in ["Resolved", "Closed"] else None,
    }

def generate_control_assessment_details():
    control_id = f"CTRL-{random.randint(1000,9999)}"
    return {
        "control_id": control_id,
        "control_name": f"{random.choice(CONTROL_TYPES)} Control for {random.choice(CRITICAL_OPERATIONS)}",
        "assessment_date": (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=random.randint(1, 180))).date().isoformat(),
        "assessor_department": random.choice(["Internal Audit", "Risk Management", "Compliance", "First Line Operations"]),
        "assessment_outcome": random.choice(ASSESSMENT_OUTCOMES),
        "findings_summary": fake.sentence(nb_words=15) if random.random() > 0.3 else None,
        "remediation_plan_id": f"REMPLN-{str(uuid.uuid4())[:6].upper()}" if random.random() > 0.5 else None,
    }

def generate_third_party_risk_event_details():
    vendor_name = fake.company()
    return {
        "vendor_id": f"VEND-{str(uuid.uuid4())[:6].upper()}",
        "vendor_name": vendor_name,
        "service_provided": fake.bs(),
        "risk_type": random.choice(THIRD_PARTY_RISK_TYPES),
        "event_description": f"Risk event identified for {vendor_name}: {fake.sentence(nb_words=8)}",
        "assessment_date": (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=random.randint(1, 90))).date().isoformat(),
        "assessment_rating": random.choice(RISK_LEVELS),
        "mitigation_actions_status": random.choice(["Pending", "In Progress", "Completed", "Not Required"]),
    }

def generate_bcp_event_details():
    scenario = random.choice(BCP_SCENARIOS)
    is_test = random.random() > 0.2 # 80% are tests
    return {
        "bcp_event_id": f"BCP-{str(uuid.uuid4())[:7].upper()}",
        "scenario_type": scenario,
        "activation_reason": "Scheduled Test" if is_test else f"Actual Event - {scenario}",
        "activation_level": random.choice(["Partial", "Full", "Departmental"]),
        "outcome": random.choice(BCP_sample_OUTCOMES) if is_test else random.choice(["Operations Restored", "Degraded Service", "Failed to Restore"]),
        "duration_minutes": random.randint(30, 1440) if not is_test else random.randint(60, 480), # Actual events can be longer
        "lessons_learned_summary": fake.paragraph(nb_sentences=2) if random.random() > 0.4 else None,
    }

def generate_change_management_event_details():
    change_type = random.choice(CHANGE_TYPES)
    return {
        "change_id": f"CHG-{random.randint(10000,99999)}",
        "change_type": change_type,
        "description": f"{change_type} for {random.choice(CRITICAL_OPERATIONS)} system.",
        "status": random.choice(CHANGE_STATUSES),
        "risk_level": random.choice(RISK_LEVELS),
        "planned_implementation_date": (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=random.randint(-30, 30))).date().isoformat(),
        "approver_role": random.choice(["Change Advisory Board", "IT Management", "Business Owner"]),
        "rollback_required": True if random.random() < 0.1 else False, # 10% chance of rollback
    }

def generate_data_management_alert_details():
    return {
        "alert_id": f"DMA-{str(uuid.uuid4())[:8].upper()}",
        "alert_type": random.choice(["Data Quality Anomaly", "Unauthorized Data Access Attempt", "Data Loss Prevention Alert", "Data Retention Policy Violation"]),
        "data_source": f"DB_{random.choice(['CUSTOMER', 'TRANSACTION', 'RISK_MODEL'])}",
        "severity": random.choice(["Medium", "High"]),
        "description": fake.sentence(nb_words=12),
        "action_taken": random.choice(["Investigating", "Escalated", "No Action Required", "Access Blocked"]),
    }


# --- Main Event Generation Function ---
def generate_cps230_event(event_count, current_datetime_utc):
    """Generates a single synthetic CPS 230 relevant event with required fields."""
    event_type_choices = list(EVENT_TYPE_WEIGHTS.keys())
    event_type_probabilities = [w / sum(EVENT_TYPE_WEIGHTS.values()) for w in EVENT_TYPE_WEIGHTS.values()]
    event_type = random.choices(event_type_choices, weights=event_type_probabilities, k=1)[0]

    # Required fields
    event_timestamp = current_datetime_utc.isoformat().replace("+00:00", "Z")
    critical_operation_id = f"CRITOP-{random.randint(1000,9999)}"
    impact_description = f"Impact to {random.choice(CRITICAL_OPERATIONS)}: {fake.sentence(nb_words=8)}"
    estimated_downtime_minutes = random.randint(5, 720) if event_type == "operational_incident" else None
    service_provider_id = f"SP-{str(uuid.uuid4())[:6].upper()}" if event_type == "third_party_risk_event" else None
    control_id_failed = f"CTRL-{random.randint(1000,9999)}" if event_type in ["operational_incident", "control_assessment"] and random.random() > 0.7 else None
    cps230_incident_severity = random.choice(INCIDENT_SEVERITY_LEVELS) if event_type == "operational_incident" else None
    apra_notification_candidate = (event_type == "operational_incident" and cps230_incident_severity in ["High", "Critical"]) or (event_type == "third_party_risk_event" and random.random() > 0.8)

    base_event = {
        "event_id": str(uuid.uuid4()),
        "event_timestamp": event_timestamp,
        "timestamp": event_timestamp,
        "entity_id": random.choice(ENTITY_IDS),
        "critical_operation_id": critical_operation_id,
        "event_type": event_type,
        "impact_description": impact_description,
        "estimated_downtime_minutes": estimated_downtime_minutes,
        "service_provider_id": service_provider_id,
        "control_id_failed": control_id_failed,
        "cps230_incident_severity": cps230_incident_severity,
        "apra_notification_candidate": apra_notification_candidate,
        "reporter_user_id": f"user_{fake.user_name()}" if random.random() > 0.1 else "SYSTEM_AUTOMATED",
        "source_system": random.choice(["GRC_Platform", "SIEM", "ServiceDesk", "MonitoringTool", "ManualInput"]),
    }

    details = {}
    if event_type == "operational_incident":
        details = generate_operational_incident_details()
    elif event_type == "control_assessment":
        details = generate_control_assessment_details()
    elif event_type == "third_party_risk_event":
        details = generate_third_party_risk_event_details()
    elif event_type == "bcp_event":
        details = generate_bcp_event_details()
    elif event_type == "change_management_event":
        details = generate_change_management_event_details()
    elif event_type == "data_management_alert":
        details = generate_data_management_alert_details()

    event = {**base_event, **details}
    event["_raw"] = json.dumps(event)  # Ensure _raw is always the last field

    return event


# --- Splunk HEC Sending Function ---
def send_events_to_splunk_hec(
    events_batch, url, token, source, sourcetype, index, verify_ssl, timeout
):
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


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Generate synthetic APRA CPS 230 relevant operational risk events."
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
        help=f"Filename to save events as CSV. If not provided and --send-to-splunk is also absent, defaults to '{DEFAULT_CSV_FILENAME}'.",
    )

    # HEC Arguments
    hec_group = parser.add_argument_group('Splunk HEC Options (if --send-to-splunk is used)')
    hec_group.add_argument("--splunk-url", default=SPLUNK_HEC_URL_DEFAULT, help="Splunk HEC URL.")
    hec_group.add_argument("--splunk-token", default=SPLUNK_HEC_TOKEN_DEFAULT, help="Splunk HEC Token.")
    hec_group.add_argument("--splunk-index", default=SPLUNK_HEC_INDEX_DEFAULT, help="Splunk Index.")
    hec_group.add_argument("--splunk-sourcetype", default=SPLUNK_HEC_SOURCETYPE_DEFAULT, help="Splunk Sourcetype.")
    hec_group.add_argument("--splunk-source", default=SPLUNK_HEC_SOURCE_DEFAULT, help="Splunk Source value for HEC events.")
    hec_group.add_argument("--splunk-batch-size", type=int, default=SPLUNK_HEC_BATCH_SIZE_DEFAULT, help="Number of events per HEC batch.")
    hec_group.add_argument(
        "--splunk-disable-ssl-verify",
        action="store_false",
        dest="splunk_verify_ssl",
        help="Disable SSL verification for Splunk HEC (use for self-signed certs).",
    )
    parser.set_defaults(splunk_verify_ssl=SPLUNK_HEC_VERIFY_SSL_DEFAULT)

    # Data Generation Arguments
    gen_group = parser.add_argument_group('Data Generation Options')
    gen_group.add_argument("--num-events", type=int, default=DEFAULT_NUM_EVENTS, help="Number of events to generate.")
    gen_group.add_argument("--hours-backfill-per-100", type=float, default=HOURS_BACKFILL_PER_100_EVENTS, help="Hours to backfill timestamp for every 100 events.")

    args = parser.parse_args()

    # Determine if any output action is requested
    if not args.send_to_splunk and not args.output_csv:
        args.output_csv = DEFAULT_CSV_FILENAME
        print(f"No explicit output specified. Defaulting to save to CSV: {args.output_csv}", file=sys.stderr)

    if args.send_to_splunk and args.splunk_token == "YOUR_SPLUNK_HEC_TOKEN":
        print("ERROR: --send-to-splunk is enabled, but SPLUNK_HEC_TOKEN is not configured. Please set it via --splunk-token or update the script default.", file=sys.stderr)
        sys.exit(1)

    if args.send_to_splunk and not args.splunk_verify_ssl:
        print("SSL verification for HEC is DISABLED.", file=sys.stderr)
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    print(f"Generating {args.num_events} CPS 230 synthetic events...", file=sys.stderr)

    all_generated_events = []
    splunk_batch = []
    total_sent_to_splunk = 0
    total_failed_splunk = 0

    start_time_utc = datetime.datetime.now(datetime.timezone.utc)
    time_offset_per_100_events = datetime.timedelta(hours=args.hours_backfill_per_100)

    for i in range(args.num_events):
        time_shift = (i // 100) * time_offset_per_100_events
        current_time_for_event = start_time_utc - time_shift

        event = generate_cps230_event(i + 1, current_time_for_event)
        all_generated_events.append(event)

        if args.send_to_splunk:
            splunk_batch.append(event)
            if len(splunk_batch) >= args.splunk_batch_size:
                print(f"  Sending batch of {len(splunk_batch)} events to Splunk HEC...", file=sys.stderr)
                if send_events_to_splunk_hec(
                    splunk_batch, args.splunk_url, args.splunk_token,
                    args.splunk_source, args.splunk_sourcetype, args.splunk_index,
                    args.splunk_verify_ssl, 30 # timeout
                ):
                    total_sent_to_splunk += len(splunk_batch)
                else:
                    total_failed_splunk += len(splunk_batch)
                splunk_batch = []

        if (i + 1) % (args.num_events // 10 or 1) == 0:
            print(f"  Generated {i + 1}/{args.num_events} events...", file=sys.stderr)

    # Send any remaining events in the Splunk batch
    if args.send_to_splunk and splunk_batch:
        print(f"  Sending final batch of {len(splunk_batch)} events to Splunk HEC...", file=sys.stderr)
        if send_events_to_splunk_hec(
            splunk_batch, args.splunk_url, args.splunk_token,
            args.splunk_source, args.splunk_sourcetype, args.splunk_index,
            args.splunk_verify_ssl, 30
        ):
            total_sent_to_splunk += len(splunk_batch)
        else:
            total_failed_splunk += len(splunk_batch)

    if args.send_to_splunk:
        print("\nSplunk HEC Sending CPS230 Summary:", file=sys.stderr)
        print(f"  Successfully sent: {total_sent_to_splunk} events", file=sys.stderr)
        print(f"  Failed to send:    {total_failed_splunk} events", file=sys.stderr)

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
    print("\nDisclaimer: This script generates synthetic data for illustrative purposes related to APRA CPS 230 themes. It does not guarantee compliance or cover all aspects of the standard.", file=sys.stderr)