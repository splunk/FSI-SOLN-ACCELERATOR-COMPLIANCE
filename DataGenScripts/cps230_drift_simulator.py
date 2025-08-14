# cps230_data_schema_drift.py
import argparse
import json
import random
import sys
import time
import uuid
import warnings # For suppressing urllib3 warnings
import re
from dateutil import parser as dateutil_parser  # Add this import at the top

import pandas as pd
import pytz
import requests
from faker import Faker
from datetime import datetime, timedelta, timezone

# Initialize Faker
fake = Faker()
Faker.seed(42)
random.seed(42)

# --- Configuration ---
DEFAULT_NUM_EVENTS = 1000 # Matched to other drift scripts
DEFAULT_CSV_FILENAME = "cps230_schema_drift_raw_logs.csv"

# --- Splunk HEC Configuration for RAW DRIFT DATA ---
SPLUNK_HEC_URL_DEFAULT = "YOUR_SPLUNK_HEC_URL/services/collector" # Batch endpoint
SPLUNK_HEC_TOKEN_DEFAULT = "YOUR_HEC_TOKEN_FOR_RAW_DATA"
SPLUNK_RAW_INDEX_DEFAULT = "drift_raw_data" # Common index
SPLUNK_CPS230_RAW_SOURCETYPE_DEFAULT = "cps230_drift_raw" # Specific sourcetype
SPLUNK_HEC_SOURCE_DEFAULT = "cps230_drift_generator"
SPLUNK_HEC_VERIFY_SSL_DEFAULT = False
SPLUNK_HEC_BATCH_SIZE_DEFAULT = 100 # Using batching
SPLUNK_HEC_TIMEOUT_DEFAULT = 30

# --- CPS 230 Specific Data Elements (from original script) ---
ENTITY_IDS = [f"ENTITY_{str(uuid.uuid4())[:4].upper()}" for _ in range(5)]
CRITICAL_OPERATIONS = [ "Payments Processing", "Customer Account Management", "Regulatory Reporting", "Insurance Claims Processing", "Superannuation Fund Administration", "Online Banking Services", "Trade Settlement", "Liquidity Management" ]
INCIDENT_SEVERITY_LEVELS = ["Low", "Medium", "High", "Critical"]
INCIDENT_STATUSES = ["Reported", "Investigating", "Contained", "Remediating", "Resolved", "Closed", "Post-Incident Review"]
CONTROL_TYPES = ["Preventive", "Detective", "Corrective", "Directive"]
ASSESSMENT_OUTCOMES = ["Effective", "Partially Effective", "Ineffective", "Requires Improvement"]
BCP_SCENARIOS = [ "Cyber Attack (Ransomware)", "Data Centre Outage", "Pandemic Event", "Natural Disaster (Flood/Fire)", "Key Supplier Failure", "Utility Disruption (Power/Network)" ]
BCP_TEST_OUTCOMES = ["Successful", "Successful with Observations", "Partially Successful", "Unsuccessful"]
CHANGE_TYPES = ["System Upgrade", "New Application Deployment", "Process Re-engineering", "Infrastructure Change", "Security Patch"]
CHANGE_STATUSES = ["Planned", "In Progress", "Completed", "Failed", "Rolled Back"]
RISK_LEVELS = ["Low", "Medium", "High", "Very High"]
THIRD_PARTY_RISK_TYPES = ["Data Security", "Service Availability", "Compliance Risk", "Financial Stability", "Concentration Risk"]
# New constants for drift
BUSINESS_UNITS_AFFECTED = ["Retail_Banking_Division", "Wealth_Management_Services", "Group_IT_Infrastructure", "Insurance_Operations_AU", "Corporate_Lending", "Treasury_Operations"]
EVENT_REVIEW_STATUSES = ["Pending_Triage", "Under_Initial_Review", "Reviewed_NoFurtherAction", "Reviewed_ActionItems_Assigned", "Escalated_To_Management", "Closed_Review_Complete"]


# --- Event Type Generation Weights (same as original) ---
EVENT_TYPE_WEIGHTS = { "operational_incident": 30, "control_assessment": 20, "third_party_risk_event": 15, "bcp_event": 10, "change_management_event": 20, "data_management_alert": 5, }

# --- Schema Drift Percentage Thresholds ---
DRIFT_ADD_COMMON_CPS_START_PCT = 0.25
DRIFT_MODIFY_INCIDENT_REMOVE_COMMON_START_PCT = 0.50
DRIFT_RENAME_COMMON_ADD_CHANGE_START_PCT = 0.75
DRIFT_DATE_FORMAT_START_PCT = 0.35
DRIFT_NUMBER_FORMAT_START_PCT = 0.60
DRIFT_STRING_PATTERN_START_PCT = 0.80

# --- Helper Functions for Schema  Value Drift ---
def drift_date_format(dt, progress_pct):
    """Change date format based on drift progress."""
    if progress_pct < DRIFT_DATE_FORMAT_START_PCT:
        return dt.isoformat()  # Default ISO
    elif progress_pct < DRIFT_NUMBER_FORMAT_START_PCT:
        return dt.strftime("%d/%m/%Y %H:%M:%S")  # European style
    else:
        return dt.strftime("%m-%d-%Y %I:%M %p")  # US style with AM/PM

def drift_number_format(num, progress_pct):
    """Change number format based on drift progress."""
    if progress_pct < DRIFT_NUMBER_FORMAT_START_PCT:
        return num  # Default
    elif progress_pct < DRIFT_STRING_PATTERN_START_PCT:
        return f"{num:,.2f}"  # Comma as thousands separator
    else:
        return f"{num:.2e}"  # Scientific notation

def drift_string_pattern(val, progress_pct):
    """Apply schema value drift: dots/spaces/dashes, extra spaces, mixed case, remove spaces."""
    if progress_pct < DRIFT_STRING_PATTERN_START_PCT:
        return val  # No drift

    drifted = val

    # 1. Randomly replace spaces/dashes with dots or vice versa
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

# --- Helper Functions for Event Details (return dictionaries) ---
# These generate the "details" part of the event. Schema drift will be applied in the main generator.
def generate_operational_incident_details():
    critical_op, severity, status = random.choice(CRITICAL_OPERATIONS), random.choice(INCIDENT_SEVERITY_LEVELS), random.choice(INCIDENT_STATUSES)
    description = f"{severity} incident impacting {critical_op}: {fake.sentence(nb_words=10)}"
    resolution_time_hours = None
    if status in ["Resolved", "Closed"]:
        resolution_time_hours = round(random.uniform(0.5, 12) if severity == "Critical" else random.uniform(0.5, 72), 1)
    return { "incident_id": f"INC-{str(uuid.uuid4())[:8].upper()}", "severity": severity, "status": status, "description": description, "impacted_operation": critical_op, "detection_method": random.choice(["Monitoring Alert", "User Reported", "Internal Audit", "System Log"]), "resolution_time_hours": resolution_time_hours, "root_cause_category": random.choice(["Technology Failure", "Process Failure", "Human Error", "External Event", "Third-Party Issue"]) if status in ["Resolved", "Closed"] else None, }
def generate_control_assessment_details():
    return { 
        "control_id": f"CTRL-{random.randint(1000,9999)}", 
        "control_name": f"{random.choice(CONTROL_TYPES)} Control for {random.choice(CRITICAL_OPERATIONS)}", 
        "assessment_date": (datetime.now(timezone.utc) - timedelta(days=random.randint(1, 180))).date().isoformat(),
        "assessor_department": random.choice(["Internal Audit", "Risk Management", "Compliance", "First Line Operations"]), "assessment_outcome": random.choice(ASSESSMENT_OUTCOMES), "findings_summary": fake.sentence(nb_words=15) if random.random() > 0.3 else None, "remediation_plan_id": f"REMPLN-{str(uuid.uuid4())[:6].upper()}" if random.random() > 0.5 else None, }
def generate_third_party_risk_event_details():
    vendor_name = fake.company()
    return { 
        "vendor_id": f"VEND-{str(uuid.uuid4())[:6].upper()}", 
        "vendor_name": vendor_name, 
        "service_provided": fake.bs(), 
        "risk_type": random.choice(THIRD_PARTY_RISK_TYPES), 
        "event_description": f"Risk event identified for {vendor_name}: {fake.sentence(nb_words=8)}", 
        "assessment_date": (datetime.now(timezone.utc) - timedelta(days=random.randint(1, 90))).date().isoformat(), 
        "assessment_rating": random.choice(RISK_LEVELS), 
        "mitigation_actions_status": random.choice(["Pending", "In Progress", "Completed", "Not Required"]), }
def generate_bcp_event_details():
    scenario = random.choice(BCP_SCENARIOS)
    is_test = random.random() > 0.2
    return { "bcp_event_id": f"BCP-{str(uuid.uuid4())[:7].upper()}", "scenario_type": scenario, "activation_reason": "Scheduled Test" if is_test else f"Actual Event - {scenario}", "activation_level": random.choice(["Partial", "Full", "Departmental"]), "outcome": random.choice(BCP_TEST_OUTCOMES) if is_test else random.choice(["Operations Restored", "Degraded Service", "Failed to Restore"]), "duration_minutes": random.randint(60, 480) if is_test else random.randint(30, 1440), "lessons_learned_summary": fake.paragraph(nb_sentences=2) if random.random() > 0.4 else None, }
def generate_change_management_event_details():
    change_type = random.choice(CHANGE_TYPES)
    return { 
        "change_id": f"CHG-{random.randint(10000,99999)}", 
        "change_type": change_type, 
        "description": f"{change_type} for {random.choice(CRITICAL_OPERATIONS)} system.", 
        "status": random.choice(CHANGE_STATUSES), 
        "risk_level": random.choice(RISK_LEVELS), 
        "planned_implementation_date": (datetime.now(timezone.utc) + timedelta(days=random.randint(-30, 30))).date().isoformat(),
        "approver_role": random.choice(["Change Advisory Board", "IT Management", "Business Owner"]), "rollback_required": True if random.random() < 0.1 else False, }
def generate_data_management_alert_details():
    return { "alert_id": f"DMA-{str(uuid.uuid4())[:8].upper()}", "alert_type": random.choice(["Data Quality Anomaly", "Unauthorized Data Access Attempt", "Data Loss Prevention Alert", "Data Retention Policy Violation"]), "data_source": f"DB_{random.choice(['CUSTOMER', 'TRANSACTION', 'RISK_MODEL'])}", "severity": random.choice(["Medium", "High"]), "description": fake.sentence(nb_words=12), "action_taken": random.choice(["Investigating", "Escalated", "No Action Required", "Access Blocked"]), }


# --- Helper Functions for Targeted Value Schema Drift ---

DRIFT_VALUE_SCHEMA_START_PCT = DRIFT_RENAME_COMMON_ADD_CHANGE_START_PCT  # Use same threshold as field drift (0.75)

def drift_critical_operations(val, progress_pct, drift_start_pct=DRIFT_VALUE_SCHEMA_START_PCT):
    """Change spaces to double spaces, remove spaces, or change space to underscore."""
    if progress_pct < drift_start_pct or not isinstance(val, str):
        return val
    if " " in val:
        drift_type = random.choice(["double_space", "remove", "underscore"])
        if drift_type == "double_space":
            return val.replace(" ", "  ")
        elif drift_type == "remove":
            return val.replace(" ", "")
        elif drift_type == "underscore":
            return val.replace(" ", "_")
    return val

def drift_bcp_scenarios(val, progress_pct, drift_start_pct=DRIFT_VALUE_SCHEMA_START_PCT):
    """Remove spaces or add double space in BCP scenario strings."""
    if progress_pct < drift_start_pct or not isinstance(val, str):
        return val
    if " " in val:
        if random.random() < 0.5:
            return val.replace(" ", "")
        else:
            return val.replace(" ", "  ")
    return val

def drift_change_statuses(val, progress_pct, drift_start_pct=DRIFT_VALUE_SCHEMA_START_PCT):
    """Remove spaces or add double space in change status strings."""
    if progress_pct < drift_start_pct or not isinstance(val, str):
        return val
    if " " in val:
        if random.random() < 0.5:
            return val.replace(" ", "")
        else:
            return val.replace(" ", "  ")
    return val

def drift_business_units(val, progress_pct, drift_start_pct=DRIFT_VALUE_SCHEMA_START_PCT):
    """Change underscore for dots, spaces, or double underscore."""
    if progress_pct < drift_start_pct or not isinstance(val, str):
        return val
    if "_" in val:
        drift_type = random.choice(["dot", "space", "double_underscore"])
        if drift_type == "dot":
            return val.replace("_", ".")
        elif drift_type == "space":
            return val.replace("_", " ")
        elif drift_type == "double_underscore":
            return val.replace("_", "__")
    return val

def drift_event_review_statuses(val, progress_pct, drift_start_pct=DRIFT_VALUE_SCHEMA_START_PCT):
    """Change underscore for dots, spaces, or double underscore."""
    if progress_pct < drift_start_pct or not isinstance(val, str):
        return val
    if "_" in val:
        drift_type = random.choice(["dot", "space", "double_underscore"])
        if drift_type == "dot":
            return val.replace("_", ".")
        elif drift_type == "space":
            return val.replace("_", " ")
        elif drift_type == "double_underscore":
            return val.replace("_", "__")
    return val

# --- Main Event Generation Function with Fixed Value Drift ---
def generate_cps230_event_with_drift(event_number, total_events, current_datetime_utc):
    current_progress_pct = event_number / total_events

    event_type_choices = list(EVENT_TYPE_WEIGHTS.keys())
    event_type_probabilities = [
        w / sum(EVENT_TYPE_WEIGHTS.values())
        for w in EVENT_TYPE_WEIGHTS.values()
    ]
    event_type = random.choices(
        event_type_choices, weights=event_type_probabilities, k=1
    )[0]

    # 1. --- Generate Base Event and Details (NO drift applied here) ---
    event = {
        "event_id": str(uuid.uuid4()),
        "timestamp": current_datetime_utc.isoformat(), # Start with clean ISO format
        "entity_id": random.choice(ENTITY_IDS),
        "event_type": event_type,
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

    # Merge details into the main event dictionary
    event.update(details)

    # 2. --- Apply Structural Schema Drift (Adding/Removing/Renaming Fields) ---
    if current_progress_pct < DRIFT_MODIFY_INCIDENT_REMOVE_COMMON_START_PCT:
        event["reporter_user_id"] = (
            f"user_{fake.user_name()}"
            if random.random() > 0.1
            else "SYSTEM_AUTOMATED_CPS"
        )

    base_source_system_value = random.choice(
        ["GRC_Maximus", "SIEM_QRadar", "ServiceDesk_Jira", "SolarWinds_Monitor", "Manual_Ops_Log"]
    )
    if current_progress_pct < DRIFT_RENAME_COMMON_ADD_CHANGE_START_PCT:
        event["source_system"] = base_source_system_value
    else:
        event["originating_platform"] = base_source_system_value

    if current_progress_pct >= DRIFT_ADD_COMMON_CPS_START_PCT:
        event["business_unit_affected"] = random.choice(BUSINESS_UNITS_AFFECTED)
        event["event_review_status"] = random.choice(EVENT_REVIEW_STATUSES)
        if (
            event_type == "operational_incident"
            and event.get("severity") in ["High", "Critical"]
        ):
            event["financial_impact_aud"] = round(
                random.uniform(1000.00, 1000000.00), 2
            )

    if current_progress_pct >= DRIFT_MODIFY_INCIDENT_REMOVE_COMMON_START_PCT:
        if event_type == "bcp_event":
            event["bcp_coordinator_name"] = fake.name()

    if current_progress_pct >= DRIFT_RENAME_COMMON_ADD_CHANGE_START_PCT:
        if event_type == "change_management_event":
            event["post_implementation_review_notes"] = fake.paragraph(
                nb_sentences=random.randint(1, 3)
            )

    # 3. --- Apply ALL Value Format Drifts (to the final, complete event) ---

    # Main timestamp drift
    event["timestamp"] = drift_date_format(
        current_datetime_utc, current_progress_pct
    )

    # Numeric drift
    if "financial_impact_aud" in event:
        event["financial_impact_aud"] = drift_number_format(
            event["financial_impact_aud"], current_progress_pct
        )

    # Other date fields drift
    for date_field in [
        "assessment_date",
        "planned_implementation_date",
    ]:
        if date_field in event and event[date_field]:
            try:
                # Use dateutil parser for flexibility with existing formats
                dt = dateutil_parser.parse(str(event[date_field]))
                event[date_field] = drift_date_format(dt, current_progress_pct)
            except (ValueError, TypeError):
                pass # Ignore if parsing fails

    # Targeted categorical value drift
    if "impacted_operation" in event:
        event["impacted_operation"] = drift_critical_operations(
            event["impacted_operation"], current_progress_pct
        )
    if "scenario_type" in event:
        event["scenario_type"] = drift_bcp_scenarios(
            event["scenario_type"], current_progress_pct
        )
    if "status" in event: # Note: This will affect multiple event types
        event["status"] = drift_change_statuses(
            event["status"], current_progress_pct
        )
    if "business_unit_affected" in event:
        event["business_unit_affected"] = drift_business_units(
            event["business_unit_affected"], current_progress_pct
        )
    if "event_review_status" in event:
        event["event_review_status"] = drift_event_review_statuses(
            event["event_review_status"], current_progress_pct
        )

    # **[FIX]** Generic string pattern drift (was previously unused)
    for key, value in event.items():
        if isinstance(value, str) and key in [
            "description",
            "control_name",
            "vendor_name",
            "event_description",
            "lessons_learned_summary",
        ]:
            event[key] = drift_string_pattern(value, current_progress_pct)

    return event

def validate_timestamp_distribution(events_sample, num_events):
    """Validate that timestamps are properly distributed"""
    if not events_sample:
        return
    
    timestamps = []
    for event in events_sample[:100]:  # Check first 100 events
        try:
            ts = datetime.datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
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

# --- Splunk HEC Sending Function (Batching, same as before) ---
def send_events_to_splunk_hec(
    events_batch, url, token, source, sourcetype, index, verify_ssl, timeout
):
    if not events_batch: return True
    headers = {"Authorization": f"Splunk {token}"}
    payload_items = []
    for event_data in events_batch:
        try:
            # Try ISO first, then fallback to flexible parsing
            try:
                dt_object = datetime.fromisoformat(event_data["timestamp"].replace("Z", "+00:00"))
            except ValueError:
                dt_object = dateutil_parser.parse(event_data["timestamp"])
            epoch_time = dt_object.timestamp()
        except (ValueError, KeyError) as e:
            print(f"Error converting timestamp for HEC: {e}. Using current time. Event: {event_data.get('event_id', 'N/A')}", file=sys.stderr)
            epoch_time = time.time()
        hec_event = {
            "time": epoch_time, "source": source, "sourcetype": sourcetype,
            "index": index, "host": event_data.get("entity_id", source), # Using entity_id as host
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
        description="Generate APRA CPS 230 logs with schema drift, send to Splunk HEC or save to CSV."
    )
    parser.add_argument("--num-events", type=int, default=DEFAULT_NUM_EVENTS, help=f"Number of events to generate (default: {DEFAULT_NUM_EVENTS}).")
    parser.add_argument("--output-csv", type=str, default=None, help=f"Filename to save logs as CSV. If not provided and --send-to-splunk is absent, defaults to '{DEFAULT_CSV_FILENAME}'.")
    parser.add_argument("--send-to-splunk", action="store_true", help="Enable sending data to Splunk HEC.")
    
    hec_group = parser.add_argument_group('Splunk HEC Options (for RAW data)')
    hec_group.add_argument("--splunk-url", type=str, default=SPLUNK_HEC_URL_DEFAULT)
    hec_group.add_argument("--splunk-token", type=str, default=SPLUNK_HEC_TOKEN_DEFAULT)
    hec_group.add_argument("--splunk-index", type=str, default=SPLUNK_RAW_INDEX_DEFAULT, help="Target Splunk Index for RAW drift data.")
    hec_group.add_argument("--splunk-source", type=str, default=SPLUNK_HEC_SOURCE_DEFAULT)
    hec_group.add_argument("--splunk-sourcetype", type=str, default=SPLUNK_CPS230_RAW_SOURCETYPE_DEFAULT, help="Target Splunk Sourcetype for CPS230 RAW drift data.")
    hec_group.add_argument("--splunk-batch-size", type=int, default=SPLUNK_HEC_BATCH_SIZE_DEFAULT)
    hec_group.add_argument("--splunk-disable-ssl-verify", action="store_false", dest="splunk_verify_ssl")
    parser.set_defaults(splunk_verify_ssl=SPLUNK_HEC_VERIFY_SSL_DEFAULT)

    gen_group = parser.add_argument_group('Data Generation Options')
    gen_group.add_argument("--events-per-hour", type=int, default=1000, help="Number of events to generate per hour of backfill (default: 1000).")

    args = parser.parse_args()

    csv_output_file = args.output_csv
    if not args.output_csv and not args.send_to_splunk:
        csv_output_file = DEFAULT_CSV_FILENAME
        print(f"No explicit output specified. Defaulting to save to CSV: {csv_output_file}", file=sys.stderr)

    if args.send_to_splunk:
        if "YOUR_SPLUNK_HEC_URL" in args.splunk_url or "YOUR_SPLUNK_HEC_TOKEN" in args.splunk_token:
            print("ERROR: Splunk HEC URL or Token for raw data is not configured.", file=sys.stderr)
            sys.exit(1)
        print(f"Splunk HEC sending for CPS230 raw data enabled: URL={args.splunk_url}, Index={args.splunk_index}, Sourcetype={args.splunk_sourcetype}", file=sys.stderr)
        if not args.splunk_verify_ssl:
            print("SSL verification for HEC is DISABLED.", file=sys.stderr)
            try:
                import urllib3
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
                warnings.filterwarnings('ignore', category=urllib3.exceptions.NotOpenSSLWarning)
            except Exception: pass

    print(f"Generating {args.num_events} CPS230-compliant log records with schema drift...", file=sys.stderr)
    log_data_list, splunk_batch = [], []
    total_sent_to_splunk, total_failed_splunk = 0, 0

    schema_drift_points_events = {
        "Add Common Fields (business_unit_affected, event_review_status) & Modify OpIncidents": int(DRIFT_ADD_COMMON_CPS_START_PCT * args.num_events),
        "Remove reporter_user_id & Add to BCP Events": int(DRIFT_MODIFY_INCIDENT_REMOVE_COMMON_START_PCT * args.num_events),
        "Rename source_system & Add to Change Management": int(DRIFT_RENAME_COMMON_ADD_CHANGE_START_PCT * args.num_events),
    }
    print(f"CPS230 Schema drift points (approx event number): {schema_drift_points_events}", file=sys.stderr)

    start_time_utc = datetime.now(timezone.utc)
    EVENTS_PER_HOUR = args.events_per_hour
    total_backfill_hours = args.num_events / EVENTS_PER_HOUR
    blocks = args.num_events // 100
    if blocks == 0:
        blocks = 1
    time_offset_per_100_events = timedelta(hours=total_backfill_hours / blocks)
    print(f"Backfill window: {total_backfill_hours:.2f} hours ({args.num_events} events at {EVENTS_PER_HOUR} per hour)", file=sys.stderr)

    for i in range(args.num_events):
        event_number = i + 1

        # Calculate which time block this event belongs to
        block_number = i // 100
        base_time_shift = block_number * time_offset_per_100_events
        base_time_for_block = start_time_utc - base_time_shift

        # Add random jitter within the time block (use 50% of block duration to avoid overlap)
        max_jitter_seconds = min(3600, int(time_offset_per_100_events.total_seconds() * 0.5))
        seconds_jitter = random.uniform(0, max_jitter_seconds)
        jitter_delta = timedelta(seconds=seconds_jitter)

        # Apply jitter by subtracting from the block start time
        current_time_for_event = base_time_for_block - jitter_delta

        # Debug output for first few events to verify distribution
        if i < 5 or (i + 1) % 100 == 1:  # First event of each block
            print(f"Event {i+1}: Block {block_number}, Base time: {base_time_for_block.strftime('%Y-%m-%d %H:%M:%S')}, "
                f"Jitter: {seconds_jitter:.1f}s, Final: {current_time_for_event.strftime('%Y-%m-%d %H:%M:%S')}", 
                file=sys.stderr) 
            
        if event_number % (args.num_events // 20 or 1) == 0:
            print(f"  Generated {event_number}/{args.num_events} logs (Progress: { (event_number/args.num_events)*100:.1f} %)...", file=sys.stderr)
        
        log_entry = generate_cps230_event_with_drift(event_number, args.num_events, current_time_for_event)
        log_data_list.append(log_entry)

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

    # Move timestamp validation OUTSIDE the loop
    if log_data_list:
        validate_timestamp_distribution(log_data_list, args.num_events)

    if args.send_to_splunk and splunk_batch:
        if send_events_to_splunk_hec(
            splunk_batch, args.splunk_url, args.splunk_token, args.splunk_source,
            args.splunk_sourcetype, args.splunk_index, args.splunk_verify_ssl, SPLUNK_HEC_TIMEOUT_DEFAULT
        ): total_sent_to_splunk += len(splunk_batch)
        else: total_failed_splunk += len(splunk_batch)

    if args.send_to_splunk:
        print("\nSplunk HEC Sending Summary (CPS230 Raw Data):", file=sys.stderr)
        print(f"  Successfully sent: {total_sent_to_splunk} logs", file=sys.stderr)
        print(f"  Failed to send:    {total_failed_splunk} logs", file=sys.stderr)

    if csv_output_file:
        print(f"\nSaving {len(log_data_list)} CPS230 raw log records to {csv_output_file}...", file=sys.stderr)
        df = pd.DataFrame(log_data_list)
        df.to_csv(csv_output_file, index=False)
        print(f"Successfully saved CPS230 raw logs to {csv_output_file}", file=sys.stderr)

    print(f"\nScript finished. Generated {args.num_events} total CPS230 raw logs with schema drift.", file=sys.stderr)
    print("\nDisclaimer: This script generates synthetic data for illustrative purposes related to APRA CPS 230 themes.", file=sys.stderr)

if __name__ == "__main__":
    main()