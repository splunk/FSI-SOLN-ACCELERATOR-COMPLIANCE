# rmit_data_schema_drift_my.py
import argparse
import datetime
import json
import random
import sys
import time
import uuid
import warnings # For suppressing urllib3 warnings

import pandas as pd
import pytz
import requests
from faker import Faker

# Initialize Faker
fake = Faker()
Faker.seed(42)
random.seed(42)

# --- Configuration ---
DEFAULT_NUM_EVENTS = 1000 # Matched to other drift scripts
DEFAULT_CSV_FILENAME = "rmit_schema_drift_raw_logs_my.csv"

# --- Splunk HEC Configuration for RAW DRIFT DATA ---
SPLUNK_HEC_URL_DEFAULT = "YOUR_SPLUNK_HEC_URL/services/collector" # Batch endpoint
SPLUNK_HEC_TOKEN_DEFAULT = "YOUR_HEC_TOKEN_FOR_RAW_DATA"
SPLUNK_RAW_INDEX_DEFAULT = "drift_raw_data" # Common index
SPLUNK_RMIT_RAW_SOURCETYPE_DEFAULT = "rmit_drift_raw" # Specific sourcetype
SPLUNK_HEC_SOURCE_DEFAULT = "rmit_drift_generator_my"
SPLUNK_HEC_VERIFY_SSL_DEFAULT = False
SPLUNK_HEC_BATCH_SIZE_DEFAULT = 100 # Using batching
SPLUNK_HEC_TIMEOUT_DEFAULT = 30


# --- RMiT Specific Data Elements (mostly same as original) ---
MALAYSIAN_FINANCIAL_INSTITUTIONS = [
    "Maybank_MY", "CIMB_Group_MY", "Public_Bank_MY", "RHB_Bank_MY", "Hong_Leong_Bank_MY",
    "AmBank_Group_MY", "UOB_Malaysia_MY", "OCBC_Bank_Malaysia_MY", "Affin_Bank_MY", "Alliance_Bank_MY"
]
CRITICAL_SYSTEMS_MY = [
    "Core_Banking_System", "RENTAS_Gateway", "IBG_Processing", "SWIFT_Interface",
    "Online_Banking_Platform", "Mobile_Banking_App", "ATM_Network_Controller",
    "Trade_Finance_System", "Treasury_Management_System", "Fraud_Detection_Engine",
    "Regulatory_Reporting_System", "Customer_Data_Hub"
]
CYBER_THREAT_TYPES_MY = [
    "Phishing_Attack", "Ransomware_Deployment", "DDoS_Attack", "Insider_Threat_Activity",
    "APT_Compromise", "Malware_Infection", "Web_Application_Attack", "Zero_Day_Exploit"
]
RMIT_INCIDENT_SEVERITY = ["Informational", "Low", "Medium", "High", "Critical"]
RMIT_INCIDENT_STATUS = [
    "Detected", "Reported_To_BNM", "Containment_In_Progress", "Eradication_In_Progress",
    "Recovery_In_Progress", "Resolved", "Post_Incident_Review", "Closed"
]
IT_CONTROL_CATEGORIES = ["Access_Control", "Change_Management_Control", "Data_Security_Control", "System_Monitoring_Control", "Patch_Management_Control", "Backup_And_Recovery_Control"]
BCM_DR_TEST_SCENARIOS_MY = ["Primary_Data_Center_Failure", "Cyber_Attack_Scenario", "Major_System_Outage", "Pandemic_Response_Test", "Key_Supplier_Disruption_Test"]
THIRD_PARTY_SERVICE_TYPES_MY = ["Cloud_Infrastructure_Provider", "SaaS_Application_Vendor", "Managed_Security_Services", "Payment_Processor_Outsourced", "Core_Banking_System_Support"]
TECHNOLOGY_DOMAINS = ["Network_Infrastructure", "Server_And_Storage", "Application_Layer", "Database_Management", "Cybersecurity_Tools", "End_User_Computing", "Cloud_Services"]
EVENT_PRIORITY_LEVELS = ["P1_Critical", "P2_High", "P3_Medium", "P4_Low"]
ASSET_CLASSIFICATIONS = ["Critical_Business_Asset", "Sensitive_Customer_Data_Store", "Internal_Operational_System", "Public_Facing_Interface"]
ATTRIBUTION_CONFIDENCE = ["High_Confidence", "Medium_Confidence", "Low_Confidence", "Unconfirmed_Attribution"]


# --- Event Type Generation Weights (same as original) ---
EVENT_TYPE_WEIGHTS_RMIT = {
    "cybersecurity_alert": 30, "it_operations_event": 25, "data_governance_event": 10,
    "bcm_dr_activity": 10, "third_party_risk_update": 10, "change_request_log": 10,
    "compliance_task_update": 5,
}

# --- Schema Drift Percentage Thresholds ---
DRIFT_ADD_COMMON_START_PCT = 0.20
DRIFT_MODIFY_CYBER_REMOVE_COMMON_START_PCT = 0.45
DRIFT_RENAME_COMMON_ADD_OPS_START_PCT = 0.70


# --- Helper Functions for Event Details (will be called by main generator) ---
# These functions now might receive current_progress_pct if drift needs to be highly specific within them,
# but for this plan, we'll try to manage schema changes in the main generate_rmit_event_with_drift.
def generate_cybersecurity_event_details_base(): # Renamed to _base
    threat = random.choice(CYBER_THREAT_TYPES_MY)
    severity = random.choice(RMIT_INCIDENT_SEVERITY) if threat != "Phishing_Attack" else random.choice(["Informational", "Low", "Medium"])
    status = random.choice(RMIT_INCIDENT_STATUS)
    bnm_notified = False
    if severity in ["High", "Critical"] and status not in ["Detected"]:
        bnm_notified = random.random() > 0.3
    return {
        "cyber_event_id": f"CYBER-{str(uuid.uuid4())[:8].upper()}", "threat_type": threat, "severity": severity,
        "status": status, "impacted_systems": random.sample(CRITICAL_SYSTEMS_MY, k=random.randint(1,3)),
        "detection_source": random.choice(["SIEM_Alert", "IDS_IPS", "EDR_Alert", "User_Reported", "Threat_Intelligence_Feed"]),
        "response_actions_taken": fake.sentence(nb_words=8) if status != "Detected" else None,
        "bnm_notification_sent": bnm_notified,
        "bnm_report_ref_id": f"BNMREP-{str(uuid.uuid4())[:6].upper()}" if bnm_notified else None,
    }

def generate_it_operations_event_details_base(): # Renamed to _base
    op_event_type = random.choice(["System_Performance_Degradation", "System_Outage", "Capacity_Threshold_Breached", "Successful_Maintenance", "Failed_Deployment"])
    severity = random.choice(RMIT_INCIDENT_SEVERITY)
    if "Successful" in op_event_type: severity = "Informational"
    return {
        "ops_event_id": f"OPS-{str(uuid.uuid4())[:8].upper()}", "operation_event_type": op_event_type,
        "affected_service": random.choice(CRITICAL_SYSTEMS_MY), "severity": severity,
        "duration_minutes": random.randint(5, 720) if "Outage" in op_event_type or "Degradation" in op_event_type else None,
        "resolution_details": fake.sentence(nb_words=10) if "Successful" not in op_event_type and random.random() > 0.2 else None,
        "technology_domain": random.choice(TECHNOLOGY_DOMAINS),
    }
# ... (Other helper functions: generate_data_governance_event_details, etc. remain structurally similar) ...
# For brevity, I'll assume they return their original set of fields.
# We will modify the final event dictionary in the main generation function.
def generate_data_governance_event_details():
    return { "data_event_id": f"DATA-{str(uuid.uuid4())[:8].upper()}", "data_event_type": random.choice(["Data_Access_Violation_Attempt", "DLP_Policy_Triggered", "Data_Classification_Review", "Data_Backup_Failure", "Data_Restore_Test"]), "data_sensitivity_level": random.choice(["Confidential", "Restricted", "Internal", "Public"]), "source_data_asset": random.choice(["Customer_Database", "Transaction_Logs", "Employee_Records", "Financial_Reports"]), "outcome_status": random.choice(["Investigating", "Action_Taken", "Resolved", "Completed", "Failed"]), "details": fake.sentence(nb_words=12), }
def generate_bcm_dr_activity_details():
    activity = random.choice(["BCM_Plan_Review", "DR_Test_Execution", "BCM_Training_Session", "Actual_DR_Invocation"])
    return { "bcm_activity_id": f"BCMDR-{str(uuid.uuid4())[:7].upper()}", "activity_type": activity, "scenario_tested": random.choice(BCM_DR_TEST_SCENARIOS_MY) if "Test" in activity or "Invocation" in activity else None, "outcome": random.choice(["Successful", "Issues_Identified", "Completed", "Failed"]) if "Test" in activity or "Invocation" in activity else "Scheduled", "rto_achieved_minutes": random.randint(30, 480) if "Test" in activity or "Invocation" in activity else None, "rpo_achieved_minutes": random.randint(0, 60) if "Test" in activity or "Invocation" in activity else None, }
def generate_third_party_risk_update_details():
    vendor = fake.company()
    return { "third_party_id": f"TPRM-{str(uuid.uuid4())[:7].upper()}", "vendor_name": vendor, "service_type": random.choice(THIRD_PARTY_SERVICE_TYPES_MY), "risk_assessment_update_reason": random.choice(["Annual_Review", "New_Service_Onboarding", "Vendor_Incident_Reported", "Contract_Renewal"]), "overall_risk_rating": random.choice(RMIT_INCIDENT_SEVERITY[1:]), "key_risks_identified": [fake.bs() for _ in range(random.randint(1,3))], "due_diligence_status": random.choice(["Completed", "In_Progress", "Pending_Information"]), }
def generate_change_request_log_details():
    return { "change_request_id": f"CRQ{random.randint(100000, 999999)}", "change_description": f"Update to {random.choice(CRITICAL_SYSTEMS_MY)} for {fake.bs()}", "change_status": random.choice(["Submitted", "Approved", "Implementation_Scheduled", "In_Progress", "Completed_Successfully", "Failed", "Rolled_Back"]), "risk_impact_assessment": random.choice(RMIT_INCIDENT_SEVERITY), "planned_start_datetime_utc": (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=random.randint(1,30))).isoformat().replace("+00:00", "Z"), "actual_end_datetime_utc": (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=random.randint(1,30), hours=random.randint(1,4))).isoformat().replace("+00:00", "Z") if random.random() > 0.3 else None, }
def generate_governance_compliance_event_details():
    return { "gov_task_id": f"GOV-{str(uuid.uuid4())[:7].upper()}", "task_type": random.choice(["Policy_Review_Cycle", "RMiT_Self_Assessment", "Internal_Audit_Finding_Remediation", "BNM_Regulatory_Submission"]), "subject_matter": f"RMiT Section {random.randint(5,15)}.{random.randint(1,10)}", "status": random.choice(["Pending", "In_Progress", "Completed", "Overdue", "Submitted_To_BNM"]), "assigned_department": random.choice(["Risk_Management", "IT_Compliance", "Internal_Audit", "Technology_Operations"]), "due_date": (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=random.randint(7,90))).date().isoformat(), }

# --- Value Schema Drift Threshold (same as field drift) ---
DRIFT_VALUE_SCHEMA_START_PCT = DRIFT_RENAME_COMMON_ADD_OPS_START_PCT  # 0.70

def drift_underscore_fields(val, progress_pct, drift_start_pct=DRIFT_VALUE_SCHEMA_START_PCT):
    """Change underscores to dashes, dots, or spaces."""
    if progress_pct < drift_start_pct or not isinstance(val, str):
        return val
    if "_" in val:
        drift_type = random.choice(["-", ".", " "])
        return val.replace("_", drift_type)
    return val

# --- Main Event Generation Function with Targeted Value Drift ---
def generate_rmit_event_with_drift(event_number, total_events, current_datetime_utc):
    """
    Generates a single RMiT-compliant log entry with a clean, refactored
    approach to schema and value drift.
    """
    current_progress_pct = event_number / total_events

    # 1. --- Generate all potential data points as clean, local variables ---
    event_type_choices = list(EVENT_TYPE_WEIGHTS_RMIT.keys())
    event_type_probabilities = [
        w / sum(EVENT_TYPE_WEIGHTS_RMIT.values())
        for w in EVENT_TYPE_WEIGHTS_RMIT.values()
    ]
    event_type = random.choices(
        event_type_choices, weights=event_type_probabilities, k=1
    )[0]

    # Get event-specific details from helper functions
    details = {}
    if event_type == "cybersecurity_alert":
        details = generate_cybersecurity_event_details_base()
    elif event_type == "it_operations_event":
        details = generate_it_operations_event_details_base()
    elif event_type == "data_governance_event":
        details = generate_data_governance_event_details()
    elif event_type == "bcm_dr_activity":
        details = generate_bcm_dr_activity_details()
    elif event_type == "third_party_risk_update":
        details = generate_third_party_risk_update_details()
    elif event_type == "change_request_log":
        details = generate_change_request_log_details()
    elif event_type == "compliance_task_update":
        details = generate_governance_compliance_event_details()

    # Store other potential values in local variables
    financial_institution_id = random.choice(MALAYSIAN_FINANCIAL_INSTITUTIONS)
    target_asset_classification = random.choice(ASSET_CLASSIFICATIONS)
    attacker_attribution_confidence = random.choice(ATTRIBUTION_CONFIDENCE)

    # 2. --- Apply value drift to the local variables and details dict ---
    if current_progress_pct >= DRIFT_VALUE_SCHEMA_START_PCT:
        # Drift top-level and newly added fields
        financial_institution_id = drift_underscore_fields(
            financial_institution_id, current_progress_pct
        )
        target_asset_classification = drift_underscore_fields(
            target_asset_classification, current_progress_pct
        )
        attacker_attribution_confidence = drift_underscore_fields(
            attacker_attribution_confidence, current_progress_pct
        )

        # Drift fields within the 'details' dictionary
        if "impacted_systems" in details and isinstance(
            details["impacted_systems"], list
        ):
            details["impacted_systems"] = [
                drift_underscore_fields(x, current_progress_pct)
                for x in details["impacted_systems"]
            ]
        if "affected_service" in details:
            details["affected_service"] = drift_underscore_fields(
                details["affected_service"], current_progress_pct
            )
        if "threat_type" in details:
            details["threat_type"] = drift_underscore_fields(
                details["threat_type"], current_progress_pct
            )
        if "status" in details:
            details["status"] = drift_underscore_fields(
                details["status"], current_progress_pct
            )
        if "scenario_tested" in details:
            details["scenario_tested"] = drift_underscore_fields(
                details["scenario_tested"], current_progress_pct
            )
        if "service_type" in details:
            details["service_type"] = drift_underscore_fields(
                details["service_type"], current_progress_pct
            )
        if "technology_domain" in details:
            details["technology_domain"] = drift_underscore_fields(
                details["technology_domain"], current_progress_pct
            )

    # 3. --- Construct the final event dictionary using the (now drifted) variables ---
    event = {
        "log_event_id": str(uuid.uuid4()),
        "event_timestamp_utc": current_datetime_utc.isoformat().replace(
            "+00:00", "Z"
        ),
        "financial_institution_id": financial_institution_id, # Use drifted value
        "rmit_event_category": event_type,
    }
    event.update(details)  # Add the potentially drifted details

    # --- Apply Structural Schema Drift (Adding/Removing/Renaming fields) ---
    if current_progress_pct < DRIFT_MODIFY_CYBER_REMOVE_COMMON_START_PCT:
        event["reporting_user_or_process"] = (
            f"{fake.job().replace(' ', '_')}_{fake.first_name()}"
            if random.random() > 0.2
            else "System_Daemon_RMiT"
        )

    base_event_source_component_value = random.choice(
        [
            "GRC_Tool_v3",
            "SIEM_Correlator",
            "ServiceNow_ITSM",
            "Manual_Input_Portal",
            "Automated_Monitoring_Agent",
        ]
    )
    if current_progress_pct < DRIFT_RENAME_COMMON_ADD_OPS_START_PCT:
        event["event_source_component"] = base_event_source_component_value
    else:
        event["originating_tech_component"] = base_event_source_component_value

    if current_progress_pct >= DRIFT_ADD_COMMON_START_PCT:
        event["risk_assessment_ref_id"] = f"RA-{str(uuid.uuid4())[:10].upper()}"
        event["event_priority_level"] = random.choice(EVENT_PRIORITY_LEVELS)

    if current_progress_pct >= DRIFT_MODIFY_CYBER_REMOVE_COMMON_START_PCT:
        if event_type == "cybersecurity_alert":
            # Use the drifted local variables here
            event["target_asset_classification"] = target_asset_classification
            event[
                "attacker_attribution_confidence"
            ] = attacker_attribution_confidence

    if current_progress_pct >= DRIFT_RENAME_COMMON_ADD_OPS_START_PCT:
        if event_type == "it_operations_event":
            event["business_service_impact_notes"] = fake.paragraph(
                nb_sentences=random.randint(1, 2), variable_nb_sentences=True
            )

    return event

def validate_timestamp_distribution(events_sample, num_events):
    """Validate that timestamps are properly distributed"""
    if not events_sample:
        return
    
    timestamps = []
    for event in events_sample[:100]:  # Check first 100 events
        try:
            ts = datetime.datetime.fromisoformat(event["event_timestamp_utc"].replace("Z", "+00:00"))
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
            # Use the correct timestamp field from the event
            dt_object = datetime.datetime.fromisoformat(event_data["event_timestamp_utc"].replace("Z", "+00:00"))
            epoch_time = dt_object.timestamp()
        except (ValueError, KeyError) as e:
            print(f"Error converting timestamp for HEC: {e}. Using current time. Event: {event_data.get('log_event_id', 'N/A')}", file=sys.stderr)
            epoch_time = time.time()
        hec_event = {
            "time": epoch_time, "source": source, "sourcetype": sourcetype,
            "index": index, "host": event_data.get("financial_institution_id", source), # Use FI ID as host
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
        description="Generate BNM RMiT logs with schema drift, send to Splunk HEC or save to CSV."
    )
    parser.add_argument("--num-events", type=int, default=DEFAULT_NUM_EVENTS, help=f"Number of events to generate (default: {DEFAULT_NUM_EVENTS}).")
    parser.add_argument("--events-per-hour", type=int, default=1000, help="Number of events to generate per hour of backfill (default: 1000).")
    # Remove --hours-backfill-per-100 argument

    parser.add_argument("--output-csv", type=str, default=None, help=f"Filename to save logs as CSV. If not provided and --send-to-splunk is absent, defaults to '{DEFAULT_CSV_FILENAME}'.")
    parser.add_argument("--send-to-splunk", action="store_true", help="Enable sending data to Splunk HEC.")
    
    hec_group = parser.add_argument_group('Splunk HEC Options (for RAW data)')
    hec_group.add_argument("--splunk-url", type=str, default=SPLUNK_HEC_URL_DEFAULT)
    hec_group.add_argument("--splunk-token", type=str, default=SPLUNK_HEC_TOKEN_DEFAULT)
    hec_group.add_argument("--splunk-index", type=str, default=SPLUNK_RAW_INDEX_DEFAULT, help="Target Splunk Index for RAW drift data.")
    hec_group.add_argument("--splunk-source", type=str, default=SPLUNK_HEC_SOURCE_DEFAULT)
    hec_group.add_argument("--splunk-sourcetype", type=str, default=SPLUNK_RMIT_RAW_SOURCETYPE_DEFAULT, help="Target Splunk Sourcetype for RMiT RAW drift data.")
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
        print(f"Splunk HEC sending for RMiT raw data enabled: URL={args.splunk_url}, Index={args.splunk_index}, Sourcetype={args.splunk_sourcetype}", file=sys.stderr)
        if not args.splunk_verify_ssl:
            print("SSL verification for HEC is DISABLED.", file=sys.stderr)
            try:
                import urllib3
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
                warnings.filterwarnings('ignore', category=urllib3.exceptions.NotOpenSSLWarning)
            except Exception: pass

    print(f"Generating {args.num_events} RMiT-compliant log records with schema drift...", file=sys.stderr)
    log_data_list, splunk_batch = [], []
    total_sent_to_splunk, total_failed_splunk = 0, 0

    schema_drift_points_events = {
        "Add Common Fields (risk_assessment_ref_id, event_priority_level)": int(DRIFT_ADD_COMMON_START_PCT * args.num_events),
        "Modify Cyber Alerts & Remove reporting_user_or_process": int(DRIFT_MODIFY_CYBER_REMOVE_COMMON_START_PCT * args.num_events),
        "Rename event_source_component & Add IT Ops Field": int(DRIFT_RENAME_COMMON_ADD_OPS_START_PCT * args.num_events),
    }
    print(f"RMiT Schema drift points (approx event number): {schema_drift_points_events}", file=sys.stderr)

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
        
        # Calculate which time block this event belongs to
        block_number = i // 100
        base_time_shift = block_number * time_offset_per_100_events
        base_time_for_block = start_time_utc - base_time_shift
        
        # Ensure each event gets a unique SECOND-level timestamp
        # Use the event index to create different second offsets within the time block
        max_seconds_in_block = int(time_offset_per_100_events.total_seconds() * 0.8)  # Use 80% of block
        
        if max_seconds_in_block > 100:  # If we have enough time space
            # Spread events across available seconds
            event_position_in_block = i % 100  # Position within current 100-event block
            seconds_step = max_seconds_in_block // 100  # How many seconds between events
            base_seconds_offset = event_position_in_block * seconds_step
            
            # Add some randomness but keep it in seconds
            random_additional_seconds = random.randint(0, min(60, seconds_step))
            total_seconds_offset = base_seconds_offset + random_additional_seconds
        else:
            # Fallback: simple second-based spacing
            total_seconds_offset = (i % 3600) + random.randint(0, 300)  # Max 1 hour + 5 min
        
        current_time_for_event = base_time_for_block - datetime.timedelta(seconds=total_seconds_offset)
        
        # Debug output for first few events of each block
        if i < 5 or i % 100 == 0:
            print(f"Event {i+1}: Block {block_number}, Time: {current_time_for_event.strftime('%Y-%m-%d %H:%M:%S')}, "
                f"Offset: {total_seconds_offset}s", file=sys.stderr)
        
        if event_number % (args.num_events // 20 or 1) == 0:
            print(f"  Generated {event_number}/{args.num_events} logs (Progress: { (event_number/args.num_events)*100:.1f} %)...", file=sys.stderr)
        
        log_entry = generate_rmit_event_with_drift(event_number, args.num_events, current_time_for_event)
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

    # Validate timestamp distribution after the loop
    if log_data_list:
        validate_timestamp_distribution(log_data_list, args.num_events)

    if args.send_to_splunk and splunk_batch:
        if send_events_to_splunk_hec(
            splunk_batch, args.splunk_url, args.splunk_token, args.splunk_source,
            args.splunk_sourcetype, args.splunk_index, args.splunk_verify_ssl, SPLUNK_HEC_TIMEOUT_DEFAULT
        ): total_sent_to_splunk += len(splunk_batch)
        else: total_failed_splunk += len(splunk_batch)

    if args.send_to_splunk:
        print("\nSplunk HEC Sending Summary (RMiT Raw Data):", file=sys.stderr)
        print(f"  Successfully sent: {total_sent_to_splunk} logs", file=sys.stderr)
        print(f"  Failed to send:    {total_failed_splunk} logs", file=sys.stderr)

    if csv_output_file:
        print(f"\nSaving {len(log_data_list)} RMiT raw log records to {csv_output_file}...", file=sys.stderr)
        df = pd.DataFrame(log_data_list)
        df.to_csv(csv_output_file, index=False)
        print(f"Successfully saved RMiT raw logs to {csv_output_file}", file=sys.stderr)

    print(f"\nScript finished. Generated {args.num_events} total RMiT raw logs with schema drift.", file=sys.stderr)
    print("\nDisclaimer: This script generates synthetic data for illustrative purposes related to BNM RMiT themes.", file=sys.stderr)

if __name__ == "__main__":
    main()