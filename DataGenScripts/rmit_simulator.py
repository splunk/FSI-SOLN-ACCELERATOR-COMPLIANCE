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

# Initialize Faker (can use 'ms_MY' for more Malaysian-specific names if desired,
# but generic Faker is often sufficient for technical logs)
# fake = Faker('ms_MY')
fake = Faker()

# --- Configuration ---
DEFAULT_NUM_EVENTS = 500
DEFAULT_CSV_FILENAME = "rmit_malaysia_synthetic_events.csv"
DEFAULT_JSON_FILENAME = "rmit_malaysia_synthetic_events.json"
# HOURS_BACKFILL_PER_100_EVENTS = 168/9 # Each 100 events, go back 12 hours
HOURS_BACKFILL_PER_100_EVENTS = 1.0  # Match PCI simulator default: 1 hour per 100 events

# --- Splunk HEC Configuration (Defaults, can be overridden) ---
SPLUNK_HEC_URL_DEFAULT = "YOUR_SPLUNK_HEC_URL"
SPLUNK_HEC_TOKEN_DEFAULT = "YOUR_SPLUNK_HEC_TOKEN"
SPLUNK_HEC_INDEX_DEFAULT = "sample_rmit"
SPLUNK_HEC_SOURCETYPE_DEFAULT = "rmit:synthetic:event"
SPLUNK_HEC_SOURCE_DEFAULT = "rmit_simulator"
SPLUNK_HEC_VERIFY_SSL_DEFAULT = False
SPLUNK_HEC_BATCH_SIZE_DEFAULT = 100

# --- RMiT Specific Data Elements ---
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
IT_CONTROL_CATEGORIES = [
    "Access_Control", "Change_Management_Control", "Data_Security_Control",
    "System_Monitoring_Control", "Patch_Management_Control", "Backup_And_Recovery_Control"
]
BCM_DR_TEST_SCENARIOS_MY = [
    "Primary_Data_Center_Failure", "Cyber_Attack_Scenario", "Major_System_Outage",
    "Pandemic_Response_Test", "Key_Supplier_Disruption_Test"
]
THIRD_PARTY_SERVICE_TYPES_MY = [
    "Cloud_Infrastructure_Provider", "SaaS_Application_Vendor", "Managed_Security_Services",
    "Payment_Processor_Outsourced", "Core_Banking_System_Support"
]
TECHNOLOGY_DOMAINS = [
    "Network_Infrastructure", "Server_And_Storage", "Application_Layer", "Database_Management",
    "Cybersecurity_Tools", "End_User_Computing", "Cloud_Services"
]

# --- Event Type Generation Weights ---
EVENT_TYPE_WEIGHTS_RMIT = {
    "cybersecurity_alert": 30,
    "it_operations_event": 25,
    "data_governance_event": 10,
    "bcm_dr_activity": 10,
    "third_party_risk_update": 10,
    "change_request_log": 10,
    "compliance_task_update": 5,
}

# --- Helper Functions for Event Details ---
def generate_cybersecurity_event_details():
    threat = random.choice(CYBER_THREAT_TYPES_MY)
    severity = random.choice(RMIT_INCIDENT_SEVERITY) if threat != "Phishing_Attack" else random.choice(["Informational", "Low", "Medium"])
    status = random.choice(RMIT_INCIDENT_STATUS)
    bnm_notified = False
    if severity in ["High", "Critical"] and status not in ["Detected"]:
        bnm_notified = random.random() > 0.3 # Higher chance of BNM notification for severe incidents

    return {
        "cyber_event_id": f"CYBER-{str(uuid.uuid4())[:8].upper()}",
        "threat_type": threat,
        "severity": severity,
        "status": status,
        "impacted_systems": random.sample(CRITICAL_SYSTEMS_MY, k=random.randint(1,3)),
        "detection_source": random.choice(["SIEM_Alert", "IDS_IPS", "EDR_Alert", "User_Reported", "Threat_Intelligence_Feed"]),
        "response_actions_taken": (
            random.choice([
                "Isolated affected systems and initiated forensic analysis.",
                "Reset user credentials and increased monitoring.",
                "Applied emergency patch and notified stakeholders.",
                "Blocked malicious IPs and updated firewall rules."
            ]) if status not in ["Detected"] else None
        ),
        "bnm_notification_sent": bnm_notified,
        "bnm_report_ref_id": f"BNMREP-{str(uuid.uuid4())[:6].upper()}" if bnm_notified else None,
    }

def generate_it_operations_event_details():
    op_event_type = random.choice(["System_Performance_Degradation", "System_Outage", "Capacity_Threshold_Breached", "Successful_Maintenance", "Failed_Deployment"])
    severity = random.choice(RMIT_INCIDENT_SEVERITY)
    if "Successful" in op_event_type: severity = "Informational"

    return {
        "ops_event_id": f"OPS-{str(uuid.uuid4())[:8].upper()}",
        "operation_event_type": op_event_type,
        "affected_service": random.choice(CRITICAL_SYSTEMS_MY),
        "severity": severity,
        "duration_minutes": random.randint(5, 720) if "Outage" in op_event_type or "Degradation" in op_event_type else None,
        "resolution_details": random.choice([
            "System rebooted and services restored successfully.",
            "Capacity increased to handle peak load.",
            "Root cause identified and mitigated.",
            "Backup restored after outage."
        ]) if "Successful" not in op_event_type and random.random() > 0.2 else None,
        "technology_domain": random.choice(TECHNOLOGY_DOMAINS),
    }

def generate_data_governance_event_details():
    return {
        "data_event_id": f"DATA-{str(uuid.uuid4())[:8].upper()}",
        "data_event_type": random.choice(["Data_Access_Violation_Attempt", "DLP_Policy_Triggered", "Data_Classification_Review", "Data_Backup_Failure", "Data_Restore_Test"]),
        "data_sensitivity_level": random.choice(["Confidential", "Restricted", "Internal", "Public"]),
        "source_data_asset": random.choice(["Customer_Database", "Transaction_Logs", "Employee_Records", "Financial_Reports"]),
        "outcome_status": random.choice(["Investigating", "Action_Taken", "Resolved", "Completed", "Failed"]),
        "details": random.choice([
            "Unauthorized access attempt detected in customer database.",
            "Data retention policy violation identified and reported.",
            "Data loss prevention alert triggered by abnormal activity.",
            "Quality anomaly found in transaction records."
        ]),
    }

def generate_bcm_dr_activity_details():
    activity = random.choice(["BCM_Plan_Review", "DR_Test_Execution", "BCM_Training_Session", "Actual_DR_Invocation"])
    return {
        "bcm_activity_id": f"BCMDR-{str(uuid.uuid4())[:7].upper()}",
        "activity_type": activity,
        "scenario_tested": random.choice(BCM_DR_TEST_SCENARIOS_MY) if "Test" in activity or "Invocation" in activity else None,
        "outcome": random.choice(["Successful", "Issues_Identified", "Completed", "Failed"]) if "Test" in activity or "Invocation" in activity else "Scheduled",
        "rto_achieved_minutes": random.randint(30, 480) if "Test" in activity or "Invocation" in activity else None,
        "rpo_achieved_minutes": random.randint(0, 60) if "Test" in activity or "Invocation" in activity else None,
    }

def generate_third_party_risk_update_details():
    vendor = random.choice([
        "Acme Financial Services", "Global Data Solutions", "SecureTech Partners", "Prime Risk Advisors", "NextGen IT Solutions"
    ])
    return {
        "third_party_id": f"TPRM-{str(uuid.uuid4())[:7].upper()}",
        "vendor_name": vendor,
        "service_type": random.choice(THIRD_PARTY_SERVICE_TYPES_MY),
        "risk_assessment_update_reason": random.choice(["Annual_Review", "New_Service_Onboarding", "Vendor_Incident_Reported", "Contract_Renewal"]),
        "overall_risk_rating": random.choice(RMIT_INCIDENT_SEVERITY[1:]), # Low to Critical
        "key_risks_identified": [random.choice([
            "Data privacy concerns", "Service availability risk", "Compliance gap", "Third-party dependency", "Contractual ambiguity"
        ]) for _ in range(random.randint(1,3))],
        "due_diligence_status": random.choice(["Completed", "In_Progress", "Pending_Information"]),
    }

def generate_change_request_log_details():
    return {
        "change_request_id": f"CRQ{random.randint(100000, 999999)}",
    "change_description": f"Update to {random.choice(CRITICAL_SYSTEMS_MY)} for {random.choice(['performance improvement', 'security enhancement', 'regulatory compliance', 'feature upgrade', 'bug fix'])}",
        "change_status": random.choice(["Submitted", "Approved", "Implementation_Scheduled", "In_Progress", "Completed_Successfully", "Failed", "Rolled_Back"]),
        "risk_impact_assessment": random.choice(RMIT_INCIDENT_SEVERITY),
        "planned_start_datetime_utc": (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=random.randint(1,30))).isoformat().replace("+00:00", "Z"),
        "actual_end_datetime_utc": (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=random.randint(1,30), hours=random.randint(1,4))).isoformat().replace("+00:00", "Z") if random.random() > 0.3 else None,
    }

def generate_governance_compliance_event_details():
    return {
        "gov_task_id": f"GOV-{str(uuid.uuid4())[:7].upper()}",
        "task_type": random.choice(["Policy_Review_Cycle", "RMiT_Self_Assessment", "Internal_Audit_Finding_Remediation", "BNM_Regulatory_Submission"]),
        "subject_matter": f"RMiT Section {random.randint(5,15)}.{random.randint(1,10)}",
        "status": random.choice(["Pending", "In_Progress", "Completed", "Overdue", "Submitted_To_BNM"]),
        "assigned_department": random.choice(["Risk_Management", "IT_Compliance", "Internal_Audit", "Technology_Operations"]),
        "due_date": (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=random.randint(7,90))).date().isoformat(),
    }

# --- Main Event Generation Function ---
def generate_rmit_event(event_count, current_datetime_utc):
    event_type_choices = list(EVENT_TYPE_WEIGHTS_RMIT.keys())
    event_type_probabilities = [w / sum(EVENT_TYPE_WEIGHTS_RMIT.values()) for w in EVENT_TYPE_WEIGHTS_RMIT.values()]
    event_type = random.choices(event_type_choices, weights=event_type_probabilities, k=1)[0]

    # Generate system_id and user_id for all events
    system_id = f"SYSTEM-{random.randint(1000,9999)}"
    user_id = f"user_{fake.user_name()}" if random.random() > 0.2 else "System_Daemon"
    change_request_id = f"CRQ{random.randint(100000, 999999)}" if event_type == "change_request_log" else None
    status_code = random.choice(["Detected", "In_Progress", "Resolved", "Closed", "Failed", "Completed"])
    source_ip = fake.ipv4_public()
    destination_ip = fake.ipv4_public()
    system_criticality = random.choice(["Critical", "High", "Medium", "Low"])
    rmit_control_violation = random.choice([True, False]) if event_type in ["cybersecurity_alert", "it_operations_event"] else False

    # Compose a generic event description
    event_description = f"{event_type.replace('_', ' ').title()} event generated for system {system_id} by {user_id}."

    base_event = {
        "log_event_id": str(uuid.uuid4()),
        "event_timestamp_utc": current_datetime_utc.isoformat().replace("+00:00", "Z"),
        "event_timestamp": current_datetime_utc.isoformat().replace("+00:00", "Z"),
        "financial_institution_id": random.choice(MALAYSIAN_FINANCIAL_INSTITUTIONS),
        "system_id": system_id,
        "event_type": event_type,
        "event_source_component": random.choice(["GRC_Tool", "SIEM_Platform", "Service_Management_System", "Manual_Log", "Automated_Monitoring"]),
        "user_id": user_id,
        "change_request_id": change_request_id,
        "status_code": status_code,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "event_description": event_description,
        "system_criticality": system_criticality,
        "rmit_control_violation": rmit_control_violation,
        "reporting_user_or_process": f"{fake.job().replace(' ', '_')}_{fake.first_name()}" if random.random() > 0.2 else "System_Daemon",
        "rmit_event_category": event_type,
    }

    # Add event-type-specific details
    details = {}
    if event_type == "cybersecurity_alert":
        details = generate_cybersecurity_event_details()
    elif event_type == "it_operations_event":
        details = generate_it_operations_event_details()
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

    event = {**base_event, **details}
    return event


# --- Splunk HEC Sending Function (same as before) ---
def send_events_to_splunk_hec(
    events_batch, url, token, source, sourcetype, index, verify_ssl, timeout
):
    if not events_batch: return True
    headers = {"Authorization": f"Splunk {token}"}
    payload_items = []
    for event_data in events_batch:
        try:
            dt_object = datetime.datetime.fromisoformat(
                event_data["event_timestamp_utc"].replace("Z", "+00:00") # Ensure key matches
            )
            epoch_time = dt_object.timestamp()
        except (ValueError, KeyError) as e:
            print(f"Error converting timestamp for HEC: {e}. Using current time.", file=sys.stderr)
            epoch_time = time.time()
        hec_event = {
            "time": epoch_time, "source": source, "sourcetype": sourcetype,
            "index": index, "event": event_data,
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


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Generate synthetic BNM RMiT relevant technology risk events."
    )
    parser.add_argument("--send-to-splunk", action="store_true", help="Enable sending data to Splunk HEC.")
    parser.add_argument(
        "--output-csv", type=str, default=None,
        help=f"Filename to save events as CSV. If not provided and --send-to-splunk is also absent, defaults to '{DEFAULT_CSV_FILENAME}'.",
    )
    parser.add_argument(
        "--output-json", type=str, default=None,
        help=f"Filename to save events as JSON (one event per line - JSONL format).",
    )
    hec_group = parser.add_argument_group('Splunk HEC Options')
    hec_group.add_argument("--splunk-url", default=SPLUNK_HEC_URL_DEFAULT)
    hec_group.add_argument("--splunk-token", default=SPLUNK_HEC_TOKEN_DEFAULT)
    hec_group.add_argument("--splunk-index", default=SPLUNK_HEC_INDEX_DEFAULT)
    hec_group.add_argument("--splunk-sourcetype", default=SPLUNK_HEC_SOURCETYPE_DEFAULT)
    hec_group.add_argument("--splunk-source", default=SPLUNK_HEC_SOURCE_DEFAULT)
    hec_group.add_argument("--splunk-batch-size", type=int, default=SPLUNK_HEC_BATCH_SIZE_DEFAULT)
    hec_group.add_argument("--splunk-disable-ssl-verify", action="store_false", dest="splunk_verify_ssl")
    parser.set_defaults(splunk_verify_ssl=SPLUNK_HEC_VERIFY_SSL_DEFAULT)
    gen_group = parser.add_argument_group('Data Generation Options')
    gen_group.add_argument("--num-events", type=int, default=DEFAULT_NUM_EVENTS)
    gen_group.add_argument("--hours-backfill-per-100", type=float, default=HOURS_BACKFILL_PER_100_EVENTS)  # Use the updated variable
    args = parser.parse_args()

    if not args.send_to_splunk and not args.output_csv and not args.output_json:
        args.output_csv = DEFAULT_CSV_FILENAME
        print(f"No explicit output specified. Defaulting to save to CSV: {args.output_csv}", file=sys.stderr)
    if args.send_to_splunk and args.splunk_token == "YOUR_SPLUNK_HEC_TOKEN":
        print("ERROR: --send-to-splunk is enabled, but SPLUNK_HEC_TOKEN is not configured.", file=sys.stderr)
        sys.exit(1)
    if args.send_to_splunk and not args.splunk_verify_ssl:
        print("SSL verification for HEC is DISABLED.", file=sys.stderr)
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    print(f"Generating {args.num_events} RMiT synthetic events...", file=sys.stderr)
    all_generated_events, splunk_batch = [], []
    total_sent_to_splunk, total_failed_splunk = 0, 0
    start_time_utc = datetime.datetime.now(datetime.timezone.utc)
    time_offset_per_100_events = datetime.timedelta(hours=args.hours_backfill_per_100)

    for i in range(args.num_events):
        time_shift = (i // 100) * time_offset_per_100_events
        current_time_for_event = start_time_utc - time_shift
        event = generate_rmit_event(i + 1, current_time_for_event)
        all_generated_events.append(event)
        if args.send_to_splunk:
            splunk_batch.append(event)
            if len(splunk_batch) >= args.splunk_batch_size:
                print(f"  Sending batch of {len(splunk_batch)} events to Splunk HEC...", file=sys.stderr)
                if send_events_to_splunk_hec(
                    splunk_batch, args.splunk_url, args.splunk_token, args.splunk_source,
                    args.splunk_sourcetype, args.splunk_index, args.splunk_verify_ssl, 30
                ): total_sent_to_splunk += len(splunk_batch)
                else: total_failed_splunk += len(splunk_batch)
                splunk_batch = []
        if (i + 1) % (args.num_events // 10 or 1) == 0:
            print(f"  Generated {i + 1}/{args.num_events} events...", file=sys.stderr)

    if args.send_to_splunk and splunk_batch:
        print(f"  Sending final batch of {len(splunk_batch)} events to Splunk HEC...", file=sys.stderr)
        if send_events_to_splunk_hec(
            splunk_batch, args.splunk_url, args.splunk_token, args.splunk_source,
            args.splunk_sourcetype, args.splunk_index, args.splunk_verify_ssl, 30
        ): total_sent_to_splunk += len(splunk_batch)
        else: total_failed_splunk += len(splunk_batch)

    if args.send_to_splunk:
        print("\nSplunk HEC Sending RMiT Summary:", file=sys.stderr)
        print(f"  Successfully sent: {total_sent_to_splunk} events", file=sys.stderr)
        print(f"  Failed to send:    {total_failed_splunk} events", file=sys.stderr)
    if args.output_csv:
        print(f"\nSaving {len(all_generated_events)} events to {args.output_csv}...", file=sys.stderr)
        df = pd.DataFrame(all_generated_events)
        try:
            df.to_csv(args.output_csv, index=False)
            print(f"Successfully saved events to {args.output_csv}", file=sys.stderr)
        except Exception as e: print(f"Error saving CSV to {args.output_csv}: {e}", file=sys.stderr)

    if args.output_json:
        print(f"\nSaving {len(all_generated_events)} events to {args.output_json}...", file=sys.stderr)
        try:
            with open(args.output_json, 'w') as f:
                for event in all_generated_events:
                    f.write(json.dumps(event) + '\n')
            print(f"Successfully saved events to {args.output_json}", file=sys.stderr)
        except Exception as e:
            print(f"Error saving JSON to {args.output_json}: {e}", file=sys.stderr)

    print(f"\nFinished generating {args.num_events} events.", file=sys.stderr)
    if args.send_to_splunk: print("Please check your Splunk instance for the ingested data.", file=sys.stderr)
    print("\nDisclaimer: This script generates synthetic data for illustrative purposes related to BNM RMiT themes. It does not guarantee compliance or cover all aspects of the policy document.", file=sys.stderr)