import csv
import random

# These should match your simulator's CRITICAL_SYSTEMS_MY and MALAYSIAN_FINANCIAL_INSTITUTIONS
CRITICAL_SYSTEMS_MY = [
    "Core_Banking_System", "RENTAS_Gateway", "IBG_Processing", "SWIFT_Interface",
    "Online_Banking_Platform", "Mobile_Banking_App", "ATM_Network_Controller",
    "Trade_Finance_System", "Treasury_Management_System", "Fraud_Detection_Engine",
    "Regulatory_Reporting_System", "Customer_Data_Hub"
]
MALAYSIAN_FINANCIAL_INSTITUTIONS = [
    "Maybank_MY", "CIMB_Group_MY", "Public_Bank_MY", "RHB_Bank_MY", "Hong_Leong_Bank_MY",
    "AmBank_Group_MY", "UOB_Malaysia_MY", "OCBC_Bank_Malaysia_MY", "Affin_Bank_MY", "Alliance_Bank_MY"
]
CRITICALITY_LEVELS = ["Tier0", "Tier1", "Tier2", "Tier3"]
DATA_CENTERS = ["SGP-DC1", "KUL-DC2", "HKG-DC3", "JPN-DC4"]

# Generate a list of hosts (system IDs) for each financial institution and system
hosts = []
for fi in MALAYSIAN_FINANCIAL_INSTITUTIONS:
    for sys in CRITICAL_SYSTEMS_MY:
        host = f"{fi}_{sys.replace(' ', '_')}"
        criticality = random.choice(CRITICALITY_LEVELS)
        service_impacted = sys
        dc_location = random.choice(DATA_CENTERS)
        hosts.append({
            "host": host,
            "criticality": criticality,
            "service_impacted": service_impacted,
            "dc_location": dc_location
        })

# Write to CSV
with open("apjc_asset_inventory.csv", "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=["host", "criticality", "service_impacted", "dc_location"])
    writer.writeheader()
    writer.writerows(hosts)

print("Lookup CSV 'apjc_asset_inventory.csv' generated.")