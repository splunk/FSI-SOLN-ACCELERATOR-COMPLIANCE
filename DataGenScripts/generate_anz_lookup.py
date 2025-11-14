import csv
import uuid

# These should match the CRITICAL_OPERATIONS and ENTITY_IDS in your simulator
CRITICAL_OPERATIONS = [
    "Payments Processing", "Customer Account Management", "Regulatory Reporting",
    "Insurance Claims Processing", "Superannuation Fund Administration", "Online Banking Services",
    "Trade Settlement", "Liquidity Management"
]
# Entity IDs must match those in cps230_simulator.py
ENTITY_IDS = [
    "ENTITY_6885",
    "ENTITY_961C",
    "ENTITY_1790",
    "ENTITY_4FC0",
    "ENTITY_FA49"
]

# Example: assign each system_id to a critical operation and a tolerance level (in minutes)
systems = []
for i, op in enumerate(CRITICAL_OPERATIONS):
    system_id = f"sys_{i+1:03d}"
    entity_id = ENTITY_IDS[i % len(ENTITY_IDS)]
    # Example tolerance: Payments = 60, Online Banking = 120, others = 180
    if "Payments" in op:
        tolerance = 60
    elif "Online Banking" in op:
        tolerance = 120
    else:
        tolerance = 180
    systems.append({
        "system_id": system_id,
        "entity_id": entity_id,
        "critical_operation_name": op,
        "tolerance_level": tolerance,
        "business_unit": "Operations"  # You can customize this
    })

# Write to CSV
with open("anz_critical_operations.csv", "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=["system_id", "entity_id", "critical_operation_name", "tolerance_level", "business_unit"])
    writer.writeheader()
    writer.writerows(systems)

print("Lookup CSV 'anz_critical_operations.csv' generated.")