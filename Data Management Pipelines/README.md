# Data Management Pipelines Overview

This folder contains regional compliance data pipeline assets used to demonstrate end-to-end data preparation, enrichment, privacy handling, filtering, and routing with [Splunk Edge Processor](https://help.splunk.com/en/splunk-cloud-platform/process-data-at-the-edge/use-edge-processors-for-splunk-cloud-platform).

## File Categories
- Pipeline Definitions (`*.spl2`): SPL2 pipeline logic tailored to each regulatory/compliance use case.
- Sample Event Sets (`*.jsonl`): JSON Lines files—one event per line—used to validate pipeline transformations locally or in a test ingest environment.
- Lookup Tables (`*.csv`): Reference dimension data joined by pipeline logic for enrichment (e.g., critical operations, asset inventory).
- Generator Instructions (`Data Generator Instructions.md`): Example CLI invocations for synthetic event generation and ingestion.

## Inventory
### Pipelines
- `cps_json_spl2`: CPS 230 (Operational Risk & Third Parties) pipeline. Enriches critical operation metadata, converts severity to numeric scale, filters for APRA-notifiable or high severity, pseudonymizes reporter, masks vendor, archives raw, and routes to APRA vs significant indexes.
- `dora_json_spl2`: DORA (EU Digital Operational Resilience Act) pipeline. Handles nested `_raw` event structure, normalizes timestamps, pseudonymizes user identifiers, enriches with service tiers, and routes incidents vs resilience test outcomes.
- `kyc_json_spl2`: KYC monitoring pipeline. Performs PII protection (hashing account/user fields), flags anomalous customer risk score changes, enriches with geo or segment metadata via lookup, and routes high-risk changes separately.
- `pci_json_spl2`: PCI DSS pipeline for cardholder data events. Drops sensitive PAN fields using `json_delete`, applies masking, enriches merchant/service taxonomy, and routes compliance violations vs routine events.
- `rmit_json_spl2`: BNM RMiT (Malaysia) technology risk pipeline. Extracts fields from `_raw`, performs asset enrichment (criticality, data center), risk leveling, masks IP addresses, pseudonymizes user_id, redacts descriptions containing PII tokens, filters by status & criticality, and routes cyber / change / TPRM events.

### Sample Event Data
- `cps_sample_events.jsonl`: Mixed CPS 230 events (operational incidents, change, control assessments, third-party risk). Used to validate severity filtering and APRA notification routing.
- `dora_sample_events.jsonl`: Includes digital resilience incidents, system disruption records, and test execution outcomes to verify normalization and routing logic.
- `kyc_sample_events.jsonl`: Customer onboarding / ongoing review events, risk score shifts; drives PII hashing and abnormal change detection.
- `pci_sample_events.jsonl`: Payment security events containing potential cardholder indicators; validate field dropping and compliance filtering.
- `rmit_sample_events.jsonl`: Technology risk events (cybersecurity alerts, IT operations, third-party risk, change logs, governance tasks) for enrichment + multi-route testing.

### Lookup Tables
- `anz_critical_operations.csv`: Maps `entity_id` to critical operation name, tolerance window, business unit. Used in `cps_json_spl2` to enrich operational and incident events.
- `apjc_asset_inventory.csv`: Maps financial institutions to criticality tiers, impacted services, and data center locations. Used in `rmit_json_spl2` for Malaysian institutional enrichment.

## Lookup Integration Guidance
- Ensure CSV uploaded to correct Edge Processor environment (`/envs.splunk.'<env-id>'.lookups`).
- Match column names precisely: e.g., `entity_id AS lookup_entity_id` followed by `OUTPUT system_id, critical_operation_name, tolerance_level, business_unit`.
- Null-safe injection pattern:
  ```spl2
  | eval _raw = if(isnotnull(enriched_field), json_set(_raw, "enriched_field", enriched_field), _raw)
  ```

## Synthetic Data Generation

To test these pipelines in an Edge Processor environment you can generate representative synthetic events using the Python scripts in the root `DataGenScripts` directory.

### Script → Pipeline Mapping
| Script | Regulation / Use Case | Corresponding Pipeline |
|--------|-----------------------|------------------------|
| `cps230_simulator.py` | CPS230 Operational Risk & Third Parties | `cps_json_spl2` |
| `dora_simulator.py`   | DORA Digital Resilience | `dora_json_spl2` |
| `pci_simulator.py`    | PCI DSS Data Security | `pci_json_spl2` |
| `kyc_simulator_v2.py` | KYC / Customer Risk Monitoring | `kyc_json_spl2` |
| `rmit_simulator.py`   | BNM RMiT Technology Risk | `rmit_json_spl2` |

### Common Flags
`--num-events <N>`: How many events to generate.
`--output-json <file.jsonl>`: Write events as JSON Lines for replay into Edge Processor.
`--send-to-splunk`: Stream directly to a Splunk HEC endpoint (requires `--splunk-url` and `--splunk-token`).
`--output-csv <file.csv>`: Optional CSV export for inspection.

### Example: Generate CPS230 Sample Events for Edge Processor
```bash
python3 DataGenScripts/cps230_simulator.py \
  --num-events 2000 \
  --output-json cps_generated_events.jsonl
```
Replay the resulting JSONL into your configured Edge Processor source (tooling will vary—use your ingestion/replay utility or a minimal custom loader).

### Example: Direct HEC Ingest (While Also Saving JSONL)
```bash
python3 DataGenScripts/rmit_simulator.py \
  --num-events 1500 \
  --send-to-splunk \
  --splunk-url https://<hec-host>:8088/services/collector \
  --splunk-token <hec-token> \
  --splunk-index sample_rmit \
  --splunk-sourcetype rmit:synthetic:event \
  --output-json rmit_events.jsonl
```

### Best Practices
1. Generate a modest initial set (e.g., 200–500 events) to validate lookup joins and routing.
2. Inspect a handful of enriched archived `_raw` payloads to confirm `json_set` operations landed properly.
3. Scale up volume only after verifying filtering thresholds (e.g., severity or notification flags) behave as expected.
4. Keep salts (e.g., for hashing user IDs) consistent across runs if you need deterministic pseudonymization.

### Troubleshooting Tips
- Missing enrichment fields: Verify lookup CSV uploaded to correct Edge Processor environment ID.
- Empty routed indexes: Re-check filter logic (`where` clauses) for overly restrictive conditions.
- Unexpected field names: Ensure no stray spaces inside `json_set` key arguments.

This synthetic data workflow lets you safely exercise compliance logic without exposing production data.