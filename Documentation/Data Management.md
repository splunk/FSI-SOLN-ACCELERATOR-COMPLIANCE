# Data Management Guide

This guide covers information related to data sources and data collection for Financial Services environments.

## Supported Data Sources

- Core banking logs
- Payment card transaction logs (PCI)
- KYC/AML onboarding events
- DORA, CPS230, and RMiT compliance events

## Data Collection

1. **Onboard Data**  
   - Use Splunk Universal Forwarder or HTTP Event Collector (HEC) for log ingestion.
   - Reference the sample log simulators for test data.

2. **Source Types**  
   - Assign appropriate sourcetypes (e.g., `kyc:raw`, `pci:raw`, `dora:incident`).

3. **Data Validation**  
   - Use the included dashboards to verify data is parsed and normalized.

## Monitoring Data Quality and Compliance

The Data Flow Dashboard helps you:
- Detect data ingestion delays or outages (freshness, latency)
- Monitor event volume and identify anomalies
- Track data retention for regulatory compliance
- Assess data completeness and source health

**Tip:**  
If a panel shows "Non-Compliant" or "Anomaly," investigate the corresponding data source or pipeline.

## Monitoring Schema Drift

- Use the Data Schema Drift Dashboard to:
  - Detect when new fields appear or existing fields are removed in your compliance data.
  - Track the number of fields and events per sourcetype over time.
  - Investigate the impact of source system or ETL changes on your Splunk data model.

- **Best Practices:**
  - Regularly review this dashboard after onboarding new data sources or making changes to log pipelines.
  - Investigate any unexpected schema changes, as they may indicate upstream issues or non-compliant data feeds.

## Monitoring Data Ingestion

- Use the Data Ingest Dashboard to:
  - Track daily event volume trends.
  - Monitor the number of sourcetypes and events in each index.
  - Quickly identify ingestion gaps or unexpected drops in data volume.

- **Best Practices:**
  - Regularly review this dashboard to ensure all expected data sources are being ingested.
  - Investigate any sudden drops or spikes in event counts, as these may indicate upstream issues.