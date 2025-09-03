# Configuration Guide

This guide provides details on how to configure the Solution Accelerator for Data Compliance Pipelines after installation.

## Steps

1. **Install or Compile the Solution Accelerator App**  
   - Download the latest release from the releases section, or compile/package the app from source if needed.
   - To compile/package: Navigate to the app directory and run:
     ```
     tar -cvzf solution_accelerator_data_compliance_pipelines.spl *
     ```
   - Install via Splunk Web or CLI using the `.spl` file you downloaded or built.

2. **Configure Knowledge Objects**  
   - Review and enable the included saved searches, event types, tags, and macros.
   - Adjust permissions as needed for your environment.

3. **Set Up Data Inputs**  
   - Configure data sources as described in the Data Management guide.
   - Validate data onboarding using the included dashboards.

4. **Customize Compliance Content**  
   - Modify correlation searches and dashboards to match your regulatory requirements.

5. **User Access**  
   - Assign roles and permissions for compliance users and administrators.

## Configuring the Data Flow Dashboard

- **Indexes & Sourcetypes:**  
  Ensure your compliance data is being ingested into the correct Splunk indexes and sourcetypes. The dashboard dynamically lists available indexes and sourcetypes.
- **SLA & Retention Thresholds:**  
  The dashboard uses default thresholds (e.g., 1 hour for freshness, 5 minutes for latency, 1 day for retention). Adjust these in the dashboard SPL if your organization has different requirements.
- **Schema Timespan:**  
  Use the "Schema Analysis Timespan" input to control the granularity of completeness and volume anomaly detection.

## Configuring the Data Schema Drift Dashboard

- **Purpose:**  
  The Data Schema Drift Dashboard helps you monitor changes in your data schema (fields) over time, so you can quickly detect and respond to unexpected changes in log formats or data onboarding.

- **Inputs:**  
  - **Analysis Time Range:** Choose how many days back to analyze.
  - **Raw Data Index/Sourcetype:** Select the Splunk index and sourcetype to monitor.
  - **Schema Analysis Timespan:** Set the granularity for schema comparison (e.g., 4h, 24h).

- **Customizing:**  
  - Adjust the default index or sourcetype in the dashboard XML if your environment uses different names.
  - You can increase the number of time windows or change the default timespan for more/less granular drift detection.

## Configuring the Data Ingest Dashboard

- **Purpose:**  
  The Data Ingest Dashboard helps you monitor the overall health and volume of your Splunk data ingestion.

- **Inputs:**  
  - **Analysis Time Range:** Select the period to analyze (e.g., last 7 days).
  - **Raw Data Index:** Choose which index to monitor. The dashboard auto-populates available indexes.

- **Customizing:**  
  - Adjust the default index in the dashboard XML if your environment uses a different default.
  - You can increase the number of days or indexes displayed by modifying the dashboard inputs.