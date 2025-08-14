# Install Guide

This guide provides detailed steps to install and configure the Solution Accelerator for Data Compliance.

## Installation Steps

1. **Download the App**
   - Obtain the latest `.spl` package from the releases section.

2. **Install in Splunk**
   - Go to Splunk Web > Apps > Manage Apps > Install app from file.
   - Upload the `.spl` package and restart Splunk if prompted.

3. **Post-Installation**
   - Verify the app appears in the Splunk Apps menu.
   - Follow the Configuration Guide to complete setup.

## Post-Installation: Accessing the Data Flow Dashboard

After installing the Solution Accelerator app, navigate to:
**Data Compliance > Dashboards > Data Flow Dashboard**

This dashboard provides real-time and historical monitoring of your compliance data ingestion, latency, retention, and completeness.

## Post-Installation: Accessing the Schema Drift Dashboard

After installing the Solution Accelerator app, navigate to:
**Data Compliance > Dashboards > Monitor Data Schema Consistency**

This dashboard provides visibility into schema changes and helps ensure your compliance data remains consistent and reliable.

## Post-Installation: Accessing the Data Ingest Dashboard

After installing the Solution Accelerator app, navigate to:
**Data Compliance > Dashboards > Data Ingest Dashboard**

This dashboard provides a high-level overview of all data ingested into your Splunk environment, including event counts, sourcetype diversity, and data distribution.

## Troubleshooting

- If the app does not appear, check `splunkd.log` for errors.
- Ensure you have the correct permissions to install apps.

---
