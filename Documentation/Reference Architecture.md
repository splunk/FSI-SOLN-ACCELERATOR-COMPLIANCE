# Reference Architecture

This document provides reference architectures for deploying Splunk in Financial Services environments.

## Example Scenarios

- **Single-Site Deployment**
  - All Splunk components deployed in a single data center.
  - Suitable for small to medium environments.

- **Multi-Site/DR Deployment**
  - Indexers and search heads distributed across primary and DR sites.
  - Data replication and failover configured.

- **Cloud/Hybrid Deployment**
  - Splunk Cloud Platform with on-premises forwarders.
  - Secure data transfer and compliance controls.

> **Recommendation:**  
> Always consult with a certified Splunk Architect to tailor the architecture to your organization’s needs and regulatory requirements.

> The Data Flow Dashboard is designed to work with both single-site and distributed Splunk deployments.  
> For best results, ensure all compliance-relevant data sources are consistently indexed and sourcetyped.

> The Data Schema Drift Dashboard is compatible with all supported Splunk deployment models.  
> For best results, ensure all compliance-relevant data sources are consistently indexed and sourcetyped.

> The Data Ingest Dashboard is compatible with all supported Splunk deployment models.  
> For best results, ensure all compliance-relevant data sources are consistently indexed and sourcetyped.
