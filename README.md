# Splunk Financial Services Industry Solution Accelerator

This repository provides resources, guides, synthetic data generators, and Splunk app content to help Financial Services and Insurance organizations accelerate implementation of key compliance and operational data practices. Releases can be directly installed in Splunk and are compatible with both Splunk Enterprise and Splunk Cloud.

> [!IMPORTANT]  
> The Solution Accelerator for Data Compliance Pipelines App is not directly supported by Splunk Support.

> [!TIP]
> For a more complete set of capabilities beyond the Solution Accelerator for Data Compliance Pipelines and integration with Splunk, please see the [Compliance Essentials for Splunk](https://splunkbase.splunk.com/app/6696), related [app documentation](https://splunk.github.io/Compliance_Essentials/), or reach out to your Splunk Sales team.

---

## Core: Solution Accelerator for Data Compliance Pipelines

- **App**:  
  This folder contains a Splunk-compatible app with all files included in the Solution Accelerator (releases can be found in the releases section of this repository).

- **Documentation Guides**:  
  This section includes the following guides:
  - **Configuration Guide** – Details on configuring the Solution Accelerator for Data Compliance Pipelines after installation, including knowledge objects.
  - **Data Management Guide** – Information on data sources and data collection specific to Financial Services environments.
  - **Install Guide** – Step-by-step instructions for installing and configuring the Solution Accelerator for Data Compliance Pipelines.
  - **Images Folder** – Contains raw images and screenshots used in documentation. You can use these images as needed for your own documentation or presentations.

- **Reference Architecture**:  
  This folder contains reference architectures for Financial Services environments, including various deployment scenarios. While this section provides guidance, it is recommended to consult with a Splunk Architect for your specific environment before deploying Splunk.

- **DataGenScripts**:  
  This folder contains Python scripts for generating synthetic compliance data (with and without schema drift) for testing, demonstration, and validation purposes. These scripts can output to CSV or Splunk HEC and are useful for simulating KYC, PCI, DORA, CPS230, and RMiT data flows.

## Extension: Data Management Pipelines (Optional Add-On)

The **Data Management Pipelines** directory (`Documentation/Data Management Pipelines`) is an **additional, optional set of demonstration assets** that extends the core Solution Accelerator. These artifacts show how upstream ingestion and transformation can be standardized using Splunk Edge Processor SPL2 before data reaches the app.

### What This Extension Adds
| Component | Purpose |
|-----------|---------|
| `*_json_spl2` | SPL2 pipeline definitions implementing regional compliance logic (CPS230, DORA, PCI, KYC, RMiT). |
| `*_sample_events.jsonl` | Representative JSON Lines samples to validate transformation, enrichment, privacy control, and routing. |
| `*.csv` lookups | Dimension data (critical operations, asset inventory) used for context enrichment and risk scoring. |
| Folder README | Deep dive into per-pipeline patterns, lookup integration, routing decisions, and testing guidance. |

### Why It Is Separate
These pipelines are not required for the app to function; they demonstrate:
- A repeatable preprocessing pattern (Extract → Enrich → Protect → Filter → Route → Archive).
- How privacy controls (hashing, masking, redaction) can be applied early.
- How multi-route compliance segmentation reduces index noise while preserving full enriched archival records.

### Highlighted Use Cases
- **CPS230**: Severity scoring + APRA notification filtering; critical operation tolerance enrichment; pseudonymization.
- **DORA**: Resilience incident/test separation; timestamp normalization and service tier context.
- **PCI**: Early removal of sensitive cardholder fields; minimal compliant payload routing.
- **KYC**: Risk change detection and PII hashing for customer identifiers.
- **RMiT**: Institutional criticality enrichment, IP masking, PII redaction, multi-domain routing (cyber/change/TPRM).

### Quick Start Workflow
1. Open a pipeline (e.g., `cps_json_spl2`) and its corresponding sample file (e.g., `cps_sample_events.jsonl`).
2. Upload the required lookup CSV(s) to the Edge Processor environment.
3. Replay the JSONL into a configured source and observe enriched `_raw` preservation plus destination routing.
4. Adapt or clone a pipeline to onboard a new regulatory feed following the same modular pattern.

> Note: These SPL2 pipelines are illustrative. Always validate transformations, privacy controls, and routing logic against formal compliance interpretations for your organization.

---

## Additional Resources

For more information and best practices on using Splunk within Financial Services and Insurance, visit [Splunk Lantern for Financial Services and Insurance](https://lantern.splunk.com/Splunk_Platform/UCE/Financial_Services_and_Insurance).

To see a comprehensive demo on how to enable Data Compliance Pipelines using Splunk Data Management, reach out to your sales team!

---
