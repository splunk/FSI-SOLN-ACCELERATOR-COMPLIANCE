# DataGenScripts

This folder contains Python scripts for generating synthetic data to support testing, validation, and demonstration of the Splunk Financial Services and Insurance Solution Accelerator - Data Compliance content.

## Overview

The scripts in this folder can generate realistic, schema-compliant, and optionally schema-drifted log data for a variety of financial services compliance domains. They are designed to help you:

- Simulate data onboarding for KYC, PCI, DORA, CPS230, and RMiT compliance use cases
- Test dashboards, alerts, and data quality monitoring in Splunk
- Validate schema drift detection and data pipeline robustness
- Output data to CSV or send directly to Splunk via HTTP Event Collector (HEC)

## Script Types

- **Drift Simulators**:  
  Generate data with intentional schema drift (field changes, type changes, missing/extra fields) to test Splunk’s ability to detect and handle evolving data sources.
- **Non-Drift Simulators**:  
  Generate stable, standard-compliant logs for each compliance domain.

## Available Scripts

| Script Name                  | Description                                                      | Drift?   |
|------------------------------|------------------------------------------------------------------|----------|
| `kyc_simulator.py`           | Generates KYC onboarding and compliance events                   | No       |
| `kyc_drift_simulator.py`     | Generates KYC events with schema drift                           | Yes      |
| `pci_simulator.py`           | Generates PCI DSS payment card transaction logs                  | No       |
| `pci_drift_simulator.py`     | Generates PCI logs with schema drift                             | Yes      |
| `dora_simulator.py`          | Generates DORA (Digital Operational Resilience Act) events       | No       |
| `dora_drift_simulator.py`    | Generates DORA events with schema drift                          | Yes      |
| `cps230_simulator.py`        | Generates CPS230 (APRA) compliance events                        | No       |
| `cps230_drift_simulator.py`  | Generates CPS230 events with schema drift                        | Yes      |
| `rmit_simulator.py`          | Generates RMiT (Risk Management in Technology) events            | No       |
| `rmit_drift_simulator.py`    | Generates RMiT events with schema drift                          | Yes      |

## Usage

Each script supports command-line arguments for:
- Number of events to generate
- Events per hour (for time distribution)
- Output to CSV file
- Sending to Splunk HEC (with URL, token, index, etc.)

Example:
```sh
python kyc_simulator.py --num-events 10000 --events-per-hour 2000 --output-csv kyc_sample.csv
python pci_drift_simulator.py --num-events 5000 --send-to-splunk --splunk-url https://splunk.example.com:8088/services/collector --splunk-token <TOKEN> 
```