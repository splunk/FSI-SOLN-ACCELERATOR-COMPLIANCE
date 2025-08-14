# Compliance Log Simulators (Drift & Non-Drift)

These scripts generate synthetic log data for various compliance domains (KYC, PCI, DORA, CPS230, RMiT).  
You can choose between **drift** simulators (which introduce schema and format drift) and **non-drift** simulators (which generate stable, standard-compliant logs).  
All scripts can send data to Splunk HEC or save it as a CSV file.  
**All scripts support dynamic control over the total number of events and the event rate per hour.**

---

## Usage

```sh
python <simulator_script>.py [OPTIONS]
```
Where `<simulator_script>.py` is one of:
- Drift simulators:
  - `kyc_drift_simulator.py`
  - `pci_drift_simulator.py`
  - `dora_drift_simulator.py`
  - `cps230_drift_simulator.py`
  - `rmit_drift_simulator.py`
- Non-drift simulators:
  - `kyc_simulator.py`
  - `pci_simulator.py`
  - `dora_simulator.py`
  - `cps230_simulator.py`
  - `rmit_simulator.py`

---

## Parameters

| Argument                | Type    | Default                      | Description                                                                                  |
|-------------------------|---------|------------------------------|----------------------------------------------------------------------------------------------|
| `--num-events`          | int     | 1000                         | Total number of events to generate.                                                          |
| `--events-per-hour`     | int     | 1000                         | Number of events to generate per hour of backfill.                                           |
| `--output-csv`          | str     | `<script>_schema_drift_raw_logs.csv` or `<script>_raw_logs.csv` | Output CSV filename. If not specified and not sending to Splunk, defaults to this filename.  |
| `--send-to-splunk`      | flag    | False                        | If set, sends generated events to Splunk HEC.                                                |

### Splunk HEC Options

| Argument                    | Type    | Default                  | Description                                 |
|-----------------------------|---------|--------------------------|---------------------------------------------|
| `--splunk-url`              | str     | YOUR_SPLUNK_HEC_URL/...  | Splunk HEC endpoint URL.                    |
| `--splunk-token`            | str     | YOUR_HEC_TOKEN_FOR_RAW_DATA | Splunk HEC authentication token.         |
| `--splunk-index`            | str     | drift_raw_data           | Splunk index for raw drift data.            |
| `--splunk-source`           | str     | `<script>_drift_generator` or `<script>_generator` | Splunk source field. |
| `--splunk-sourcetype`       | str     | `<script>_drift_raw` or `<script>_raw`     | Splunk sourcetype for data.                 |
| `--splunk-batch-size`       | int     | 100                      | Number of events per batch sent to HEC.      |
| `--splunk-disable-ssl-verify` | flag  | False                    | Disable SSL verification for HEC endpoint.   |

---

## Example Commands

**Generate 10,000 PCI events with drift at 2,000 events per hour, save to CSV:**
```sh
python pci_drift_simulator.py --num-events 10000 --events-per-hour 2000 --output-csv my_pci_logs.csv
```

**Generate 10,000 PCI events (no drift) at 2,000 events per hour, save to CSV:**
```sh
python pci_simulator.py --num-events 10000 --events-per-hour 2000 --output-csv my_pci_logs.csv
```

**Generate 24,000 DORA events with drift at 1,000 events per hour and send to Splunk:**
```sh
python dora_drift_simulator.py --num-events 24000 --events-per-hour 1000 --send-to-splunk \
  --splunk-url https://splunk.example.com:8088/services/collector \
  --splunk-token YOUR_TOKEN --splunk-index my_index
```

**Generate 24,000 DORA events (no drift) at 1,000 events per hour and send to Splunk:**
```sh
python dora_simulator.py --num-events 24000 --events-per-hour 1000 --send-to-splunk \
  --splunk-url https://splunk.example.com:8088/services/collector \
  --splunk-token YOUR_TOKEN --splunk-index my_index
```

**Generate 168,000 RMiT events with drift at 1,000 events per hour (1 week of hourly data):**
```sh
python rmit_drift_simulator.py --num-events 168000 --events-per-hour 1000 --output-csv rmit_week.csv
```

**Generate 168,000 RMiT events (no drift) at 1,000 events per hour (1 week of hourly data):**
```sh
python rmit_simulator.py --num-events 168000 --events-per-hour 1000 --output-csv rmit_week.csv
```

---

## Notes

- The script will automatically spread the generated events evenly over the calculated backfill window (`num-events / events-per-hour` hours).
- If neither `--output-csv` nor `--send-to-splunk` is specified, the script will default to saving the logs as `<script>_schema_drift_raw_logs.csv` for drift simulators or `<script>_raw_logs.csv` for non-drift simulators.
- For Splunk HEC, ensure the URL and token are set to valid values.
- Each script supports its own compliance domain and may have additional options or schema drift logic (for drift simulators).
- Use drift simulators to test Splunk or other SIEM/data pipelines for schema evolution and robustness; use non-drift simulators for standard, stable log ingestion and analytics.