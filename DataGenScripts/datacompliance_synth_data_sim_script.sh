python3 kyc_simulator_v2.py     --send-to-splunk \
                                --splunk-url "https://localhost:8088/services/collector" \
                                --splunk-token "242f4d3b-aa1c-4c7f-8c47-9efa78a0799d" \
                                --splunk-index "sample_kyc" \
                                --num-events 10000

python3 pci_simulator.py  --send-to-splunk \
                                  --splunk-url "https://localhost:8088/services/collector" \
                                --splunk-token "242f4d3b-aa1c-4c7f-8c47-9efa78a0799d" \
                                  --splunk-index "sample_pci" \
                                   --num-events 10000

python3 dora_simulator.py --send-to-splunk \
                                    --splunk-url "https://localhost:8088/services/collector" \
                                  --splunk-token "242f4d3b-aa1c-4c7f-8c47-9efa78a0799d" \
                                    --splunk-index "sample_dora" \
                                    --num-events 10000

python3 cps230_simulator.py          --send-to-splunk \
                                    --splunk-url "https://localhost:8088/services/collector" \
                                  --splunk-token "242f4d3b-aa1c-4c7f-8c47-9efa78a0799d" \
                                    --splunk-index "sample_cps" \
                                    --num-events 10000

python3 rmit_simulator.py          --send-to-splunk \
                                    --splunk-url "https://localhost:8088/services/collector" \
                                  --splunk-token "242f4d3b-aa1c-4c7f-8c47-9efa78a0799d" \
                                    --splunk-index "sample_rmit" \
                                    --num-events 10000

python3 kyc_drift_simulator.py     --send-to-splunk \
                                --splunk-url "https://localhost:8088/services/collector" \
                                --splunk-token "242f4d3b-aa1c-4c7f-8c47-9efa78a0799d" \
                                --splunk-index "drift_raw_data" \
                                --num-events 168000 \
                                   --events-per-hour 1000                              

python3 pci_drift_simulator.py  --send-to-splunk \
                                  --splunk-url "https://localhost:8088/services/collector" \
                                --splunk-token "242f4d3b-aa1c-4c7f-8c47-9efa78a0799d" \
                                  --splunk-index "drift_raw_data" \
                                   --num-events 168000 \
                                   --events-per-hour 1000                                    

python3 dora_drift_simulator.py --send-to-splunk \
                                  --splunk-url "https://localhost:8088/services/collector" \
                                --splunk-token "242f4d3b-aa1c-4c7f-8c47-9efa78a0799d" \
                                   --splunk-index "drift_raw_data" \
                                   --num-events 168000 \
                                   --events-per-hour 1000                                    

python3 cps230_drift_simulator.py          --send-to-splunk \
                                  --splunk-url "https://localhost:8088/services/collector" \
                                --splunk-token "242f4d3b-aa1c-4c7f-8c47-9efa78a0799d" \
                                   --splunk-index "drift_raw_data" \
                                   --num-events 168000 \
                                   --events-per-hour 1000                                    

python3 rmit_drift_simulator.py          --send-to-splunk \
                                  --splunk-url "https://localhost:8088/services/collector" \
                                --splunk-token "242f4d3b-aa1c-4c7f-8c47-9efa78a0799d" \
                                   --splunk-index "drift_raw_data" \
                                   --num-events 168000 \
                                   --events-per-hour 1000 