python3 kyc_simulator_v2.py     --send-to-splunk \
                                --splunk-url "https://localhost:8088/services/collector" \
                                --splunk-token "0123456-789a-bcde-f012-3456789a" \
                                --splunk-index "sample_kyc" \
                                --num-events 10000

python3 pci_simulator.py  --send-to-splunk \
                                  --splunk-url "https://localhost:8088/services/collector" \
                                --splunk-token "0123456-789a-bcde-f012-3456789a" \
                                  --splunk-index "sample_pci" \
                                   --num-events 10000

python3 dora_simulator.py --send-to-splunk \
                                    --splunk-url "https://localhost:8088/services/collector" \
                                  --splunk-token "0123456-789a-bcde-f012-3456789a" \
                                    --splunk-index "sample_dora" \
                                    --num-events 10000

python3 cps230_simulator.py          --send-to-splunk \
                                    --splunk-url "https://localhost:8088/services/collector" \
                                  --splunk-token "0123456-789a-bcde-f012-3456789a" \
                                    --splunk-index "sample_cps" \
                                    --num-events 10000

python3 rmit_simulator.py          --send-to-splunk \
                                    --splunk-url "https://localhost:8088/services/collector" \
                                  --splunk-token "0123456-789a-bcde-f012-3456789a" \
                                    --splunk-index "sample_rmit" \
                                    --num-events 10000

python3 kyc_drift_simulator.py     --send-to-splunk \
                                --splunk-url "https://localhost:8088/services/collector" \
                                --splunk-token "0123456-789a-bcde-f012-3456789a" \
                                --splunk-index "drift_raw_data" \
                                --num-events 168000 \
                                   --events-per-hour 1000                              

python3 pci_drift_simulator.py  --send-to-splunk \
                                  --splunk-url "https://localhost:8088/services/collector" \
                                --splunk-token "0123456-789a-bcde-f012-3456789a" \
                                  --splunk-index "drift_raw_data" \
                                   --num-events 168000 \
                                   --events-per-hour 1000                                    

python3 dora_drift_simulator.py --send-to-splunk \
                                  --splunk-url "https://localhost:8088/services/collector" \
                                --splunk-token "0123456-789a-bcde-f012-3456789a" \
                                   --splunk-index "drift_raw_data" \
                                   --num-events 168000 \
                                   --events-per-hour 1000                                    

python3 cps230_drift_simulator.py          --send-to-splunk \
                                  --splunk-url "https://localhost:8088/services/collector" \
                                --splunk-token "0123456-789a-bcde-f012-3456789a" \
                                   --splunk-index "drift_raw_data" \
                                   --num-events 168000 \
                                   --events-per-hour 1000                                    

python3 rmit_drift_simulator.py          --send-to-splunk \
                                  --splunk-url "https://localhost:8088/services/collector" \
                                --splunk-token "0123456-789a-bcde-f012-3456789a" \
                                   --splunk-index "drift_raw_data" \
                                   --num-events 168000 \
                                   --events-per-hour 1000 