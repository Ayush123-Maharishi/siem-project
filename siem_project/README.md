# Basic SIEM Tool

A simplified Security Information & Event Management system.
Pipeline: **Log Generator -> Detector -> SQLite -> Streamlit dashboard**

## Setup
    pip install -r requirements.txt

## Run (one stage at a time, good for demos)
    python generate_logs.py     # 1. creates data/logs.csv
    python detector.py          # 2+3. applies rules, stores alerts in data/siem.db
    streamlit run dashboard.py  # 4. opens the dashboard in your browser

The dashboard also has a sidebar button that regenerates logs and re-runs detection.

## Files
| File | Role |
|---|---|
| generate_logs.py | Simulated login logs with injected attacks |
| detector.py | Brute-force and unusual-IP rules (thresholds at the top of the file) |
| db.py | SQLite helpers (alerts table) |
| dashboard.py | Streamlit UI: filters, metrics, charts, alert table |

## Expected alerts on the default data
1. Brute-Force Login - 198.51.100.7 against bob (High)
2. Brute-Force Login - 45.33.12.99 against admin (High)
3. Login After Brute Force - admin from 45.33.12.99 (Critical)
4. Unusual Login IP - alice from 203.0.113.44 (Medium)
(carol's 3 failures stay below the threshold and correctly raise no alert)
