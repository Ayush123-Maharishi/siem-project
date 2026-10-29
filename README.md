# 🛡️ DEFENDER SOC — Next-Gen SIEM & Threat Defense Platform

An enterprise-grade **Security Information & Event Management (SIEM)** platform built for security operations centers (SOC). Features multi-source log ingestion, rule-based sliding-window threat correlation, MITRE ATT&CK framework mapping, IP geolocation & threat intelligence scoring, automated containment (firewall blocklist), and an interactive SOC Analyst Dashboard.

---

## 🏛️ System Architecture

```text
       +--------------------------------------------------------------+
       |                     LOG INGESTION LAYER                      |
       |  Simulated Logs  |  Windows Event Logs  |  Web / Syslog API  |
       +-------------------------------+------------------------------+
                                       |
                                       v
       +--------------------------------------------------------------+
       |                 CORRELATION & DETECTION ENGINE               |
       |  - Sliding-Window Brute Force (T1110)                        |
       |  - Account Compromise Detection (T1078)                      |
       |  - Anomalous Subnet / Geolocation (T1078)                    |
       |  - SQL Injection & Web Attacks (T1190)                       |
       |  - Cross-Site Scripting (XSS) (T1189)                        |
       |  - Port Scanning & Network Recon (T1046)                     |
       |  - Volumetric DDoS Detection (T1498)                         |
       +-------------------------------+------------------------------+
                                       |
                     +-----------------+-----------------+
                     |                                   |
                     v                                   v
+-----------------------------+         +-----------------------------+
|    THREAT INTEL & ENRICH    |         |    ALERT NOTIFICATIONS      |
|  - IP Geolocation & ASN     |         |  - Discord Webhooks (Embed) |
|  - AbuseIPDB / Reputation   |         |  - Slack Webhooks           |
|  - Dynamic Threat Score     |         |  - Email (SMTP)             |
+--------------+--------------+         +-----------------------------+
               |
               v
+---------------------------------------------------------------------+
|                  STORAGE & INCIDENT MANAGEMENT (SQLite)             |
|  Alerts  |  Incidents  |  Investigation Notes  |  Blocked IPs (FW)  |
+---------------------------------------------------------------------+
                                       |
                                       v
+---------------------------------------------------------------------+
|                     INTERACTIVE SOC ANALYST UI                      |
|  Executive KPIs | Triage Cases | Deep-Dive | MITRE Matrix | Reports |
+---------------------------------------------------------------------+
```

---

## ✨ Key Features & Integrations

1. **Multi-Source Log Collectors**:
   - **Simulated Enterprise Logs**: Benign multi-day business-hours activity mixed with realistic attack scenarios.
   - **Live Windows Event Log Ingestion**: Collects Windows Security Event ID `4624` (Successful Logon) and `4625` (Failed Logon) directly from the OS.
   - **Real-Time Stream Tailer**: Watches log files as entries are appended in real-time.
   - **Ad-Hoc Log File Upload**: SOC analysts can upload custom `.csv` or `.log` files directly through the dashboard.

2. **Advanced Correlation & Threat Detection Rules**:
   - **Brute-Force Authentication**: Flagged after $\ge 5$ failures within a 5-minute sliding window.
   - **Account Compromise**: Immediate critical alert when a successful logon succeeds after repeated failures from the same IP.
   - **Unusual IP / Subnet Login**: Identifies impossible travel or unfamiliar subnets once an account baseline is learned.
   - **SQL Injection (SQLi)**: Detects `UNION SELECT`, `' OR '1'='1'`, `SLEEP()`, and comment evasion syntax.
   - **Cross-Site Scripting (XSS)**: Flags `<script>`, `onerror=`, and cookie-stealing payloads.
   - **Network Port Scanning**: Flags single IPs probing $\ge 4$ distinct destination ports within 60 seconds.
   - **DDoS / HTTP Flood**: Flags volumetric request bursts exceeding safe operational limits.

3. **Threat Intelligence & Entity Enrichment**:
   - Offline-resilient IP Geolocation with Country flags and ISP mapping.
   - AbuseIPDB integration for external reputation checks and abuse confidence scoring.
   - Automated Threat Scoring ($0 - 100$) combining asset criticality, attack severity, and recurrence.

4. **Incident Response & SOC Workflow**:
   - Incident lifecycle states: `New` -> `Investigating` -> `Contained` -> `Resolved` -> `False Positive`.
   - Analyst assignment and persistent investigation case notes with timestamps.
   - **One-Click Firewall Block**: Active IP containment and blocklist management.

5. **External Alerting**:
   - Real-time formatted Discord webhook notifications with severity color tags and target metadata.
   - Slack webhook integration.

6. **Executive Reporting**:
   - One-click export of incidents to CSV.
   - Formal Markdown executive security summary report generation.

---

## 🚀 Quick Start Guide

### 1. Prerequisites & Installation
Ensure Python 3.10+ is installed:
```bash
pip install -r requirements.txt
```

### 2. Run the Full Detection Pipeline (CLI)
Generate simulated logs, collect Windows logon events, and run threat correlation:
```bash
python run_siem.py --all
```

Alternatively, run individual stages:
```bash
python generate_logs.py     # 1. Generates data/logs.csv
python detector.py          # 2. Applies correlation rules and stores alerts in data/siem.db
```

### 3. Launch the SOC Dashboard
Start the interactive Streamlit SOC dashboard:
```bash
streamlit run dashboard.py
```
Or via the orchestrator:
```bash
python run_siem.py --dashboard
```

---

## 📂 Project Structure

```text
siem_project/
├── data/
│   ├── logs.csv                  # Ingested multi-vector log records
│   ├── live_stream.log           # Real-time tailing log file
│   └── siem.db                   # SQLite database (alerts, incidents, blocklist)
├── config/
│   └── config.json               # Detection thresholds, webhooks, API keys
├── core/
│   ├── db.py                     # Database models, queries, incident notes, blocklist
│   ├── engine.py                 # Correlation engine & sliding-window detectors
│   ├── enrichment.py             # IP Geolocation & Threat Scoring (0-100)
│   └── rules.py                  # MITRE ATT&CK framework mapping & definitions
├── collectors/
│   ├── generator.py              # Multi-vector enterprise log simulator
│   ├── windows_events.py         # Live Windows Security Event collector (4624/4625)
│   ├── file_watcher.py           # Real-time file stream tailer
│   └── syslog_parser.py          # Apache/Nginx and Syslog RFC format parser
├── integrations/
│   ├── notifier.py               # Discord & Slack webhook dispatcher
│   └── threat_intel.py           # AbuseIPDB API & threat reputation query handler
├── dashboard.py                  # Multi-tab Streamlit SOC Analyst Web Interface
├── run_siem.py                   # Master CLI runner
├── requirements.txt              # Project Python dependencies
├── README.md                     # Project documentation
└── VIVA_QUESTIONS.md             # Top 20 viva/exam questions and answers
```

---

## 🎯 MITRE ATT&CK Mapping Reference

| Rule Name | MITRE Technique ID | MITRE Tactic | Default Severity |
|---|---|---|---|
| **Brute-Force Login** | T1110.001 | Credential Access | High |
| **Login After Brute Force** | T1078.003 | Persistence & Defense Evasion | Critical |
| **Unusual Login IP** | T1078 | Initial Access | Medium |
| **SQL Injection Attack** | T1190 | Initial Access | Critical |
| **Cross-Site Scripting (XSS)** | T1189 | Initial Access | High |
| **Port Scanning / Recon** | T1046 | Discovery | High |
| **DDoS / HTTP Flood** | T1498 | Impact | Critical |
| **Privileged Account Abuse** | T1068 | Privilege Escalation | Critical |

---

## 🛠️ Configuration (`config/config.json`)

To enable Discord notifications or adjust detection sensitivity, edit `config/config.json`:
```json
{
  "detection": {
    "brute_force_fail_threshold": 5,
    "brute_force_window_minutes": 5,
    "unusual_ip_baseline_logins": 5,
    "port_scan_port_threshold": 4,
    "port_scan_window_seconds": 60,
    "ddos_request_threshold": 15,
    "ddos_window_seconds": 10
  },
  "notifications": {
    "discord_webhook_url": "YOUR_DISCORD_WEBHOOK_URL_HERE",
    "slack_webhook_url": "",
    "min_severity_to_notify": "High"
  },
  "threat_intel": {
    "abuseipdb_api_key": ""
  }
}
```
*(You can also modify these directly from the **Integrations & Webhooks** tab in the dashboard!)*
