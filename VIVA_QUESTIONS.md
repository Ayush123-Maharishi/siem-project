# 🎓 College SIEM Project — Top 20 Viva Questions & Model Answers

Use this guide to prepare for your viva voce, project defense, or seminar presentation.

---

### Q1: What is a SIEM, and what problem does it solve?
**Answer:**  
SIEM stands for **Security Information and Event Management**. In modern organizations, thousands of devices (servers, firewalls, applications, workstations) generate millions of raw logs daily. A human analyst cannot manually review every log. A SIEM solves this by:
1. **Aggregating** logs from diverse endpoints into a central repository.
2. **Normalizing** different log formats into a common schema.
3. **Correlating** events across time to detect active cyber attacks.
4. **Alerting** security teams and facilitating rapid incident triage.

---

### Q2: What is the architecture of your SIEM project?
**Answer:**  
Our SIEM follows a modular 4-tier pipeline architecture:
1. **Log Ingestion & Collection Layer:** Ingests simulated multi-vector enterprise logs, live Windows Security Events (4624/4625), and file-watcher streams.
2. **Correlation & Detection Engine:** Normalizes timestamps and executes stateful sliding-window rules across authentication, web, and network vectors.
3. **Threat Intelligence & Enrichment Layer:** Adds GeoIP location, ISP metadata, and calculates an intelligence threat risk score ($0-100$).
4. **Storage & SOC Analyst Dashboard:** Backed by SQLite for persistent incident cases and interactive Streamlit UI for triage, containment, and reporting.

---

### Q3: What is the MITRE ATT&CK framework, and how is it used in your project?
**Answer:**  
MITRE ATT&CK is a globally accessible knowledge base of adversary tactics, techniques, and procedures (TTPs) based on real-world observations.  
In our SIEM, every detection rule is mapped directly to a MITRE technique and tactic (e.g. Brute Force to `T1110` under *Credential Access*, SQL Injection to `T1190` under *Initial Access*). This provides SOC analysts with standardized contextual definitions and actionable remediation playbooks.

---

### Q4: How does your brute force detection rule work?
**Answer:**  
We employ a stateful **sliding time window** algorithm using double-ended queues (`collections.deque`):
- For every IP, we maintain recent failed login timestamps.
- As new events arrive, timestamps older than the configured window (e.g. 5 minutes) are evicted (`popleft()`).
- If the count of failed logins within the active window reaches or exceeds the threshold (e.g. $\ge 5$), a High-severity alert is raised.
- If a subsequent login from that same flagged IP succeeds, the engine immediately triggers a **Critical "Login After Brute Force"** alert indicating possible account takeover.

---

### Q5: How do you detect an "Unusual Login IP" or anomalous access?
**Answer:**  
We use baseline behavioral profiling:
- For every user account, the system monitors their initial successful logins (e.g. baseline of 5 logins) to learn their standard subnets (e.g. `/24` network range).
- Once the baseline is established, if the user successfully authenticates from an unfamiliar external subnet never seen before, a Medium-severity alert is triggered for impossible travel / anomalous origin.

---

### Q6: How are Web Application attacks (SQLi and XSS) detected?
**Answer:**  
Our engine inspects HTTP request URIs, query strings, and POST payloads using compiled regular expression signatures:
- **SQL Injection:** Looks for keywords such as `UNION SELECT`, `OR '1'='1'`, `SLEEP()`, `--`, and SQL comment sequences.
- **Cross-Site Scripting (XSS):** Looks for JavaScript script tags `<script>`, event handlers like `onerror=`, `onload=`, and cookie-harvesting code.

---

### Q7: How does your Port Scan detection work?
**Answer:**  
We track destination ports targeted by each external IP address within a short sliding window (e.g., 60 seconds). If an IP attempts connections across $\ge 4$ distinct destination ports in that time window, it is flagged as reconnaissance activity under MITRE `T1046` (Network Service Discovery).

---

### Q8: What is the difference between a Security Event and a Security Alert?
**Answer:**  
- **Event:** Any observable occurrence in a system or network (e.g. a user logging in, a file being opened, or an HTTP GET request). Most events are benign.
- **Alert:** An event or combination of correlated events that violates a security detection rule and requires investigation by an analyst.

---

### Q9: How does the system prevent alert fatigue?
**Answer:**  
Alert fatigue occurs when analysts are overwhelmed by false or repetitive alarms:
1. **Burst Suppression:** Once an IP triggers a brute-force alert, subsequent failures within the same burst update the timestamp without spawning duplicate alerts.
2. **Decoy Thresholds:** Occasional user typos (e.g. 2 or 3 mistyped passwords) stay below the alert threshold.
3. **Threshold Tuning:** SOC teams can dynamically configure sliding window duration and failure thresholds in `config.json`.

---

### Q10: How does your SIEM handle Incident Response and Containment?
**Answer:**  
Our SIEM includes an **Active Firewall Blocklist**:
- When an analyst investigates a Critical/High alert, they can click **"🛡️ Block Attacker IP"**.
- The IP is recorded in the `blocked_ips` table and flagged as blocked across the dashboard.
- The analyst can assign the case to a team member, update the incident status (`New` -> `Investigating` -> `Contained` -> `Resolved`), and append audit notes.

---

### Q11: How did you integrate live Windows Event Logs?
**Answer:**  
We query the Windows Security event channel using PowerShell's `Get-WinEvent` cmdlet targeting:
- **Event ID 4625:** An account failed to log on (captures target username, source IP, failure sub-status).
- **Event ID 4624:** An account was successfully logged on (captures target user, logon type).  
The raw XML/JSON output is parsed and normalized into standard SIEM event schema.

---

### Q12: How are external notifications delivered?
**Answer:**  
We integrated HTTP Webhook dispatchers for **Discord** and **Slack**:
- When an alert meets or exceeds the configured notification severity (e.g. High or Critical), an asynchronous payload is sent to the webhook URL.
- In Discord, it renders as a rich, color-coded embed containing the attacker IP, target account, threat score, and MITRE classification.

---

### Q13: How is Threat Scoring calculated?
**Answer:**  
The threat scoring function calculates a risk score from $1$ to $100$ based on:
1. **Base Severity:** Critical (+45), High (+30), Medium (+15).
2. **Target Asset Criticality:** Privileged accounts (`admin`, `root`, `administrator`) add +15.
3. **Network Origin:** Public external IPs add +10.
4. **Volume:** Failure frequency beyond threshold adds scalable penalty points.

---

### Q14: What database is used and why?
**Answer:**  
We chose **SQLite**:
- Lightweight, zero-configuration, and fully self-contained serverless relational database.
- Perfect for local demonstration, college submissions, and embedded SOC storage without requiring external daemon setups like PostgreSQL or MySQL.

---

### Q15: What is the difference between Rule-Based Detection and Anomaly-Based Detection?
**Answer:**  
- **Rule-Based (Signature-Based):** Detects known attack patterns using deterministic rules (e.g. $X$ failed logins in $Y$ minutes, or SQLi regex). Very accurate with low false positives for known attacks.
- **Anomaly-Based:** Establishes a mathematical baseline of normal user behavior and alerts when deviations occur (e.g. our Unusual Login IP detection). Can detect zero-day or novel attacks.

---

### Q16: How does your real-time File Watcher work?
**Answer:**  
The file watcher uses a generator loop with file pointer tracking (`seek(0, SEEK_END)`). It continuously tails new lines appended to `live_stream.log`, parses them with regular expressions, and passes them to the correlation pipeline in real time.

---

### Q17: Can an analyst upload custom log files for ad-hoc analysis?
**Answer:**  
Yes. In the **Log Explorer** tab of the dashboard, analysts can upload any standard CSV log file. The correlation engine processes the uploaded events and outputs all detected threats immediately.

---

### Q18: What is MTTR and MTTD in a SOC?
**Answer:**  
- **MTTD (Mean Time to Detect):** The average time elapsed between when an attacker begins an exploit and when the SIEM generates an alert.
- **MTTR (Mean Time to Respond/Remediate):** The average time taken by SOC analysts to contain and resolve the security incident.

---

### Q19: What are the main challenges of scaling this SIEM to enterprise scale?
**Answer:**  
In enterprise production:
1. Log ingestion would require distributed streaming message brokers like **Apache Kafka**.
2. Storage would use distributed search clusters like **Elasticsearch / OpenSearch** or ClickHouse.
3. High availability and distributed correlation nodes would be necessary to handle gigabytes of logs per second.

---

### Q20: How would you summarize your project in one sentence?
**Answer:**  
*"Our project is an end-to-end, MITRE ATT&CK-aligned SIEM platform that ingests multi-source logs, correlates multi-stage cyber attacks in real time, enriches threats with geolocation and intelligence scoring, and provides SOC analysts with rapid incident response and containment workflows."*
