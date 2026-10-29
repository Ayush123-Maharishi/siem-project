"""dashboard.py - Enterprise-grade Streamlit SOC SIEM Dashboard.

Run with:
    streamlit run dashboard.py
"""
import io
import json
from datetime import datetime
from pathlib import Path

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from collectors import generator, syslog_parser, windows_events
from core import db, engine, enrichment, rules
from integrations import notifier, threat_intel

# Page Configuration
st.set_page_config(
    page_title="DEFENDER SOC — SIEM Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom Cyber SOC Dark Mode CSS
st.markdown(
    """
    <style>
        .reportview-container {
            background: #0d1117;
        }
        .metric-card {
            background: linear-gradient(135deg, #161b22 0%, #21262d 100%);
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 16px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
            text-align: center;
        }
        .metric-val {
            font-size: 28px;
            font-weight: 700;
            color: #58a6ff;
        }
        .metric-title {
            font-size: 13px;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: #8b949e;
        }
        .badge-crit {
            background-color: #f85149;
            color: white;
            padding: 3px 8px;
            border-radius: 4px;
            font-weight: 600;
            font-size: 12px;
        }
        .badge-high {
            background-color: #db6d28;
            color: white;
            padding: 3px 8px;
            border-radius: 4px;
            font-weight: 600;
            font-size: 12px;
        }
        .badge-med {
            background-color: #d29922;
            color: black;
            padding: 3px 8px;
            border-radius: 4px;
            font-weight: 600;
            font-size: 12px;
        }
        .badge-low {
            background-color: #388bfd;
            color: white;
            padding: 3px 8px;
            border-radius: 4px;
            font-weight: 600;
            font-size: 12px;
        }
    </style>
    """,
    unsafe_allow_html=True,
)

# Ensure database tables exist
db.init_db()

# ---- SIDEBAR CONTROLS ----
with st.sidebar:
    st.image(
        "https://cdn-icons-png.flaticon.com/512/2092/2092663.png",
        width=70,
    )
    st.title("🛡️ SOC Operations")
    st.caption("Next-Gen SIEM & Threat Defense")

    st.markdown("---")
    st.subheader("⚡ Quick Pipeline Actions")

    if st.button("🚀 Run Full Detection Pipeline", width="stretch", type="primary"):
        with st.spinner("Generating logs & running threat correlation..."):
            generator.generate()
            alerts = engine.run_pipeline(save_to_db=True, notify=True)
            st.success(f"Pipeline executed! Detected {len(alerts)} alerts.")
            st.rerun()

    if st.button("🪟 Ingest Windows Event Logs", width="stretch"):
        with st.spinner("Querying Windows Security Events..."):
            win_events = windows_events.collect_live_windows_events(max_events=40)
            if win_events:
                engine.run_pipeline(events=win_events, save_to_db=True, notify=False)
                st.success(f"Ingested {len(win_events)} live Windows logon events!")
                st.rerun()
            else:
                st.warning("No new Windows security events found.")

    if st.button("🧹 Clear All Stored Alerts", width="stretch"):
        db.clear_alerts()
        st.info("Database alerts cleared.")
        st.rerun()

    st.markdown("---")
    st.markdown(
        "**System Status**\n"
        "• Correlation Engine: `Active 🟢`\n"
        "• Threat Intel API: `Ready 🟢`\n"
        "• Blocklist Enforcer: `Enforcing 🔒`\n"
        "• MITRE ATT&CK Matrix: `v14.1`"
    )

# ---- HEADER ----
st.title("🛡️ DEFENDER SOC — SIEM Platform")
st.markdown(
    "**Enterprise Security Information & Event Management** | "
    "Real-time Threat Correlation • MITRE ATT&CK Mapping • Automated Incident Response"
)

# ---- EXECUTIVE METRICS RIBBON ----
metrics = db.get_soc_metrics()
c1, c2, c3, c4, c5, c6 = st.columns(6)

with c1:
    st.markdown(
        f'<div class="metric-card"><div class="metric-val">{metrics["total_logs"]}</div><div class="metric-title">Ingested Logs</div></div>',
        unsafe_allow_html=True,
    )
with c2:
    st.markdown(
        f'<div class="metric-card"><div class="metric-val">{metrics["total_alerts"]}</div><div class="metric-title">Total Alerts</div></div>',
        unsafe_allow_html=True,
    )
with c3:
    st.markdown(
        f'<div class="metric-card"><div class="metric-val" style="color:#f85149;">{metrics["critical_alerts"]}</div><div class="metric-title">Critical Threats</div></div>',
        unsafe_allow_html=True,
    )
with c4:
    st.markdown(
        f'<div class="metric-card"><div class="metric-val" style="color:#db6d28;">{metrics["high_alerts"]}</div><div class="metric-title">High Priority</div></div>',
        unsafe_allow_html=True,
    )
with c5:
    st.markdown(
        f'<div class="metric-card"><div class="metric-val" style="color:#d29922;">{metrics["active_incidents"]}</div><div class="metric-title">Active Cases</div></div>',
        unsafe_allow_html=True,
    )
with c6:
    st.markdown(
        f'<div class="metric-card"><div class="metric-val" style="color:#2ea043;">{metrics["blocked_ips"]}</div><div class="metric-title">Blocked IPs</div></div>',
        unsafe_allow_html=True,
    )

st.markdown("<br>", unsafe_allow_html=True)

# Fetch all alerts
all_alerts = db.get_alerts()
df_alerts = pd.DataFrame(all_alerts) if all_alerts else pd.DataFrame()

# ---- NAVIGATION TABS ----
tab_overview, tab_triage, tab_deepdive, tab_mitre, tab_logs, tab_firewall, tab_integrations, tab_reports = st.tabs([
    "📊 Executive Overview",
    "🚨 Alert Triage & SOC Cases",
    "🔍 Threat Deep-Dive",
    "🛡️ MITRE ATT&CK Matrix",
    "📜 Log Explorer",
    "🚫 Firewall Blocklist",
    "⚙️ Integrations & Webhooks",
    "📄 Incident Reports",
])

# ==============================================================================
# TAB 1: EXECUTIVE OVERVIEW
# ==============================================================================
with tab_overview:
    if df_alerts.empty:
        st.info("ℹ️ No alerts currently in database. Click **🚀 Run Full Detection Pipeline** in the sidebar to simulate enterprise attacks!")
    else:
        col_chart1, col_chart2 = st.columns([1, 1])

        with col_chart1:
            st.subheader("Severity Distribution")
            sev_counts = df_alerts["severity"].value_counts().reset_index()
            sev_counts.columns = ["Severity", "Count"]
            color_map = {
                "Critical": "#f85149",
                "High": "#db6d28",
                "Medium": "#d29922",
                "Low": "#388bfd",
            }
            fig_sev = px.pie(
                sev_counts,
                values="Count",
                names="Severity",
                color="Severity",
                color_discrete_map=color_map,
                hole=0.45,
            )
            fig_sev.update_layout(margin=dict(t=10, b=10, l=10, r=10), height=300)
            st.plotly_chart(fig_sev, width="stretch")

        with col_chart2:
            st.subheader("Threats by Detection Category")
            type_counts = df_alerts["alert_type"].value_counts().reset_index()
            type_counts.columns = ["Alert Type", "Count"]
            fig_type = px.bar(
                type_counts,
                x="Count",
                y="Alert Type",
                orientation="h",
                color="Count",
                color_continuous_scale="Reds",
            )
            fig_type.update_layout(margin=dict(t=10, b=10, l=10, r=10), height=300)
            st.plotly_chart(fig_type, width="stretch")

        col_ip, col_user = st.columns(2)
        with col_ip:
            st.subheader("Top Attacker IPs & Origin")
            top_ips = df_alerts["ip"].value_counts().head(5).reset_index()
            top_ips.columns = ["Attacker IP", "Alerts Triggered"]
            top_ips["Geo / Country"] = top_ips["Attacker IP"].apply(
                lambda ip: f"{enrichment.get_ip_location(ip).get('flag', '')} {enrichment.get_ip_location(ip).get('country', 'Unknown')}"
            )
            top_ips["Firewall Status"] = top_ips["Attacker IP"].apply(
                lambda ip: "🚫 Blocked" if db.is_ip_blocked(ip) else "⚠️ Active"
            )
            st.dataframe(top_ips, width="stretch", hide_index=True)

        with col_user:
            st.subheader("Top Targeted User Accounts")
            top_users = df_alerts["username"].value_counts().head(5).reset_index()
            top_users.columns = ["Target Account", "Incident Count"]
            top_users["Risk Level"] = top_users["Target Account"].apply(
                lambda u: "🔴 High Profile" if u in ("admin", "root", "administrator") else "🟡 Standard User"
            )
            st.dataframe(top_users, width="stretch", hide_index=True)


# ==============================================================================
# TAB 2: ALERT TRIAGE & SOC CASES
# ==============================================================================
with tab_triage:
    st.subheader("🚨 Real-Time Alert Triage & Incident Workflow")

    if df_alerts.empty:
        st.info("No security alerts detected. Generate logs from the sidebar.")
    else:
        # Filters
        f1, f2, f3 = st.columns(3)
        with f1:
            all_sevs = ["Critical", "High", "Medium", "Low"]
            sel_sev = st.multiselect("Filter Severity", all_sevs, default=all_sevs)
        with f2:
            all_statuses = ["New", "Investigating", "Contained", "Resolved", "False Positive"]
            sel_status = st.multiselect("Filter Incident Status", all_statuses, default=all_statuses)
        with f3:
            search_query = st.text_input("Search Alert / IP / User", placeholder="e.g. admin or 45.33")

        filtered_alerts = db.get_alerts(severity=sel_sev, status=sel_status, search=search_query)

        st.caption(f"Showing **{len(filtered_alerts)}** filtered incident(s)")

        for alert in filtered_alerts:
            aid = alert["id"]
            sev = alert["severity"]
            badge_class = f"badge-{sev.lower()[:4]}"
            is_blocked = db.is_ip_blocked(alert["ip"])

            with st.expander(
                f"[{sev.upper()}] #{aid} — {alert['alert_type']} | User: {alert['username']} | IP: {alert['ip']} ({alert['status']})",
                expanded=(sev == "Critical"),
            ):
                d1, d2, d3, d4 = st.columns(4)
                d1.metric("Threat Score", f"{alert['threat_score']}/100")
                d2.write(f"**Timestamp:** `{alert['event_time']}`")
                d3.write(f"**MITRE Technique:** `{alert['mitre_technique']}`")
                d4.write(f"**MITRE Tactic:** `{alert['mitre_tactic']}`")

                st.write(f"**Details:** {alert['details']}")

                # SOC Action Controls
                st.markdown("---")
                ac1, ac2, ac3, ac4 = st.columns([2, 2, 2, 2])

                with ac1:
                    new_status = st.selectbox(
                        "Update Status",
                        ["New", "Investigating", "Contained", "Resolved", "False Positive"],
                        index=["New", "Investigating", "Contained", "Resolved", "False Positive"].index(alert["status"])
                        if alert["status"] in ["New", "Investigating", "Contained", "Resolved", "False Positive"]
                        else 0,
                        key=f"status_{aid}",
                    )
                    if st.button("Apply Status", key=f"btn_status_{aid}"):
                        db.update_alert_status(aid, new_status)
                        st.success(f"Alert #{aid} updated to {new_status}!")
                        st.rerun()

                with ac2:
                    analyst = st.text_input(
                        "Assign SOC Analyst",
                        value=alert.get("assigned_to", "Unassigned"),
                        key=f"analyst_{aid}",
                    )
                    if st.button("Assign", key=f"btn_assign_{aid}"):
                        db.update_alert_status(aid, alert["status"], analyst)
                        st.success(f"Assigned to {analyst}!")
                        st.rerun()

                with ac3:
                    if not is_blocked:
                        if st.button("🛡️ Block Attacker IP", key=f"blk_{aid}", type="primary"):
                            db.block_ip(alert["ip"], f"Automated block triggered from Alert #{aid} ({alert['alert_type']})")
                            st.error(f"IP {alert['ip']} added to Firewall Blocklist!")
                            st.rerun()
                    else:
                        st.success("🔒 IP Already Blocked")
                        if st.button("🔓 Unblock IP", key=f"unblk_{aid}"):
                            db.unblock_ip(alert["ip"])
                            st.warning(f"IP {alert['ip']} unblocked.")
                            st.rerun()

                with ac4:
                    # Test webhook dispatch
                    if st.button("📢 Send Discord Alert", key=f"btn_disc_{aid}"):
                        ok = notifier.send_discord_alert(alert)
                        if ok:
                            st.success("Discord notification dispatched!")
                        else:
                            st.warning("Discord webhook not configured or failed.")

                # Incident Notes section
                st.markdown("##### 📝 Case Investigation Notes")
                notes = db.get_incident_notes(aid)
                for n in notes:
                    st.markdown(f"- **{n['author']}** (`{n['created_at']}`): {n['note']}")

                col_n1, col_n2 = st.columns([3, 1])
                with col_n1:
                    note_text = st.text_input("Add investigation note", key=f"note_txt_{aid}", placeholder="e.g. Confirmed false positive on developer test subnet.")
                with col_n2:
                    if st.button("Add Note", key=f"note_btn_{aid}"):
                        if note_text.strip():
                            db.add_incident_note(aid, "Analyst", note_text.strip())
                            st.success("Note saved!")
                            st.rerun()


# ==============================================================================
# TAB 3: THREAT DEEP-DIVE
# ==============================================================================
with tab_deepdive:
    st.subheader("🔍 Entity Threat Deep-Dive & Geolocation Investigation")

    if df_alerts.empty:
        st.info("No entities available for investigation yet.")
    else:
        unique_ips = sorted(df_alerts["ip"].unique())
        selected_ip = st.selectbox("Select Target IP to Investigate", unique_ips)

        if selected_ip:
            geo_info = enrichment.get_ip_location(selected_ip)
            intel_info = threat_intel.query_abuseipdb(selected_ip)

            i1, i2, i3, i4 = st.columns(4)
            i1.metric("Country", f"{geo_info.get('flag', '')} {geo_info.get('country', 'Unknown')}")
            i2.metric("ISP / Network", geo_info.get("isp", "Unknown"))
            i3.metric("Abuse Confidence Score", f"{intel_info.get('abuse_score', 0)}%")
            i4.metric("Threat Reports", intel_info.get("total_reports", 0))

            # Threat score gauge
            fig_gauge = go.Figure(
                go.Indicator(
                    mode="gauge+number",
                    value=intel_info.get("abuse_score", 0),
                    title={"text": "Threat Intelligence Risk Index"},
                    gauge={
                        "axis": {"range": [0, 100]},
                        "bar": {"color": "#f85149" if intel_info.get("abuse_score", 0) > 70 else "#db6d28"},
                        "steps": [
                            {"range": [0, 30], "color": "#238636"},
                            {"range": [30, 70], "color": "#d29922"},
                            {"range": [70, 100], "color": "#da3633"},
                        ],
                    },
                )
            )
            fig_gauge.update_layout(height=240, margin=dict(t=30, b=10, l=10, r=10))
            st.plotly_chart(fig_gauge, width="stretch")

            # History of events for this IP
            st.subheader(f"All Correlated Security Events for {selected_ip}")
            ip_alerts = df_alerts[df_alerts["ip"] == selected_ip]
            st.dataframe(
                ip_alerts[["event_time", "severity", "alert_type", "username", "status", "details"]],
                width="stretch",
                hide_index=True,
            )


# ==============================================================================
# TAB 4: MITRE ATT&CK MATRIX
# ==============================================================================
with tab_mitre:
    st.subheader("🛡️ MITRE ATT&CK Matrix Alignment")
    st.markdown(
        "The SIEM automatically categorizes detected suspicious activities against the "
        "[MITRE ATT&CK Enterprise Framework](https://attack.mitre.org/), empowering SOC teams with "
        "adversary tactics, techniques, and validated remediation playbooks."
    )

    tactic_groups = {}
    for rule_name, meta in rules.MITRE_MATRIX.items():
        tac = meta["tactic"]
        if tac not in tactic_groups:
            tactic_groups[tac] = []
        tactic_groups[tac].append((rule_name, meta))

    cols = st.columns(len(tactic_groups))
    for idx, (tactic, items) in enumerate(tactic_groups.items()):
        with cols[idx]:
            st.markdown(f"#### 🎯 {tactic}")
            for rule_name, meta in items:
                # Check if currently active in alerts
                is_active = not df_alerts.empty and rule_name in df_alerts["alert_type"].values
                color_border = "#f85149" if is_active else "#30363d"
                st.markdown(
                    f"""
                    <div style="border: 2px solid {color_border}; border-radius: 6px; padding: 10px; margin-bottom: 10px; background: #161b22;">
                        <div style="font-weight: 700; color: #58a6ff;">{meta['technique_id']}</div>
                        <div style="font-size: 13px; font-weight: 600;">{rule_name}</div>
                        <div style="font-size: 11px; color: #8b949e; margin-top: 4px;">{meta['technique_name']}</div>
                        <div style="margin-top: 6px;">
                            <span style="font-size: 11px; color: {'#f85149' if is_active else '#8b949e'}; font-weight: bold;">
                                {'🔴 ACTIVE DETECTION' if is_active else '⚪ Inactive'}
                            </span>
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
                with st.expander(f"Remediation Playbook"):
                    st.write(f"**Description:** {meta['description']}")
                    st.write(f"**Recommended Action:** {meta['remediation']}")


# ==============================================================================
# TAB 5: LOG EXPLORER
# ==============================================================================
with tab_logs:
    st.subheader("📜 Raw Log Ingestion & Forensic Search")

    col_l1, col_l2 = st.columns([1, 2])
    with col_l1:
        log_source = st.selectbox("Log Source Filter", ["All", "Auth", "Web", "Network", "Windows"])
    with col_l2:
        log_search = st.text_input("Filter Raw Logs by Keyword", placeholder="e.g. 45.33 or FAILED or HTTP")

    raw_logs = db.get_logs(limit=300, source=log_source)
    if raw_logs:
        df_logs = pd.DataFrame(raw_logs)
        if log_search:
            mask = df_logs.apply(lambda row: row.astype(str).str.contains(log_search, case=False).any(), axis=1)
            df_logs = df_logs[mask]

        st.caption(f"Showing **{len(df_logs)}** log records")
        st.dataframe(
            df_logs[["timestamp", "source", "ip", "username", "action", "status", "details"]],
            width="stretch",
            hide_index=True,
        )
    else:
        st.info("No logs in database. Run the pipeline from the sidebar to populate logs.")

    st.markdown("---")
    st.subheader("📤 Ad-Hoc Log File Ingestion")
    uploaded_file = st.file_uploader("Upload custom CSV log file (with timestamp, source, username, ip, status)", type=["csv", "log"])
    if uploaded_file:
        try:
            df_upload = pd.read_csv(uploaded_file)
            st.success(f"Uploaded {len(df_upload)} records successfully!")
            st.dataframe(df_upload.head(5), width="stretch")
            if st.button("Run Threat Correlation on Uploaded Logs"):
                events = df_upload.to_dict(orient="records")
                alerts = engine.run_pipeline(events=events, save_to_db=True, notify=False)
                st.success(f"Analysis complete! Detected {len(alerts)} alerts.")
                st.rerun()
        except Exception as ex:
            st.error(f"Error parsing uploaded file: {ex}")


# ==============================================================================
# TAB 6: FIREWALL BLOCKLIST
# ==============================================================================
with tab_firewall:
    st.subheader("🚫 Active Firewall Blocklist & Defense Controls")
    st.markdown("Automated containment rules actively drop traffic from flagged threat actors.")

    col_b1, col_b2 = st.columns([2, 1])
    with col_b1:
        blocked_list = db.get_blocked_ips()
        if blocked_list:
            df_blocked = pd.DataFrame(blocked_list)
            st.dataframe(
                df_blocked[["ip", "reason", "blocked_at", "status"]],
                width="stretch",
                hide_index=True,
            )
        else:
            st.info("Firewall blocklist is currently empty.")

    with col_b2:
        st.markdown("#### ➕ Manual Block / Unblock")
        manual_ip = st.text_input("IP Address to Block", placeholder="e.g. 198.51.100.7")
        manual_reason = st.text_input("Block Reason", value="Manual SOC containment policy")
        if st.button("🚫 Enforce Block", type="primary"):
            if manual_ip.strip():
                db.block_ip(manual_ip.strip(), manual_reason)
                st.success(f"IP {manual_ip.strip()} blocked!")
                st.rerun()

        if manual_ip.strip() and st.button("🔓 Remove Block"):
            db.unblock_ip(manual_ip.strip())
            st.warning(f"IP {manual_ip.strip()} unblocked.")
            st.rerun()


# ==============================================================================
# TAB 7: INTEGRATIONS & WEBHOOKS
# ==============================================================================
with tab_integrations:
    st.subheader("⚙️ SIEM Integrations & SOC Notification Hub")

    config = engine.load_config()
    cur_notif = config.get("notifications", {})
    cur_thresh = config.get("detection", {})

    col_int1, col_int2 = st.columns(2)

    with col_int1:
        st.markdown("#### 🔔 Webhook Alert Dispatchers")
        discord_url = st.text_input(
            "Discord Webhook URL",
            value=cur_notif.get("discord_webhook_url", ""),
            placeholder="https://discord.com/api/webhooks/...",
            help="Paste your Discord channel webhook URL here to receive real-time embed alerts.",
        )
        slack_url = st.text_input(
            "Slack Webhook URL",
            value=cur_notif.get("slack_webhook_url", ""),
            placeholder="https://hooks.slack.com/services/...",
        )
        min_severity = st.selectbox(
            "Minimum Alert Severity to Dispatch",
            ["Critical", "High", "Medium", "Low"],
            index=["Critical", "High", "Medium", "Low"].index(cur_notif.get("min_severity_to_notify", "High")),
        )

        if st.button("Save Webhook Settings"):
            config["notifications"]["discord_webhook_url"] = discord_url.strip()
            config["notifications"]["slack_webhook_url"] = slack_url.strip()
            config["notifications"]["min_severity_to_notify"] = min_severity
            with open(engine.CONFIG_FILE, "w") as f:
                json.dump(config, f, indent=2)
            st.success("Notification settings saved!")

        st.markdown("---")
        st.markdown("#### 🧪 Test Webhook Delivery")
        if st.button("📢 Send Test Discord Alert"):
            test_alert = {
                "event_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "alert_type": "TEST SOC ALERT - Discord Integration",
                "severity": "Critical",
                "username": "admin",
                "ip": "45.33.12.99",
                "details": "This is a verified test alert sent from the DEFENDER SIEM platform.",
                "mitre_tactic": "Initial Access",
                "mitre_technique": "T1110.001 (Password Guessing)",
                "threat_score": 95,
            }
            if discord_url.strip():
                ok = notifier.send_discord_alert(test_alert, webhook_url=discord_url.strip())
                if ok:
                    st.success("Test alert successfully delivered to Discord!")
                else:
                    st.error("Failed to deliver alert. Please verify webhook URL.")
            else:
                st.warning("Please enter a Discord Webhook URL first.")

    with col_int2:
        st.markdown("#### ⚙️ Detection Thresholds & Rule Engine")
        bf_thresh = st.number_input(
            "Brute Force Failure Threshold",
            min_value=2,
            max_value=20,
            value=int(cur_thresh.get("brute_force_fail_threshold", 5)),
        )
        bf_window = st.number_input(
            "Brute Force Sliding Window (Minutes)",
            min_value=1,
            max_value=60,
            value=int(cur_thresh.get("brute_force_window_minutes", 5)),
        )
        ps_thresh = st.number_input(
            "Port Scan Distinct Port Threshold",
            min_value=2,
            max_value=20,
            value=int(cur_thresh.get("port_scan_port_threshold", 4)),
        )
        ddos_thresh = st.number_input(
            "DDoS Request Threshold per 10s Window",
            min_value=5,
            max_value=100,
            value=int(cur_thresh.get("ddos_request_threshold", 15)),
        )

        if st.button("Save Detection Thresholds"):
            config["detection"]["brute_force_fail_threshold"] = bf_thresh
            config["detection"]["brute_force_window_minutes"] = bf_window
            config["detection"]["port_scan_port_threshold"] = ps_thresh
            config["detection"]["ddos_request_threshold"] = ddos_thresh
            with open(engine.CONFIG_FILE, "w") as f:
                json.dump(config, f, indent=2)
            st.success("Detection rules configuration updated!")


# ==============================================================================
# TAB 8: INCIDENT REPORTS
# ==============================================================================
with tab_reports:
    st.subheader("📄 SOC Executive Incident Report Generator")
    st.markdown("Export comprehensive incident audit logs and metrics for college submission or management review.")

    if df_alerts.empty:
        st.info("No incident records available to generate report.")
    else:
        rep_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        report_md = f"""# 🛡️ DEFENDER SOC — INCIDENT AUDIT REPORT
**Generated:** {rep_date}  
**Classification:** CONFIDENTIAL / COLLEGE EVALUATION  

---

## 1. Executive Summary
- **Total Ingested Log Events:** {metrics['total_logs']}
- **Total Incidents Detected:** {metrics['total_alerts']}
- **Critical Severity Incidents:** {metrics['critical_alerts']}
- **High Severity Incidents:** {metrics['high_alerts']}
- **Active Firewall Blocks:** {metrics['blocked_ips']}

---

## 2. Security Incident Log
| ID | Timestamp | Severity | Alert Type | Target Account | Attacker IP | Threat Score | Status |
|---|---|---|---|---|---|---|---|
"""
        for a in all_alerts:
            report_md += f"| #{a['id']} | {a['event_time']} | {a['severity']} | {a['alert_type']} | {a['username']} | {a['ip']} | {a['threat_score']}/100 | {a['status']} |\n"

        report_md += """
---
## 3. Defense Recommendations
1. Enforce multi-factor authentication (MFA) on all administrative portals.
2. Maintain active IP perimeter blocking on repeat offensive subnets.
3. Apply Web Application Firewall (WAF) signatures for SQL injection and cross-site scripting prevention.
4. Review Windows Event Security Audit policies for continuous logon monitoring.
"""

        st.markdown(report_md)

        # Download buttons
        csv_buffer = io.StringIO()
        df_alerts.to_csv(csv_buffer, index=False)
        st.download_button(
            label="📥 Download Alerts as CSV",
            data=csv_buffer.getvalue(),
            file_name=f"SIEM_Alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv",
        )

        st.download_button(
            label="📥 Download Executive Summary (Markdown)",
            data=report_md,
            file_name=f"SIEM_Executive_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md",
            mime="text/markdown",
        )
