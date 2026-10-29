"""dashboard.py - Streamlit dashboard (stage 4: Dashboard).  Run: streamlit run dashboard.py"""
import pandas as pd
import streamlit as st

import db
import detector
import generate_logs

st.set_page_config(page_title="Basic SIEM Tool", page_icon="🛡️", layout="wide")
st.title("🛡️ Basic SIEM Tool")
st.caption("Simulated logs → rule-based detection → SQLite → dashboard")

# ---- sidebar: re-run the pipeline ----
with st.sidebar:
    st.header("Pipeline")
    if st.button("Regenerate logs & re-run detection", use_container_width=True):
        generate_logs.generate()
        detector.run()
        st.rerun()
    st.markdown(
        f"**Rules in use**\n- Brute force: {detector.FAIL_THRESHOLD}+ failures in "
        f"{detector.WINDOW_MINUTES} min per IP\n- Unusual IP: new network for a known user"
    )

alerts = pd.DataFrame(db.get_alerts())
if alerts.empty:
    st.info("No alerts yet. Click **Regenerate logs & re-run detection** in the sidebar.")
    st.stop()

# ---- filters ----
c1, c2 = st.columns(2)
sev = c1.multiselect("Severity", ["Critical", "High", "Medium"], default=["Critical", "High", "Medium"])
types = c2.multiselect("Alert type", sorted(alerts["alert_type"].unique()),
                       default=sorted(alerts["alert_type"].unique()))
view = alerts[alerts["severity"].isin(sev) & alerts["alert_type"].isin(types)]

# ---- summary numbers ----
m1, m2, m3, m4 = st.columns(4)
m1.metric("Total alerts", len(view))
m2.metric("Critical", int((view["severity"] == "Critical").sum()))
m3.metric("Brute-force alerts", int((view["alert_type"] == "Brute-Force Login").sum()))
m4.metric("Unusual-IP alerts", int((view["alert_type"] == "Unusual Login IP").sum()))

# ---- charts ----
left, right = st.columns(2)
with left:
    st.subheader("Alerts by type")
    st.bar_chart(view["alert_type"].value_counts())
with right:
    st.subheader("Top suspicious IPs")
    st.bar_chart(view["ip"].value_counts().head(5))

if detector.LOG_FILE.exists():
    logs = pd.read_csv(detector.LOG_FILE, parse_dates=["timestamp"])
    failed = logs[logs["status"] == "FAILED"]
    st.subheader("Failed logins over time")
    st.line_chart(failed.set_index("timestamp").resample("1h").size().rename("failed logins"))

# ---- alert table ----
st.subheader("Alert details")
st.dataframe(
    view[["event_time", "severity", "alert_type", "username", "ip", "details"]],
    use_container_width=True, hide_index=True,
)
