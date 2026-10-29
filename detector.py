"""detector.py - SIEM detection engine entry point (backward-compatible)."""
from core import engine, db

FAIL_THRESHOLD = 5
WINDOW_MINUTES = 5
BASELINE_LOGINS = 5
LOG_FILE = engine.DEFAULT_LOG_FILE


def run():
    alerts = engine.run_pipeline(save_to_db=True, notify=True)
    return alerts


if __name__ == "__main__":
    found = run()
    print(f"[+] SIEM Analysis complete. Raised {len(found)} alert(s):")
    for a in found:
        print(f"  [{a['severity']:<8}] {a['event_time']} | {a['alert_type']:<28} | User: {a['username']:<10} | IP: {a['ip']}")
