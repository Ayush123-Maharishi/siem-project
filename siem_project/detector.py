"""detector.py - rule-based detection (stage 2: Detector).

Rule 1  Brute force : >= FAIL_THRESHOLD failed logins from one IP within WINDOW_MINUTES.
        If that IP then logs in successfully, a Critical "possible compromise" alert is added.
Rule 2  Unusual IP  : a user logs in successfully from a network (/24) never seen for that
        account, once we have BASELINE_LOGINS successful logins to learn their normal.
"""
import csv
from collections import defaultdict, deque, Counter
from datetime import datetime, timedelta
from pathlib import Path

import db

LOG_FILE = Path(__file__).parent / "data" / "logs.csv"

FAIL_THRESHOLD = 5      # failed logins that trigger an alert
WINDOW_MINUTES = 5      # ...within this many minutes
BASELINE_LOGINS = 5     # successful logins needed before "unusual IP" applies
WINDOW = timedelta(minutes=WINDOW_MINUTES)


def load_events(path=LOG_FILE):
    with open(path, newline="") as f:
        events = [
            {**row, "timestamp": datetime.strptime(row["timestamp"], "%Y-%m-%d %H:%M:%S")}
            for row in csv.DictReader(f)
        ]
    events.sort(key=lambda e: e["timestamp"])
    return events


def _alert(event_time, alert_type, severity, username, ip, details):
    return {
        "event_time": event_time.strftime("%Y-%m-%d %H:%M:%S"),
        "alert_type": alert_type,
        "severity": severity,
        "username": username,
        "ip": ip,
        "details": details,
    }


def detect_brute_force(events):
    alerts = []
    recent_fails = defaultdict(deque)   # ip -> recent failed events
    flagged = {}                        # ip -> time of last failure in a flagged burst

    for e in events:
        ip, t = e["ip"], e["timestamp"]

        # forget old failures; end a flagged burst once the IP has been quiet
        q = recent_fails[ip]
        while q and t - q[0]["timestamp"] > WINDOW:
            q.popleft()
        if ip in flagged and t - flagged[ip] > WINDOW:
            del flagged[ip]

        if e["status"] == "FAILED":
            q.append(e)
            if ip in flagged:
                flagged[ip] = t         # burst continues, don't re-alert
            elif len(q) >= FAIL_THRESHOLD:
                flagged[ip] = t
                targets = ", ".join(sorted({x["username"] for x in q}))
                alerts.append(_alert(
                    t, "Brute-Force Login", "High", targets, ip,
                    f"{len(q)} failed logins from {ip} within {WINDOW_MINUTES} minutes",
                ))
        elif ip in flagged:             # success right after a flagged burst
            alerts.append(_alert(
                t, "Login After Brute Force", "Critical", e["username"], ip,
                f"'{e['username']}' logged in from {ip} right after repeated failures "
                f"- account may be compromised",
            ))
            del flagged[ip]
            q.clear()
    return alerts


def _subnet(ip):
    return ".".join(ip.split(".")[:3])


def detect_unusual_ip(events):
    alerts = []
    known = defaultdict(set)            # user -> set of networks seen
    successes = Counter()               # user -> successful logins so far

    for e in events:
        if e["status"] != "SUCCESS":
            continue
        user, net = e["username"], _subnet(e["ip"])
        if successes[user] >= BASELINE_LOGINS and net not in known[user]:
            alerts.append(_alert(
                e["timestamp"], "Unusual Login IP", "Medium", user, e["ip"],
                f"'{user}' logged in from {e['ip']}, a network never seen for this account "
                f"(usual: {', '.join(sorted(n + '.x' for n in known[user]))})",
            ))
        known[user].add(net)
        successes[user] += 1
    return alerts


def run():
    """Load logs, apply both rules, replace stored alerts. Returns the alerts."""
    events = load_events()
    alerts = detect_brute_force(events) + detect_unusual_ip(events)
    alerts.sort(key=lambda a: a["event_time"])
    db.init_db()
    db.clear_alerts()                   # rebuild from scratch so re-runs don't duplicate
    if alerts:
        db.save_alerts(alerts)
    return alerts


if __name__ == "__main__":
    found = run()
    print(f"Analysed logs, raised {len(found)} alert(s):")
    for a in found:
        print(f"  [{a['severity']:<8}] {a['event_time']}  {a['alert_type']:<24} {a['details']}")
