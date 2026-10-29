"""engine.py - SIEM Correlation and Threat Detection Engine."""
import csv
import json
import re
from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

from core import db, enrichment, rules

CONFIG_FILE = Path(__file__).resolve().parent.parent / "config" / "config.json"
DEFAULT_LOG_FILE = Path(__file__).resolve().parent.parent / "data" / "logs.csv"


def load_config() -> Dict[str, Any]:
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return {
        "detection": {
            "brute_force_fail_threshold": 5,
            "brute_force_window_minutes": 5,
            "unusual_ip_baseline_logins": 5,
            "port_scan_port_threshold": 4,
            "port_scan_window_seconds": 60,
            "ddos_request_threshold": 15,
            "ddos_window_seconds": 10,
        }
    }


def _parse_ts(val: Any) -> datetime:
    if isinstance(val, datetime):
        return val
    val_str = str(val).strip()
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%d/%b/%Y:%H:%M:%S"):
        try:
            return datetime.strptime(val_str, fmt)
        except ValueError:
            pass
    return datetime.now()


def _subnet(ip: str) -> str:
    parts = ip.strip().split(".")
    if len(parts) >= 3:
        return ".".join(parts[:3])
    return ip


def build_alert(
    event_time: datetime,
    alert_type: str,
    severity: str,
    username: str,
    ip: str,
    details: str,
    fail_count: int = 1,
) -> Dict[str, Any]:
    """Create an enriched SIEM alert object with MITRE mapping and risk score."""
    mitre = rules.get_rule_metadata(alert_type)
    score, risk_label = enrichment.calculate_threat_score(
        alert_type=alert_type,
        severity=severity,
        username=username,
        ip=ip,
        fail_count=fail_count,
    )
    geo = enrichment.get_ip_location(ip)

    return {
        "event_time": event_time.strftime("%Y-%m-%d %H:%M:%S"),
        "alert_type": alert_type,
        "severity": severity,
        "username": username or "Unknown",
        "ip": ip or "0.0.0.0",
        "details": f"{details} | Origin: {geo.get('country', 'Unknown')} ({geo.get('flag', '')})",
        "mitre_technique": f"{mitre['technique_id']} ({mitre['technique_name']})",
        "mitre_tactic": mitre["tactic"],
        "threat_score": score,
        "status": "New",
        "assigned_to": "Unassigned",
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


def detect_brute_force_and_compromise(events: List[Dict[str, Any]], cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Detect repeated failed authentications and subsequent successful logins."""
    alerts = []
    fail_threshold = cfg.get("brute_force_fail_threshold", 5)
    window = timedelta(minutes=cfg.get("brute_force_window_minutes", 5))

    recent_fails = defaultdict(deque)  # ip -> deque of failed events
    flagged = {}                       # ip -> last failure timestamp

    auth_events = [e for e in events if e.get("source", "Auth") == "Auth"]

    for e in auth_events:
        ip = e.get("ip", "")
        t = e["timestamp"]
        status = e.get("status", "").upper()
        user = e.get("username", "unknown")

        q = recent_fails[ip]
        while q and t - q[0]["timestamp"] > window:
            q.popleft()
        if ip in flagged and t - flagged[ip] > window:
            del flagged[ip]

        if status == "FAILED":
            q.append(e)
            if ip in flagged:
                flagged[ip] = t
            elif len(q) >= fail_threshold:
                flagged[ip] = t
                targets = ", ".join(sorted({x["username"] for x in q if x.get("username")}))
                alerts.append(
                    build_alert(
                        event_time=t,
                        alert_type="Brute-Force Login",
                        severity="High",
                        username=targets,
                        ip=ip,
                        details=f"{len(q)} failed logins targeting [{targets}] within {window.seconds // 60}m",
                        fail_count=len(q),
                    )
                )
        elif status == "SUCCESS" and ip in flagged:
            alerts.append(
                build_alert(
                    event_time=t,
                    alert_type="Login After Brute Force",
                    severity="Critical",
                    username=user,
                    ip=ip,
                    details=f"Target account '{user}' successfully logged in right after brute-force surge from {ip}",
                    fail_count=fail_threshold + 2,
                )
            )
            del flagged[ip]
            q.clear()

    return alerts


def detect_unusual_ip(events: List[Dict[str, Any]], cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Detect anomalous logins from unfamiliar IP subnets."""
    alerts = []
    baseline_threshold = cfg.get("unusual_ip_baseline_logins", 5)
    known_subnets = defaultdict(set)
    user_success_counts = Counter()

    auth_successes = [
        e for e in events
        if e.get("source", "Auth") == "Auth" and e.get("status", "").upper() == "SUCCESS"
    ]

    for e in auth_successes:
        user = e.get("username", "")
        ip = e.get("ip", "")
        if not user or not ip:
            continue
        net = _subnet(ip)
        t = e["timestamp"]

        if user_success_counts[user] >= baseline_threshold and net not in known_subnets[user]:
            usual_nets = ", ".join(sorted(n + ".x" for n in known_subnets[user]))
            alerts.append(
                build_alert(
                    event_time=t,
                    alert_type="Unusual Login IP",
                    severity="Medium",
                    username=user,
                    ip=ip,
                    details=f"User '{user}' logged in from new subnet {net}.x (Known subnets: {usual_nets})",
                )
            )
        known_subnets[user].add(net)
        user_success_counts[user] += 1

    return alerts


def detect_web_attacks(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Detect SQL Injection and Cross-Site Scripting patterns in web access logs."""
    alerts = []
    sqli_regex = re.compile(
        r"(\b(union\s+select|select\s+.*\s+from|insert\s+into|or\s+['\d]=['\d]|--|drop\s+table|sleep\(\d+\))\b)",
        re.IGNORECASE,
    )
    xss_regex = re.compile(
        r"(<script.*?>|javascript:|onload=|onerror=|alert\(|document\.cookie)",
        re.IGNORECASE,
    )

    web_events = [e for e in events if e.get("source") == "Web"]

    for e in web_events:
        details = e.get("details", "")
        ip = e.get("ip", "")
        user = e.get("username", "anonymous")
        t = e["timestamp"]

        if sqli_regex.search(details):
            alerts.append(
                build_alert(
                    event_time=t,
                    alert_type="SQL Injection Attack",
                    severity="Critical",
                    username=user,
                    ip=ip,
                    details=f"Injected SQL syntax detected in request payload: {details[:80]}...",
                )
            )
        elif xss_regex.search(details):
            alerts.append(
                build_alert(
                    event_time=t,
                    alert_type="Cross-Site Scripting (XSS)",
                    severity="High",
                    username=user,
                    ip=ip,
                    details=f"XSS malicious payload detected in web parameters: {details[:80]}...",
                )
            )

    return alerts


def detect_port_scans(events: List[Dict[str, Any]], cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Detect horizontal or vertical port scanning."""
    alerts = []
    threshold = cfg.get("port_scan_port_threshold", 4)
    window = timedelta(seconds=cfg.get("port_scan_window_seconds", 60))

    recent_probes = defaultdict(deque)  # ip -> deque of (timestamp, port)
    alerted_ips = set()

    scan_events = [e for e in events if e.get("source") == "Network" or "port" in e.get("details", "").lower()]

    for e in scan_events:
        ip = e.get("ip", "")
        t = e["timestamp"]
        # extract port
        match = re.search(r"port\s*[:=]?\s*(\d+)", e.get("details", ""), re.IGNORECASE)
        port = match.group(1) if match else "0"

        q = recent_probes[ip]
        while q and t - q[0][0] > window:
            q.popleft()

        q.append((t, port))
        distinct_ports = {p for _, p in q}

        if len(distinct_ports) >= threshold and ip not in alerted_ips:
            alerted_ips.add(ip)
            alerts.append(
                build_alert(
                    event_time=t,
                    alert_type="Port Scanning / Reconnaissance",
                    severity="High",
                    username=e.get("username", "N/A"),
                    ip=ip,
                    details=f"Probed {len(distinct_ports)} distinct ports ({', '.join(sorted(distinct_ports)[:6])}) within {window.seconds}s",
                )
            )

    return alerts


def detect_ddos(events: List[Dict[str, Any]], cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Detect HTTP flood / volumetric DoS."""
    alerts = []
    threshold = cfg.get("ddos_request_threshold", 15)
    window = timedelta(seconds=cfg.get("ddos_window_seconds", 10))

    recent_requests = defaultdict(deque)
    flagged = set()

    for e in events:
        ip = e.get("ip", "")
        t = e["timestamp"]
        q = recent_requests[ip]

        while q and t - q[0] > window:
            q.popleft()

        q.append(t)
        if len(q) >= threshold and ip not in flagged:
            flagged.add(ip)
            alerts.append(
                build_alert(
                    event_time=t,
                    alert_type="DDoS / HTTP Flood",
                    severity="Critical",
                    username=e.get("username", "N/A"),
                    ip=ip,
                    details=f"Excessive rate of {len(q)} requests in {window.seconds}s from single source IP",
                )
            )

    return alerts


def run_pipeline(
    events: Optional[List[Dict[str, Any]]] = None,
    log_file: Optional[Path] = None,
    save_to_db: bool = True,
    notify: bool = True,
) -> List[Dict[str, Any]]:
    """
    Execute end-to-end detection pipeline:
    1. Parse and normalize log stream
    2. Execute all correlation rules
    3. Store alerts & ingested logs in SQLite
    4. Dispatch notifications for high/critical threats
    """
    config = load_config()
    detection_cfg = config.get("detection", {})

    # Load from CSV if not supplied in-memory
    if events is None:
        target_path = log_file or DEFAULT_LOG_FILE
        if not target_path.exists():
            return []
        events = []
        with open(target_path, "r", newline="", encoding="utf-8", errors="ignore") as f:
            reader = csv.DictReader(f)
            for row in reader:
                ts = _parse_ts(row.get("timestamp", ""))
                events.append({
                    "timestamp": ts,
                    "source": row.get("source", "Auth"),
                    "username": row.get("username", "unknown"),
                    "ip": row.get("ip", "0.0.0.0"),
                    "action": row.get("action", "LOGIN"),
                    "status": row.get("status", "SUCCESS"),
                    "details": row.get("details", ""),
                })

    # Sort chronologically for sliding window evaluation
    events.sort(key=lambda x: x["timestamp"])

    # Run detection rules
    alerts: List[Dict[str, Any]] = []
    alerts.extend(detect_brute_force_and_compromise(events, detection_cfg))
    alerts.extend(detect_unusual_ip(events, detection_cfg))
    alerts.extend(detect_web_attacks(events))
    alerts.extend(detect_port_scans(events, detection_cfg))
    alerts.extend(detect_ddos(events, detection_cfg))

    alerts.sort(key=lambda a: a["event_time"])

    if save_to_db:
        db.init_db()
        db.clear_alerts()
        if alerts:
            db.save_alerts(alerts)

        # Store ingested logs sample in DB for fast UI searching
        db.clear_logs()
        formatted_logs = [
            {
                "timestamp": e["timestamp"].strftime("%Y-%m-%d %H:%M:%S"),
                "source": e.get("source", "Auth"),
                "username": e.get("username", "N/A"),
                "ip": e.get("ip", "N/A"),
                "action": e.get("action", "EVENT"),
                "status": e.get("status", "SUCCESS"),
                "details": e.get("details", ""),
            }
            for e in events[-2000:]  # archive up to latest 2000 events
        ]
        db.save_logs(formatted_logs)

    # Trigger notifications
    if notify and alerts:
        try:
            from integrations import notifier
            for a in alerts:
                if a["severity"] in ("Critical", "High"):
                    notifier.dispatch_alert(a)
        except Exception:
            pass

    return alerts
