"""db.py - SQLite storage for SIEM alerts, incidents, blocked IPs, and logs."""
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

DB_FILE = Path(__file__).resolve().parent.parent / "data" / "siem.db"


def get_connection() -> sqlite3.Connection:
    DB_FILE.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Create all required tables for the SIEM system."""
    with get_connection() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS alerts (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                event_time      TEXT NOT NULL,
                alert_type      TEXT NOT NULL,
                severity        TEXT NOT NULL,   -- Low / Medium / High / Critical
                username        TEXT,
                ip              TEXT,
                details         TEXT,
                mitre_technique TEXT,
                mitre_tactic    TEXT,
                threat_score    INTEGER DEFAULT 50,
                status          TEXT DEFAULT 'New', -- New / Investigating / Contained / Resolved / False Positive
                assigned_to     TEXT DEFAULT 'Unassigned',
                created_at      TEXT
            );

            CREATE TABLE IF NOT EXISTS blocked_ips (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                ip         TEXT UNIQUE NOT NULL,
                reason     TEXT,
                blocked_at TEXT,
                status     TEXT DEFAULT 'Active'
            );

            CREATE TABLE IF NOT EXISTS incident_notes (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id   INTEGER NOT NULL,
                author     TEXT,
                note       TEXT,
                created_at TEXT,
                FOREIGN KEY(alert_id) REFERENCES alerts(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS ingested_logs (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp  TEXT NOT NULL,
                source     TEXT NOT NULL,       -- Auth / Web / Network / Windows
                username   TEXT,
                ip         TEXT,
                action     TEXT,
                status     TEXT,                -- SUCCESS / FAILED / BLOCKED / ALLOWED
                details    TEXT
            );
            """
        )


def clear_alerts() -> None:
    """Clear all alerts and incident notes (useful for fresh simulation runs)."""
    with get_connection() as conn:
        conn.execute("DELETE FROM incident_notes")
        conn.execute("DELETE FROM alerts")


def clear_logs() -> None:
    """Clear ingested logs table."""
    with get_connection() as conn:
        conn.execute("DELETE FROM ingested_logs")


def clear_all() -> None:
    """Clear everything except blocked IPs."""
    clear_alerts()
    clear_logs()


def save_alerts(alerts: List[Dict[str, Any]]) -> None:
    """Bulk insert alerts into the database."""
    init_db()
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    records = []
    for a in alerts:
        records.append({
            "event_time": a.get("event_time", now_str),
            "alert_type": a.get("alert_type", "Unknown Alert"),
            "severity": a.get("severity", "Medium"),
            "username": a.get("username", "N/A"),
            "ip": a.get("ip", "N/A"),
            "details": a.get("details", ""),
            "mitre_technique": a.get("mitre_technique", "T1078"),
            "mitre_tactic": a.get("mitre_tactic", "Initial Access"),
            "threat_score": a.get("threat_score", 50),
            "status": a.get("status", "New"),
            "assigned_to": a.get("assigned_to", "Unassigned"),
            "created_at": a.get("created_at", now_str),
        })

    with get_connection() as conn:
        conn.executemany(
            """
            INSERT INTO alerts (
                event_time, alert_type, severity, username, ip, details,
                mitre_technique, mitre_tactic, threat_score, status, assigned_to, created_at
            )
            VALUES (
                :event_time, :alert_type, :severity, :username, :ip, :details,
                :mitre_technique, :mitre_tactic, :threat_score, :status, :assigned_to, :created_at
            )
            """,
            records,
        )


def get_alerts(
    severity: Optional[List[str]] = None,
    status: Optional[List[str]] = None,
    search: Optional[str] = None
) -> List[Dict[str, Any]]:
    """Query alerts with optional filtering."""
    init_db()
    query = "SELECT * FROM alerts WHERE 1=1"
    params: List[Any] = []

    if severity:
        placeholders = ",".join("?" * len(severity))
        query += f" AND severity IN ({placeholders})"
        params.extend(severity)

    if status:
        placeholders = ",".join("?" * len(status))
        query += f" AND status IN ({placeholders})"
        params.extend(status)

    if search:
        query += " AND (username LIKE ? OR ip LIKE ? OR alert_type LIKE ? OR details LIKE ?)"
        term = f"%{search}%"
        params.extend([term, term, term, term])

    query += " ORDER BY event_time DESC, id DESC"

    with get_connection() as conn:
        rows = conn.execute(query, params).fetchall()
    return [dict(r) for r in rows]


def get_alert_by_id(alert_id: int) -> Optional[Dict[str, Any]]:
    init_db()
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    return dict(row) if row else None


def update_alert_status(alert_id: int, status: str, assigned_to: Optional[str] = None) -> None:
    init_db()
    with get_connection() as conn:
        if assigned_to:
            conn.execute(
                "UPDATE alerts SET status = ?, assigned_to = ? WHERE id = ?",
                (status, assigned_to, alert_id),
            )
        else:
            conn.execute(
                "UPDATE alerts SET status = ? WHERE id = ?",
                (status, alert_id),
            )


def add_incident_note(alert_id: int, author: str, note: str) -> None:
    init_db()
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO incident_notes (alert_id, author, note, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (alert_id, author, note, now_str),
        )


def get_incident_notes(alert_id: int) -> List[Dict[str, Any]]:
    init_db()
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM incident_notes WHERE alert_id = ? ORDER BY created_at ASC",
            (alert_id,),
        ).fetchall()
    return [dict(r) for r in rows]


def block_ip(ip: str, reason: str = "SIEM automated/analyst defense rule") -> bool:
    init_db()
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with get_connection() as conn:
        try:
            conn.execute(
                """
                INSERT INTO blocked_ips (ip, reason, blocked_at, status)
                VALUES (?, ?, ?, 'Active')
                ON CONFLICT(ip) DO UPDATE SET status='Active', reason=excluded.reason, blocked_at=excluded.blocked_at
                """,
                (ip, reason, now_str),
            )
            return True
        except Exception:
            return False


def unblock_ip(ip: str) -> bool:
    init_db()
    with get_connection() as conn:
        conn.execute("UPDATE blocked_ips SET status = 'Unblocked' WHERE ip = ?", (ip,))
        return True


def get_blocked_ips() -> List[Dict[str, Any]]:
    init_db()
    with get_connection() as conn:
        rows = conn.execute("SELECT * FROM blocked_ips ORDER BY blocked_at DESC").fetchall()
    return [dict(r) for r in rows]


def is_ip_blocked(ip: str) -> bool:
    init_db()
    with get_connection() as conn:
        row = conn.execute("SELECT id FROM blocked_ips WHERE ip = ? AND status = 'Active'", (ip,)).fetchone()
    return row is not None


def save_logs(logs: List[Dict[str, Any]]) -> None:
    init_db()
    with get_connection() as conn:
        conn.executemany(
            """
            INSERT INTO ingested_logs (timestamp, source, username, ip, action, status, details)
            VALUES (:timestamp, :source, :username, :ip, :action, :status, :details)
            """,
            logs,
        )


def get_logs(limit: int = 500, source: Optional[str] = None) -> List[Dict[str, Any]]:
    init_db()
    with get_connection() as conn:
        if source and source != "All":
            rows = conn.execute(
                "SELECT * FROM ingested_logs WHERE source = ? ORDER BY timestamp DESC LIMIT ?",
                (source, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM ingested_logs ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            ).fetchall()
    return [dict(r) for r in rows]


def get_soc_metrics() -> Dict[str, Any]:
    init_db()
    with get_connection() as conn:
        total_alerts = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        critical_alerts = conn.execute("SELECT COUNT(*) FROM alerts WHERE severity = 'Critical'").fetchone()[0]
        high_alerts = conn.execute("SELECT COUNT(*) FROM alerts WHERE severity = 'High'").fetchone()[0]
        active_incidents = conn.execute("SELECT COUNT(*) FROM alerts WHERE status IN ('New', 'Investigating')").fetchone()[0]
        blocked_ips = conn.execute("SELECT COUNT(*) FROM blocked_ips WHERE status = 'Active'").fetchone()[0]
        total_logs = conn.execute("SELECT COUNT(*) FROM ingested_logs").fetchone()[0]

    return {
        "total_alerts": total_alerts,
        "critical_alerts": critical_alerts,
        "high_alerts": high_alerts,
        "active_incidents": active_incidents,
        "blocked_ips": blocked_ips,
        "total_logs": total_logs,
    }
