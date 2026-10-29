"""db.py - SQLite storage for alerts (stage 3: Database)."""
import sqlite3
from pathlib import Path

DB_FILE = Path(__file__).parent / "data" / "siem.db"


def get_connection():
    DB_FILE.parent.mkdir(exist_ok=True)
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create the alerts table if it doesn't exist."""
    with get_connection() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS alerts (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                event_time TEXT NOT NULL,   -- when the suspicious event happened
                alert_type TEXT NOT NULL,   -- e.g. Brute-Force Login
                severity   TEXT NOT NULL,   -- Medium / High / Critical
                username   TEXT,
                ip         TEXT,
                details    TEXT
            )
            """
        )


def clear_alerts():
    with get_connection() as conn:
        conn.execute("DELETE FROM alerts")


def save_alerts(alerts):
    """alerts: list of dicts with keys event_time, alert_type, severity, username, ip, details."""
    with get_connection() as conn:
        conn.executemany(
            """
            INSERT INTO alerts (event_time, alert_type, severity, username, ip, details)
            VALUES (:event_time, :alert_type, :severity, :username, :ip, :details)
            """,
            alerts,
        )


def get_alerts():
    """Return all alerts, newest first, as a list of dicts."""
    init_db()
    with get_connection() as conn:
        rows = conn.execute("SELECT * FROM alerts ORDER BY event_time DESC").fetchall()
    return [dict(r) for r in rows]
