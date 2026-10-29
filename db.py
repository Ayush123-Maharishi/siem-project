"""db.py - SQLite database interface (backward-compatible)."""
from core.db import (
    DB_FILE,
    add_incident_note,
    block_ip,
    clear_alerts,
    clear_all,
    clear_logs,
    get_alert_by_id,
    get_alerts,
    get_blocked_ips,
    get_connection,
    get_incident_notes,
    get_logs,
    get_soc_metrics,
    init_db,
    is_ip_blocked,
    save_alerts,
    save_logs,
    unblock_ip,
    update_alert_status,
)

if __name__ == "__main__":
    init_db()
    metrics = get_soc_metrics()
    print("[+] Database Initialized:")
    for k, v in metrics.items():
        print(f"    - {k}: {v}")
