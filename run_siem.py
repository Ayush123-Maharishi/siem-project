"""run_siem.py - Central CLI orchestrator for the SIEM project."""
import argparse
import subprocess
import sys
from pathlib import Path

from collectors import generator, windows_events
from core import db, engine


def main():
    parser = argparse.ArgumentParser(description="🛡️ Enterprise SIEM Command-Line Orchestrator")
    parser.add_argument("--generate", action="store_true", help="Generate simulated enterprise logs")
    parser.add_argument("--detect", action="store_true", help="Execute SIEM correlation detection engine")
    parser.add_argument("--windows", action="store_true", help="Ingest live Windows Security Event logs")
    parser.add_argument("--dashboard", action="store_true", help="Launch interactive Streamlit SOC Dashboard")
    parser.add_argument("--all", action="store_true", help="Generate logs, ingest Windows events, detect, and report")

    args = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help()
        print("\n[Tip] Run 'python run_siem.py --all' for full pipeline or 'python run_siem.py --dashboard' to open UI.")
        return

    db.init_db()

    if args.generate or args.all:
        print("[*] Generating enterprise multi-vector security logs...")
        count = generator.generate()
        print(f"[+] Generated {count} log events into data/logs.csv")

    if args.windows or args.all:
        print("[*] Ingesting Windows Security Event Logs...")
        win_events = windows_events.collect_live_windows_events(max_events=30)
        print(f"[+] Collected {len(win_events)} Windows security logon events.")
        if win_events:
            engine.run_pipeline(events=win_events, save_to_db=True, notify=False)

    if args.detect or args.all:
        print("[*] Running SIEM correlation & threat detection rules...")
        alerts = engine.run_pipeline(save_to_db=True, notify=True)
        print(f"[+] Detection complete. Found {len(alerts)} security alerts:")
        for a in alerts:
            print(f"    [{a['severity']:<8}] {a['event_time']} | {a['alert_type']:<28} | User: {a['username']:<10} | IP: {a['ip']}")

    if args.dashboard:
        print("[*] Launching Streamlit SOC Dashboard...")
        dash_path = Path(__file__).parent / "dashboard.py"
        subprocess.run([sys.executable, "-m", "streamlit", "run", str(dash_path)])


if __name__ == "__main__":
    main()
