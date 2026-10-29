"""file_watcher.py - Real-time log file tailer and live event stream consumer."""
import os
import time
from pathlib import Path
from typing import Callable, Optional

from collectors import syslog_parser
from core import engine

WATCH_FILE = Path(__file__).resolve().parent.parent / "data" / "live_stream.log"


def tail_log_stream(
    filepath: Optional[Path] = None,
    callback: Optional[Callable] = None,
    poll_interval: float = 1.0,
    max_loops: Optional[int] = None,
) -> None:
    """
    Tail a log file in real time, parse new entries, and pass to SIEM detection engine.
    """
    target = filepath or WATCH_FILE
    target.parent.mkdir(parents=True, exist_ok=True)
    if not target.exists():
        target.touch()

    print(f"[*] Starting SIEM Real-time Watcher on: {target}")

    with open(target, "r", encoding="utf-8", errors="ignore") as f:
        # Seek to end of file to only process newly appended lines
        f.seek(0, os.SEEK_END)
        loops = 0

        while True:
            line = f.readline()
            if line:
                event = syslog_parser.parse_log_line(line)
                if event:
                    print(f"[STREAM] Ingested: [{event['source']}] {event['ip']} -> {event['status']}")
                    engine.run_pipeline([event], save_to_db=True, notify=True)
                    if callback:
                        callback(event)
            else:
                time.sleep(poll_interval)

            loops += 1
            if max_loops and loops >= max_loops:
                break


if __name__ == "__main__":
    tail_log_stream()
