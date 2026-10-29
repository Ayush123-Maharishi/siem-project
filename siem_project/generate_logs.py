"""generate_logs.py - simulated login logs (stage 1: Log Generator).

Creates data/logs.csv with normal activity plus a few injected attacks:
  * brute force on 'admin' from 45.33.12.99 (7 failures, then success)
  * brute force on 'bob' from 198.51.100.7 (6 failures, never succeeds)
  * 'alice' suddenly logging in from 203.0.113.44 (unusual IP)
  * 3 failures from one IP (below the threshold -> should NOT alert)
"""
import csv
import random
from datetime import datetime, timedelta
from pathlib import Path

LOG_FILE = Path(__file__).parent / "data" / "logs.csv"

# Each user's usual network (first three octets of their IP)
USERS = {
    "alice": "192.168.1",
    "bob": "192.168.2",
    "carol": "10.0.0",
    "dave": "172.16.5",
    "eve": "192.168.3",
}
DAYS = 7


def _ts(dt):
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def generate(seed=42):
    random.seed(seed)
    end = datetime.now().replace(minute=0, second=0, microsecond=0)
    start = end - timedelta(days=DAYS)
    events = []

    # --- normal activity: a few working-hours logins per user per day ---
    for day in range(DAYS):
        base = start + timedelta(days=day)
        for user, net in USERS.items():
            for _ in range(random.randint(3, 6)):
                t = base + timedelta(hours=random.randint(8, 18),
                                     minutes=random.randint(0, 59),
                                     seconds=random.randint(0, 59))
                ip = f"{net}.{random.randint(10, 60)}"
                if random.random() < 0.06:  # occasional typo'd password
                    events.append((t - timedelta(seconds=20), user, ip, "FAILED"))
                events.append((t, user, ip, "SUCCESS"))

    # --- attack 1: brute force on admin, then success ---
    t = start + timedelta(days=DAYS - 2, hours=2, minutes=14)
    for i in range(7):
        events.append((t + timedelta(seconds=i * 15), "admin", "45.33.12.99", "FAILED"))
    events.append((t + timedelta(seconds=7 * 15), "admin", "45.33.12.99", "SUCCESS"))

    # --- attack 2: brute force on bob, never gets in ---
    t = start + timedelta(days=DAYS - 4, hours=23, minutes=40)
    for i in range(6):
        events.append((t + timedelta(seconds=i * 20), "bob", "198.51.100.7", "FAILED"))

    # --- attack 3: alice logs in from a brand-new IP ---
    t = start + timedelta(days=DAYS - 1, hours=3, minutes=30)
    events.append((t, "alice", "203.0.113.44", "SUCCESS"))

    # --- decoy: only 3 failures (below threshold, must not alert) ---
    t = start + timedelta(days=DAYS - 3, hours=11, minutes=5)
    for i in range(3):
        events.append((t + timedelta(seconds=i * 30), "carol", "10.0.0.77", "FAILED"))

    events.sort(key=lambda e: e[0])

    LOG_FILE.parent.mkdir(exist_ok=True)
    with open(LOG_FILE, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["timestamp", "username", "ip", "status"])
        for t, user, ip, status in events:
            w.writerow([_ts(t), user, ip, status])
    return len(events)


if __name__ == "__main__":
    n = generate()
    print(f"Generated {n} log events -> {LOG_FILE}")
