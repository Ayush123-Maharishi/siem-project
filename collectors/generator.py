"""generator.py - Multi-vector enterprise log generator for SIEM simulation."""
import csv
import random
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List

LOG_FILE = Path(__file__).resolve().parent.parent / "data" / "logs.csv"
STREAM_FILE = Path(__file__).resolve().parent.parent / "data" / "live_stream.log"

USERS = {
    "alice": "192.168.1",
    "bob": "192.168.2",
    "carol": "10.0.0",
    "dave": "172.16.5",
    "eve": "192.168.3",
}

COMMON_ENDPOINTS = [
    "/index.html",
    "/dashboard",
    "/api/v1/metrics",
    "/login",
    "/profile",
    "/settings",
    "/assets/style.css",
]

DAYS = 7


def _fmt(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def generate(seed: int = 42) -> int:
    """Generate simulated enterprise security logs including benign events and multi-stage attacks."""
    random.seed(seed)
    end = datetime.now().replace(minute=0, second=0, microsecond=0)
    start = end - timedelta(days=DAYS)
    events: List[Dict[str, Any]] = []

    # 1. Normal Working-Hours Authentication & Web Access
    for day in range(DAYS):
        base = start + timedelta(days=day)
        for user, net in USERS.items():
            # Auth events
            for _ in range(random.randint(3, 6)):
                t = base + timedelta(
                    hours=random.randint(8, 18),
                    minutes=random.randint(0, 59),
                    seconds=random.randint(0, 59),
                )
                ip = f"{net}.{random.randint(10, 60)}"
                if random.random() < 0.05:  # Occasional innocent typo
                    events.append({
                        "timestamp": t - timedelta(seconds=15),
                        "source": "Auth",
                        "username": user,
                        "ip": ip,
                        "action": "LOGIN",
                        "status": "FAILED",
                        "details": "Invalid credentials provided",
                    })
                events.append({
                    "timestamp": t,
                    "source": "Auth",
                    "username": user,
                    "ip": ip,
                    "action": "LOGIN",
                    "status": "SUCCESS",
                    "details": "User authentication successful via password + session token",
                })

            # Normal Web HTTP traffic
            for _ in range(random.randint(8, 15)):
                tw = base + timedelta(
                    hours=random.randint(8, 19),
                    minutes=random.randint(0, 59),
                    seconds=random.randint(0, 59),
                )
                endpoint = random.choice(COMMON_ENDPOINTS)
                ip = f"{net}.{random.randint(10, 60)}"
                events.append({
                    "timestamp": tw,
                    "source": "Web",
                    "username": user,
                    "ip": ip,
                    "action": "HTTP_GET",
                    "status": "SUCCESS",
                    "details": f"GET {endpoint} HTTP/1.1 200 OK - Mozilla/5.0",
                })

    # 2. Attack Scenario 1: Brute Force on 'admin' followed by Compromise (Critical)
    t_atk1 = start + timedelta(days=DAYS - 2, hours=2, minutes=14)
    atk1_ip = "45.33.12.99"
    for i in range(7):
        events.append({
            "timestamp": t_atk1 + timedelta(seconds=i * 12),
            "source": "Auth",
            "username": "admin",
            "ip": atk1_ip,
            "action": "LOGIN",
            "status": "FAILED",
            "details": f"Failed password attempt ({i+1}/7) for user admin",
        })
    events.append({
        "timestamp": t_atk1 + timedelta(seconds=7 * 12),
        "source": "Auth",
        "username": "admin",
        "ip": atk1_ip,
        "action": "LOGIN",
        "status": "SUCCESS",
        "details": "Authentication succeeded after multiple failure attempts",
    })

    # 3. Attack Scenario 2: Persistent Brute Force on 'bob' (High)
    t_atk2 = start + timedelta(days=DAYS - 4, hours=23, minutes=40)
    atk2_ip = "198.51.100.7"
    for i in range(6):
        events.append({
            "timestamp": t_atk2 + timedelta(seconds=i * 18),
            "source": "Auth",
            "username": "bob",
            "ip": atk2_ip,
            "action": "LOGIN",
            "status": "FAILED",
            "details": f"Repeated login failure ({i+1}/6) for user bob",
        })

    # 4. Attack Scenario 3: Impossible Travel / Unusual Subnet Login for 'alice' (Medium)
    t_atk3 = start + timedelta(days=DAYS - 1, hours=3, minutes=30)
    events.append({
        "timestamp": t_atk3,
        "source": "Auth",
        "username": "alice",
        "ip": "203.0.113.44",
        "action": "LOGIN",
        "status": "SUCCESS",
        "details": "Successful login from brand new external IP 203.0.113.44",
    })

    # 5. Attack Scenario 4: SQL Injection Web Attack (Critical)
    t_sqli = start + timedelta(days=DAYS - 1, hours=14, minutes=10)
    sqli_ip = "91.240.118.172"
    sqli_payloads = [
        "GET /api/v1/users?id=1' UNION SELECT username,password FROM accounts-- HTTP/1.1",
        "POST /login username=admin' OR '1'='1'--&pass=x HTTP/1.1",
    ]
    for i, payload in enumerate(sqli_payloads):
        events.append({
            "timestamp": t_sqli + timedelta(seconds=i * 25),
            "source": "Web",
            "username": "anonymous",
            "ip": sqli_ip,
            "action": "HTTP_PAYLOAD",
            "status": "BLOCKED",
            "details": payload,
        })

    # 6. Attack Scenario 5: Cross-Site Scripting (XSS) (High)
    t_xss = start + timedelta(days=DAYS - 1, hours=16, minutes=45)
    xss_ip = "185.220.101.5"
    events.append({
        "timestamp": t_xss,
        "source": "Web",
        "username": "guest",
        "ip": xss_ip,
        "action": "HTTP_POST",
        "status": "SUCCESS",
        "details": "POST /feedback content=<script>alert('XSS-Exploit')</script> HTTP/1.1",
    })

    # 7. Attack Scenario 6: Network Port Scan Reconnaissance (High)
    t_scan = start + timedelta(days=DAYS - 2, hours=19, minutes=5)
    scan_ip = "103.251.167.20"
    target_ports = [21, 22, 23, 80, 443, 3306, 8080]
    for i, p in enumerate(target_ports):
        events.append({
            "timestamp": t_scan + timedelta(seconds=i * 4),
            "source": "Network",
            "username": "N/A",
            "ip": scan_ip,
            "action": "TCP_SYN",
            "status": "BLOCKED" if p in (21, 23) else "ALLOWED",
            "details": f"Inbound connection probe targeting destination port: {p}",
        })

    # 8. Attack Scenario 7: HTTP Flood / DDoS Volumetric Burst (Critical)
    t_ddos = start + timedelta(days=DAYS - 1, hours=21, minutes=15)
    ddos_ip = "45.33.12.99"
    for i in range(18):
        events.append({
            "timestamp": t_ddos + timedelta(milliseconds=i * 400),
            "source": "Web",
            "username": "anonymous",
            "ip": ddos_ip,
            "action": "HTTP_GET",
            "status": "SUCCESS" if i < 10 else "RATE_LIMITED",
            "details": f"GET /search?q=stress_test_{i} HTTP/1.1 429 Too Many Requests",
        })

    # 9. Decoy Benign Noise: 3 failures (below threshold, MUST NOT alert)
    t_decoy = start + timedelta(days=DAYS - 3, hours=11, minutes=5)
    for i in range(3):
        events.append({
            "timestamp": t_decoy + timedelta(seconds=i * 30),
            "source": "Auth",
            "username": "carol",
            "ip": "10.0.0.77",
            "action": "LOGIN",
            "status": "FAILED",
            "details": "Occasional mistyped password attempt",
        })

    # Sort events chronologically
    events.sort(key=lambda e: e["timestamp"])

    # Write logs to CSV
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(LOG_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "source", "username", "ip", "action", "status", "details"])
        for e in events:
            writer.writerow([
                _fmt(e["timestamp"]),
                e["source"],
                e["username"],
                e["ip"],
                e["action"],
                e["status"],
                e["details"],
            ])

    # Also append latest 50 events to live_stream.log for real-time tailer demo
    with open(STREAM_FILE, "w", encoding="utf-8") as sf:
        for e in events[-50:]:
            sf.write(f"[{_fmt(e['timestamp'])}] [{e['source']}] [{e['ip']}] [{e['username']}] {e['status']}: {e['details']}\n")

    return len(events)


if __name__ == "__main__":
    count = generate()
    print(f"[+] Successfully generated {count} multi-vector security logs -> {LOG_FILE}")
