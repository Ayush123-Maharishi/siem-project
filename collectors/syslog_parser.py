"""syslog_parser.py - Parser for Apache/Nginx and Syslog RFC formatted logs."""
import re
from datetime import datetime
from typing import Any, Dict, Optional

# Regex for Nginx/Apache Combined Log Format
APACHE_REGEX = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<time>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<url>\S+)\s+[^"]+"\s+(?P<status>\d+)\s+(?P<size>\S+)'
)

# Regex for SSH / Syslog Auth lines
SSHD_REGEX = re.compile(
    r'(?P<status>Failed|Accepted)\s+password\s+for\s+(?:invalid\s+user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)'
)


def parse_log_line(line: str) -> Optional[Dict[str, Any]]:
    """Parse a single raw log string into a normalized SIEM event dictionary."""
    line = line.strip()
    if not line:
        return None

    # Check Apache / Nginx
    match_apache = APACHE_REGEX.match(line)
    if match_apache:
        d = match_apache.groupdict()
        user = d["user"] if d["user"] != "-" else "anonymous"
        status_code = int(d["status"])
        status = "SUCCESS" if status_code < 400 else ("BLOCKED" if status_code == 403 else "FAILED")
        return {
            "timestamp": datetime.now(),
            "source": "Web",
            "username": user,
            "ip": d["ip"],
            "action": d["method"],
            "status": status,
            "details": f"{d['method']} {d['url']} HTTP {status_code}",
        }

    # Check SSH syslog
    match_ssh = SSHD_REGEX.search(line)
    if match_ssh:
        d = match_ssh.groupdict()
        status = "FAILED" if d["status"].lower() == "failed" else "SUCCESS"
        return {
            "timestamp": datetime.now(),
            "source": "Auth",
            "username": d["user"],
            "ip": d["ip"],
            "action": "SSH_AUTH",
            "status": status,
            "details": f"SSH password attempt on port {d['port']} ({status})",
        }

    # Fallback generic line
    return {
        "timestamp": datetime.now(),
        "source": "Syslog",
        "username": "system",
        "ip": "127.0.0.1",
        "action": "RAW_LOG",
        "status": "SUCCESS",
        "details": line[:120],
    }
