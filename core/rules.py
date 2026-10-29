"""rules.py - MITRE ATT&CK Framework Mapping and Rule Definitions."""
from typing import Any, Dict

# MITRE ATT&CK Framework mapping database
MITRE_MATRIX: Dict[str, Dict[str, str]] = {
    "Brute-Force Login": {
        "technique_id": "T1110.001",
        "technique_name": "Password Guessing",
        "tactic": "Credential Access",
        "tactic_id": "TA0006",
        "description": "Adversaries may attempt to guess passwords for accounts on systems.",
        "remediation": "Enforce account lockout, MFA, and rate-limiting on login endpoints.",
    },
    "Login After Brute Force": {
        "technique_id": "T1078.003",
        "technique_name": "Local Accounts",
        "tactic": "Persistence & Defense Evasion",
        "tactic_id": "TA0003",
        "description": "Adversary successfully gained access right after multiple failed authentication attempts.",
        "remediation": "Isolate user session immediately, force password reset, review audit logs.",
    },
    "Unusual Login IP": {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts: Impossible Travel / Anomalous Origin",
        "tactic": "Initial Access",
        "tactic_id": "TA0001",
        "description": "Account authenticated from an IP address or geographic location outside normal baseline.",
        "remediation": "Prompt user for MFA step-up verification, challenge suspicious login session.",
    },
    "SQL Injection Attack": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "tactic_id": "TA0001",
        "description": "Adversary injected malicious SQL syntax into web application parameters.",
        "remediation": "Use parameterized queries (prepared statements), deploy WAF rules, sanitize input.",
    },
    "Cross-Site Scripting (XSS)": {
        "technique_id": "T1189",
        "technique_name": "Drive-by Compromise",
        "tactic": "Initial Access",
        "tactic_id": "TA0001",
        "description": "Adversary injected malicious JavaScript or HTML tags into application inputs.",
        "remediation": "Enable Content Security Policy (CSP), HTML entity encoding on output.",
    },
    "Port Scanning / Reconnaissance": {
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "tactic": "Discovery",
        "tactic_id": "TA0007",
        "description": "Adversary systematically probed network ports to identify active services and vulnerabilities.",
        "remediation": "Block scanning IP at perimeter firewall, verify external attack surface exposure.",
    },
    "DDoS / HTTP Flood": {
        "technique_id": "T1498",
        "technique_name": "Network Denial of Service",
        "tactic": "Impact",
        "tactic_id": "TA0040",
        "description": "High volume of HTTP/service requests exceeding normal operational threshold.",
        "remediation": "Enable cloud DDoS scrubbing, rate limiting, and temporary IP throttling.",
    },
    "Privileged Account Abuse": {
        "technique_id": "T1068",
        "technique_name": "Exploitation for Privilege Escalation",
        "tactic": "Privilege Escalation",
        "tactic_id": "TA0004",
        "description": "Privileged account (root/admin) accessed from unauthorized subnet or at unusual hours.",
        "remediation": "Audit administrative activity, enforce Just-In-Time (JIT) access policies.",
    },
}


def get_rule_metadata(alert_type: str) -> Dict[str, str]:
    """Retrieve MITRE tactic, technique, and remediation for an alert type."""
    if alert_type in MITRE_MATRIX:
        return MITRE_MATRIX[alert_type]
    return {
        "technique_id": "T1078",
        "technique_name": "Generic Suspicious Activity",
        "tactic": "Execution",
        "tactic_id": "TA0002",
        "description": "Suspicious behavior detected by SIEM correlation engine.",
        "remediation": "Review system audit logs and investigate origin IP.",
    }
