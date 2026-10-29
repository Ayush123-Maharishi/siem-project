"""enrichment.py - Threat Intelligence, IP Geolocation, and Risk Scoring."""
import ipaddress
import re
from typing import Any, Dict, Tuple

# Pre-populated local GeoIP cache for simulated / common test IPs
GEO_CACHE: Dict[str, Dict[str, str]] = {
    "45.33.12.99": {"country": "United States", "city": "Fremont", "isp": "Linode LLC", "country_code": "US", "flag": "🇺🇸"},
    "198.51.100.7": {"country": "Russia", "city": "Moscow", "isp": "BadNet Hosting", "country_code": "RU", "flag": "🇷🇺"},
    "203.0.113.44": {"country": "China", "city": "Beijing", "isp": "Asia Pacific Network", "country_code": "CN", "flag": "🇨🇳"},
    "185.220.101.5": {"country": "Germany", "city": "Frankfurt", "isp": "Tor Exit Node Network", "country_code": "DE", "flag": "🇩🇪"},
    "103.251.167.20": {"country": "India", "city": "Mumbai", "isp": "Tata Communications", "country_code": "IN", "flag": "🇮🇳"},
    "91.240.118.172": {"country": "Netherlands", "city": "Amsterdam", "isp": "Serverius Holding", "country_code": "NL", "flag": "🇳🇱"},
    "8.8.8.8": {"country": "United States", "city": "Mountain View", "isp": "Google LLC", "country_code": "US", "flag": "🇺🇸"},
}


def is_private_ip(ip: str) -> bool:
    """Check if an IP is a private/local RFC-1918 or loopback address."""
    try:
        ip_obj = ipaddress.ip_address(ip.strip())
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
    except ValueError:
        return False


def get_ip_location(ip: str) -> Dict[str, str]:
    """Resolve IP to geographic and organization details (offline safe)."""
    ip_clean = ip.strip()

    if is_private_ip(ip_clean):
        return {
            "country": "Internal Network",
            "city": "Corporate LAN",
            "isp": "Private RFC 1918",
            "country_code": "LAN",
            "flag": "🏢",
            "is_private": True,
        }

    # Check local static lookup
    if ip_clean in GEO_CACHE:
        data = GEO_CACHE[ip_clean].copy()
        data["is_private"] = False
        return data

    # Subnet hash fallback for consistent simulation
    try:
        octets = [int(o) for o in ip_clean.split(".")]
        hash_val = sum(octets) % 4
        fallback_regions = [
            {"country": "United States", "city": "Dallas", "isp": "Cloud Provider", "country_code": "US", "flag": "🇺🇸"},
            {"country": "Netherlands", "city": "Rotterdam", "isp": "Hosting B.V.", "country_code": "NL", "flag": "🇳🇱"},
            {"country": "Singapore", "city": "Singapore", "isp": "SingTel", "country_code": "SG", "flag": "🇸🇬"},
            {"country": "United Kingdom", "city": "London", "isp": "British Telecom", "country_code": "GB", "flag": "🇬🇧"},
        ]
        chosen = fallback_regions[hash_val].copy()
        chosen["is_private"] = False
        return chosen
    except Exception:
        return {
            "country": "Unknown",
            "city": "Unknown",
            "isp": "Unknown ISP",
            "country_code": "XX",
            "flag": "🌐",
            "is_private": False,
        }


def calculate_threat_score(
    alert_type: str,
    severity: str,
    username: str,
    ip: str,
    fail_count: int = 1
) -> Tuple[int, str]:
    """
    Calculate an intelligence risk score (0-100) and risk category.
    Incorporates severity, target sensitivity, known malicious subnets, and repeat offenders.
    """
    score = 30  # Baseline

    # Severity weights
    if severity == "Critical":
        score += 45
    elif severity == "High":
        score += 30
    elif severity == "Medium":
        score += 15
    elif severity == "Low":
        score += 5

    # Target account sensitivity
    high_value_accounts = {"admin", "administrator", "root", "sysadmin", "billing", "database"}
    if username.lower() in high_value_accounts:
        score += 15

    # Public vs Private origin
    if not is_private_ip(ip):
        score += 10

    # High frequency / brute force weight
    if fail_count > 5:
        score += min(20, (fail_count - 5) * 3)

    # Attack type heuristics
    if "Compromise" in alert_type or "Brute Force" in alert_type:
        score += 10
    elif "SQL Injection" in alert_type:
        score += 15
    elif "Port Scan" in alert_type:
        score += 8

    # Cap score at 100
    score = max(5, min(99, score))

    if score >= 85:
        label = "Critical Risk"
    elif score >= 65:
        label = "High Risk"
    elif score >= 45:
        label = "Medium Risk"
    else:
        label = "Low Risk"

    return score, label
