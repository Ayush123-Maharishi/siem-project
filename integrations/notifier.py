"""notifier.py - Alert Notification Dispatcher (Discord, Slack, Email)."""
import json
from pathlib import Path
from typing import Any, Dict, Optional
import requests

CONFIG_FILE = Path(__file__).resolve().parent.parent / "config" / "config.json"

SEVERITY_COLORS = {
    "Critical": 0xE74C3C,  # Crimson Red
    "High": 0xE67E22,      # Orange
    "Medium": 0xF1C40F,    # Amber / Gold
    "Low": 0x3498DB,       # Blue
}


def _get_config() -> Dict[str, Any]:
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def send_discord_alert(alert: Dict[str, Any], webhook_url: Optional[str] = None) -> bool:
    """Send formatted rich embed alert to Discord channel."""
    cfg = _get_config()
    url = webhook_url or cfg.get("notifications", {}).get("discord_webhook_url", "")
    if not url:
        return False

    severity = alert.get("severity", "Medium")
    color = SEVERITY_COLORS.get(severity, 0x95A5A6)

    payload = {
        "username": "SIEM SOC Alert Bot",
        "avatar_url": "https://cdn-icons-png.flaticon.com/512/2092/2092663.png",
        "embeds": [
            {
                "title": f"🚨 [{severity.upper()}] {alert.get('alert_type', 'Security Alert')}",
                "description": alert.get("details", "Suspicious event detected."),
                "color": color,
                "fields": [
                    {"name": "🎯 Target Account", "value": f"`{alert.get('username', 'N/A')}`", "inline": True},
                    {"name": "🌐 Attacker IP", "value": f"`{alert.get('ip', 'N/A')}`", "inline": True},
                    {"name": "🔥 Threat Score", "value": f"`{alert.get('threat_score', 50)}/100`", "inline": True},
                    {"name": "🛡️ MITRE Tactic", "value": f"`{alert.get('mitre_tactic', 'N/A')}`", "inline": True},
                    {"name": "🔬 MITRE Technique", "value": f"`{alert.get('mitre_technique', 'N/A')}`", "inline": True},
                    {"name": "🕒 Event Timestamp", "value": f"`{alert.get('event_time', 'N/A')}`", "inline": True},
                ],
                "footer": {"text": "Enterprise SIEM Automated Threat Defense • SOC Alert Engine"},
            }
        ],
    }

    try:
        resp = requests.post(url, json=payload, timeout=5)
        return resp.status_code in (200, 204)
    except Exception:
        return False


def send_slack_alert(alert: Dict[str, Any], webhook_url: Optional[str] = None) -> bool:
    """Send alert message to Slack incoming webhook."""
    cfg = _get_config()
    url = webhook_url or cfg.get("notifications", {}).get("slack_webhook_url", "")
    if not url:
        return False

    severity = alert.get("severity", "Medium")
    text = (
        f"*[SIEM ALERT - {severity.upper()}]* {alert.get('alert_type')}\n"
        f"• *User:* `{alert.get('username')}` | *IP:* `{alert.get('ip')}` | *Score:* `{alert.get('threat_score')}`\n"
        f"• *Details:* {alert.get('details')}\n"
        f"• *MITRE:* {alert.get('mitre_tactic')} - {alert.get('mitre_technique')}"
    )

    try:
        resp = requests.post(url, json={"text": text}, timeout=5)
        return resp.status_code == 200
    except Exception:
        return False


def dispatch_alert(alert: Dict[str, Any]) -> None:
    """Dispatch alert to all configured notification channels."""
    cfg = _get_config().get("notifications", {})
    min_sev = cfg.get("min_severity_to_notify", "High")
    sev = alert.get("severity", "Medium")

    sev_rank = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
    if sev_rank.get(sev, 1) < sev_rank.get(min_sev, 3):
        return

    # Trigger Discord if configured
    if cfg.get("discord_webhook_url"):
        send_discord_alert(alert)

    # Trigger Slack if configured
    if cfg.get("slack_webhook_url"):
        send_slack_alert(alert)
