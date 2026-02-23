"""
SOC Assist — Webhook Notifications Service
Sends alerts to Microsoft Teams and Slack when an incident is classified
as 'critico' or 'brecha'.
"""
import json
from app.services.threat_intel import load_ti_config

try:
    import httpx
    _HTTPX_AVAILABLE = True
except ImportError:
    _HTTPX_AVAILABLE = False

# Classification order for threshold comparison
_LEVELS = ["informativo", "sospechoso", "incidente", "critico", "brecha"]

CLASSIFICATION_LABELS = {
    "informativo": "🟢 Informativo",
    "sospechoso":  "🟡 Sospechoso",
    "incidente":   "🟠 Incidente",
    "critico":     "🔴 Incidente Crítico",
    "brecha":      "🚨 Brecha Confirmada",
}

CLASSIFICATION_COLORS = {
    "informativo": "00b050",
    "sospechoso":  "ffc000",
    "incidente":   "ff6600",
    "critico":     "dc3545",
    "brecha":      "8b0000",
}


def _should_notify(classification: str, min_classification: str) -> bool:
    try:
        return _LEVELS.index(classification) >= _LEVELS.index(min_classification)
    except ValueError:
        return False


async def _send_teams(url: str, incident_id: int, classification: str,
                      final_score: float, analyst_name: str,
                      hard_rule: str | None, base_url: str = "http://localhost:8000") -> bool:
    """Send an Adaptive Card notification to Microsoft Teams."""
    label = CLASSIFICATION_LABELS.get(classification, classification.upper())
    color = CLASSIFICATION_COLORS.get(classification, "666666")
    detail_url = f"{base_url}/incidentes/{incident_id}"

    payload = {
        "@type":    "MessageCard",
        "@context": "https://schema.org/extensions",
        "themeColor": color,
        "summary": f"SOC Assist — {label}",
        "sections": [{
            "activityTitle":    f"**{label}**",
            "activitySubtitle": f"SOC Assist — Evaluación #{incident_id}",
            "activityImage":    "https://img.icons8.com/color/48/shield.png",
            "facts": [
                {"name": "Clasificación",  "value": label},
                {"name": "Score Final",    "value": str(round(final_score, 1))},
                {"name": "Analista",       "value": analyst_name or "Anónimo"},
                {"name": "Regla de corte", "value": hard_rule if hard_rule else "Ninguna"},
            ],
            "markdown": True,
        }],
        "potentialAction": [{
            "@type": "OpenUri",
            "name":  "Ver Detalle del Incidente",
            "targets": [{"os": "default", "uri": detail_url}],
        }],
    }

    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.post(url, json=payload)
        r.raise_for_status()
    return True


async def _send_slack(url: str, incident_id: int, classification: str,
                      final_score: float, analyst_name: str,
                      hard_rule: str | None, base_url: str = "http://localhost:8000") -> bool:
    """Send a Block Kit notification to Slack."""
    label = CLASSIFICATION_LABELS.get(classification, classification.upper())
    detail_url = f"{base_url}/incidentes/{incident_id}"
    color = f"#{CLASSIFICATION_COLORS.get(classification, '666666')}"

    payload = {
        "attachments": [{
            "color": color,
            "blocks": [
                {
                    "type": "header",
                    "text": {"type": "plain_text", "text": f"SOC Assist — {label}"},
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Evaluación:*\n#{incident_id}"},
                        {"type": "mrkdwn", "text": f"*Analista:*\n{analyst_name or 'Anónimo'}"},
                        {"type": "mrkdwn", "text": f"*Score Final:*\n{round(final_score, 1)}"},
                        {"type": "mrkdwn", "text": f"*Regla de corte:*\n{hard_rule if hard_rule else 'Ninguna'}"},
                    ],
                },
                {
                    "type": "actions",
                    "elements": [{
                        "type":  "button",
                        "text":  {"type": "plain_text", "text": "Ver Detalle"},
                        "url":   detail_url,
                        "style": "danger" if classification == "brecha" else "primary",
                    }],
                },
            ],
        }],
    }

    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.post(url, json=payload)
        r.raise_for_status()
    return True


async def notify_incident(
    incident_id: int,
    classification: str,
    final_score: float,
    analyst_name: str,
    hard_rule: str | None = None,
    base_url: str = "http://localhost:8000",
) -> dict:
    """
    Send webhook notifications if classification meets the threshold.

    Returns a dict with per-channel results:
    {
      "sent": bool,
      "teams": "ok" | "skipped" | "error: ...",
      "slack": "ok" | "skipped" | "error: ...",
    }
    """
    results = {"sent": False, "teams": "skipped", "slack": "skipped"}

    if not _HTTPX_AVAILABLE:
        return {"sent": False, "teams": "error: httpx no instalado",
                "slack": "error: httpx no instalado"}

    config = load_ti_config()
    wh = config.get("webhooks", {})
    min_cls = wh.get("min_classification", "critico")

    if not _should_notify(classification, min_cls):
        return results

    # Teams
    teams = wh.get("teams", {})
    if teams.get("enabled") and teams.get("url"):
        try:
            await _send_teams(teams["url"], incident_id, classification,
                              final_score, analyst_name, hard_rule, base_url)
            results["teams"] = "ok"
            results["sent"] = True
        except Exception as e:
            results["teams"] = f"error: {e}"

    # Slack
    slack = wh.get("slack", {})
    if slack.get("enabled") and slack.get("url"):
        try:
            await _send_slack(slack["url"], incident_id, classification,
                              final_score, analyst_name, hard_rule, base_url)
            results["slack"] = "ok"
            results["sent"] = True
        except Exception as e:
            results["slack"] = f"error: {e}"

    return results
