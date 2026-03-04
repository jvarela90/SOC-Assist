"""
SOC Assist — Integración TheHive v5
Exporta incidentes de SOC Assist como casos en TheHive.
Config: thehive_config.json (thehive_url, api_key, default_org)
"""
import json
import logging
from pathlib import Path

import httpx

logger = logging.getLogger(__name__)

_CFG_PATH = Path(__file__).resolve().parent.parent.parent / "thehive_config.json"

_DEFAULT_CFG = {
    "thehive_url": "",      # ej: https://thehive.corp.local:9000
    "api_key":     "",      # TheHive API key (v5: Bearer token)
    "default_org": "",      # Organización en TheHive (opcional)
    "verify_ssl":  True,
}


def load_thehive_config() -> dict:
    if _CFG_PATH.exists():
        try:
            data = json.loads(_CFG_PATH.read_text("utf-8"))
            return {**_DEFAULT_CFG, **data}
        except Exception:
            pass
    return dict(_DEFAULT_CFG)


def save_thehive_config(cfg: dict) -> None:
    # Never write sensitive keys from defaults if they're blank
    _CFG_PATH.write_text(json.dumps(cfg, indent=2, ensure_ascii=False), "utf-8")


def is_configured() -> bool:
    cfg = load_thehive_config()
    return bool(cfg.get("thehive_url") and cfg.get("api_key"))


# ── Severity / TLP / PAP mapping ─────────────────────────────────────────────

_SEVERITY_MAP = {
    "informativo": 1,   # Low
    "sospechoso":  2,   # Medium
    "incidente":   2,   # Medium
    "critico":     3,   # High
    "brecha":      4,   # Critical
}

_TLP_MAP = {
    "informativo": 1,   # GREEN
    "sospechoso":  2,   # AMBER
    "incidente":   2,   # AMBER
    "critico":     3,   # RED
    "brecha":      3,   # RED
}


async def export_incident_to_thehive(incident, analyst_name: str = "SOC Assist") -> dict:
    """
    Crea un Case en TheHive v5 a partir de un Incident de SOC Assist.
    Retorna {"case_id": str, "case_number": int, "url": str} o lanza ValueError.
    """
    cfg = load_thehive_config()
    if not cfg["thehive_url"] or not cfg["api_key"]:
        raise ValueError("TheHive no configurado. Ve a Admin → TheHive.")

    cls   = incident.classification or "informativo"
    score = incident.final_score or 0

    # Parse network context
    ctx = {}
    try:
        ctx = json.loads(incident.network_context or "{}")
    except Exception:
        pass

    # Build case description
    lines = [
        f"**SOC Assist Incident #{incident.id}**",
        f"- **Score:** {score}",
        f"- **Clasificación:** {cls.upper()}",
        f"- **Analista:** {analyst_name}",
        f"- **Fecha:** {incident.timestamp.isoformat() if incident.timestamp else '—'}",
    ]
    if ctx.get("ip_src"):
        lines.append(f"- **IP Origen:** `{ctx['ip_src']}`")
    if ctx.get("ip_dst"):
        lines.append(f"- **IP Destino:** `{ctx['ip_dst']}`")
    if ctx.get("url"):
        lines.append(f"- **URL:** `{ctx['url']}`")
    if incident.analyst_notes:
        lines.append(f"\n**Notas del analista:**\n{incident.analyst_notes}")

    # Build observables
    observables = []
    for field, data_type in [("ip_src", "ip"), ("ip_dst", "ip"), ("url", "url"), ("mac", "other")]:
        val = ctx.get(field)
        if val:
            observables.append({
                "dataType": data_type,
                "data": val,
                "message": f"{field} from SOC Assist",
                "tlp": _TLP_MAP.get(cls, 2),
            })

    case_payload = {
        "title":       f"[SOC Assist #{incident.id}] {cls.upper()} — score {score}",
        "description": "\n".join(lines),
        "severity":    _SEVERITY_MAP.get(cls, 2),
        "tlp":         _TLP_MAP.get(cls, 2),
        "pap":         _TLP_MAP.get(cls, 2),
        "tags":        ["soc-assist", cls, f"score-{int(score)}"],
        "flag":        cls in ("critico", "brecha"),
    }
    if cfg.get("default_org"):
        case_payload["organisation"] = cfg["default_org"]

    base_url = cfg["thehive_url"].rstrip("/")
    headers  = {"Authorization": f"Bearer {cfg['api_key']}", "Content-Type": "application/json"}
    verify   = cfg.get("verify_ssl", True)

    async with httpx.AsyncClient(verify=verify, timeout=15) as client:
        # Create case
        r = await client.post(f"{base_url}/api/v1/case", json=case_payload, headers=headers)
        if r.status_code not in (200, 201):
            raise ValueError(f"TheHive error {r.status_code}: {r.text[:200]}")
        case = r.json()
        case_id  = case.get("_id", "")
        case_num = case.get("number", 0)

        # Add observables (ignore failures — best-effort)
        for obs in observables:
            try:
                await client.post(
                    f"{base_url}/api/v1/case/{case_id}/observable",
                    json=obs, headers=headers,
                )
            except Exception:
                pass

    logger.info(f"[TheHive] Case #{case_num} creado para incident/{incident.id}")
    return {
        "case_id":     case_id,
        "case_number": case_num,
        "url":         f"{base_url}/cases/{case_id}/details",
    }
