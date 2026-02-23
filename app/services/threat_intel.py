"""
SOC Assist — Threat Intelligence Service
Queries VirusTotal, AbuseIPDB, and IBM X-Force Exchange.
Enforces private IP validation before any external query.
"""
import ipaddress
import json
import re
import base64
from pathlib import Path
from typing import Optional

try:
    import httpx
    _HTTPX_AVAILABLE = True
except ImportError:
    _HTTPX_AVAILABLE = False

# ── Private / reserved IP ranges (never query externally) ─────────────────────
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),         # "This" network
    ipaddress.ip_network("10.0.0.0/8"),        # RFC 1918 Class A
    ipaddress.ip_network("100.64.0.0/10"),     # Shared Address Space (RFC 6598)
    ipaddress.ip_network("127.0.0.0/8"),       # Loopback
    ipaddress.ip_network("169.254.0.0/16"),    # Link-local (APIPA)
    ipaddress.ip_network("172.16.0.0/12"),     # RFC 1918 Class B
    ipaddress.ip_network("192.0.0.0/24"),      # IETF Protocol Assignments
    ipaddress.ip_network("192.168.0.0/16"),    # RFC 1918 Class C
    ipaddress.ip_network("198.18.0.0/15"),     # Benchmark Testing (RFC 2544)
    ipaddress.ip_network("198.51.100.0/24"),   # Documentation (RFC 5737)
    ipaddress.ip_network("203.0.113.0/24"),    # Documentation (RFC 5737)
    ipaddress.ip_network("224.0.0.0/4"),       # Multicast
    ipaddress.ip_network("240.0.0.0/4"),       # Reserved
    ipaddress.ip_network("255.255.255.255/32"),# Broadcast
    # IPv6
    ipaddress.ip_network("::1/128"),           # Loopback
    ipaddress.ip_network("fc00::/7"),          # Unique Local (ULA)
    ipaddress.ip_network("fe80::/10"),         # Link-local
    ipaddress.ip_network("ff00::/8"),          # Multicast
]

TI_CONFIG_PATH = Path(__file__).resolve().parent.parent.parent / "ti_config.json"

TIMEOUT_SECONDS = 10


# ── Helpers ───────────────────────────────────────────────────────────────────

def is_private_ip(addr: str) -> bool:
    """Return True if the IP is in a private/reserved/loopback range."""
    try:
        ip = ipaddress.ip_address(addr.strip())
        return any(ip in net for net in _PRIVATE_NETWORKS)
    except ValueError:
        return False


def is_valid_ip(addr: str) -> bool:
    """Return True if the string is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(addr.strip())
        return True
    except ValueError:
        return False


def load_ti_config() -> dict:
    """Load TI configuration from ti_config.json."""
    if TI_CONFIG_PATH.exists():
        try:
            return json.loads(TI_CONFIG_PATH.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {
        "virustotal":  {"api_key": ""},
        "abuseipdb":   {"api_key": ""},
        "xforce":      {"api_key": "", "api_password": ""},
    }


def save_ti_config(config: dict):
    """Persist TI configuration to ti_config.json."""
    TI_CONFIG_PATH.write_text(
        json.dumps(config, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )


# ── VirusTotal ────────────────────────────────────────────────────────────────

async def _vt_query_ip(ip: str, api_key: str) -> dict:
    """Query VirusTotal for an IP address."""
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": api_key}
    async with httpx.AsyncClient(timeout=TIMEOUT_SECONDS) as client:
        r = await client.get(url, headers=headers)
        r.raise_for_status()
        data = r.json()

    attrs = data.get("data", {}).get("attributes", {})
    last = attrs.get("last_analysis_stats", {})
    malicious = last.get("malicious", 0)
    suspicious = last.get("suspicious", 0)
    total = sum(last.values()) if last else 0

    return {
        "source": "VirusTotal",
        "indicator": ip,
        "type": "ip",
        "malicious_votes": malicious,
        "suspicious_votes": suspicious,
        "total_engines": total,
        "reputation": attrs.get("reputation", 0),
        "country": attrs.get("country", "N/A"),
        "as_owner": attrs.get("as_owner", "N/A"),
        "categories": list(attrs.get("categories", {}).values())[:5],
        "verdict": "MALICIOSO" if malicious > 3 else ("SOSPECHOSO" if malicious > 0 or suspicious > 0 else "LIMPIO"),
        "raw_url": f"https://www.virustotal.com/gui/ip-address/{ip}",
    }


async def _vt_query_domain(domain: str, api_key: str) -> dict:
    """Query VirusTotal for a domain."""
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": api_key}
    async with httpx.AsyncClient(timeout=TIMEOUT_SECONDS) as client:
        r = await client.get(url, headers=headers)
        r.raise_for_status()
        data = r.json()

    attrs = data.get("data", {}).get("attributes", {})
    last = attrs.get("last_analysis_stats", {})
    malicious = last.get("malicious", 0)
    suspicious = last.get("suspicious", 0)
    total = sum(last.values()) if last else 0

    return {
        "source": "VirusTotal",
        "indicator": domain,
        "type": "domain",
        "malicious_votes": malicious,
        "suspicious_votes": suspicious,
        "total_engines": total,
        "reputation": attrs.get("reputation", 0),
        "categories": list(attrs.get("categories", {}).values())[:5],
        "verdict": "MALICIOSO" if malicious > 3 else ("SOSPECHOSO" if malicious > 0 or suspicious > 0 else "LIMPIO"),
        "raw_url": f"https://www.virustotal.com/gui/domain/{domain}",
    }


# ── AbuseIPDB ──────────────────────────────────────────────────────────────────

async def _abuseipdb_query_ip(ip: str, api_key: str) -> dict:
    """Query AbuseIPDB for an IP address."""
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": "90", "verbose": ""}
    async with httpx.AsyncClient(timeout=TIMEOUT_SECONDS) as client:
        r = await client.get(url, headers=headers, params=params)
        r.raise_for_status()
        data = r.json()

    d = data.get("data", {})
    score = d.get("abuseConfidenceScore", 0)

    return {
        "source": "AbuseIPDB",
        "indicator": ip,
        "type": "ip",
        "abuse_score": score,
        "total_reports": d.get("totalReports", 0),
        "distinct_users": d.get("numDistinctUsers", 0),
        "country": d.get("countryCode", "N/A"),
        "isp": d.get("isp", "N/A"),
        "domain": d.get("domain", "N/A"),
        "usage_type": d.get("usageType", "N/A"),
        "is_tor": d.get("isTor", False),
        "is_whitelisted": d.get("isWhitelisted", False),
        "last_reported": d.get("lastReportedAt", "N/A"),
        "verdict": "MALICIOSO" if score >= 75 else ("SOSPECHOSO" if score >= 25 else "LIMPIO"),
        "raw_url": f"https://www.abuseipdb.com/check/{ip}",
    }


# ── IBM X-Force Exchange ──────────────────────────────────────────────────────

async def _xforce_query_ip(ip: str, api_key: str, api_password: str) -> dict:
    """Query IBM X-Force Exchange for an IP address."""
    url = f"https://api.xforce.ibmcloud.com/ipr/{ip}"
    token = base64.b64encode(f"{api_key}:{api_password}".encode()).decode()
    headers = {"Authorization": f"Basic {token}", "Accept": "application/json"}
    async with httpx.AsyncClient(timeout=TIMEOUT_SECONDS) as client:
        r = await client.get(url, headers=headers)
        r.raise_for_status()
        data = r.json()

    score = data.get("score", 0)
    cats = data.get("cats", {})
    geo = data.get("geo", {})

    return {
        "source": "IBM X-Force",
        "indicator": ip,
        "type": "ip",
        "risk_score": score,
        "categories": list(cats.keys())[:5],
        "country": geo.get("country", "N/A"),
        "isp": data.get("subnets", [{}])[0].get("asns", [{}])[0].get("company", "N/A") if data.get("subnets") else "N/A",
        "verdict": "MALICIOSO" if score >= 7 else ("SOSPECHOSO" if score >= 4 else "LIMPIO"),
        "raw_url": f"https://exchange.xforce.ibmcloud.com/ip/{ip}",
    }


async def _xforce_query_url(url_indicator: str, api_key: str, api_password: str) -> dict:
    """Query IBM X-Force Exchange for a URL/domain."""
    import urllib.parse
    encoded = urllib.parse.quote(url_indicator, safe='')
    url = f"https://api.xforce.ibmcloud.com/url/{encoded}"
    token = base64.b64encode(f"{api_key}:{api_password}".encode()).decode()
    headers = {"Authorization": f"Basic {token}", "Accept": "application/json"}
    async with httpx.AsyncClient(timeout=TIMEOUT_SECONDS) as client:
        r = await client.get(url, headers=headers)
        r.raise_for_status()
        data = r.json()

    result = data.get("result", {})
    score = result.get("score", 0)
    cats = result.get("cats", {})

    return {
        "source": "IBM X-Force",
        "indicator": url_indicator,
        "type": "url",
        "risk_score": score,
        "categories": list(cats.keys())[:5],
        "verdict": "MALICIOSO" if score >= 7 else ("SOSPECHOSO" if score >= 4 else "LIMPIO"),
        "raw_url": f"https://exchange.xforce.ibmcloud.com/url/{url_indicator}",
    }


# ── Main lookup function ──────────────────────────────────────────────────────

async def lookup(
    indicator: str,
    indicator_type: str = "auto",
    sources: Optional[list[str]] = None,
) -> dict:
    """
    Query one or more TI sources for the given indicator.

    Args:
        indicator:      IP address or domain/URL string
        indicator_type: "ip", "domain", "url", or "auto" (auto-detect)
        sources:        List of sources to query. None = all configured.

    Returns:
        {
          "indicator": str,
          "type": "ip" | "domain" | "url",
          "blocked": bool,         # True if private IP blocked
          "block_reason": str,
          "results": [{ source, verdict, ... }, ...],
          "errors": [{ source, error }, ...]
          "summary_verdict": "MALICIOSO" | "SOSPECHOSO" | "LIMPIO" | "BLOQUEADO"
        }
    """
    if not _HTTPX_AVAILABLE:
        return {
            "indicator": indicator,
            "blocked": False,
            "errors": [{"source": "system", "error": "httpx no instalado. Ejecuta: pip install httpx"}],
            "results": [],
            "summary_verdict": "ERROR",
        }

    indicator = indicator.strip()

    # Auto-detect type
    if indicator_type == "auto":
        indicator_type = "ip" if is_valid_ip(indicator) else "domain"

    # Block private IPs
    if indicator_type == "ip" and is_private_ip(indicator):
        return {
            "indicator": indicator,
            "type": "ip",
            "blocked": True,
            "block_reason": (
                "IP en rango privado / reservado (RFC 1918, loopback, link-local). "
                "No se envía a fuentes externas de inteligencia de amenazas."
            ),
            "results": [],
            "errors": [],
            "summary_verdict": "BLOQUEADO",
        }

    config = load_ti_config()
    if sources is None:
        sources = ["virustotal", "abuseipdb", "xforce"]

    results = []
    errors = []

    for source in sources:
        try:
            if source == "virustotal":
                key = config.get("virustotal", {}).get("api_key", "")
                if not key:
                    errors.append({"source": "VirusTotal", "error": "API key no configurada."})
                    continue
                if indicator_type == "ip":
                    r = await _vt_query_ip(indicator, key)
                else:
                    r = await _vt_query_domain(indicator, key)
                results.append(r)

            elif source == "abuseipdb":
                if indicator_type != "ip":
                    # AbuseIPDB only supports IPs
                    continue
                key = config.get("abuseipdb", {}).get("api_key", "")
                if not key:
                    errors.append({"source": "AbuseIPDB", "error": "API key no configurada."})
                    continue
                r = await _abuseipdb_query_ip(indicator, key)
                results.append(r)

            elif source == "xforce":
                xf = config.get("xforce", {})
                key = xf.get("api_key", "")
                pwd = xf.get("api_password", "")
                if not key or not pwd:
                    errors.append({"source": "IBM X-Force", "error": "API key o password no configurados."})
                    continue
                if indicator_type == "ip":
                    r = await _xforce_query_ip(indicator, key, pwd)
                else:
                    r = await _xforce_query_url(indicator, key, pwd)
                results.append(r)

        except httpx.HTTPStatusError as e:
            status = e.response.status_code
            msg = {
                401: "Autenticación fallida — verifica la API key.",
                403: "Acceso denegado — plan gratuito puede no soportar este endpoint.",
                404: "Indicador no encontrado en la base de datos.",
                429: "Límite de rate excedido — intenta más tarde.",
            }.get(status, f"Error HTTP {status}")
            errors.append({"source": source, "error": msg})
        except Exception as e:
            errors.append({"source": source, "error": str(e)})

    # Aggregate verdict
    verdicts = [r.get("verdict", "LIMPIO") for r in results]
    if "MALICIOSO" in verdicts:
        summary = "MALICIOSO"
    elif "SOSPECHOSO" in verdicts:
        summary = "SOSPECHOSO"
    elif verdicts:
        summary = "LIMPIO"
    else:
        summary = "SIN_RESULTADOS"

    return {
        "indicator": indicator,
        "type": indicator_type,
        "blocked": False,
        "block_reason": "",
        "results": results,
        "errors": errors,
        "summary_verdict": summary,
    }
