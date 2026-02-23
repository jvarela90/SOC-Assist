"""
SOC Assist — Threat Intelligence & MAC OUI API Routes
"""
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from app.services import threat_intel as ti_service
from app.services import mac_oui

router = APIRouter(prefix="/api")


@router.post("/ti/lookup", response_class=JSONResponse)
async def ti_lookup(request: Request):
    """
    Query configured TI sources for an IP or domain.

    Body JSON:
        {
          "indicator": "1.2.3.4" | "evil.example.com",
          "type": "auto" | "ip" | "domain",
          "sources": ["virustotal", "abuseipdb", "xforce"]  // optional
        }
    """
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "JSON inválido"}, status_code=400)

    indicator = (body.get("indicator") or "").strip()
    if not indicator:
        return JSONResponse({"error": "Campo 'indicator' requerido."}, status_code=400)

    ind_type = body.get("type", "auto")
    sources = body.get("sources", None)

    result = await ti_service.lookup(indicator, ind_type, sources)
    return JSONResponse(result)


@router.get("/mac/lookup", response_class=JSONResponse)
async def mac_lookup(mac: str):
    """
    Look up a MAC address prefix (OUI) to identify the device vendor/category.

    Query param: ?mac=00:0C:29:AB:CD:EF
    """
    if not mac:
        return JSONResponse({"error": "Parámetro 'mac' requerido."}, status_code=400)
    result = mac_oui.lookup_mac(mac)
    return JSONResponse(result)


@router.get("/ti/check-private", response_class=JSONResponse)
async def check_private(ip: str):
    """
    Check if an IP is in a private/reserved range.
    Returns {is_private: bool, ip: str}
    """
    is_p = ti_service.is_private_ip(ip)
    is_v = ti_service.is_valid_ip(ip)
    return JSONResponse({
        "ip": ip,
        "is_valid": is_v,
        "is_private": is_p,
        "message": (
            "IP en rango privado — no se consultará en fuentes externas."
            if is_p else
            ("IP pública — apta para consulta en TI." if is_v else "Formato de IP inválido.")
        ),
    })
