"""
SOC Assist — Admin: Integraciones externas.
Rutas: /admin/ti-keys, /admin/webhooks, /admin/smtp, /admin/thehive.
"""
from fastapi import Depends, Request
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy.orm import Session

from app.models.database import get_db, audit
from app.core.auth import require_admin
from app.services.threat_intel import load_ti_config, save_ti_config
from app.services.mailer import load_smtp_config, save_smtp_config, test_smtp_connection

from ._base import router


# ─── Claves TI ────────────────────────────────────────────────────────────────

@router.post("/ti-keys")
async def save_ti_keys(
    request: Request,
    db: Session = Depends(get_db),
    _user: dict = Depends(require_admin),
):
    """Guarda claves API de Threat Intelligence en ti_config.json."""
    form   = await request.form()
    config = load_ti_config()
    updated = []

    vt_key = form.get("vt_api_key", "").strip()
    if vt_key and not vt_key.startswith("*"):
        config.setdefault("virustotal", {})["api_key"] = vt_key
        updated.append("virustotal")

    abuse_key = form.get("abuse_api_key", "").strip()
    if abuse_key and not abuse_key.startswith("*"):
        config.setdefault("abuseipdb", {})["api_key"] = abuse_key
        updated.append("abuseipdb")

    xf_key = form.get("xforce_api_key", "").strip()
    xf_pwd = form.get("xforce_api_password", "").strip()
    if xf_key and not xf_key.startswith("*"):
        config.setdefault("xforce", {})["api_key"] = xf_key
        updated.append("xforce")
    if xf_pwd and not xf_pwd.startswith("*"):
        config.setdefault("xforce", {})["api_password"] = xf_pwd

    save_ti_config(config)
    if updated:
        audit(db, _user.get("username", "?"), "ti_keys_updated",
              details=f"Claves TI actualizadas: {', '.join(updated)}",
              ip=request.client.host if request.client else None)
        db.commit()
    return RedirectResponse(url="/admin?msg=ti_keys_saved", status_code=303)


@router.post("/ti-keys/clear")
async def clear_ti_keys(
    request: Request,
    db: Session = Depends(get_db),
    _user: dict = Depends(require_admin),
):
    """Elimina claves API de TI seleccionadas o todas."""
    form   = await request.form()
    source = form.get("source", "all")
    config = load_ti_config()

    if source in ("all", "virustotal"):
        config.setdefault("virustotal", {})["api_key"] = ""
    if source in ("all", "abuseipdb"):
        config.setdefault("abuseipdb", {})["api_key"] = ""
    if source in ("all", "xforce"):
        config.setdefault("xforce", {})["api_key"] = ""
        config.setdefault("xforce", {})["api_password"] = ""

    save_ti_config(config)
    audit(db, _user.get("username", "?"), "ti_keys_cleared",
          details=f"Claves TI eliminadas: {source}",
          ip=request.client.host if request.client else None)
    db.commit()
    return RedirectResponse(url="/admin?msg=ti_keys_cleared", status_code=303)


# ─── Webhooks ─────────────────────────────────────────────────────────────────

@router.post("/webhooks")
async def save_webhooks(
    request: Request,
    db: Session = Depends(get_db),
    _user: dict = Depends(require_admin),
):
    """Guarda configuración de webhooks Teams y Slack."""
    form   = await request.form()
    config = load_ti_config()

    teams_url     = form.get("teams_url", "").strip()
    teams_enabled = "teams_enabled" in form
    slack_url     = form.get("slack_url", "").strip()
    slack_enabled = "slack_enabled" in form

    config.setdefault("webhooks", {})
    config["webhooks"]["teams"] = {"url": teams_url, "enabled": teams_enabled}
    config["webhooks"]["slack"] = {"url": slack_url, "enabled": slack_enabled}
    if "min_classification" not in config["webhooks"]:
        config["webhooks"]["min_classification"] = "critico"

    save_ti_config(config)
    active = [s for s, cfg in [("teams", {"url": teams_url, "enabled": teams_enabled}),
                                ("slack", {"url": slack_url, "enabled": slack_enabled})]
              if cfg["enabled"] and cfg["url"]]
    audit(db, _user.get("username", "?"), "webhooks_updated",
          details=f"Webhooks activos: {', '.join(active) or 'ninguno'}",
          ip=request.client.host if request.client else None)
    db.commit()
    return RedirectResponse(url="/admin?msg=webhooks_saved", status_code=303)


# ─── SMTP ─────────────────────────────────────────────────────────────────────

@router.post("/smtp")
async def save_smtp(
    request: Request,
    db: Session = Depends(get_db),
    _user: dict = Depends(require_admin),
):
    """Guarda configuración SMTP para alertas por email."""
    form     = await request.form()
    existing = load_smtp_config()

    enabled  = "smtp_enabled" in form
    password = form.get("smtp_password", "").strip()
    if password == "••••••••":
        password = existing.get("smtp_password", "")

    cfg = {
        "enabled":       enabled,
        "smtp_host":     form.get("smtp_host", "").strip(),
        "smtp_port":     int(form.get("smtp_port", "587") or "587"),
        "smtp_tls":      "smtp_tls" in form,
        "smtp_user":     form.get("smtp_user", "").strip(),
        "smtp_password": password,
        "smtp_from":     form.get("smtp_from", "").strip(),
        "notify_emails": form.get("notify_emails", "").strip(),
    }
    save_smtp_config(cfg)
    audit(db, _user.get("username", "?"), "smtp_config_saved",
          details=f"enabled={enabled}, host={cfg['smtp_host']}",
          ip=request.client.host if request.client else None)
    db.commit()
    return RedirectResponse(url="/admin?msg=smtp_saved", status_code=303)


@router.post("/smtp/test")
async def test_smtp(request: Request, _user: dict = Depends(require_admin)):
    """Prueba la conexión SMTP con la configuración actual."""
    cfg = load_smtp_config()
    ok, msg = test_smtp_connection(cfg)
    return JSONResponse({"ok": ok, "message": msg})


# ─── TheHive ──────────────────────────────────────────────────────────────────

@router.get("/thehive")
async def thehive_config_page(
    request: Request,
    db: Session = Depends(get_db),
    _user: dict = Depends(require_admin),
):
    """Página de configuración de integración con TheHive SOAR."""
    from app.services.thehive import load_thehive_config
    cfg = load_thehive_config()
    return templates.TemplateResponse("thehive_config.html", {
        "request": request,
        "cfg":     cfg,
        "user":    _user,
        "saved":   request.query_params.get("saved"),
    })


@router.post("/thehive")
async def save_thehive_config_route(
    request: Request,
    db: Session = Depends(get_db),
    _user: dict = Depends(require_admin),
):
    """Guarda configuración de TheHive SOAR."""
    from app.services.thehive import save_thehive_config, load_thehive_config
    form = await request.form()
    cfg  = load_thehive_config()
    cfg["thehive_url"] = str(form.get("thehive_url", "")).strip().rstrip("/")
    cfg["api_key"]     = str(form.get("api_key", "")).strip()
    cfg["default_org"] = str(form.get("default_org", "")).strip()
    cfg["verify_ssl"]  = form.get("verify_ssl") == "on"
    save_thehive_config(cfg)
    audit(db, _user["username"], "thehive_config_updated", target="thehive_config")
    db.commit()
    return RedirectResponse("/admin/thehive?saved=1", status_code=303)


