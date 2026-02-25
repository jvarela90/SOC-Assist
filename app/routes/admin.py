"""
SOC Assist — Panel de Administración
Edición de pesos, umbrales, calibración manual, claves de TI y gestión de usuarios.
"""
import io
import json
import re
import secrets
import string
import zipfile
from datetime import datetime
from pathlib import Path
from fastapi import APIRouter, Request, Depends, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func
from sqlalchemy.orm import Session
from app.models.database import get_db, CalibrationLog, WeightHistory, User, AuditLog, Incident, audit
from app.core.engine import engine_instance
from app.core.calibration import run_calibration
from app.core.auth import require_admin, hash_password
from app.services.threat_intel import load_ti_config, save_ti_config

router = APIRouter(prefix="/admin")
templates = Jinja2Templates(directory="app/templates")

BASE_DIR = Path(__file__).resolve().parent.parent.parent
CONFIG_PATH = BASE_DIR / "config_engine.json"
QUESTIONS_PATH = BASE_DIR / "questions.json"


def _load_json(path: Path) -> dict:
    raw = path.read_text(encoding="utf-8")
    clean = re.sub(r'//[^\n]*', '', raw)
    return json.loads(clean)


def _save_json(path: Path, data: dict):
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


@router.get("", response_class=HTMLResponse)
@router.get("/", response_class=HTMLResponse)
async def admin_home(request: Request, db: Session = Depends(get_db), _user: dict = Depends(require_admin)):
    config = _load_json(CONFIG_PATH)
    q_data = _load_json(QUESTIONS_PATH)
    ti_config = load_ti_config()

    cal_logs = db.query(CalibrationLog).order_by(CalibrationLog.run_at.desc()).limit(5).all()
    weight_history = db.query(WeightHistory).order_by(WeightHistory.adjusted_at.desc()).limit(20).all()

    # Mask API keys for display (show only last 4 chars)
    def _mask(key: str) -> str:
        if not key or len(key) < 5:
            return "" if not key else "****"
        return "*" * (len(key) - 4) + key[-4:]

    ti_display = {
        "virustotal": {
            "api_key_masked": _mask(ti_config.get("virustotal", {}).get("api_key", "")),
            "configured": bool(ti_config.get("virustotal", {}).get("api_key", "")),
        },
        "abuseipdb": {
            "api_key_masked": _mask(ti_config.get("abuseipdb", {}).get("api_key", "")),
            "configured": bool(ti_config.get("abuseipdb", {}).get("api_key", "")),
        },
        "xforce": {
            "api_key_masked": _mask(ti_config.get("xforce", {}).get("api_key", "")),
            "api_password_masked": _mask(ti_config.get("xforce", {}).get("api_password", "")),
            "configured": bool(
                ti_config.get("xforce", {}).get("api_key", "") and
                ti_config.get("xforce", {}).get("api_password", "")
            ),
        },
    }

    # Webhook config for display
    wh_raw = ti_config.get("webhooks", {})
    webhooks = {
        "teams": {
            "url":     wh_raw.get("teams", {}).get("url", ""),
            "enabled": wh_raw.get("teams", {}).get("enabled", False),
        },
        "slack": {
            "url":     wh_raw.get("slack", {}).get("url", ""),
            "enabled": wh_raw.get("slack", {}).get("enabled", False),
        },
    }

    users_list = db.query(User).order_by(User.username).all()

    return templates.TemplateResponse("admin.html", {
        "request": request,
        "config": config,
        "modules": q_data["modules"],
        "questions": q_data["questions"],
        "cal_logs": cal_logs,
        "weight_history": weight_history,
        "thresholds": engine_instance.thresholds,
        "ti_display": ti_display,
        "webhooks": webhooks,
        "users_list": users_list,
    })


@router.post("/module-weights")
async def update_module_weights(request: Request, db: Session = Depends(get_db), _user: dict = Depends(require_admin)):
    form = await request.form()
    config = _load_json(CONFIG_PATH)

    for mod in config["module_weights"]:
        key = f"weight_{mod}"
        if key in form:
            try:
                old = config["module_weights"][mod]
                new = round(float(form[key]), 3)
                new = max(0.1, min(5.0, new))
                if abs(new - old) > 0.001:
                    config["module_weights"][mod] = new
                    db.add(WeightHistory(
                        module=mod,
                        change_type="module_weight",
                        old_value=old,
                        new_value=new,
                        reason="Edición manual vía panel admin"
                    ))
            except ValueError:
                pass

    _save_json(CONFIG_PATH, config)
    engine_instance.reload()
    audit(db, _user.get("username", "?"), "module_weights_updated",
          details="Pesos de módulos editados manualmente", ip=request.client.host if request.client else None)
    db.commit()
    return RedirectResponse(url="/admin?msg=module_weights_saved", status_code=303)


@router.post("/thresholds")
async def update_thresholds(request: Request, db: Session = Depends(get_db), _user: dict = Depends(require_admin)):
    form = await request.form()
    config = _load_json(CONFIG_PATH)

    for key in config["thresholds"]:
        min_key = f"thresh_{key}_min"
        max_key = f"thresh_{key}_max"
        if min_key in form and max_key in form:
            try:
                config["thresholds"][key]["min"] = int(form[min_key])
                config["thresholds"][key]["max"] = int(form[max_key])
            except ValueError:
                pass

    _save_json(CONFIG_PATH, config)
    engine_instance.reload()
    audit(db, _user.get("username", "?"), "thresholds_updated",
          details="Umbrales de clasificación editados manualmente", ip=request.client.host if request.client else None)
    db.commit()
    return RedirectResponse(url="/admin?msg=thresholds_saved", status_code=303)


@router.post("/question-weight/{question_id}")
async def update_question_weight(
    question_id: str,
    request: Request,
    db: Session = Depends(get_db),
    _user: dict = Depends(require_admin),
):
    form = await request.form()
    q_data = _load_json(QUESTIONS_PATH)

    for q in q_data["questions"]:
        if q["id"] == question_id:
            try:
                old = float(q.get("weight", 1.0))
                new = round(float(form["weight"]), 3)
                new = max(0.1, min(5.0, new))
                q["weight"] = new
                db.add(WeightHistory(
                    question_id=question_id,
                    module=q["module"],
                    change_type="question_weight",
                    old_value=old,
                    new_value=new,
                    reason="Edición manual vía panel admin"
                ))
            except (ValueError, KeyError):
                pass
            break

    _save_json(QUESTIONS_PATH, q_data)
    engine_instance.reload()
    audit(db, _user.get("username", "?"), "question_weight_updated",
          target=question_id, details=f"Peso de pregunta editado manualmente",
          ip=request.client.host if request.client else None)
    db.commit()
    return RedirectResponse(url="/admin?msg=question_saved", status_code=303)


@router.post("/calibrate")
async def manual_calibration(request: Request, db: Session = Depends(get_db), _user: dict = Depends(require_admin)):
    result = run_calibration(db)
    engine_instance.reload()
    status = result.get("status", "unknown")
    audit(db, _user.get("username", "?"), "calibration_run",
          details=f"Calibración manual ejecutada — estado: {status}",
          ip=request.client.host if request.client else None)
    db.commit()
    return RedirectResponse(url=f"/admin?msg=calibration_{status}", status_code=303)


@router.post("/ti-keys")
async def save_ti_keys(request: Request, db: Session = Depends(get_db), _user: dict = Depends(require_admin)):
    """Save Threat Intelligence API keys to ti_config.json."""
    form = await request.form()
    config = load_ti_config()

    updated = []
    # VirusTotal
    vt_key = form.get("vt_api_key", "").strip()
    if vt_key and not vt_key.startswith("*"):
        config.setdefault("virustotal", {})["api_key"] = vt_key
        updated.append("virustotal")

    # AbuseIPDB
    abuse_key = form.get("abuse_api_key", "").strip()
    if abuse_key and not abuse_key.startswith("*"):
        config.setdefault("abuseipdb", {})["api_key"] = abuse_key
        updated.append("abuseipdb")

    # IBM X-Force
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
async def clear_ti_keys(request: Request, db: Session = Depends(get_db), _user: dict = Depends(require_admin)):
    """Clear all Threat Intelligence API keys."""
    form = await request.form()
    source = form.get("source", "all")
    config = load_ti_config()

    if source == "all" or source == "virustotal":
        config.setdefault("virustotal", {})["api_key"] = ""
    if source == "all" or source == "abuseipdb":
        config.setdefault("abuseipdb", {})["api_key"] = ""
    if source == "all" or source == "xforce":
        config.setdefault("xforce", {})["api_key"] = ""
        config.setdefault("xforce", {})["api_password"] = ""

    save_ti_config(config)
    audit(db, _user.get("username", "?"), "ti_keys_cleared",
          details=f"Claves TI eliminadas: {source}",
          ip=request.client.host if request.client else None)
    db.commit()
    return RedirectResponse(url="/admin?msg=ti_keys_cleared", status_code=303)


@router.post("/webhooks")
async def save_webhooks(request: Request, db: Session = Depends(get_db), _user: dict = Depends(require_admin)):
    """Save webhook notification settings."""
    form = await request.form()
    config = load_ti_config()

    teams_url = form.get("teams_url", "").strip()
    teams_enabled = "teams_enabled" in form  # checkbox

    slack_url = form.get("slack_url", "").strip()
    slack_enabled = "slack_enabled" in form

    config.setdefault("webhooks", {})
    config["webhooks"]["teams"] = {"url": teams_url, "enabled": teams_enabled}
    config["webhooks"]["slack"] = {"url": slack_url, "enabled": slack_enabled}

    # Keep existing min_classification if set
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


# ── User management ──────────────────────────────────────────────────────────

@router.post("/users/add")
async def add_user(request: Request, db: Session = Depends(get_db), _user: dict = Depends(require_admin)):
    form = await request.form()
    username = form.get("username", "").strip()
    password = form.get("password", "").strip()
    role = form.get("role", "analyst")

    if not username or not password:
        return RedirectResponse(url="/admin?msg=user_error&tab=users", status_code=303)
    if role not in ("analyst", "admin"):
        role = "analyst"
    if db.query(User).filter(User.username == username).first():
        return RedirectResponse(url="/admin?msg=user_exists&tab=users", status_code=303)

    db.add(User(username=username, password_hash=hash_password(password), role=role))
    audit(db, _user.get("username", "?"), "user_created",
          target=username, details=f"Rol: {role}",
          ip=request.client.host if request.client else None)
    db.commit()
    return RedirectResponse(url="/admin?msg=user_added&tab=users", status_code=303)


@router.post("/users/{user_id}/password")
async def change_user_password(
    user_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_admin),
):
    form = await request.form()
    new_password = form.get("new_password", "").strip()
    if not new_password:
        return RedirectResponse(url="/admin?msg=user_error&tab=users", status_code=303)

    user = db.query(User).filter(User.id == user_id).first()
    if user:
        user.password_hash       = hash_password(new_password)
        user.password_changed_at = datetime.utcnow()
        audit(db, current_user.get("username", "?"), "user_password_changed",
              target=user.username, ip=request.client.host if request.client else None)
        db.commit()
    return RedirectResponse(url="/admin/usuarios?msg=password_changed", status_code=303)


@router.post("/users/{user_id}/delete")
async def delete_user(
    user_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_admin),
):
    # Prevent deleting own account
    if user_id == current_user.get("id"):
        return RedirectResponse(url="/admin?msg=user_self_delete&tab=users", status_code=303)

    user = db.query(User).filter(User.id == user_id).first()
    if user:
        deleted_username = user.username
        db.delete(user)
        audit(db, current_user.get("username", "?"), "user_deleted",
              target=deleted_username, ip=request.client.host if request.client else None)
        db.commit()
    return RedirectResponse(url="/admin?msg=user_deleted&tab=users", status_code=303)


# ── Extended user management ─────────────────────────────────────────────────

@router.get("/usuarios", response_class=HTMLResponse)
async def usuarios_page(
    request: Request,
    db: Session = Depends(get_db),
    _user: dict = Depends(require_admin),
):
    """Dedicated user management page with full traceability."""
    users = db.query(User).order_by(User.username).all()

    # Last incident per user (match analyst_name == username, case-insensitive)
    last_incidents: dict[int, object] = {}
    for u in users:
        inc = (
            db.query(Incident)
            .filter(func.lower(Incident.analyst_name) == u.username.lower())
            .order_by(Incident.timestamp.desc())
            .first()
        )
        if inc:
            last_incidents[u.id] = inc

    # Stats
    total   = len(users)
    active  = sum(1 for u in users if u.is_active)
    admins  = sum(1 for u in users if u.role == "admin")
    with_rc = sum(1 for u in users if u.recovery_code_hash)

    # Recovery flash (generated code to show once)
    recovery_flash = request.session.pop("_recovery_flash", None)

    msg = request.query_params.get("msg", "")

    return templates.TemplateResponse("users.html", {
        "request":        request,
        "users":          users,
        "last_incidents": last_incidents,
        "stats":          {"total": total, "active": active, "admins": admins, "with_rc": with_rc},
        "current_user":   _user,
        "recovery_flash": recovery_flash,
        "msg":            msg,
        "thresholds":     engine_instance.thresholds,
    })


@router.post("/users/{user_id}/toggle-active")
async def toggle_user_active(
    user_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_admin),
):
    """Activate or deactivate a user account."""
    if user_id == current_user.get("id"):
        return RedirectResponse(url="/admin/usuarios?msg=user_self_deactivate", status_code=303)

    user = db.query(User).filter(User.id == user_id).first()
    if user:
        user.is_active = not user.is_active
        action = "user_activated" if user.is_active else "user_deactivated"
        audit(db, current_user.get("username", "?"), action,
              target=user.username, ip=request.client.host if request.client else None)
        db.commit()
    return RedirectResponse(url="/admin/usuarios?msg=status_changed", status_code=303)


@router.post("/users/{user_id}/role")
async def change_user_role(
    user_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_admin),
):
    """Change a user's role (analyst ↔ admin)."""
    if user_id == current_user.get("id"):
        return RedirectResponse(url="/admin/usuarios?msg=user_self_role", status_code=303)

    form = await request.form()
    new_role = form.get("role", "analyst")
    if new_role not in ("analyst", "admin"):
        new_role = "analyst"

    user = db.query(User).filter(User.id == user_id).first()
    if user:
        old_role = user.role
        user.role = new_role
        audit(db, current_user.get("username", "?"), "user_role_changed",
              target=user.username, details=f"{old_role} → {new_role}",
              ip=request.client.host if request.client else None)
        db.commit()
    return RedirectResponse(url="/admin/usuarios?msg=role_changed", status_code=303)


@router.post("/users/{user_id}/notes")
async def update_user_notes(
    user_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_admin),
):
    """Update admin notes for a user."""
    form = await request.form()
    notes = (form.get("notes") or "").strip()[:1000]

    user = db.query(User).filter(User.id == user_id).first()
    if user:
        user.notes = notes or None
        audit(db, current_user.get("username", "?"), "user_notes_updated",
              target=user.username, ip=request.client.host if request.client else None)
        db.commit()
    return RedirectResponse(url="/admin/usuarios?msg=notes_saved", status_code=303)


@router.post("/users/{user_id}/generate-recovery")
async def generate_recovery_code(
    user_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_admin),
):
    """Generate a single-use recovery code for a user. Code is shown ONCE."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        return RedirectResponse(url="/admin/usuarios?msg=user_not_found", status_code=303)

    # Generate a readable recovery code: XXXX-XXXX-XXXX-XXXX (hex segments)
    code = "-".join(
        "".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(6))
        for _ in range(4)
    )

    user.recovery_code_hash = hash_password(code)
    user.recovery_set_at    = datetime.utcnow()
    audit(db, current_user.get("username", "?"), "user_recovery_generated",
          target=user.username, ip=request.client.host if request.client else None)
    db.commit()

    # Store code in session to show ONCE on next page load
    request.session["_recovery_flash"] = {
        "username": user.username,
        "code":     code,
        "set_at":   datetime.utcnow().strftime("%d/%m/%Y %H:%M"),
    }
    return RedirectResponse(url="/admin/usuarios?msg=recovery_generated", status_code=303)


@router.post("/users/{user_id}/revoke-recovery")
async def revoke_recovery_code(
    user_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_admin),
):
    """Revoke an existing recovery code."""
    user = db.query(User).filter(User.id == user_id).first()
    if user and user.recovery_code_hash:
        user.recovery_code_hash = None
        user.recovery_set_at    = None
        audit(db, current_user.get("username", "?"), "user_recovery_revoked",
              target=user.username, ip=request.client.host if request.client else None)
        db.commit()
    return RedirectResponse(url="/admin/usuarios?msg=recovery_revoked", status_code=303)


# ── Backup (#55) ──────────────────────────────────────────────────────────────

@router.get("/backup")
async def download_backup(request: Request, db: Session = Depends(get_db), _user: dict = Depends(require_admin)):
    """Download a ZIP backup of the database and all config files."""
    buf = io.BytesIO()
    files_to_backup = [
        BASE_DIR / "soc_assist.db",
        CONFIG_PATH,
        QUESTIONS_PATH,
        BASE_DIR / "playbooks.json",
        BASE_DIR / "ti_config.json",
    ]

    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for fpath in files_to_backup:
            if fpath.exists():
                zf.write(fpath, arcname=fpath.name)

    buf.seek(0)
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    filename = f"soc_assist_backup_{ts}.zip"
    audit(db, _user.get("username", "?"), "backup_downloaded",
          details=filename, ip=request.client.host if request.client else None)
    db.commit()
    return StreamingResponse(
        buf,
        media_type="application/zip",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


# ── Audit Log viewer (#54) ────────────────────────────────────────────────────

@router.get("/audit-log", response_class=HTMLResponse)
async def view_audit_log(
    request: Request,
    db: Session = Depends(get_db),
    _user: dict = Depends(require_admin),
    page: int = 1,
):
    """Display the admin audit log, paginated."""
    per_page = 50
    offset = (page - 1) * per_page
    total = db.query(AuditLog).count()
    logs = (
        db.query(AuditLog)
        .order_by(AuditLog.timestamp.desc())
        .offset(offset)
        .limit(per_page)
        .all()
    )
    return templates.TemplateResponse("audit_log.html", {
        "request": request,
        "logs": logs,
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": max(1, (total + per_page - 1) // per_page),
    })
