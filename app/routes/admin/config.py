"""
SOC Assist — Admin: Configuración del motor de scoring.
Rutas: GET/POST /admin (página principal), /admin/module-weights,
       /admin/thresholds, /admin/question-weight/{id}, /admin/calibrate.
"""
from fastapi import Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from app.models.database import get_db, CalibrationLog, WeightHistory, audit
from app.core.engine import engine_instance
from app.core.calibration import run_calibration
from app.core.auth import require_admin
from app.services.threat_intel import load_ti_config
from app.services.mailer import load_smtp_config
from app.services.config_loader import load_json_file

from ._base import router, templates, CONFIG_PATH, QUESTIONS_PATH, save_json


# ─── Panel principal ──────────────────────────────────────────────────────────

@router.get("", response_class=HTMLResponse)
@router.get("/", response_class=HTMLResponse)
async def admin_home(
    request: Request,
    db: Session = Depends(get_db),
    _user: dict = Depends(require_admin),
):
    """Renderiza el panel de administración con todas las secciones en tabs."""
    config    = load_json_file(CONFIG_PATH)
    q_data    = load_json_file(QUESTIONS_PATH)
    ti_config = load_ti_config()

    cal_logs       = db.query(CalibrationLog).order_by(CalibrationLog.run_at.desc()).limit(5).all()
    weight_history = db.query(WeightHistory).order_by(WeightHistory.adjusted_at.desc()).limit(20).all()

    def _mask(key: str) -> str:
        """Enmascara claves API para mostrar solo los últimos 4 caracteres."""
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

    wh_raw = ti_config.get("webhooks", {})
    webhooks = {
        "teams": {"url": wh_raw.get("teams", {}).get("url", ""),
                  "enabled": wh_raw.get("teams", {}).get("enabled", False)},
        "slack": {"url": wh_raw.get("slack", {}).get("url", ""),
                  "enabled": wh_raw.get("slack", {}).get("enabled", False)},
    }

    from app.models.database import User
    users_list = db.query(User).order_by(User.username).all()

    smtp_cfg = load_smtp_config()
    smtp_display = dict(smtp_cfg)
    if smtp_display.get("smtp_password"):
        smtp_display["smtp_password"] = "••••••••"

    return templates.TemplateResponse("admin.html", {
        "request":        request,
        "config":         config,
        "modules":        q_data["modules"],
        "questions":      q_data["questions"],
        "cal_logs":       cal_logs,
        "weight_history": weight_history,
        "thresholds":     engine_instance.thresholds,
        "ti_display":     ti_display,
        "webhooks":       webhooks,
        "smtp":           smtp_display,
        "users_list":     users_list,
    })


# ─── Pesos de módulos ─────────────────────────────────────────────────────────

@router.post("/module-weights")
async def update_module_weights(
    request: Request,
    db: Session = Depends(get_db),
    _user: dict = Depends(require_admin),
):
    """Actualiza los pesos de los módulos de scoring desde el formulario."""
    form   = await request.form()
    config = load_json_file(CONFIG_PATH)

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
                        module=mod, change_type="module_weight",
                        old_value=old, new_value=new,
                        reason="Edición manual vía panel admin",
                    ))
            except ValueError:
                pass

    save_json(CONFIG_PATH, config)
    engine_instance.reload()
    audit(db, _user.get("username", "?"), "module_weights_updated",
          details="Pesos de módulos editados manualmente",
          ip=request.client.host if request.client else None)
    db.commit()
    return RedirectResponse(url="/admin?msg=module_weights_saved", status_code=303)


# ─── Umbrales de clasificación ────────────────────────────────────────────────

@router.post("/thresholds")
async def update_thresholds(
    request: Request,
    db: Session = Depends(get_db),
    _user: dict = Depends(require_admin),
):
    """Actualiza los umbrales numéricos de cada nivel de clasificación."""
    form   = await request.form()
    config = load_json_file(CONFIG_PATH)

    for key in config["thresholds"]:
        min_key = f"thresh_{key}_min"
        max_key = f"thresh_{key}_max"
        if min_key in form and max_key in form:
            try:
                config["thresholds"][key]["min"] = int(form[min_key])
                config["thresholds"][key]["max"] = int(form[max_key])
            except ValueError:
                pass

    save_json(CONFIG_PATH, config)
    engine_instance.reload()
    audit(db, _user.get("username", "?"), "thresholds_updated",
          details="Umbrales de clasificación editados manualmente",
          ip=request.client.host if request.client else None)
    db.commit()
    return RedirectResponse(url="/admin?msg=thresholds_saved", status_code=303)


# ─── Peso individual de pregunta ──────────────────────────────────────────────

@router.post("/question-weight/{question_id}")
async def update_question_weight(
    question_id: str,
    request: Request,
    db: Session = Depends(get_db),
    _user: dict = Depends(require_admin),
):
    """Actualiza el peso de una pregunta individual en questions.json."""
    form   = await request.form()
    q_data = load_json_file(QUESTIONS_PATH)

    for q in q_data["questions"]:
        if q["id"] == question_id:
            try:
                old = float(q.get("weight", 1.0))
                new = round(float(form["weight"]), 3)
                new = max(0.1, min(5.0, new))
                q["weight"] = new
                db.add(WeightHistory(
                    question_id=question_id, module=q["module"],
                    change_type="question_weight", old_value=old, new_value=new,
                    reason="Edición manual vía panel admin",
                ))
            except (ValueError, KeyError):
                pass
            break

    save_json(QUESTIONS_PATH, q_data)
    engine_instance.reload()
    audit(db, _user.get("username", "?"), "question_weight_updated",
          target=question_id, details="Peso de pregunta editado manualmente",
          ip=request.client.host if request.client else None)
    db.commit()
    return RedirectResponse(url="/admin?msg=question_saved", status_code=303)


# ─── Calibración automática ───────────────────────────────────────────────────

@router.post("/calibrate")
async def manual_calibration(
    request: Request,
    db: Session = Depends(get_db),
    _user: dict = Depends(require_admin),
):
    """Ejecuta la calibración automática de pesos basada en datos históricos."""
    result = run_calibration(db)
    engine_instance.reload()
    status = result.get("status", "unknown")
    audit(db, _user.get("username", "?"), "calibration_run",
          details=f"Calibración manual ejecutada — estado: {status}",
          ip=request.client.host if request.client else None)
    db.commit()
    return RedirectResponse(url=f"/admin?msg=calibration_{status}", status_code=303)
