"""
SOC Assist — Panel de Administración
Edición de pesos, umbrales, calibración manual y claves de TI.
"""
import json
import re
from pathlib import Path
from fastapi import APIRouter, Request, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from app.models.database import get_db, CalibrationLog, WeightHistory
from app.core.engine import engine_instance
from app.core.calibration import run_calibration
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
async def admin_home(request: Request, db: Session = Depends(get_db)):
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

    return templates.TemplateResponse("admin.html", {
        "request": request,
        "config": config,
        "modules": q_data["modules"],
        "questions": q_data["questions"],
        "cal_logs": cal_logs,
        "weight_history": weight_history,
        "thresholds": engine_instance.thresholds,
        "ti_display": ti_display,
    })


@router.post("/module-weights")
async def update_module_weights(request: Request, db: Session = Depends(get_db)):
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
    db.commit()
    return RedirectResponse(url="/admin?msg=module_weights_saved", status_code=303)


@router.post("/thresholds")
async def update_thresholds(request: Request, db: Session = Depends(get_db)):
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
    db.commit()
    return RedirectResponse(url="/admin?msg=thresholds_saved", status_code=303)


@router.post("/question-weight/{question_id}")
async def update_question_weight(
    question_id: str,
    request: Request,
    db: Session = Depends(get_db)
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
    db.commit()
    return RedirectResponse(url="/admin?msg=question_saved", status_code=303)


@router.post("/calibrate")
async def manual_calibration(request: Request, db: Session = Depends(get_db)):
    result = run_calibration(db)
    engine_instance.reload()
    status = result.get("status", "unknown")
    return RedirectResponse(url=f"/admin?msg=calibration_{status}", status_code=303)


@router.post("/ti-keys")
async def save_ti_keys(request: Request):
    """Save Threat Intelligence API keys to ti_config.json."""
    form = await request.form()
    config = load_ti_config()

    # VirusTotal
    vt_key = form.get("vt_api_key", "").strip()
    if vt_key and not vt_key.startswith("*"):
        config.setdefault("virustotal", {})["api_key"] = vt_key

    # AbuseIPDB
    abuse_key = form.get("abuse_api_key", "").strip()
    if abuse_key and not abuse_key.startswith("*"):
        config.setdefault("abuseipdb", {})["api_key"] = abuse_key

    # IBM X-Force
    xf_key = form.get("xforce_api_key", "").strip()
    xf_pwd = form.get("xforce_api_password", "").strip()
    if xf_key and not xf_key.startswith("*"):
        config.setdefault("xforce", {})["api_key"] = xf_key
    if xf_pwd and not xf_pwd.startswith("*"):
        config.setdefault("xforce", {})["api_password"] = xf_pwd

    save_ti_config(config)
    return RedirectResponse(url="/admin?msg=ti_keys_saved", status_code=303)


@router.post("/ti-keys/clear")
async def clear_ti_keys(request: Request):
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
    return RedirectResponse(url="/admin?msg=ti_keys_cleared", status_code=303)
