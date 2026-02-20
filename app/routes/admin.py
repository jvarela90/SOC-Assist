"""
SOC Assist — Panel de Administración
Edición de pesos, umbrales y calibración manual.
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

    cal_logs = db.query(CalibrationLog).order_by(CalibrationLog.run_at.desc()).limit(5).all()
    weight_history = db.query(WeightHistory).order_by(WeightHistory.adjusted_at.desc()).limit(20).all()

    return templates.TemplateResponse("admin.html", {
        "request": request,
        "config": config,
        "modules": q_data["modules"],
        "questions": q_data["questions"],
        "cal_logs": cal_logs,
        "weight_history": weight_history,
        "thresholds": engine_instance.thresholds,
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
