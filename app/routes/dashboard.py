"""
SOC Assist — Dashboard ejecutivo y historial de incidentes
"""
from datetime import datetime, timedelta
from collections import defaultdict
from fastapi import APIRouter, Request, Depends
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.models.database import get_db, Incident, IncidentAnswer
from app.core.engine import engine_instance
from app.core.auth import require_auth

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")

CLASSIFICATION_ORDER = ["informativo", "sospechoso", "incidente", "critico", "brecha"]


@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request, db: Session = Depends(get_db), _user: dict = Depends(require_auth)):
    all_incidents = db.query(Incident).order_by(Incident.timestamp.desc()).all()
    total = len(all_incidents)

    # KPI cards
    now = datetime.utcnow()
    today_count = sum(1 for i in all_incidents if i.timestamp.date() == now.date())
    critical_count = sum(1 for i in all_incidents if i.classification in ("critico", "brecha"))
    avg_score = round(sum(i.final_score for i in all_incidents) / total, 1) if total else 0

    # Classification breakdown (for donut chart)
    class_counts = defaultdict(int)
    for i in all_incidents:
        class_counts[i.classification] += 1

    classification_labels = []
    classification_data = []
    classification_colors = {
        "informativo": "#198754",
        "sospechoso":  "#ffc107",
        "incidente":   "#fd7e14",
        "critico":     "#dc3545",
        "brecha":      "#6f1a1a",
    }
    for key in CLASSIFICATION_ORDER:
        classification_labels.append(engine_instance.thresholds[key]["label"])
        classification_data.append(class_counts.get(key, 0))

    # Score trend — last 30 days (daily average)
    thirty_days_ago = now - timedelta(days=30)
    recent = [i for i in all_incidents if i.timestamp >= thirty_days_ago]
    daily_scores: dict[str, list] = defaultdict(list)
    for i in recent:
        day = i.timestamp.strftime("%d/%m")
        daily_scores[day].append(i.final_score)

    trend_labels = []
    trend_data = []
    for d in range(30, -1, -1):
        day = (now - timedelta(days=d)).strftime("%d/%m")
        trend_labels.append(day)
        vals = daily_scores.get(day, [])
        trend_data.append(round(sum(vals) / len(vals), 1) if vals else 0)

    # Top risk factors (questions with highest total contribution)
    factor_contributions: dict[str, float] = defaultdict(float)
    factor_labels_map: dict[str, str] = {}
    questions_map = engine_instance.questions_map

    for ans in db.query(IncidentAnswer).all():
        factor_contributions[ans.question_id] += ans.contribution
        if ans.question_id in questions_map:
            factor_labels_map[ans.question_id] = questions_map[ans.question_id]["text"][:50]

    top_factors = sorted(factor_contributions.items(), key=lambda x: x[1], reverse=True)[:10]
    factor_bar_labels = [factor_labels_map.get(qid, qid) for qid, _ in top_factors]
    factor_bar_data = [round(val, 1) for _, val in top_factors]

    # Module contribution averages
    module_contrib: dict[str, list] = defaultdict(list)
    for ans in db.query(IncidentAnswer).all():
        module_contrib[ans.module].append(ans.contribution)

    mod_labels = {m["id"]: m["label"] for m in engine_instance.modules}
    module_avg_labels = []
    module_avg_data = []
    for mod in engine_instance.module_weights:
        vals = module_contrib.get(mod, [])
        module_avg_labels.append(mod_labels.get(mod, mod))
        module_avg_data.append(round(sum(vals) / len(vals), 2) if vals else 0)

    # Recent 10 incidents for table
    recent_incidents = all_incidents[:10]

    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "total": total,
        "today_count": today_count,
        "critical_count": critical_count,
        "avg_score": avg_score,
        "classification_labels": classification_labels,
        "classification_data": classification_data,
        "classification_colors": list(classification_colors.values()),
        "trend_labels": trend_labels,
        "trend_data": trend_data,
        "factor_bar_labels": factor_bar_labels,
        "factor_bar_data": factor_bar_data,
        "module_avg_labels": module_avg_labels,
        "module_avg_data": module_avg_data,
        "recent_incidents": recent_incidents,
        "thresholds": engine_instance.thresholds,
    })


@router.get("/incidentes", response_class=HTMLResponse)
async def incidents_list(request: Request, db: Session = Depends(get_db), _user: dict = Depends(require_auth)):
    incidents = db.query(Incident).order_by(Incident.timestamp.desc()).all()
    return templates.TemplateResponse("incidents.html", {
        "request": request,
        "incidents": incidents,
        "thresholds": engine_instance.thresholds,
        "total": len(incidents),
    })


@router.get("/incidentes/{incident_id}", response_class=HTMLResponse)
async def incident_detail(incident_id: int, request: Request, db: Session = Depends(get_db), _user: dict = Depends(require_auth)):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        return HTMLResponse("<h2>Incidente no encontrado</h2>", status_code=404)

    questions_map = engine_instance.questions_map
    mod_labels = {m["id"]: m["label"] for m in engine_instance.modules}

    # Group answers by module
    answers_by_module: dict[str, list] = defaultdict(list)
    for ans in sorted(incident.answers, key=lambda a: a.contribution, reverse=True):
        answers_by_module[ans.module].append(ans)

    return templates.TemplateResponse("incident_detail.html", {
        "request": request,
        "incident": incident,
        "thresholds": engine_instance.thresholds,
        "answers_by_module": dict(answers_by_module),
        "mod_labels": mod_labels,
        "questions_map": questions_map,
    })
