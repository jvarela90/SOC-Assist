"""
SOC Assist — Rutas del formulario de evaluación
"""
from fastapi import APIRouter, Request, Depends
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from app.models.database import get_db, Incident, IncidentAnswer
from app.core.engine import engine_instance

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


@router.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@router.get("/evaluar", response_class=HTMLResponse)
async def evaluar_form(request: Request):
    modules = engine_instance.get_module_info()
    questions_by_module = engine_instance.get_questions_by_module()
    module_weights = engine_instance.module_weights

    # Pre-calculate weighted scores for real-time JavaScript indicator
    questions_with_scores = {}
    for mod, qs in questions_by_module.items():
        mod_w = module_weights.get(mod, 1.0)
        for q in qs:
            q_w = q.get("weight", 1.0)
            scored_opts = []
            for opt in q.get("options", []):
                scored_opts.append({
                    **opt,
                    "weighted_score": round(opt["score"] * mod_w * q_w, 2)
                })
            questions_with_scores[q["id"]] = scored_opts

    return templates.TemplateResponse("form.html", {
        "request": request,
        "modules": modules,
        "questions_by_module": questions_by_module,
        "questions_with_scores": questions_with_scores,
        "total_questions": len(engine_instance.questions),
    })


@router.post("/evaluar", response_class=HTMLResponse)
async def evaluar_submit(request: Request, db: Session = Depends(get_db)):
    form_data = await request.form()
    answers = dict(form_data)

    # Remove non-question fields
    answers.pop("analyst_name", None)
    analyst_name = dict(await request.form()).get("analyst_name", "")

    # Clean answers: only keep q_xxx keys
    clean_answers = {k: v for k, v in answers.items() if k.startswith("q_")}

    # Evaluate
    result = engine_instance.evaluate(clean_answers)

    # Save to DB
    incident = Incident(
        base_score=result["base_score"],
        final_score=result["final_score"],
        multiplier=result["multiplier"],
        classification=result["classification"],
        hard_rule_id=result["hard_rule"]["id"] if result["hard_rule"] else None,
        escalated=result["classification"] in ("critico", "brecha"),
        analyst_name=analyst_name or "Anónimo",
    )
    db.add(incident)
    db.flush()  # get the incident.id

    for detail in result["answer_details"]:
        ans = IncidentAnswer(
            incident_id=incident.id,
            question_id=detail["question_id"],
            module=detail["module"],
            value=detail["value"],
            raw_score=detail["raw_score"],
            contribution=detail["contribution"],
        )
        db.add(ans)

    db.commit()
    db.refresh(incident)

    # Module label lookup
    mod_labels = {m["id"]: m["label"] for m in engine_instance.modules}

    return templates.TemplateResponse("result.html", {
        "request": request,
        "result": result,
        "incident_id": incident.id,
        "mod_labels": mod_labels,
        "analyst_name": analyst_name,
    })


@router.post("/api/score-preview", response_class=JSONResponse)
async def score_preview(request: Request):
    """Real-time score calculation for JavaScript."""
    body = await request.json()
    answers = body.get("answers", {})
    result = engine_instance.evaluate(answers)
    return {
        "final_score": result["final_score"],
        "classification": result["classification"],
        "threshold_info": result["threshold_info"],
    }


@router.post("/incident/{incident_id}/resolve")
async def resolve_incident(
    incident_id: int,
    request: Request,
    db: Session = Depends(get_db)
):
    form_data = await request.form()
    resolution = form_data.get("resolution")
    notes = form_data.get("notes", "")

    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if incident:
        incident.resolution = resolution
        incident.analyst_notes = notes
        incident.escalated = resolution in ("tp_escalated",)
        db.commit()

    from fastapi.responses import RedirectResponse
    return RedirectResponse(url=f"/incidentes/{incident_id}", status_code=303)
