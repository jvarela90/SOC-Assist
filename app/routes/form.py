"""
SOC Assist — Rutas del formulario de evaluación
Navegación por bloques temáticos (no por módulos).
"""
import asyncio
from fastapi import APIRouter, Request, Depends
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from app.models.database import get_db, Incident, IncidentAnswer
from app.core.engine import engine_instance
from app.core.auth import require_auth
from app.services.notifications import notify_incident

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


def _build_blocks_data() -> tuple[list, dict]:
    """
    Build display blocks from questions.json.
    Returns:
        blocks_ordered: list of block defs sorted by id
        questions_by_block: { block_id: [question, ...] } sorted by display_position
    """
    q_data = engine_instance.questions
    block_defs = getattr(engine_instance, '_q_data_blocks', [])

    # Reload blocks from raw data each time (engine may have reloaded)
    import json, re
    from pathlib import Path
    raw = (Path(__file__).parent.parent.parent / "questions.json").read_text(encoding="utf-8")
    data = json.loads(re.sub(r'//[^\n]*', '', raw))
    block_defs = data.get("blocks", [])
    blocks_ordered = sorted(block_defs, key=lambda b: b["id"])

    questions_by_block: dict[int, list] = {}
    for q in q_data:
        b = q.get("display_block", 0)
        if b not in questions_by_block:
            questions_by_block[b] = []
        questions_by_block[b].append(q)

    for b in questions_by_block:
        questions_by_block[b].sort(key=lambda q: q.get("display_position", 0))

    return blocks_ordered, questions_by_block


def _build_weighted_options(questions_by_block: dict) -> dict:
    """
    Pre-calculate weighted score per option for the JS real-time indicator.
    Scores are stored in data attributes — NOT displayed to user.
    """
    module_weights = engine_instance.module_weights
    result = {}
    for _block, qs in questions_by_block.items():
        for q in qs:
            mod_w = module_weights.get(q["module"], 1.0)
            q_w = q.get("weight", 1.0)
            opts = []
            for opt in q.get("options", []):
                opts.append({
                    **opt,
                    "weighted_score": round(opt["score"] * mod_w * q_w, 2)
                })
            result[q["id"]] = opts
    return result


@router.get("/", response_class=HTMLResponse)
async def index(request: Request, _user: dict = Depends(require_auth)):
    return templates.TemplateResponse("index.html", {"request": request})


@router.get("/evaluar", response_class=HTMLResponse)
async def evaluar_form(request: Request, _user: dict = Depends(require_auth)):
    blocks_ordered, questions_by_block = _build_blocks_data()
    weighted_options = _build_weighted_options(questions_by_block)
    total_questions = sum(len(qs) for qs in questions_by_block.values())

    return templates.TemplateResponse("form.html", {
        "request": request,
        "blocks": blocks_ordered,
        "questions_by_block": questions_by_block,
        "weighted_options": weighted_options,
        "total_blocks": len(blocks_ordered),
        "total_questions": total_questions,
    })


@router.post("/evaluar", response_class=HTMLResponse)
async def evaluar_submit(request: Request, db: Session = Depends(get_db), _user: dict = Depends(require_auth)):
    form_data = await request.form()
    all_data = dict(form_data)
    analyst_name = all_data.get("analyst_name", "Anónimo") or "Anónimo"

    clean_answers = {k: v for k, v in all_data.items() if k.startswith("q_")}

    result = engine_instance.evaluate(clean_answers)

    incident = Incident(
        base_score=result["base_score"],
        final_score=result["final_score"],
        multiplier=result["multiplier"],
        classification=result["classification"],
        hard_rule_id=result["hard_rule"]["id"] if result["hard_rule"] else None,
        escalated=result["classification"] in ("critico", "brecha"),
        analyst_name=analyst_name,
    )
    db.add(incident)
    db.flush()

    for detail in result["answer_details"]:
        db.add(IncidentAnswer(
            incident_id=incident.id,
            question_id=detail["question_id"],
            module=detail["module"],
            value=detail["value"],
            raw_score=detail["raw_score"],
            contribution=detail["contribution"],
        ))

    db.commit()
    db.refresh(incident)

    # Fire-and-forget webhook notification (non-blocking)
    hard_rule_id = result["hard_rule"]["id"] if result["hard_rule"] else None
    base_url = str(request.base_url).rstrip("/")
    asyncio.create_task(notify_incident(
        incident_id=incident.id,
        classification=result["classification"],
        final_score=result["final_score"],
        analyst_name=analyst_name,
        hard_rule=hard_rule_id,
        base_url=base_url,
    ))

    mod_labels = {m["id"]: m["label"] for m in engine_instance.modules}

    return templates.TemplateResponse("result.html", {
        "request": request,
        "result": result,
        "incident_id": incident.id,
        "mod_labels": mod_labels,
        "analyst_name": analyst_name,
    })


@router.post("/api/score-preview", response_class=JSONResponse)
async def score_preview(request: Request, _user: dict = Depends(require_auth)):
    body = await request.json()
    answers = body.get("answers", {})
    result = engine_instance.evaluate(answers)
    return {
        "final_score": result["final_score"],
        "classification": result["classification"],
        "threshold_info": result["threshold_info"],
    }


@router.post("/incident/{incident_id}/resolve")
async def resolve_incident(incident_id: int, request: Request, db: Session = Depends(get_db), _user: dict = Depends(require_auth)):
    form_data = await request.form()
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if incident:
        incident.resolution = form_data.get("resolution")
        incident.analyst_notes = form_data.get("notes", "")
        incident.escalated = incident.resolution in ("tp_escalated",)
        db.commit()
    return RedirectResponse(url=f"/incidentes/{incident_id}", status_code=303)
