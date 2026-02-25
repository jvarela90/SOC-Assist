"""
SOC Assist — Rutas del formulario de evaluación
Navegación por bloques temáticos (no por módulos).
"""
import asyncio
import json
import re
from pathlib import Path
from fastapi import APIRouter, Request, Depends, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from app.models.database import get_db, Incident, IncidentAnswer, IncidentComment, audit
from app.core.engine import engine_instance
from app.core.auth import require_auth
from app.core.rate_limit import rate_limit_evaluar
from app.services.notifications import notify_incident
from app.services.mitre import get_techniques_for_incident
from app.services.threat_intel import lookup as ti_lookup, is_private_ip, is_valid_ip

_PLAYBOOKS_PATH = Path(__file__).resolve().parent.parent.parent / "playbooks.json"


def _load_playbooks() -> dict:
    if _PLAYBOOKS_PATH.exists():
        raw = _PLAYBOOKS_PATH.read_text(encoding="utf-8")
        return json.loads(re.sub(r'//[^\n]*', '', raw))
    return {}

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


_SEVERITY_ORDER = ["informativo", "sospechoso", "incidente", "critico", "brecha"]


def _max_severity(a: str, b: str) -> str:
    """Return the higher severity of the two classification strings."""
    ia = _SEVERITY_ORDER.index(a) if a in _SEVERITY_ORDER else 0
    ib = _SEVERITY_ORDER.index(b) if b in _SEVERITY_ORDER else 0
    return _SEVERITY_ORDER[max(ia, ib)]


async def _run_ti_lookups(indicators: list[str]) -> list[dict]:
    """Run concurrent TI lookups with an 8-second timeout. Returns list of results."""
    if not indicators:
        return []
    tasks = [ti_lookup(ind, "auto") for ind in indicators]
    try:
        results = await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), timeout=8)
        return [r for r in results if isinstance(r, dict)]
    except asyncio.TimeoutError:
        return []


@router.post("/evaluar", response_class=HTMLResponse, dependencies=[Depends(rate_limit_evaluar)])
async def evaluar_submit(request: Request, db: Session = Depends(get_db), _user: dict = Depends(require_auth)):
    form_data = await request.form()
    all_data = dict(form_data)
    analyst_name = all_data.get("analyst_name", "Anónimo") or "Anónimo"

    # ── Extract network context fields (ctx_* prefix) ──────────────────────────
    ctx = {
        "ip_src":    all_data.get("ctx_ip_src", "").strip(),
        "ip_dst":    all_data.get("ctx_ip_dst", "").strip(),
        "direction": all_data.get("ctx_ip_direction", "unknown"),
        "url":       all_data.get("ctx_url", "").strip(),
        "mac":       all_data.get("ctx_mac", "").strip(),
    }

    # Only pass q_* answers to the scoring engine
    clean_answers = {k: v for k, v in all_data.items() if k.startswith("q_")}

    result = engine_instance.evaluate(clean_answers)

    # ── Run TI lookups concurrently on public IPs/URLs ──────────────────────────
    indicators_to_check = []
    for ind in [ctx["ip_src"], ctx["ip_dst"], ctx["url"]]:
        if ind and not is_private_ip(ind):
            indicators_to_check.append(ind)

    ti_results = await _run_ti_lookups(indicators_to_check)

    # ── Determine TI verdict and potential score adjustment ─────────────────────
    ti_summary = "LIMPIO"
    for r in ti_results:
        v = r.get("summary_verdict", "")
        if v == "MALICIOSO":
            ti_summary = "MALICIOSO"
            break
        if v == "SOSPECHOSO" and ti_summary != "MALICIOSO":
            ti_summary = "SOSPECHOSO"

    ti_adjustment = None
    if ti_summary in ("MALICIOSO", "SOSPECHOSO"):
        adj_mult = 1.5 if ti_summary == "MALICIOSO" else 1.2
        adj_score = round(result["final_score"] * adj_mult)
        adj_cls = engine_instance._classify(adj_score) if hasattr(engine_instance, "_classify") else result["classification"]
        if ti_summary == "MALICIOSO":
            adj_cls = _max_severity(adj_cls, "critico")
        ti_adjustment = {
            "multiplier":     adj_mult,
            "score":          adj_score,
            "classification": adj_cls,
        }

    ctx["ti_summary"] = ti_summary

    # ── Persist incident ────────────────────────────────────────────────────────
    incident = Incident(
        base_score=result["base_score"],
        final_score=result["final_score"],
        multiplier=result["multiplier"],
        classification=result["classification"],
        hard_rule_id=result["hard_rule"]["id"] if result["hard_rule"] else None,
        escalated=result["classification"] in ("critico", "brecha"),
        analyst_name=analyst_name,
        network_context=json.dumps(ctx, ensure_ascii=False),
        ti_enrichment=json.dumps(ti_results, ensure_ascii=False, default=str),
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

    playbook = _load_playbooks().get(result["classification"], {})
    mitre_techniques = get_techniques_for_incident(
        module_scores=result.get("module_scores", {}),
        hard_rule_id=hard_rule_id,
    )

    return templates.TemplateResponse("result.html", {
        "request": request,
        "result": result,
        "incident_id": incident.id,
        "mod_labels": mod_labels,
        "analyst_name": analyst_name,
        "playbook": playbook,
        "mitre_techniques": mitre_techniques,
        "ti_summary": ti_summary,
        "ti_adjustment": ti_adjustment,
        "thresholds": engine_instance.thresholds,
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
async def resolve_incident(incident_id: int, request: Request, db: Session = Depends(get_db), user: dict = Depends(require_auth)):
    form_data = await request.form()
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if incident:
        old_res = incident.resolution
        incident.resolution = form_data.get("resolution")
        incident.analyst_notes = form_data.get("notes", "")
        incident.escalated = incident.resolution in ("tp_escalated",)
        audit(db, user["username"], "resolve_incident",
              target=f"incident/{incident_id}",
              details=f"{old_res} → {incident.resolution}")
        db.commit()
    return RedirectResponse(url=f"/incidentes/{incident_id}", status_code=303)


@router.post("/incident/{incident_id}/comment")
async def add_comment(incident_id: int, request: Request, db: Session = Depends(get_db), user: dict = Depends(require_auth)):
    """Add a collaborative comment to an incident (#45)."""
    form_data = await request.form()
    text = form_data.get("text", "").strip()
    if text:
        db.add(IncidentComment(
            incident_id=incident_id,
            author=user["username"],
            text=text,
        ))
        db.commit()
    return RedirectResponse(url=f"/incidentes/{incident_id}#comments", status_code=303)


@router.post("/incident/{incident_id}/assign")
async def assign_incident(incident_id: int, request: Request, db: Session = Depends(get_db), user: dict = Depends(require_auth)):
    """Assign incident to an analyst (#46)."""
    form_data = await request.form()
    assigned_to = form_data.get("assigned_to", "").strip()
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if incident:
        old_assigned = incident.assigned_to
        incident.assigned_to = assigned_to or None
        audit(db, user["username"], "assign_incident",
              target=f"incident/{incident_id}",
              details=f"{old_assigned} → {incident.assigned_to}")
        db.commit()
    return RedirectResponse(url=f"/incidentes/{incident_id}", status_code=303)


@router.post("/incident/{incident_id}/apply-ti-adjustment")
async def apply_ti_adjustment(incident_id: int, request: Request, db: Session = Depends(get_db), user: dict = Depends(require_auth)):
    """Analyst confirms applying TI-based score adjustment to an incident."""
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incidente no encontrado")

    ctx_raw = incident.network_context
    if not ctx_raw:
        return RedirectResponse(url=f"/incidentes/{incident_id}", status_code=303)

    try:
        ctx = json.loads(ctx_raw)
    except Exception:
        return RedirectResponse(url=f"/incidentes/{incident_id}", status_code=303)

    ti_summary = ctx.get("ti_summary", "LIMPIO")
    if ti_summary not in ("MALICIOSO", "SOSPECHOSO"):
        return RedirectResponse(url=f"/incidentes/{incident_id}", status_code=303)

    adj_mult = 1.5 if ti_summary == "MALICIOSO" else 1.2
    new_final = round(incident.final_score * adj_mult, 2)
    new_mult  = round(incident.multiplier * adj_mult, 3)

    # Reclassify at new score
    new_cls = incident.classification
    for cls_name, info in sorted(engine_instance.thresholds.items(),
                                  key=lambda x: x[1].get("min_score", 0)):
        min_s = info.get("min_score", info.get("min", 0))
        if new_final >= min_s:
            new_cls = cls_name
    if ti_summary == "MALICIOSO":
        new_cls = _max_severity(new_cls, "critico")

    old_final = incident.final_score
    incident.final_score    = new_final
    incident.multiplier     = new_mult
    incident.classification = new_cls
    incident.ti_adjusted    = True
    incident.escalated      = new_cls in ("critico", "brecha")

    audit(db, user["username"], "ti_adjustment_applied",
          target=f"incident/{incident_id}",
          details=f"TI {ti_summary}: {old_final} → {new_final} → {new_cls}",
          ip=request.client.host if request.client else None)
    db.commit()
    return RedirectResponse(url=f"/incidentes/{incident_id}?msg=ti_adjusted", status_code=303)
