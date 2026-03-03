"""
SOC Assist — Rutas del Chatbot (Web UI)
Interfaz conversacional alternativa al formulario wizard.
"""
from __future__ import annotations
import asyncio
import json
import uuid
from datetime import datetime
from pathlib import Path

from fastapi import APIRouter, Request, Depends, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.models.database import (
    get_db, ChatSession, Incident, IncidentAnswer, audit, get_visible_org_ids,
)
from app.core.engine import engine_instance
from app.core.auth import require_auth
from app.services.threat_intel import lookup as ti_lookup, is_private_ip
from app.services.notifications import notify_incident
from app.services.mailer import send_incident_alert
from app.routes.assets import lookup_asset_by_identifier, CRITICALITY_MULTIPLIERS
from app.services.chatbot_engine import (
    GATEWAY_QUESTIONS, CATEGORY_LABELS,
    build_question_data, infer_category, ti_to_auto_answers,
    get_question_queue, calculate_score_preview, build_threat_classification,
)

router = APIRouter(prefix="/chatbot", tags=["Chatbot"])
templates = Jinja2Templates(directory="app/templates")

_BASE_DIR = Path(__file__).resolve().parent.parent.parent


# ─── Helpers internos ────────────────────────────────────────────────────────

def _load_session(session_uuid: str, db: Session) -> ChatSession:
    s = db.query(ChatSession).filter(ChatSession.session_uuid == session_uuid).first()
    if not s:
        raise HTTPException(status_code=404, detail="Sesión no encontrada")
    return s


def _jloads(text: str, default):
    try:
        return json.loads(text or "")
    except Exception:
        return default


def _save_session(s: ChatSession, db: Session, **fields):
    for k, v in fields.items():
        setattr(s, k, v)
    s.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(s)


async def _run_ti_lookups(indicators: list[str]) -> list[dict]:
    if not indicators:
        return []
    tasks = [ti_lookup(ind) for ind in indicators]
    try:
        results = await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), timeout=8)
        return [r for r in results if isinstance(r, dict)]
    except Exception:
        return []


def _build_next_response(s: ChatSession, done: bool = False) -> dict:
    """Construye el payload de respuesta con la siguiente pregunta."""
    queue = _jloads(s.question_queue, [])
    answered = _jloads(s.answered_questions, [])
    ti_auto = _jloads(s.ti_answers, {})

    # Total estimado = preguntas ya respondidas + cola restante
    total = len(answered) + len(queue)
    num = len(answered) + 1

    next_q_data = None
    if not done and queue:
        next_q_id = queue[0]
        next_q_data = build_question_data(next_q_id)
        if next_q_data:
            next_q_data["question_num"] = num
            next_q_data["total_questions"] = total

    preview = calculate_score_preview(_jloads(s.answers, {}))

    return {
        "question":         next_q_data,
        "done":             done or (not next_q_data),
        "phase":            s.phase,
        "category":         s.inferred_category,
        "category_label":   CATEGORY_LABELS.get(s.inferred_category or "unknown", "Sin categoría"),
        "confidence":       round(s.category_confidence, 2),
        "classification_preview": preview,
        "answered_count":   len(answered),
        "total_questions":  total,
        "auto_answered":    list(ti_auto.keys()),
    }


# ─── UI principal ────────────────────────────────────────────────────────────

@router.get("", response_class=HTMLResponse)
async def chatbot_page(request: Request, _user: dict = Depends(require_auth)):
    return templates.TemplateResponse("chatbot.html", {
        "request": request,
        "user": _user,
    })


# ─── Gestión de sesión ────────────────────────────────────────────────────────

@router.post("/session/start")
async def session_start(
    request: Request,
    db: Session = Depends(get_db),
    _user: dict = Depends(require_auth),
):
    """Crea una nueva ChatSession y retorna la primera pregunta gateway."""
    body = await request.json() if request.headers.get("content-type", "").startswith("application/json") else {}

    s = ChatSession(
        session_uuid=str(uuid.uuid4()),
        user_id=_user.get("id"),
        organization_id=_user.get("org_id"),
        question_queue=json.dumps(GATEWAY_QUESTIONS),
    )
    db.add(s)
    db.commit()
    db.refresh(s)

    # Primera pregunta
    first_q = build_question_data(GATEWAY_QUESTIONS[0])
    if first_q:
        first_q["question_num"] = 1
        first_q["total_questions"] = len(GATEWAY_QUESTIONS)

    return JSONResponse({
        "session_id": s.session_uuid,
        "question":   first_q,
        "phase":      "gateway",
        "category":   None,
        "confidence": 0.0,
        "done":       False,
    })


@router.post("/session/iocs")
async def session_iocs(
    request: Request,
    db: Session = Depends(get_db),
    _user: dict = Depends(require_auth),
):
    """
    Recibe IoCs, ejecuta TI lookup y auto-responde preguntas de Bloque 2.
    Actualiza la categoría inferida basándose en los resultados TI.
    """
    body = await request.json()
    session_id = body.get("session_id", "")
    s = _load_session(session_id, db)

    iocs = {
        "ip_src":  body.get("ip_src", "").strip(),
        "ip_dst":  body.get("ip_dst", "").strip(),
        "url":     body.get("url", "").strip(),
        "hash":    body.get("hash", "").strip(),
        "domain":  body.get("domain", "").strip(),
    }

    # TI lookups para IPs y URL públicas
    indicators = [v for k, v in iocs.items() if v and k != "hash" and not is_private_ip(v)]
    ti_results = await _run_ti_lookups(indicators)

    # Auto-responder preguntas desde TI
    ti_answers = ti_to_auto_answers(ti_results)

    # Re-inferir categoría con datos TI
    current_answers = _jloads(s.answers, {})
    category, confidence, probs = infer_category(current_answers, ti_results)

    # Actualizar queue: quitar las auto-respondidas
    current_queue = _jloads(s.question_queue, [])
    already_answered = _jloads(s.answered_questions, [])
    new_queue = [q for q in current_queue if q not in ti_answers]

    _save_session(s, db,
        iocs=json.dumps(iocs),
        ti_results=json.dumps(ti_results, default=str),
        ti_answers=json.dumps(ti_answers),
        inferred_category=category,
        category_confidence=confidence,
        category_probs=json.dumps(probs),
        question_queue=json.dumps(new_queue),
        answers=json.dumps({**current_answers, **ti_answers}),
    )

    return JSONResponse({
        "ti_results":    ti_results,
        "auto_answered": ti_answers,
        "category":      category,
        "category_label": CATEGORY_LABELS.get(category, "Sin categoría"),
        "confidence":    round(confidence, 2),
        "probs":         probs,
        "indicators_checked": indicators,
    })


@router.post("/session/answer")
async def session_answer(
    request: Request,
    db: Session = Depends(get_db),
    _user: dict = Depends(require_auth),
):
    """Registra la respuesta del analista y retorna la siguiente pregunta."""
    body = await request.json()
    session_id  = body.get("session_id", "")
    question_id = body.get("question_id", "")
    answer_val  = body.get("answer_value", "")

    s = _load_session(session_id, db)
    if s.status == "completed":
        raise HTTPException(400, "Sesión ya completada")

    # Actualizar answers
    answers = _jloads(s.answers, {})
    answers[question_id] = answer_val

    # Actualizar cola: quitar la pregunta respondida
    queue = _jloads(s.question_queue, [])
    if question_id in queue:
        queue.remove(question_id)

    answered = _jloads(s.answered_questions, [])
    if question_id not in answered:
        answered.append(question_id)

    # Re-inferir categoría
    ti_results = _jloads(s.ti_results, [])
    category, confidence, probs = infer_category(answers, ti_results)

    # ¿Cambió la fase? Después de las gateway questions, construir cola dirigida
    ti_auto = _jloads(s.ti_answers, {})
    gateway_done = all(q in answers or q in ti_auto for q in GATEWAY_QUESTIONS)
    phase = s.phase

    if gateway_done and phase == "gateway":
        phase = "targeted"
        # Construir nueva cola para la categoría inferida
        queue = get_question_queue(category, answered, list(ti_auto.keys()))

    # ¿Se acabaron las preguntas?
    done = len(queue) == 0

    _save_session(s, db,
        answers=json.dumps(answers),
        question_queue=json.dumps(queue),
        answered_questions=json.dumps(answered),
        inferred_category=category,
        category_confidence=confidence,
        category_probs=json.dumps(probs),
        phase=phase,
    )

    return JSONResponse(_build_next_response(s, done))


@router.post("/session/skip")
async def session_skip(
    request: Request,
    db: Session = Depends(get_db),
    _user: dict = Depends(require_auth),
):
    """Omite la pregunta actual (no guarda respuesta) y avanza."""
    body = await request.json()
    session_id  = body.get("session_id", "")
    question_id = body.get("question_id", "")

    s = _load_session(session_id, db)
    queue = _jloads(s.question_queue, [])
    answered = _jloads(s.answered_questions, [])

    if question_id in queue:
        queue.remove(question_id)
    if question_id not in answered:
        answered.append(question_id)  # marcada como visitada/omitida

    done = len(queue) == 0
    _save_session(s, db,
        question_queue=json.dumps(queue),
        answered_questions=json.dumps(answered),
    )

    return JSONResponse(_build_next_response(s, done))


@router.post("/session/back")
async def session_back(
    request: Request,
    db: Session = Depends(get_db),
    _user: dict = Depends(require_auth),
):
    """Deshace la última respuesta y vuelve a esa pregunta."""
    body = await request.json()
    s = _load_session(body.get("session_id", ""), db)

    answered = _jloads(s.answered_questions, [])
    answers  = _jloads(s.answers, {})
    queue    = _jloads(s.question_queue, [])

    if not answered:
        return JSONResponse({"error": "No hay preguntas previas"}, status_code=400)

    last_q = answered.pop()
    answers.pop(last_q, None)
    # Reinsertar al frente de la cola
    queue.insert(0, last_q)

    _save_session(s, db,
        answers=json.dumps(answers),
        answered_questions=json.dumps(answered),
        question_queue=json.dumps(queue),
    )

    return JSONResponse(_build_next_response(s))


@router.post("/session/complete")
async def session_complete(
    request: Request,
    db: Session = Depends(get_db),
    _user: dict = Depends(require_auth),
):
    """
    Calcula el score final y construye la clasificación multidimensional.
    NO crea el incidente — devuelve el resultado para que el analista confirme.
    """
    body = await request.json()
    s = _load_session(body.get("session_id", ""), db)

    all_answers = _jloads(s.answers, {})
    ti_results  = _jloads(s.ti_results, [])

    result = engine_instance.evaluate(all_answers)

    category = s.inferred_category or "unknown"
    threat_cls = build_threat_classification(all_answers, category, ti_results, result)

    from app.services.config_loader import load_json_file
    from pathlib import Path
    playbooks = load_json_file(Path(__file__).resolve().parent.parent.parent / "playbooks.json")
    playbook  = playbooks.get(result["classification"], {})

    _save_session(s, db,
        phase="complete",
        final_score=result["final_score"],
        final_classification=result["classification"],
        threat_classification=json.dumps(threat_cls),
    )

    thresholds = engine_instance.thresholds
    cls_info = thresholds.get(result["classification"], {})

    return JSONResponse({
        "classification":      result["classification"],
        "classification_label": cls_info.get("label", result["classification"].title()),
        "classification_color": cls_info.get("color", "secondary"),
        "classification_emoji": cls_info.get("emoji", ""),
        "final_score":         result["final_score"],
        "base_score":          result["base_score"],
        "multiplier":          result["multiplier"],
        "recommendation":      result.get("recommendation", ""),
        "hard_rule":           result.get("hard_rule"),
        "active_multipliers":  result.get("active_multipliers", []),
        "top_factors":         sorted(
            result.get("answer_details", []),
            key=lambda d: d.get("contribution", 0),
            reverse=True
        )[:8],
        "threat_classification": threat_cls,
        "playbook":            playbook,
        "category":            category,
        "category_label":      CATEGORY_LABELS.get(category, "Sin categoría"),
    })


@router.post("/session/save")
async def session_save(
    request: Request,
    db: Session = Depends(get_db),
    _user: dict = Depends(require_auth),
):
    """
    Crea el Incident + IncidentAnswer en base de datos y retorna el incident_id.
    Equivalente al final de evaluar_submit() en form.py.
    """
    body = await request.json()
    s = _load_session(body.get("session_id", ""), db)

    if s.status == "completed" and s.incident_id:
        return JSONResponse({"incident_id": s.incident_id})

    all_answers = _jloads(s.answers, {})
    ti_results  = _jloads(s.ti_results, [])
    iocs        = _jloads(s.iocs, {})

    result = engine_instance.evaluate(all_answers)

    # TI summary
    ti_summary = "LIMPIO"
    for r in ti_results:
        v = r.get("summary_verdict", "")
        if v == "MALICIOSO":
            ti_summary = "MALICIOSO"
            break
        if v == "SOSPECHOSO":
            ti_summary = "SOSPECHOSO"

    # Contexto de red
    ctx = {
        "ip_src":    iocs.get("ip_src", ""),
        "ip_dst":    iocs.get("ip_dst", ""),
        "direction": iocs.get("direction", "unknown"),
        "url":       iocs.get("url", ""),
        "mac":       iocs.get("mac", ""),
        "ti_summary": ti_summary,
    }

    # Asset lookup
    org_ids = get_visible_org_ids(_user, db)
    matched_asset = None
    asset_mult = 1.0
    for candidate in [ctx["ip_src"], ctx["ip_dst"]]:
        if candidate:
            found = lookup_asset_by_identifier(candidate, org_ids, db)
            if found:
                matched_asset = found
                break

    if matched_asset:
        asset_mult = CRITICALITY_MULTIPLIERS.get(matched_asset.criticality, 1.0)
        result["final_score"]    = round(result["final_score"] * asset_mult, 2)
        result["multiplier"]     = round(result["multiplier"] * asset_mult, 3)
        result["classification"] = engine_instance._classify(result["final_score"])

    analyst_name = _user.get("username", "Chatbot")

    incident = Incident(
        base_score=result["base_score"],
        final_score=result["final_score"],
        multiplier=result["multiplier"],
        classification=result["classification"],
        hard_rule_id=result["hard_rule"]["id"] if result.get("hard_rule") else None,
        escalated=result["classification"] in ("critico", "brecha"),
        analyst_name=analyst_name,
        network_context=json.dumps(ctx, ensure_ascii=False),
        ti_enrichment=json.dumps(ti_results, ensure_ascii=False, default=str),
        organization_id=_user.get("org_id"),
        asset_id=matched_asset.id if matched_asset else None,
        asset_criticality_applied=bool(matched_asset and asset_mult != 1.0),
    )
    db.add(incident)
    db.flush()

    for detail in result.get("answer_details", []):
        db.add(IncidentAnswer(
            incident_id=incident.id,
            question_id=detail["question_id"],
            module=detail["module"],
            value=detail["value"],
            raw_score=detail["raw_score"],
            contribution=detail["contribution"],
        ))

    _save_session(s, db,
        status="completed",
        incident_id=incident.id,
        final_score=result["final_score"],
        final_classification=result["classification"],
    )
    db.commit()
    db.refresh(incident)

    audit(db, analyst_name, "chatbot_incident_created",
          target=f"incident/{incident.id}",
          details=f"via chatbot | {result['classification']} | score {result['final_score']}",
          org_id=_user.get("org_id"))
    db.commit()

    base_url = str(request.base_url).rstrip("/")
    asyncio.create_task(notify_incident(
        incident_id=incident.id,
        classification=result["classification"],
        final_score=result["final_score"],
        analyst_name=analyst_name,
        hard_rule=result["hard_rule"]["id"] if result.get("hard_rule") else None,
        base_url=base_url,
    ))
    asyncio.create_task(asyncio.to_thread(
        send_incident_alert,
        incident.id, result["classification"], result["final_score"], analyst_name, base_url,
    ))

    return JSONResponse({"incident_id": incident.id})
