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

import csv
import io

from fastapi import APIRouter, Request, Depends, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.models.database import (
    get_db, ChatSession, Incident, IncidentAnswer, audit, get_visible_org_ids,
)
from app.services.chatbot_utils import (
    jloads as _jloads_util, load_session as _load_session_util,
    save_session as _save_session_util, run_ti_lookups as _run_ti_lookups_util,
)
from app.core.engine import engine_instance
from app.core.auth import require_auth
from app.core.rate_limit import rate_limit_evaluar as _rate_limit
from app.services.threat_intel import lookup as ti_lookup, is_private_ip
from app.services.notifications import notify_incident
from app.services.mailer import send_incident_alert
from app.routes.assets import lookup_asset_by_identifier, CRITICALITY_MULTIPLIERS
from app.services.chatbot_engine import (
    GATEWAY_QUESTIONS, CATEGORY_LABELS,
    build_question_data, infer_category, ti_to_auto_answers,
    get_question_queue, calculate_score_preview, build_threat_classification,
)
from app.services.citizen_engine import (
    CITIZEN_GATEWAY, CITIZEN_CATEGORY_LABELS,
    build_citizen_question, citizen_infer_category,
    get_citizen_queue, citizen_classify, BRIDGE_MAP,
)

router = APIRouter(prefix="/chatbot", tags=["Chatbot"])
templates = Jinja2Templates(directory="app/templates")

_BASE_DIR = Path(__file__).resolve().parent.parent.parent


# ─── Helpers internos ────────────────────────────────────────────────────────
# Delegados a app/services/chatbot_utils para evitar duplicación con chatbot_api.py

def _load_session(session_uuid: str, db: Session) -> ChatSession:
    """Carga ChatSession por UUID o lanza HTTP 404."""
    return _load_session_util(session_uuid, db)


def _jloads(text: str, default):
    """Deserializa JSON con valor por defecto seguro."""
    return _jloads_util(text, default)


def _save_session(s: ChatSession, db: Session, **fields):
    """Persiste campos en ChatSession y hace commit."""
    _save_session_util(s, db, **fields)


async def _run_ti_lookups(indicators: list[str]) -> list[dict]:
    """Lookups TI en paralelo con timeout — delega a chatbot_utils."""
    return await _run_ti_lookups_util(indicators)


def _build_next_response(s: ChatSession, done: bool = False) -> dict:
    """Construye el payload de respuesta con la siguiente pregunta (SOC o ciudadano)."""
    queue    = _jloads(s.question_queue, [])
    answered = _jloads(s.answered_questions, [])
    ti_auto  = _jloads(s.ti_answers, {})
    mode     = s.mode or "soc"
    is_citizen = mode in ("ciudadano", "unificado") and s.phase in ("gateway", "targeted")

    total = len(answered) + len(queue)
    num   = len(answered) + 1

    next_q_data = None
    if not done and queue:
        next_q_id = queue[0]
        if is_citizen:
            next_q_data = build_citizen_question(next_q_id, num, total)
        else:
            next_q_data = build_question_data(next_q_id)
            if next_q_data:
                next_q_data["question_num"]    = num
                next_q_data["total_questions"] = total

    cat   = s.inferred_category or "unknown"
    label = (CITIZEN_CATEGORY_LABELS if is_citizen else CATEGORY_LABELS).get(cat, "Sin categoría")

    preview = {} if is_citizen else calculate_score_preview(_jloads(s.answers, {}))

    return {
        "question":               next_q_data,
        "done":                   done or (not next_q_data),
        "phase":                  s.phase,
        "mode":                   mode,
        "category":               cat,
        "category_label":         label,
        "confidence":             round(s.category_confidence, 2),
        "classification_preview": preview,
        "answered_count":         len(answered),
        "total_questions":        total,
        "auto_answered":          list(ti_auto.keys()),
    }


# ─── UI principal ────────────────────────────────────────────────────────────

@router.get("", response_class=HTMLResponse)
async def chatbot_page(request: Request, _user: dict = Depends(require_auth)):
    return templates.TemplateResponse("chatbot.html", {
        "request": request,
        "user": _user,
    })


# ─── Print / PDF de sesión (N1) ──────────────────────────────────────────────

@router.get("/session/{session_uuid}/print", response_class=HTMLResponse)
async def print_session(
    session_uuid: str,
    request: Request,
    db: Session = Depends(get_db),
    _user: dict = Depends(require_auth),
):
    """Página imprimible/PDF del resultado de una sesión completada."""
    s = _load_session(session_uuid, db)
    if s.phase != "complete" and not s.final_classification:
        raise HTTPException(400, "La sesión no está finalizada")

    mode     = s.mode or "soc"
    category = s.inferred_category or "unknown"
    all_answers = _jloads(s.answers, {})
    threat_cls  = _jloads(s.threat_classification, {})
    ti_results  = _jloads(s.ti_results, [])
    iocs        = _jloads(s.iocs, {})
    answered    = _jloads(s.answered_questions, [])

    # Build answered question list for display
    from app.services.chatbot_engine import build_question_data
    from app.services.citizen_engine import build_citizen_question, CITIZEN_CATEGORY_LABELS
    is_citizen = mode == "ciudadano"

    qa_list = []
    for qid in answered:
        val = all_answers.get(qid)
        if val is None:
            continue
        if is_citizen:
            q_data = build_citizen_question(qid, 1, 1)
        else:
            q_data = build_question_data(qid)
        if q_data:
            # Find option label
            label = next((o["label"] for o in q_data.get("options", []) if o["value"] == val), val)
            qa_list.append({"question": q_data["text"], "answer": label, "module": q_data.get("module", "")})

    MODE_LABELS = {"soc": "SOC Analista", "experto": "Experto+", "ciudadano": "Ciudadano", "unificado": "Unificado"}

    return templates.TemplateResponse("chatbot_print.html", {
        "request":         request,
        "user":            _user,
        "session":         s,
        "mode":            mode,
        "mode_label":      MODE_LABELS.get(mode, mode),
        "category":        category,
        "category_label":  (CITIZEN_CATEGORY_LABELS if is_citizen else CATEGORY_LABELS).get(category, ""),
        "threat_cls":      threat_cls,
        "iocs":            iocs,
        "qa_list":         qa_list,
        "ti_results":      ti_results,
        "generated_at":    datetime.utcnow().strftime("%d/%m/%Y %H:%M UTC"),
    })


# ─── Historial de sesiones (P2) ──────────────────────────────────────────────

@router.get("/sessions")
async def list_sessions(
    request: Request,
    db: Session = Depends(get_db),
    _user: dict = Depends(require_auth),
):
    """Retorna las últimas 30 sesiones del usuario actual."""
    from sqlalchemy import desc as _desc
    sessions = (
        db.query(ChatSession)
        .filter(ChatSession.user_id == _user["id"])
        .order_by(_desc(ChatSession.created_at))
        .limit(30)
        .all()
    )

    MODE_LABELS = {
        "soc":       "SOC Analista",
        "experto":   "Experto+",
        "ciudadano": "Ciudadano",
        "unificado": "Unificado",
    }

    def _fmt(s: ChatSession) -> dict:
        answered = _jloads(s.answered_questions, [])
        return {
            "session_uuid":     s.session_uuid,
            "mode":             s.mode or "soc",
            "mode_label":       MODE_LABELS.get(s.mode or "soc", s.mode),
            "status":           s.status,
            "phase":            s.phase,
            "classification":   s.final_classification,
            "final_score":      s.final_score,
            "category":         s.inferred_category,
            "answered_count":   len(answered),
            "incident_id":      s.incident_id,
            "created_at":       s.created_at.strftime("%d/%m/%Y %H:%M") if s.created_at else "",
            "updated_at":       s.updated_at.strftime("%d/%m/%Y %H:%M") if s.updated_at else "",
        }

    return JSONResponse({"sessions": [_fmt(s) for s in sessions]})


# ─── Gestión de sesión ────────────────────────────────────────────────────────

@router.post("/session/start")
async def session_start(
    request: Request,
    db: Session = Depends(get_db),
    _user: dict = Depends(require_auth),
):
    """Crea una nueva ChatSession y retorna la primera pregunta gateway."""
    body = await request.json() if request.headers.get("content-type", "").startswith("application/json") else {}
    mode = body.get("mode", "soc")
    if mode not in ("soc", "experto", "ciudadano", "unificado"):
        mode = "soc"
    test_mode = bool(body.get("test_mode", False))

    # Seleccionar gateway según modo
    is_citizen = mode in ("ciudadano", "unificado")
    gw = CITIZEN_GATEWAY if is_citizen else GATEWAY_QUESTIONS

    s = ChatSession(
        session_uuid=str(uuid.uuid4()),
        user_id=_user.get("id"),
        organization_id=_user.get("org_id"),
        question_queue=json.dumps(gw),
        mode=mode,
        test_mode=test_mode,
    )
    db.add(s)
    db.commit()
    db.refresh(s)

    # Primera pregunta
    if is_citizen:
        first_q = build_citizen_question(gw[0], 1, len(gw))
    else:
        first_q = build_question_data(gw[0])
        if first_q:
            first_q["question_num"]    = 1
            first_q["total_questions"] = len(gw)

    return JSONResponse({
        "session_id": s.session_uuid,
        "question":   first_q,
        "phase":      "gateway",
        "mode":       mode,
        "test_mode":  test_mode,
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
    _rl: None = Depends(_rate_limit),
):
    """Registra la respuesta y retorna la siguiente pregunta (multi-modo)."""
    body        = await request.json()
    session_id  = body.get("session_id", "")
    question_id = body.get("question_id", "")
    answer_val  = body.get("answer_value", "")

    s = _load_session(session_id, db)
    if s.status == "completed":
        raise HTTPException(400, "Sesión ya completada")

    mode     = s.mode or "soc"
    answers  = _jloads(s.answers, {})
    queue    = _jloads(s.question_queue, [])
    answered = _jloads(s.answered_questions, [])
    ti_auto  = _jloads(s.ti_answers, {})
    phase    = s.phase

    answers[question_id] = answer_val
    if question_id in queue:
        queue.remove(question_id)
    if question_id not in answered:
        answered.append(question_id)

    # ── Modo ciudadano / unificado (preguntas N) ──────────────────────────────
    if mode in ("ciudadano", "unificado") and phase in ("gateway", "targeted"):
        category, confidence, probs = citizen_infer_category(answers)

        gw_done = all(q in answers for q in CITIZEN_GATEWAY)
        if gw_done and phase == "gateway":
            phase = "targeted"
            queue = get_citizen_queue(category, answered)

        done = len(queue) == 0

        # Unificado: cuando el ciudadano termina, pasar al puente SOC
        if done and mode == "unificado":
            phase = "bridge"
            bridge_entry = BRIDGE_MAP.get(category, ["q_002"])
            from app.services.chatbot_engine import get_question_queue as soc_queue
            soc_q = soc_queue(category if category != "unknown" else "unknown", answered, [])
            # Priorizar preguntas del bridge al inicio
            soc_q = [q for q in bridge_entry if q not in answered] + \
                    [q for q in soc_q if q not in bridge_entry and q not in answered]
            queue = soc_q
            done  = False

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

    # ── Modo SOC / experto / fase SOC en unificado ────────────────────────────
    ti_results = _jloads(s.ti_results, [])
    category, confidence, probs = infer_category(answers, ti_results)

    gw_soc = GATEWAY_QUESTIONS
    gateway_done = all(q in answers or q in ti_auto for q in gw_soc)

    if gateway_done and phase in ("gateway", "bridge"):
        phase = "targeted"
        queue = get_question_queue(category, answered, list(ti_auto.keys()))

    # Experto: transición temprana si confianza ya supera el umbral
    elif mode == "experto" and confidence >= 0.45 and phase == "gateway":
        phase = "targeted"
        queue = get_question_queue(category, answered, list(ti_auto.keys()))

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
    mode        = s.mode or "soc"
    category    = s.inferred_category or "unknown"

    # ── Clasificación ciudadana (P1-P4) ───────────────────────────────────────
    if mode == "ciudadano":
        p_cls = citizen_classify(all_answers, category)
        _save_session(s, db,
            phase="complete",
            final_score=0.0,
            final_classification=p_cls["level"],
            threat_classification=json.dumps(p_cls),
        )
        return JSONResponse({
            "mode":                  "ciudadano",
            "classification":        p_cls["level"],
            "classification_label":  p_cls["label"],
            "classification_color":  p_cls["color"],
            "classification_emoji":  p_cls["label"].split()[0],
            "final_score":           0,
            "recommendation":        p_cls["recommendation"],
            "threat_classification": p_cls,
            "category":              category,
            "category_label":        CITIZEN_CATEGORY_LABELS.get(category, "Sin categoría"),
            "top_factors":           [],
        })

    # ── Clasificación SOC (informativo/brecha) ────────────────────────────────
    result     = engine_instance.evaluate(all_answers)
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
    cls_info   = thresholds.get(result["classification"], {})

    return JSONResponse({
        "mode":                  mode,
        "classification":        result["classification"],
        "classification_label":  cls_info.get("label", result["classification"].title()),
        "classification_color":  cls_info.get("color", "secondary"),
        "classification_emoji":  cls_info.get("emoji", ""),
        "final_score":           result["final_score"],
        "base_score":            result["base_score"],
        "multiplier":            result["multiplier"],
        "recommendation":        result.get("recommendation", ""),
        "hard_rule":             result.get("hard_rule"),
        "active_multipliers":    result.get("active_multipliers", []),
        "top_factors":           sorted(
            result.get("answer_details", []),
            key=lambda d: d.get("contribution", 0),
            reverse=True
        )[:8],
        "threat_classification": threat_cls,
        "playbook":              playbook,
        "category":              category,
        "category_label":        CATEGORY_LABELS.get(category, "Sin categoría"),
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
        return JSONResponse({"incident_id": s.incident_id, "test_mode": s.test_mode})

    # ── Modo simulacro (P1): no crear Incident real ───────────────────────────
    if s.test_mode:
        all_answers = _jloads(s.answers, {})
        result = engine_instance.evaluate(all_answers)
        _save_session(s, db,
            status="completed",
            final_score=result["final_score"],
            final_classification=result["classification"],
        )
        return JSONResponse({
            "incident_id": None,
            "test_mode":   True,
            "classification": result["classification"],
            "final_score":    result["final_score"],
            "message": "Sesión de simulacro completada. No se creó ningún incidente.",
        })

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


# ─── Exportación JSON / CSV (N2) ──────────────────────────────────────────────

@router.get("/session/{session_uuid}/export")
async def export_session(
    session_uuid: str,
    request: Request,
    db: Session = Depends(get_db),
    _user: dict = Depends(require_auth),
    format: str = "json",
):
    """
    Exporta la sesión completada como JSON o CSV.
    GET /chatbot/session/{uuid}/export?format=json|csv
    """
    s = _load_session(session_uuid, db)
    if s.phase != "complete" and not s.final_classification:
        raise HTTPException(400, "La sesión no está finalizada")

    mode        = s.mode or "soc"
    all_answers = _jloads(s.answers, {})
    answered    = _jloads(s.answered_questions, [])
    iocs        = _jloads(s.iocs, {})
    ti_results  = _jloads(s.ti_results, [])
    threat_cls  = _jloads(s.threat_classification, {})

    from app.services.citizen_engine import build_citizen_question, CITIZEN_CATEGORY_LABELS
    is_citizen = mode == "ciudadano"

    # Construir lista Q&A
    qa_list = []
    for qid in answered:
        val = all_answers.get(qid)
        if val is None:
            continue
        if is_citizen:
            q_data = build_citizen_question(qid, 1, 1)
        else:
            q_data = build_question_data(qid)
        if q_data:
            label = next((o["label"] for o in q_data.get("options", []) if o["value"] == val), val)
            qa_list.append({
                "question_id": qid,
                "module":      q_data.get("module", ""),
                "question":    q_data["text"],
                "answer_value": val,
                "answer_label": label,
            })

    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

    # ── JSON ──────────────────────────────────────────────────────────────────
    if format == "json":
        export_data = {
            "export_generated_at": datetime.utcnow().isoformat() + "Z",
            "session_uuid":        s.session_uuid,
            "mode":                mode,
            "test_mode":           bool(s.test_mode),
            "analyst":             _user.get("username"),
            "created_at":          s.created_at.isoformat() if s.created_at else None,
            "classification":      s.final_classification,
            "final_score":         s.final_score,
            "inferred_category":   s.inferred_category,
            "category_confidence": round(s.category_confidence, 3),
            "incident_id":         s.incident_id,
            "iocs":                iocs,
            "ti_results":          ti_results,
            "threat_classification": threat_cls,
            "answers":             all_answers,
            "qa_list":             qa_list,
        }
        content = json.dumps(export_data, ensure_ascii=False, indent=2, default=str)
        filename = f"soc_assist_session_{ts}.json"
        return StreamingResponse(
            io.BytesIO(content.encode("utf-8")),
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename={filename}"},
        )

    # ── CSV ───────────────────────────────────────────────────────────────────
    buf = io.StringIO()
    writer = csv.writer(buf)

    # Cabecera del informe
    writer.writerow(["SOC Assist — Exportación de sesión"])
    writer.writerow(["session_uuid", s.session_uuid])
    writer.writerow(["modo", mode])
    writer.writerow(["simulacro", "Sí" if s.test_mode else "No"])
    writer.writerow(["analista", _user.get("username", "")])
    writer.writerow(["fecha", s.created_at.strftime("%d/%m/%Y %H:%M UTC") if s.created_at else ""])
    writer.writerow(["clasificación", s.final_classification or ""])
    writer.writerow(["score_final", s.final_score or ""])
    writer.writerow(["categoría", s.inferred_category or ""])
    writer.writerow(["incidente_id", s.incident_id or ""])
    writer.writerow([])

    # IoCs
    writer.writerow(["── IoCs ──"])
    for k, v in iocs.items():
        if v:
            writer.writerow([k, v])
    writer.writerow([])

    # Q&A
    writer.writerow(["── Preguntas y respuestas ──"])
    writer.writerow(["ID", "Módulo", "Pregunta", "Respuesta"])
    for item in qa_list:
        writer.writerow([item["question_id"], item["module"], item["question"], item["answer_label"]])

    content = buf.getvalue()
    filename = f"soc_assist_session_{ts}.csv"
    return StreamingResponse(
        io.BytesIO(content.encode("utf-8-sig")),   # BOM para Excel
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )
