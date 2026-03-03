"""
SOC Assist — Chatbot REST API
Permite a sistemas SOAR/SIEM interactuar con el chatbot programáticamente.
Auth: session cookie O HTTP Basic (igual que /api/v1).
"""
from __future__ import annotations
import json
import uuid
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Request, Depends, HTTPException
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.models.database import get_db, ChatSession, User, get_visible_org_ids
from app.core.auth import verify_password
from app.services.chatbot_engine import (
    GATEWAY_QUESTIONS, CATEGORY_LABELS,
    build_question_data, infer_category, ti_to_auto_answers,
    get_question_queue, build_threat_classification,
)
from app.core.engine import engine_instance

router = APIRouter(prefix="/api/v1/chat", tags=["Chat API v1"])
_security = HTTPBasic(auto_error=False)


# ─── Auth (igual que api.py) ──────────────────────────────────────────────────

async def _api_auth(
    request: Request,
    credentials: Optional[HTTPBasicCredentials] = Depends(_security),
    db: Session = Depends(get_db),
) -> dict:
    user = request.session.get("user")
    if user:
        return user
    if credentials:
        db_user = db.query(User).filter(
            User.username == credentials.username,
            User.is_active == True,
        ).first()
        if db_user and verify_password(credentials.password, db_user.password_hash):
            return {
                "id":       db_user.id,
                "username": db_user.username,
                "role":     db_user.role,
                "org_id":   db_user.organization_id,
            }
    raise HTTPException(
        status_code=401,
        detail="Credenciales inválidas",
        headers={"WWW-Authenticate": "Basic"},
    )


# ─── Pydantic schemas ─────────────────────────────────────────────────────────

class SessionCreateIn(BaseModel):
    iocs: dict = {}
    category_hint: Optional[str] = None

    model_config = {"from_attributes": True}


class IoCsIn(BaseModel):
    ip_src:  str = ""
    ip_dst:  str = ""
    url:     str = ""
    hash:    str = ""
    domain:  str = ""

    model_config = {"from_attributes": True}


class AnswerIn(BaseModel):
    question_id:  str
    answer_value: str

    model_config = {"from_attributes": True}


class SkipIn(BaseModel):
    question_id: str

    model_config = {"from_attributes": True}


class CompleteIn(BaseModel):
    create_incident: bool = False

    model_config = {"from_attributes": True}


class SessionStateOut(BaseModel):
    session_uuid:       str
    status:             str
    phase:              str
    inferred_category:  Optional[str]
    category_label:     str
    category_confidence: float
    answers_count:      int
    questions_remaining: int
    created_at:         str

    model_config = {"from_attributes": True}


class QuestionOut(BaseModel):
    id:             str
    text:           str
    help:           str
    module:         str
    options:        list[dict]
    question_num:   int
    total_questions: int

    model_config = {"from_attributes": True}


class ChatResultOut(BaseModel):
    classification:        str
    classification_label:  str
    final_score:           float
    threat_classification: dict
    incident_id:           Optional[int]

    model_config = {"from_attributes": True}


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _jloads(text: str, default):
    try:
        return json.loads(text or "")
    except Exception:
        return default


def _load_session(session_uuid: str, db: Session) -> ChatSession:
    s = db.query(ChatSession).filter(ChatSession.session_uuid == session_uuid).first()
    if not s:
        raise HTTPException(404, "Sesión no encontrada")
    return s


def _save(s: ChatSession, db: Session, **fields):
    for k, v in fields.items():
        setattr(s, k, v)
    s.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(s)


def _next_question_payload(s: ChatSession) -> dict | None:
    queue = _jloads(s.question_queue, [])
    answered = _jloads(s.answered_questions, [])
    if not queue:
        return None
    q = build_question_data(queue[0])
    if q:
        q["question_num"] = len(answered) + 1
        q["total_questions"] = len(answered) + len(queue)
    return q


# ─── Endpoints ────────────────────────────────────────────────────────────────

@router.post("/sessions", summary="Iniciar sesión de chatbot")
async def create_session(
    body: SessionCreateIn,
    db: Session = Depends(get_db),
    _user: dict = Depends(_api_auth),
):
    """
    Inicia una nueva sesión de chatbot.
    Opcionalmente acepta IoCs y una pista de categoría.
    Retorna session_uuid y la primera pregunta.
    """
    s = ChatSession(
        session_uuid=str(uuid.uuid4()),
        user_id=_user.get("id"),
        organization_id=_user.get("org_id"),
        question_queue=json.dumps(GATEWAY_QUESTIONS),
        iocs=json.dumps(body.iocs),
    )

    # Si se proporciona category_hint, aplicar ruta directa
    if body.category_hint and body.category_hint in ("ransomware", "phishing",
        "apt_intrusion", "ddos", "insider", "credential_theft"):
        s.inferred_category = body.category_hint
        s.category_confidence = 0.60

    db.add(s)
    db.commit()
    db.refresh(s)

    first_q = build_question_data(GATEWAY_QUESTIONS[0])
    if first_q:
        first_q["question_num"] = 1
        first_q["total_questions"] = len(GATEWAY_QUESTIONS)

    return {
        "session_uuid": s.session_uuid,
        "phase":        s.phase,
        "question":     first_q,
        "category":     s.inferred_category,
        "confidence":   s.category_confidence,
    }


@router.get("/sessions/{session_uuid}", summary="Estado de sesión")
async def get_session(
    session_uuid: str,
    db: Session = Depends(get_db),
    _user: dict = Depends(_api_auth),
):
    """Retorna el estado actual de una sesión de chatbot."""
    s = _load_session(session_uuid, db)
    queue    = _jloads(s.question_queue, [])
    answered = _jloads(s.answered_questions, [])

    return {
        "session_uuid":        s.session_uuid,
        "status":              s.status,
        "phase":               s.phase,
        "inferred_category":   s.inferred_category,
        "category_label":      CATEGORY_LABELS.get(s.inferred_category or "unknown", "Sin categoría"),
        "category_confidence": round(s.category_confidence, 2),
        "category_probs":      _jloads(s.category_probs, {}),
        "answers_count":       len(answered),
        "questions_remaining": len(queue),
        "current_question":    _next_question_payload(s),
        "answers":             _jloads(s.answers, {}),
        "incident_id":         s.incident_id,
        "created_at":          s.created_at.isoformat() if s.created_at else None,
    }


@router.post("/sessions/{session_uuid}/iocs", summary="Proporcionar IoCs")
async def session_iocs(
    session_uuid: str,
    body: IoCsIn,
    request: Request,
    db: Session = Depends(get_db),
    _user: dict = Depends(_api_auth),
):
    """
    Ejecuta TI lookup sobre los IoCs proporcionados.
    Auto-responde preguntas del Bloque 2 y actualiza la categoría inferida.
    No requiere servidor uvicorn asyncio — usa asyncio directamente.
    """
    import asyncio
    from app.services.threat_intel import lookup as ti_lookup, is_private_ip

    s = _load_session(session_uuid, db)
    iocs_dict = body.model_dump()

    indicators = [v for k, v in iocs_dict.items()
                  if v and k != "hash" and not is_private_ip(v)]

    ti_results: list[dict] = []
    if indicators:
        tasks = [ti_lookup(ind) for ind in indicators]
        try:
            results = await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), timeout=8)
            ti_results = [r for r in results if isinstance(r, dict)]
        except Exception:
            pass

    ti_answers = ti_to_auto_answers(ti_results)

    current_answers = _jloads(s.answers, {})
    category, confidence, probs = infer_category(current_answers, ti_results)

    current_queue = _jloads(s.question_queue, [])
    new_queue = [q for q in current_queue if q not in ti_answers]

    _save(s, db,
        iocs=json.dumps(iocs_dict),
        ti_results=json.dumps(ti_results, default=str),
        ti_answers=json.dumps(ti_answers),
        inferred_category=category,
        category_confidence=confidence,
        category_probs=json.dumps(probs),
        question_queue=json.dumps(new_queue),
        answers=json.dumps({**current_answers, **ti_answers}),
    )

    return {
        "auto_answered":      ti_answers,
        "questions_removed":  len(ti_answers),
        "category":           category,
        "category_label":     CATEGORY_LABELS.get(category, "Sin categoría"),
        "confidence":         round(confidence, 2),
        "probs":              probs,
        "ti_summary":         max(
            (r.get("summary_verdict", "LIMPIO") for r in ti_results),
            default="LIMPIO",
            key=lambda v: {"MALICIOSO": 2, "SOSPECHOSO": 1, "LIMPIO": 0}.get(v, 0),
        ),
    }


@router.post("/sessions/{session_uuid}/answer", summary="Responder pregunta")
async def session_answer(
    session_uuid: str,
    body: AnswerIn,
    db: Session = Depends(get_db),
    _user: dict = Depends(_api_auth),
):
    """
    Registra la respuesta del analista y retorna la siguiente pregunta.
    Cuando se completan las gateway questions, transiciona a la ruta dirigida.
    """
    s = _load_session(session_uuid, db)
    if s.status == "completed":
        raise HTTPException(400, "Sesión ya completada")

    answers  = _jloads(s.answers, {})
    queue    = _jloads(s.question_queue, [])
    answered = _jloads(s.answered_questions, [])
    ti_auto  = _jloads(s.ti_answers, {})

    answers[body.question_id] = body.answer_value
    if body.question_id in queue:
        queue.remove(body.question_id)
    if body.question_id not in answered:
        answered.append(body.question_id)

    ti_results = _jloads(s.ti_results, [])
    category, confidence, probs = infer_category(answers, ti_results)

    # Transición de fase: gateway → targeted
    phase = s.phase
    gateway_done = all(q in answers or q in ti_auto for q in GATEWAY_QUESTIONS)
    if gateway_done and phase == "gateway":
        phase = "targeted"
        queue = get_question_queue(category, answered, list(ti_auto.keys()))

    done = len(queue) == 0

    _save(s, db,
        answers=json.dumps(answers),
        question_queue=json.dumps(queue),
        answered_questions=json.dumps(answered),
        inferred_category=category,
        category_confidence=confidence,
        category_probs=json.dumps(probs),
        phase=phase,
    )

    next_q = _next_question_payload(s) if not done else None

    return {
        "next_question":  next_q,
        "done":           done,
        "phase":          phase,
        "category":       category,
        "category_label": CATEGORY_LABELS.get(category, "Sin categoría"),
        "confidence":     round(confidence, 2),
        "answers_count":  len(answered),
    }


@router.post("/sessions/{session_uuid}/skip", summary="Omitir pregunta")
async def session_skip(
    session_uuid: str,
    body: SkipIn,
    db: Session = Depends(get_db),
    _user: dict = Depends(_api_auth),
):
    """Omite la pregunta actual y avanza a la siguiente."""
    s = _load_session(session_uuid, db)
    queue    = _jloads(s.question_queue, [])
    answered = _jloads(s.answered_questions, [])

    if body.question_id in queue:
        queue.remove(body.question_id)
    if body.question_id not in answered:
        answered.append(body.question_id)

    done = len(queue) == 0
    _save(s, db,
        question_queue=json.dumps(queue),
        answered_questions=json.dumps(answered),
    )

    return {
        "next_question": _next_question_payload(s) if not done else None,
        "done":          done,
    }


@router.post("/sessions/{session_uuid}/back", summary="Volver pregunta anterior")
async def session_back(
    session_uuid: str,
    db: Session = Depends(get_db),
    _user: dict = Depends(_api_auth),
):
    """Deshace la última respuesta y regresa a esa pregunta."""
    s = _load_session(session_uuid, db)
    answered = _jloads(s.answered_questions, [])
    answers  = _jloads(s.answers, {})
    queue    = _jloads(s.question_queue, [])

    if not answered:
        raise HTTPException(400, "No hay preguntas previas")

    last_q = answered.pop()
    answers.pop(last_q, None)
    queue.insert(0, last_q)

    _save(s, db,
        answers=json.dumps(answers),
        answered_questions=json.dumps(answered),
        question_queue=json.dumps(queue),
    )

    return {
        "previous_question": build_question_data(last_q),
        "answers_count": len(answered),
    }


@router.post("/sessions/{session_uuid}/complete", summary="Finalizar y calcular resultado")
async def session_complete(
    session_uuid: str,
    body: CompleteIn,
    request: Request,
    db: Session = Depends(get_db),
    _user: dict = Depends(_api_auth),
):
    """
    Calcula el score final y la clasificación multidimensional.
    Si create_incident=true, crea el Incident en base de datos.
    """
    s = _load_session(session_uuid, db)

    if s.status == "completed" and s.incident_id:
        return {
            "classification":       s.final_classification,
            "final_score":          s.final_score,
            "threat_classification": _jloads(s.threat_classification, {}),
            "incident_id":          s.incident_id,
        }

    all_answers = _jloads(s.answers, {})
    ti_results  = _jloads(s.ti_results, [])
    result      = engine_instance.evaluate(all_answers)
    category    = s.inferred_category or "unknown"
    threat_cls  = build_threat_classification(all_answers, category, ti_results, result)

    _save(s, db,
        phase="complete",
        final_score=result["final_score"],
        final_classification=result["classification"],
        threat_classification=json.dumps(threat_cls),
    )

    incident_id = None
    if body.create_incident:
        # Llamar al endpoint save via función interna
        from app.routes.chatbot import session_save as _save_fn
        from fastapi import Request as FRequest
        # Crear incidente directamente (evitar doble request)
        from app.models.database import Incident, IncidentAnswer, audit
        from app.routes.assets import CRITICALITY_MULTIPLIERS, lookup_asset_by_identifier
        iocs = _jloads(s.iocs, {})
        ti_summary = "LIMPIO"
        for r in ti_results:
            v = r.get("summary_verdict", "")
            if v == "MALICIOSO":
                ti_summary = "MALICIOSO"
                break
            if v == "SOSPECHOSO":
                ti_summary = "SOSPECHOSO"
        ctx = {
            "ip_src": iocs.get("ip_src", ""), "ip_dst": iocs.get("ip_dst", ""),
            "direction": "unknown", "url": iocs.get("url", ""),
            "mac": iocs.get("mac", ""), "ti_summary": ti_summary,
        }
        org_ids = get_visible_org_ids(_user, db)
        matched_asset = None
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

        analyst_name = _user.get("username", "API")
        incident = Incident(
            base_score=result["base_score"], final_score=result["final_score"],
            multiplier=result["multiplier"], classification=result["classification"],
            hard_rule_id=result["hard_rule"]["id"] if result.get("hard_rule") else None,
            escalated=result["classification"] in ("critico", "brecha"),
            analyst_name=analyst_name,
            network_context=json.dumps(ctx, ensure_ascii=False),
            ti_enrichment=json.dumps(ti_results, ensure_ascii=False, default=str),
            organization_id=_user.get("org_id"),
            asset_id=matched_asset.id if matched_asset else None,
            asset_criticality_applied=bool(matched_asset),
        )
        db.add(incident)
        db.flush()
        for detail in result.get("answer_details", []):
            db.add(IncidentAnswer(
                incident_id=incident.id, question_id=detail["question_id"],
                module=detail["module"], value=detail["value"],
                raw_score=detail["raw_score"], contribution=detail["contribution"],
            ))
        _save(s, db, status="completed", incident_id=incident.id)
        db.commit()
        db.refresh(incident)
        audit(db, analyst_name, "chatbot_api_incident_created",
              target=f"incident/{incident.id}",
              details=f"via API | {result['classification']} | score {result['final_score']}",
              org_id=_user.get("org_id"))
        db.commit()
        incident_id = incident.id

    thresholds = engine_instance.thresholds
    cls_info = thresholds.get(result["classification"], {})

    return {
        "classification":       result["classification"],
        "classification_label": cls_info.get("label", result["classification"].title()),
        "classification_emoji": cls_info.get("emoji", ""),
        "final_score":          result["final_score"],
        "base_score":           result["base_score"],
        "multiplier":           result["multiplier"],
        "recommendation":       result.get("recommendation", ""),
        "threat_classification": threat_cls,
        "incident_id":          incident_id,
        "session_uuid":         s.session_uuid,
    }


@router.get("/sessions/{session_uuid}/result", summary="Obtener resultado final")
async def get_result(
    session_uuid: str,
    db: Session = Depends(get_db),
    _user: dict = Depends(_api_auth),
):
    """Retorna el resultado final de una sesión completada."""
    s = _load_session(session_uuid, db)
    if s.phase != "complete" and not s.final_classification:
        raise HTTPException(400, "La sesión no está finalizada. Llama primero a /complete")

    return {
        "session_uuid":         s.session_uuid,
        "classification":       s.final_classification,
        "final_score":          s.final_score,
        "threat_classification": _jloads(s.threat_classification, {}),
        "incident_id":          s.incident_id,
        "category":             s.inferred_category,
        "category_label":       CATEGORY_LABELS.get(s.inferred_category or "unknown", "Sin categoría"),
        "answers":              _jloads(s.answers, {}),
        "answered_count":       len(_jloads(s.answered_questions, [])),
    }
