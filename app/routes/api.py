"""
SOC Assist — REST API v1 (#40)
OpenAPI-documented endpoints for SIEM / external integration.

Authentication:
  - Session cookie  (browser, already logged in)
  - HTTP Basic Auth (SIEM clients — username + password)

Base URL: /api/v1
OpenAPI docs: /docs   (Swagger UI)
              /redoc  (ReDoc)
"""
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.auth import verify_password
from app.core.engine import engine_instance
from app.models.database import get_db, Incident, User

router = APIRouter(prefix="/api/v1", tags=["API v1"])
_security = HTTPBasic(auto_error=False)


# ── API authentication dependency ────────────────────────────────────────────

async def api_auth(
    request: Request,
    credentials: Optional[HTTPBasicCredentials] = Depends(_security),
    db: Session = Depends(get_db),
) -> dict:
    """Allow access via session cookie OR HTTP Basic credentials."""
    # 1) Browser session
    user = request.session.get("user")
    if user:
        return user

    # 2) HTTP Basic Auth (SIEM / scripts)
    if credentials:
        db_user = (
            db.query(User)
            .filter(User.username == credentials.username, User.is_active == True)
            .first()
        )
        if db_user and verify_password(credentials.password, db_user.password_hash):
            return {"id": db_user.id, "username": db_user.username, "role": db_user.role}

    raise HTTPException(
        status_code=401,
        detail="Credenciales requeridas",
        headers={"WWW-Authenticate": "Basic realm='SOC Assist API'"},
    )


# ── Pydantic schemas ──────────────────────────────────────────────────────────

class AnswerOut(BaseModel):
    question_id: str
    module: str
    value: str
    contribution: float

    model_config = {"from_attributes": True}


class IncidentOut(BaseModel):
    id: int
    timestamp: datetime
    classification: str
    base_score: float
    final_score: float
    multiplier: float
    escalated: bool
    hard_rule_id: Optional[str] = None
    analyst_name: Optional[str] = None
    assigned_to: Optional[str] = None
    resolution: Optional[str] = None
    analyst_notes: Optional[str] = None

    model_config = {"from_attributes": True}


class IncidentDetailOut(IncidentOut):
    answers: list[AnswerOut] = []


class StatsOut(BaseModel):
    total: int
    by_classification: dict[str, int]
    by_resolution: dict[str, int]
    unresolved: int


class ResolutionIn(BaseModel):
    resolution: Optional[str] = None   # tp_escalated | tp_resolved | fp | ongoing | ""
    notes: Optional[str] = None
    assigned_to: Optional[str] = None


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get(
    "/incidents",
    response_model=list[IncidentOut],
    summary="Listar incidentes",
    description=(
        "Devuelve la lista paginada de incidentes, ordenados del más reciente al más antiguo. "
        "Soporta filtros por clasificación y resolución."
    ),
)
async def list_incidents(
    skip: int = Query(0, ge=0, description="Desplazamiento para paginación"),
    limit: int = Query(50, ge=1, le=500, description="Número máximo de resultados"),
    classification: Optional[str] = Query(
        None,
        description="Filtrar por clasificación: informativo | sospechoso | incidente | critico | brecha",
    ),
    resolution: Optional[str] = Query(
        None,
        description="Filtrar por resolución: tp_escalated | tp_resolved | fp | ongoing | unresolved",
    ),
    db: Session = Depends(get_db),
    _auth: dict = Depends(api_auth),
):
    q = db.query(Incident)
    if classification:
        q = q.filter(Incident.classification == classification)
    if resolution == "unresolved":
        q = q.filter(Incident.resolution == None)
    elif resolution:
        q = q.filter(Incident.resolution == resolution)
    return q.order_by(Incident.timestamp.desc()).offset(skip).limit(limit).all()


@router.get(
    "/incidents/{incident_id}",
    response_model=IncidentDetailOut,
    summary="Detalle de incidente",
    description="Devuelve el incidente con la lista completa de respuestas y sus aportes al score.",
)
async def get_incident(
    incident_id: int,
    db: Session = Depends(get_db),
    _auth: dict = Depends(api_auth),
):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incidente no encontrado")
    return incident


@router.patch(
    "/incidents/{incident_id}",
    response_model=IncidentOut,
    summary="Actualizar incidente",
    description="Actualiza la resolución, notas o asignación de un incidente. Solo envía los campos a cambiar.",
)
async def update_incident(
    incident_id: int,
    body: ResolutionIn,
    db: Session = Depends(get_db),
    _auth: dict = Depends(api_auth),
):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incidente no encontrado")

    _valid_resolutions = {"tp_escalated", "tp_resolved", "fp", "ongoing", "", None}
    if body.resolution is not None:
        if body.resolution not in _valid_resolutions:
            raise HTTPException(
                status_code=422,
                detail="Resolución inválida. Valores: tp_escalated, tp_resolved, fp, ongoing",
            )
        incident.resolution = body.resolution or None

    if body.notes is not None:
        incident.analyst_notes = body.notes

    if body.assigned_to is not None:
        incident.assigned_to = body.assigned_to or None

    db.commit()
    db.refresh(incident)
    return incident


@router.get(
    "/stats",
    response_model=StatsOut,
    summary="Estadísticas globales",
    description="KPIs y conteos agregados de todos los incidentes almacenados.",
)
async def get_stats(
    db: Session = Depends(get_db),
    _auth: dict = Depends(api_auth),
):
    total = db.query(Incident).count()

    by_class = dict(
        db.query(Incident.classification, func.count(Incident.id))
        .group_by(Incident.classification)
        .all()
    )

    by_res_raw = dict(
        db.query(Incident.resolution, func.count(Incident.id))
        .group_by(Incident.resolution)
        .all()
    )
    by_res = {str(k or "unresolved"): v for k, v in by_res_raw.items()}

    unresolved = db.query(Incident).filter(Incident.resolution == None).count()

    return {
        "total": total,
        "by_classification": by_class,
        "by_resolution": by_res,
        "unresolved": unresolved,
    }


@router.get(
    "/classifications",
    summary="Niveles de clasificación",
    description="Devuelve los niveles de clasificación con sus rangos de score y etiquetas.",
)
async def get_classifications(_auth: dict = Depends(api_auth)):
    return {
        cls: {
            "min": info.min_score,
            "max": info.max_score,
            "label": info.label,
            "emoji": info.emoji,
        }
        for cls, info in engine_instance.thresholds.items()
    }
