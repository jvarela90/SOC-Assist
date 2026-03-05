"""
SOC Assist — Utilidades compartidas para el módulo chatbot.
Contiene helpers usados por chatbot.py (UI web) y chatbot_api.py (REST API).

Funciones exportadas:
    jloads(text, default)          — deserialización JSON segura
    load_session(uuid, db)         — carga ChatSession o lanza HTTP 404
    save_session(s, db, **fields)  — persiste campos y hace commit
    run_ti_lookups(indicators)     — lookups TI paralelos con timeout
"""
from __future__ import annotations

import asyncio
import json
from datetime import datetime

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.core.constants import TI_TIMEOUT


# ─── JSON helpers ─────────────────────────────────────────────────────────────

def jloads(text: str, default):
    """Deserializa JSON con valor por defecto si el texto es inválido o vacío.

    Args:
        text:    Cadena JSON a parsear.
        default: Valor retornado si el parseo falla.

    Returns:
        El objeto deserializado o `default`.
    """
    try:
        return json.loads(text or "")
    except Exception:
        return default


# ─── ChatSession CRUD helpers ─────────────────────────────────────────────────

def load_session(session_uuid: str, db: Session):
    """Carga una ChatSession por UUID o lanza HTTP 404.

    Args:
        session_uuid: UUID de la sesión a cargar.
        db:           Sesión de SQLAlchemy.

    Returns:
        La instancia ChatSession encontrada.

    Raises:
        HTTPException(404): Si no existe la sesión.
    """
    from app.models.database import ChatSession  # deferred to avoid circular import
    s = db.query(ChatSession).filter(ChatSession.session_uuid == session_uuid).first()
    if not s:
        raise HTTPException(status_code=404, detail="Sesión no encontrada")
    return s


def save_session(s, db: Session, **fields) -> None:
    """Actualiza campos de una ChatSession y hace commit.

    Args:
        s:      Instancia ChatSession a modificar.
        db:     Sesión de SQLAlchemy.
        fields: Pares clave=valor a asignar al objeto.
    """
    for k, v in fields.items():
        setattr(s, k, v)
    s.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(s)


# ─── Threat Intelligence helpers ──────────────────────────────────────────────

async def run_ti_lookups(indicators: list[str]) -> list[dict]:
    """Ejecuta lookups TI en paralelo con timeout configurado en TI_TIMEOUT.

    Args:
        indicators: Lista de indicadores a consultar (IPs, URLs, hashes, etc.).

    Returns:
        Lista de resultados dict de los lookups exitosos.
        Retorna lista vacía si no hay indicadores o se produce timeout.
    """
    if not indicators:
        return []

    from app.services.threat_intel import lookup as ti_lookup  # deferred import

    tasks = [ti_lookup(ind) for ind in indicators]
    try:
        results = await asyncio.wait_for(
            asyncio.gather(*tasks, return_exceptions=True),
            timeout=TI_TIMEOUT,
        )
        return [r for r in results if isinstance(r, dict)]
    except Exception:
        return []
