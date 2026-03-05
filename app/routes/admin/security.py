"""
SOC Assist — Admin: Seguridad y auditoría.
Rutas: /admin/backup, /admin/audit-log, /admin/api-tokens/*.
"""
import io
import secrets
import zipfile
from datetime import datetime

import bcrypt as _bcrypt
from fastapi import Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from sqlalchemy.orm import Session

from app.models.database import get_db, AuditLog, APIToken, audit
from app.core.auth import require_admin
from app.core.constants import PAGINATION_SIZE

from ._base import router, templates, BASE_DIR, CONFIG_PATH, QUESTIONS_PATH


# ─── Backup ZIP ───────────────────────────────────────────────────────────────

@router.get("/backup")
async def download_backup(
    request: Request,
    db: Session = Depends(get_db),
    _user: dict = Depends(require_admin),
):
    """Descarga un backup ZIP con la base de datos y todos los archivos de configuración."""
    buf            = io.BytesIO()
    files_to_backup = [
        BASE_DIR / "soc_assist.db",
        CONFIG_PATH,
        QUESTIONS_PATH,
        BASE_DIR / "playbooks.json",
        BASE_DIR / "ti_config.json",
    ]

    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for fpath in files_to_backup:
            if fpath.exists():
                zf.write(fpath, arcname=fpath.name)

    buf.seek(0)
    ts       = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    filename = f"soc_assist_backup_{ts}.zip"
    audit(db, _user.get("username", "?"), "backup_downloaded",
          details=filename, ip=request.client.host if request.client else None)
    db.commit()
    return StreamingResponse(
        buf,
        media_type="application/zip",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


# ─── Audit Log ────────────────────────────────────────────────────────────────

@router.get("/audit-log", response_class=HTMLResponse)
async def view_audit_log(
    request: Request,
    db: Session = Depends(get_db),
    _user: dict = Depends(require_admin),
    page: int = 1,
):
    """Muestra el log de auditoría del sistema, paginado."""
    per_page = PAGINATION_SIZE
    offset   = (page - 1) * per_page
    total    = db.query(AuditLog).count()
    logs     = (
        db.query(AuditLog)
        .order_by(AuditLog.timestamp.desc())
        .offset(offset)
        .limit(per_page)
        .all()
    )
    return templates.TemplateResponse("audit_log.html", {
        "request":  request,
        "logs":     logs,
        "total":    total,
        "page":     page,
        "per_page": per_page,
        "pages":    max(1, (total + per_page - 1) // per_page),
    })


# ─── API Tokens ───────────────────────────────────────────────────────────────

@router.get("/api-tokens", response_class=HTMLResponse)
async def api_tokens_page(
    request: Request,
    db: Session = Depends(get_db),
    _user: dict = Depends(require_admin),
):
    """Lista los tokens API del usuario actual."""
    tokens = (
        db.query(APIToken)
        .filter(APIToken.user_id == _user["id"])
        .order_by(APIToken.created_at.desc())
        .all()
    )
    return templates.TemplateResponse("api_tokens.html", {
        "request": request,
        "tokens":  tokens,
        "user":    _user,
    })


@router.post("/api-tokens/create")
async def create_api_token(
    request: Request,
    db: Session = Depends(get_db),
    _user: dict = Depends(require_admin),
):
    """Genera un nuevo token API seguro. El token se muestra UNA VEZ."""
    form = await request.form()
    name = str(form.get("name", "")).strip()[:100]
    if not name:
        raise HTTPException(400, "El nombre es requerido")

    raw_token  = "soc_" + secrets.token_urlsafe(30)
    prefix     = raw_token[:8]
    token_hash = _bcrypt.hashpw(raw_token.encode(), _bcrypt.gensalt()).decode()

    tok = APIToken(
        name=name, token_hash=token_hash, token_prefix=prefix,
        user_id=_user["id"], organization_id=_user.get("org_id"),
    )
    db.add(tok)
    db.commit()
    db.refresh(tok)
    audit(db, _user["username"], "api_token_created",
          target=f"api_token/{tok.id}", details=f"name={name}")
    db.commit()

    return templates.TemplateResponse("api_tokens.html", {
        "request":        request,
        "tokens":         db.query(APIToken).filter(APIToken.user_id == _user["id"])
                            .order_by(APIToken.created_at.desc()).all(),
        "user":           _user,
        "new_token":      raw_token,
        "new_token_name": name,
    })


@router.post("/api-tokens/{token_id}/revoke")
async def revoke_api_token(
    token_id: int,
    request: Request,
    db: Session = Depends(get_db),
    _user: dict = Depends(require_admin),
):
    """Revoca (desactiva) un token API existente."""
    tok = db.query(APIToken).filter(
        APIToken.id == token_id,
        APIToken.user_id == _user["id"],
    ).first()
    if not tok:
        raise HTTPException(404, "Token no encontrado")
    tok.is_active = False
    audit(db, _user["username"], "api_token_revoked",
          target=f"api_token/{tok.id}", details=f"name={tok.name}")
    db.commit()
    return RedirectResponse("/admin/api-tokens", status_code=303)
