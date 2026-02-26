"""
SOC Assist — Adjuntos de Evidencia para Incidentes (#48)
Upload, serve and delete files attached as evidence to incidents.
"""
import uuid
from pathlib import Path
from fastapi import APIRouter, Request, Depends, HTTPException, UploadFile
from fastapi.responses import FileResponse, RedirectResponse
from sqlalchemy.orm import Session
from app.models.database import get_db, Incident, IncidentAttachment, audit
from app.core.auth import require_auth, require_admin

router = APIRouter()

UPLOAD_DIR = Path("app/uploads")

ALLOWED_EXTENSIONS = {
    # Images
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp",
    # Documents
    ".pdf", ".txt", ".log", ".csv", ".json", ".xml",
    # Archives / evidence
    ".zip", ".gz", ".tar",
    # Network captures
    ".pcap", ".pcapng",
    # Other
    ".html", ".md",
}

MAX_SIZE = 10 * 1024 * 1024  # 10 MB

ICON_MAP = {
    ".pdf":    "bi-file-earmark-pdf text-danger",
    ".jpg":    "bi-file-earmark-image text-info",
    ".jpeg":   "bi-file-earmark-image text-info",
    ".png":    "bi-file-earmark-image text-info",
    ".gif":    "bi-file-earmark-image text-info",
    ".webp":   "bi-file-earmark-image text-info",
    ".txt":    "bi-file-earmark-text text-muted",
    ".log":    "bi-file-earmark-text text-warning",
    ".csv":    "bi-file-earmark-spreadsheet text-success",
    ".json":   "bi-filetype-json text-warning",
    ".xml":    "bi-file-earmark-code text-info",
    ".zip":    "bi-file-earmark-zip text-secondary",
    ".gz":     "bi-file-earmark-zip text-secondary",
    ".pcap":   "bi-file-earmark-binary text-primary",
    ".pcapng": "bi-file-earmark-binary text-primary",
}


def _fmt_size(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    elif n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n / 1024 / 1024:.1f} MB"


@router.post("/incidentes/{incident_id}/adjuntar")
async def upload_attachment(
    incident_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: dict = Depends(require_auth),
):
    """Upload a file as evidence for an incident."""
    form = await request.form()
    file: UploadFile = form.get("file")
    description = (form.get("description") or "").strip()[:500]

    if not file or not file.filename:
        return RedirectResponse(
            url=f"/incidentes/{incident_id}?msg=no_file#evidencia", status_code=303
        )

    suffix = Path(file.filename).suffix.lower()
    if suffix not in ALLOWED_EXTENSIONS:
        return RedirectResponse(
            url=f"/incidentes/{incident_id}?msg=file_type#evidencia", status_code=303
        )

    content = await file.read()
    if len(content) > MAX_SIZE:
        return RedirectResponse(
            url=f"/incidentes/{incident_id}?msg=file_too_large#evidencia", status_code=303
        )

    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404)

    # Store file on disk using a UUID-based name (prevents path traversal)
    incident_dir = UPLOAD_DIR / str(incident_id)
    incident_dir.mkdir(parents=True, exist_ok=True)
    stored_name = f"{uuid.uuid4().hex}{suffix}"
    (incident_dir / stored_name).write_bytes(content)

    att = IncidentAttachment(
        incident_id=incident_id,
        uploaded_by=user["username"],
        filename=file.filename,
        stored_name=stored_name,
        file_size=len(content),
        mime_type=file.content_type or "application/octet-stream",
        description=description or None,
    )
    db.add(att)
    audit(
        db, user["username"], "attachment_uploaded",
        target=f"incident/{incident_id}",
        details=f"{file.filename} ({_fmt_size(len(content))})",
        ip=request.client.host if request.client else None,
    )
    db.commit()
    return RedirectResponse(
        url=f"/incidentes/{incident_id}?msg=file_uploaded#evidencia", status_code=303
    )


@router.get("/adjuntos/{attachment_id}")
async def serve_attachment(
    attachment_id: int,
    db: Session = Depends(get_db),
    user: dict = Depends(require_auth),
):
    """Download / view an attachment (authenticated users only)."""
    att = db.query(IncidentAttachment).filter(
        IncidentAttachment.id == attachment_id
    ).first()
    if not att:
        raise HTTPException(status_code=404)

    file_path = UPLOAD_DIR / str(att.incident_id) / att.stored_name
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Archivo no encontrado en disco")

    return FileResponse(
        path=str(file_path),
        filename=att.filename,
        media_type=att.mime_type or "application/octet-stream",
    )


@router.post("/adjuntos/{attachment_id}/eliminar")
async def delete_attachment(
    attachment_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: dict = Depends(require_admin),
):
    """Delete an attachment — admin only."""
    att = db.query(IncidentAttachment).filter(
        IncidentAttachment.id == attachment_id
    ).first()
    if not att:
        raise HTTPException(status_code=404)

    incident_id = att.incident_id
    file_path = UPLOAD_DIR / str(incident_id) / att.stored_name
    if file_path.exists():
        file_path.unlink(missing_ok=True)

    audit(
        db, user["username"], "attachment_deleted",
        target=f"incident/{incident_id}",
        details=att.filename,
        ip=request.client.host if request.client else None,
    )
    db.delete(att)
    db.commit()
    return RedirectResponse(
        url=f"/incidentes/{incident_id}?msg=file_deleted#evidencia", status_code=303
    )
