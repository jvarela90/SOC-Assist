"""
SOC Assist — Inventario de Activos (CMDB)
Gestión de activos críticos de la organización con criticidad bidireccional.
"""
import csv
import io
import ipaddress
import json
from datetime import datetime, timedelta
from pathlib import Path
from fastapi import APIRouter, Request, Depends, HTTPException, UploadFile, File
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from sqlalchemy import or_
from app.models.database import (
    get_db, Asset, AssetContact, AssetLocation, Organization,
    audit, get_visible_org_ids, get_descendant_org_ids
)
from app.core.auth import require_auth, require_admin

router = APIRouter(prefix="/activos")
templates = Jinja2Templates(directory="app/templates")

ASSET_TYPES = [
    ("ip",              "Dirección IP"),
    ("hostname",        "Hostname / FQDN"),
    ("server",          "Servidor"),
    ("service",         "Servicio / Aplicación"),
    ("network_segment", "Segmento de Red / CIDR"),
    ("user_account",    "Cuenta de Usuario"),
    ("critical_user",   "Usuario Crítico / Privilegiado"),
    ("other",           "Otro"),
]

CONTACT_TYPES = [
    ("responsible",  "Responsable Principal"),
    ("admin_user",   "Administrador del Activo"),
    ("backup",       "Responsable de Respaldo"),
    ("escalation",   "Contacto de Escalamiento"),
]

# Criticality → score multiplier mapping
CRITICALITY_MULTIPLIERS = {
    5: 1.5,   # Crítico → fuerte incremento de urgencia
    4: 1.3,   # Alto
    3: 1.1,   # Medio → leve incremento
    2: 0.9,   # Bajo → leve reducción (caso conocido/rutinario)
    1: 0.8,   # Mínimo → puede tratarse como rutina
}

CRITICALITY_LABELS = {
    5: ("Crítico",  "danger"),
    4: ("Alto",     "warning"),
    3: ("Medio",    "info"),
    2: ("Bajo",     "secondary"),
    1: ("Mínimo",   "dark"),
}

# CSV template fields (in order)
CSV_FIELDS = [
    "name", "asset_type", "identifier", "criticality",
    "description", "tags", "review_cycle",
    "contact_name", "contact_type", "contact_email",
    "contact_phone_personal", "contact_phone_corporate",
    "location_label", "location_address",
]


def _get_user_org_ids(user: dict, db: Session) -> list[int] | None:
    return get_visible_org_ids(user, db)


def _apply_org_filter(query, user: dict, db: Session):
    org_ids = _get_user_org_ids(user, db)
    if org_ids is None:
        return query  # super_admin: no filter
    return query.filter(Asset.organization_id.in_(org_ids))


@router.get("", response_class=HTMLResponse)
async def assets_list(request: Request, db: Session = Depends(get_db),
                      user: dict = Depends(require_auth)):
    q         = request.query_params.get("q", "").strip()
    atype     = request.query_params.get("type", "")
    crit      = request.query_params.get("criticality", "")
    show_inactive = request.query_params.get("inactive", "") == "1"
    review_due    = request.query_params.get("review_due", "") == "1"
    msg = request.query_params.get("msg", "")

    query = db.query(Asset)
    query = _apply_org_filter(query, user, db)

    if not show_inactive:
        query = query.filter(Asset.is_active == True)
    if atype:
        query = query.filter(Asset.asset_type == atype)
    if crit and crit.isdigit():
        query = query.filter(Asset.criticality == int(crit))
    if q:
        query = query.filter(
            or_(
                Asset.name.ilike(f"%{q}%"),
                Asset.identifier.ilike(f"%{q}%"),
                Asset.description.ilike(f"%{q}%"),
            )
        )
    if review_due:
        now = datetime.utcnow()
        query = query.filter(
            Asset.next_review_at <= now + timedelta(days=30)
        )

    assets = query.order_by(Asset.criticality.desc(), Asset.name).all()

    # Stats
    org_ids = _get_user_org_ids(user, db)
    base_q = db.query(Asset)
    if org_ids is not None:
        base_q = base_q.filter(Asset.organization_id.in_(org_ids))

    now = datetime.utcnow()
    overdue_count = base_q.filter(
        Asset.next_review_at != None,
        Asset.next_review_at < now,
        Asset.is_active == True,
    ).count()
    upcoming_count = base_q.filter(
        Asset.next_review_at != None,
        Asset.next_review_at >= now,
        Asset.next_review_at <= now + timedelta(days=30),
        Asset.is_active == True,
    ).count()

    # Orgs for new asset form
    if user.get("role") == "super_admin":
        orgs = db.query(Organization).filter(Organization.is_active == True).all()
    else:
        org_id = user.get("org_id")
        ids = get_descendant_org_ids(db, org_id) if org_id else []
        orgs = db.query(Organization).filter(Organization.id.in_(ids)).all()

    return templates.TemplateResponse("assets.html", {
        "request": request,
        "assets": assets,
        "asset_types": ASSET_TYPES,
        "contact_types": CONTACT_TYPES,
        "criticality_labels": CRITICALITY_LABELS,
        "criticality_multipliers": CRITICALITY_MULTIPLIERS,
        "orgs": orgs,
        "filters": {"q": q, "type": atype, "criticality": crit,
                    "inactive": show_inactive, "review_due": review_due},
        "overdue_count": overdue_count,
        "upcoming_count": upcoming_count,
        "total": len(assets),
        "now": now,
        "msg": msg,
        "user": user,
    })


@router.post("/nuevo")
async def create_asset(request: Request, db: Session = Depends(get_db),
                       user: dict = Depends(require_auth)):
    form = await request.form()

    name       = form.get("name", "").strip()
    asset_type = form.get("asset_type", "other")
    identifier = form.get("identifier", "").strip()
    criticality = int(form.get("criticality", "3"))
    description = form.get("description", "").strip() or None
    tags_raw    = form.get("tags", "").strip()
    review_cycle = int(form.get("review_cycle", "6"))
    org_id_raw  = form.get("organization_id", "").strip()

    if not name or not identifier:
        return RedirectResponse(url="/activos?msg=fields_required", status_code=303)

    # Determine organization
    if user.get("role") == "super_admin" and org_id_raw and org_id_raw.isdigit():
        org_id = int(org_id_raw)
    else:
        org_id = user.get("org_id")

    if not org_id:
        return RedirectResponse(url="/activos?msg=no_org", status_code=303)

    tags = [t.strip() for t in tags_raw.split(",") if t.strip()] if tags_raw else []

    now = datetime.utcnow()
    next_review = now + timedelta(days=review_cycle * 30)

    asset = Asset(
        organization_id=org_id,
        name=name,
        asset_type=asset_type,
        identifier=identifier,
        criticality=max(1, min(5, criticality)),
        description=description,
        tags=json.dumps(tags, ensure_ascii=False) if tags else None,
        review_cycle=review_cycle,
        next_review_at=next_review,
    )
    db.add(asset)
    db.flush()

    # Contact (optional)
    c_name = form.get("contact_name", "").strip()
    if c_name:
        db.add(AssetContact(
            asset_id=asset.id,
            contact_type=form.get("contact_type", "responsible"),
            name=c_name,
            email=form.get("contact_email", "").strip() or None,
            phone_personal=form.get("contact_phone_personal", "").strip() or None,
            phone_corporate=form.get("contact_phone_corporate", "").strip() or None,
            notes=form.get("contact_notes", "").strip() or None,
        ))

    # Location (optional)
    loc_label = form.get("location_label", "").strip()
    if loc_label:
        db.add(AssetLocation(
            asset_id=asset.id,
            label=loc_label,
            address=form.get("location_address", "").strip() or None,
        ))

    audit(db, user["username"], "asset_created",
          target=f"asset/{asset.id}",
          details=f"{asset_type}: {name} ({identifier}), criticidad: {criticality}",
          ip=request.client.host if request.client else None,
          org_id=org_id)
    db.commit()
    return RedirectResponse(url=f"/activos/{asset.id}?msg=created", status_code=303)


@router.get("/{asset_id}", response_class=HTMLResponse)
async def asset_detail(asset_id: int, request: Request, db: Session = Depends(get_db),
                       user: dict = Depends(require_auth)):
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Activo no encontrado")

    # Access control
    org_ids = _get_user_org_ids(user, db)
    if org_ids is not None and asset.organization_id not in org_ids:
        raise HTTPException(status_code=403)

    from app.models.database import Incident
    linked_incidents = (
        db.query(Incident)
        .filter(Incident.asset_id == asset_id)
        .order_by(Incident.timestamp.desc())
        .limit(20)
        .all()
    )

    from app.core.engine import engine_instance
    msg = request.query_params.get("msg", "")

    tags_list = []
    if asset.tags:
        try:
            tags_list = json.loads(asset.tags)
        except Exception:
            pass

    return templates.TemplateResponse("asset_detail.html", {
        "request": request,
        "asset": asset,
        "asset_types": dict(ASSET_TYPES),
        "contact_types": dict(CONTACT_TYPES),
        "criticality_labels": CRITICALITY_LABELS,
        "criticality_multiplier": CRITICALITY_MULTIPLIERS.get(asset.criticality, 1.0),
        "linked_incidents": linked_incidents,
        "thresholds": engine_instance.thresholds,
        "tags_list": tags_list,
        "now": datetime.utcnow(),
        "msg": msg,
        "user": user,
    })


@router.post("/{asset_id}/editar")
async def edit_asset(asset_id: int, request: Request, db: Session = Depends(get_db),
                     user: dict = Depends(require_auth)):
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404)

    org_ids = _get_user_org_ids(user, db)
    if org_ids is not None and asset.organization_id not in org_ids:
        raise HTTPException(status_code=403)

    form = await request.form()
    asset.name        = form.get("name", asset.name).strip() or asset.name
    asset.asset_type  = form.get("asset_type", asset.asset_type)
    asset.identifier  = form.get("identifier", asset.identifier).strip() or asset.identifier
    asset.criticality = max(1, min(5, int(form.get("criticality", asset.criticality))))
    asset.description = form.get("description", "").strip() or None
    asset.review_cycle = int(form.get("review_cycle", asset.review_cycle))
    asset.updated_at  = datetime.utcnow()

    tags_raw = form.get("tags", "").strip()
    if tags_raw:
        asset.tags = json.dumps([t.strip() for t in tags_raw.split(",") if t.strip()],
                                ensure_ascii=False)

    audit(db, user["username"], "asset_edited",
          target=f"asset/{asset_id}",
          details=f"Criticidad: {asset.criticality}, Tipo: {asset.asset_type}",
          ip=request.client.host if request.client else None,
          org_id=asset.organization_id)
    db.commit()
    return RedirectResponse(url=f"/activos/{asset_id}?msg=updated", status_code=303)


@router.post("/{asset_id}/toggle-active")
async def toggle_asset(asset_id: int, request: Request, db: Session = Depends(get_db),
                       user: dict = Depends(require_admin)):
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404)
    org_ids = _get_user_org_ids(user, db)
    if org_ids is not None and asset.organization_id not in org_ids:
        raise HTTPException(status_code=403)

    asset.is_active = not asset.is_active
    asset.updated_at = datetime.utcnow()
    audit(db, user["username"], "asset_toggled",
          target=f"asset/{asset_id}",
          details=f"is_active → {asset.is_active}",
          org_id=asset.organization_id)
    db.commit()
    return RedirectResponse(url=f"/activos/{asset_id}?msg=toggled", status_code=303)


@router.post("/{asset_id}/revisar")
async def mark_reviewed(asset_id: int, request: Request, db: Session = Depends(get_db),
                        user: dict = Depends(require_auth)):
    """Mark an asset as reviewed — resets next_review_at."""
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404)

    now = datetime.utcnow()
    asset.last_reviewed_at = now
    asset.next_review_at   = now + timedelta(days=asset.review_cycle * 30)
    asset.updated_at       = now

    audit(db, user["username"], "asset_reviewed",
          target=f"asset/{asset_id}",
          details=f"Próxima revisión: {asset.next_review_at.strftime('%Y-%m-%d')}",
          org_id=asset.organization_id)
    db.commit()
    return RedirectResponse(url=f"/activos/{asset_id}?msg=reviewed", status_code=303)


@router.post("/{asset_id}/contacto/agregar")
async def add_contact(asset_id: int, request: Request, db: Session = Depends(get_db),
                      user: dict = Depends(require_auth)):
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404)

    form = await request.form()
    c_name = form.get("name", "").strip()
    if not c_name:
        return RedirectResponse(url=f"/activos/{asset_id}?msg=contact_name_required", status_code=303)

    db.add(AssetContact(
        asset_id=asset_id,
        contact_type=form.get("contact_type", "responsible"),
        name=c_name,
        email=form.get("email", "").strip() or None,
        phone_personal=form.get("phone_personal", "").strip() or None,
        phone_corporate=form.get("phone_corporate", "").strip() or None,
        notes=form.get("notes", "").strip() or None,
    ))
    db.commit()
    return RedirectResponse(url=f"/activos/{asset_id}?msg=contact_added", status_code=303)


@router.post("/{asset_id}/contacto/{contact_id}/eliminar")
async def delete_contact(asset_id: int, contact_id: int, request: Request,
                         db: Session = Depends(get_db), user: dict = Depends(require_admin)):
    contact = db.query(AssetContact).filter(
        AssetContact.id == contact_id, AssetContact.asset_id == asset_id
    ).first()
    if contact:
        db.delete(contact)
        db.commit()
    return RedirectResponse(url=f"/activos/{asset_id}?msg=contact_deleted", status_code=303)


@router.post("/{asset_id}/ubicacion/agregar")
async def add_location(asset_id: int, request: Request, db: Session = Depends(get_db),
                       user: dict = Depends(require_auth)):
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404)

    form = await request.form()
    label = form.get("label", "").strip()
    if not label:
        return RedirectResponse(url=f"/activos/{asset_id}?msg=location_label_required", status_code=303)

    db.add(AssetLocation(
        asset_id=asset_id,
        label=label,
        address=form.get("address", "").strip() or None,
    ))
    db.commit()
    return RedirectResponse(url=f"/activos/{asset_id}?msg=location_added", status_code=303)


@router.post("/{asset_id}/ubicacion/{loc_id}/eliminar")
async def delete_location(asset_id: int, loc_id: int, request: Request,
                          db: Session = Depends(get_db), user: dict = Depends(require_admin)):
    loc = db.query(AssetLocation).filter(
        AssetLocation.id == loc_id, AssetLocation.asset_id == asset_id
    ).first()
    if loc:
        db.delete(loc)
        db.commit()
    return RedirectResponse(url=f"/activos/{asset_id}?msg=location_deleted", status_code=303)


# ── CSV Export ────────────────────────────────────────────────────────────────

@router.get("/exportar/csv")
async def export_csv(request: Request, db: Session = Depends(get_db),
                     user: dict = Depends(require_auth)):
    """Export all active assets as CSV."""
    query = db.query(Asset)
    org_ids = _get_user_org_ids(user, db)
    if org_ids is not None:
        query = query.filter(Asset.organization_id.in_(org_ids))
    assets = query.order_by(Asset.criticality.desc(), Asset.name).all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(CSV_FIELDS)

    for a in assets:
        contacts = a.contacts
        locations = a.locations
        c = contacts[0] if contacts else None
        l = locations[0] if locations else None
        tags = ", ".join(json.loads(a.tags)) if a.tags else ""
        writer.writerow([
            a.name, a.asset_type, a.identifier, a.criticality,
            a.description or "", tags, a.review_cycle,
            c.name if c else "",
            c.contact_type if c else "",
            c.email if c else "",
            c.phone_personal if c else "",
            c.phone_corporate if c else "",
            l.label if l else "",
            l.address if l else "",
        ])

    output.seek(0)
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M")
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename=activos_soc_{ts}.csv"},
    )


@router.get("/exportar/template")
async def download_template(request: Request, user: dict = Depends(require_auth)):
    """Download a CSV template with headers and one example row."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(CSV_FIELDS)
    # Example row
    writer.writerow([
        "Servidor Web Principal",  # name
        "server",                  # asset_type (ip|hostname|server|service|network_segment|user_account|critical_user|other)
        "web01.empresa.local",     # identifier
        "5",                       # criticality (1=Mínimo, 2=Bajo, 3=Medio, 4=Alto, 5=Crítico)
        "Servidor web Apache producción", # description
        "produccion, web, apache", # tags (separados por coma)
        "6",                       # review_cycle (3 o 6 meses)
        "Juan Pérez",              # contact_name
        "responsible",             # contact_type (responsible|admin_user|backup|escalation)
        "juan.perez@empresa.com",  # contact_email
        "+54 9 11 1234-5678",      # contact_phone_personal
        "+54 11 5555-0000 int 123", # contact_phone_corporate
        "Sede Central - Rack 3, U12", # location_label
        "Av. Corrientes 1234, CABA",  # location_address
    ])
    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": "attachment; filename=activos_template.csv"},
    )


@router.post("/importar")
async def import_csv(request: Request, db: Session = Depends(get_db),
                     user: dict = Depends(require_admin)):
    """Import assets from CSV file."""
    form = await request.form()
    file: UploadFile = form.get("file")
    org_id_raw = form.get("organization_id", "").strip()

    if not file or not file.filename.endswith(".csv"):
        return RedirectResponse(url="/activos?msg=invalid_file", status_code=303)

    # Determine target org
    if user.get("role") == "super_admin" and org_id_raw and org_id_raw.isdigit():
        org_id = int(org_id_raw)
    else:
        org_id = user.get("org_id")

    if not org_id:
        return RedirectResponse(url="/activos?msg=no_org", status_code=303)

    content = await file.read()
    try:
        text = content.decode("utf-8-sig")  # handle BOM
    except UnicodeDecodeError:
        text = content.decode("latin-1")

    reader = csv.DictReader(io.StringIO(text))
    created = 0
    errors = 0
    now = datetime.utcnow()

    for row in reader:
        name       = (row.get("name") or "").strip()
        identifier = (row.get("identifier") or "").strip()
        if not name or not identifier:
            errors += 1
            continue

        try:
            criticality  = max(1, min(5, int(row.get("criticality") or "3")))
            review_cycle = int(row.get("review_cycle") or "6")
        except (ValueError, TypeError):
            criticality  = 3
            review_cycle = 6

        tags_raw = (row.get("tags") or "").strip()
        tags = [t.strip() for t in tags_raw.split(",") if t.strip()] if tags_raw else []

        asset = Asset(
            organization_id=org_id,
            name=name,
            asset_type=(row.get("asset_type") or "other").strip(),
            identifier=identifier,
            criticality=criticality,
            description=(row.get("description") or "").strip() or None,
            tags=json.dumps(tags, ensure_ascii=False) if tags else None,
            review_cycle=review_cycle,
            next_review_at=now + timedelta(days=review_cycle * 30),
        )
        db.add(asset)
        db.flush()

        c_name = (row.get("contact_name") or "").strip()
        if c_name:
            db.add(AssetContact(
                asset_id=asset.id,
                contact_type=(row.get("contact_type") or "responsible").strip(),
                name=c_name,
                email=(row.get("contact_email") or "").strip() or None,
                phone_personal=(row.get("contact_phone_personal") or "").strip() or None,
                phone_corporate=(row.get("contact_phone_corporate") or "").strip() or None,
            ))

        loc_label = (row.get("location_label") or "").strip()
        if loc_label:
            db.add(AssetLocation(
                asset_id=asset.id,
                label=loc_label,
                address=(row.get("location_address") or "").strip() or None,
            ))

        created += 1

    audit(db, user["username"], "assets_imported",
          details=f"Importados: {created}, Errores: {errors}, Org: {org_id}",
          org_id=org_id)
    db.commit()
    return RedirectResponse(url=f"/activos?msg=imported_{created}", status_code=303)


# ── Internal helper: lookup asset by identifier ───────────────────────────────

def lookup_asset_by_identifier(identifier: str, org_ids: list[int] | None,
                                db: Session) -> Asset | None:
    """
    Look up an active asset matching the given identifier (IP, hostname, etc.)
    within the visible organizations. Returns the highest-criticality match.

    Matching strategy (in priority order):
    1. Exact string match (case-insensitive) — all asset types
    2. CIDR containment — if identifier is a valid IP and asset type is
       'network_segment' with a CIDR notation identifier (e.g. 10.0.0.0/8)
    The highest-criticality result across both strategies is returned.
    """
    if not identifier:
        return None

    base_q = db.query(Asset).filter(Asset.is_active == True)
    if org_ids is not None:
        base_q = base_q.filter(Asset.organization_id.in_(org_ids))

    # 1. Exact match (case-insensitive for hostnames/domains)
    exact = (
        base_q.filter(Asset.identifier.ilike(identifier))
        .order_by(Asset.criticality.desc())
        .first()
    )

    # 2. CIDR containment — only when identifier is a valid IP address
    cidr_match: Asset | None = None
    try:
        ip_obj = ipaddress.ip_address(identifier)
        segments = base_q.filter(Asset.asset_type == "network_segment").all()
        best: Asset | None = None
        for seg in segments:
            if not seg.identifier:
                continue
            try:
                network = ipaddress.ip_network(seg.identifier, strict=False)
                if ip_obj in network:
                    if best is None or seg.criticality > best.criticality:
                        best = seg
            except ValueError:
                pass  # identifier is not a valid CIDR — skip
        cidr_match = best
    except ValueError:
        pass  # identifier is not a valid IP — skip CIDR check

    # Return highest criticality between exact and CIDR match
    if exact and cidr_match:
        return exact if exact.criticality >= cidr_match.criticality else cidr_match
    return exact or cidr_match
