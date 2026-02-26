"""
SOC Assist — Gestión de Organizaciones (Multi-Tenant)
Rutas para crear, editar y visualizar la jerarquía de organizaciones.
Solo accesible para super_admin (o admin dentro de su propia org).
"""
import re
from fastapi import APIRouter, Request, Depends, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from app.models.database import (
    get_db, Organization, User, Incident, Asset,
    audit, get_descendant_org_ids
)
from app.core.auth import require_admin, require_super_admin

router = APIRouter(prefix="/admin/orgs")
templates = Jinja2Templates(directory="app/templates")

ORG_TYPES = [
    ("central",    "Sede Central / Nacional"),
    ("regional",   "Sede Regional"),
    ("provincial", "Sede Provincial"),
    ("local",      "Sede Local / Mini-sede"),
    ("flat",       "Organización Plana (1 nivel)"),
    ("shift",      "Organización por Turnos"),
]


def _build_tree(orgs: list) -> list:
    """Build a nested tree structure from a flat list of orgs."""
    org_map = {o.id: {"org": o, "children": []} for o in orgs}
    roots = []
    for o in orgs:
        if o.parent_id and o.parent_id in org_map:
            org_map[o.parent_id]["children"].append(org_map[o.id])
        else:
            roots.append(org_map[o.id])
    return roots


def _slugify(name: str) -> str:
    """Convert org name to a URL-safe slug."""
    slug = name.lower().strip()
    slug = re.sub(r'[^a-z0-9]+', '-', slug)
    slug = slug.strip('-')
    return slug[:80]


@router.get("", response_class=HTMLResponse)
async def orgs_list(request: Request, db: Session = Depends(get_db),
                    _user: dict = Depends(require_admin)):
    user_role = _user.get("role")
    user_org_id = _user.get("org_id")
    msg = request.query_params.get("msg", "")

    if user_role == "super_admin":
        orgs = db.query(Organization).order_by(Organization.name).all()
    else:
        # Admin can only see their org and descendants
        visible_ids = get_descendant_org_ids(db, user_org_id) if user_org_id else []
        orgs = db.query(Organization).filter(
            Organization.id.in_(visible_ids)
        ).order_by(Organization.name).all()

    tree = _build_tree(orgs)

    # Stats per org
    stats = {}
    for o in orgs:
        stats[o.id] = {
            "users": db.query(User).filter(User.organization_id == o.id).count(),
            "incidents": db.query(Incident).filter(Incident.organization_id == o.id).count(),
            "assets": db.query(Asset).filter(Asset.organization_id == o.id).count(),
        }

    # All orgs for parent selector (super_admin only)
    all_orgs = orgs if user_role == "super_admin" else []

    return templates.TemplateResponse("orgs.html", {
        "request": request,
        "tree": tree,
        "orgs": orgs,
        "all_orgs": all_orgs,
        "stats": stats,
        "org_types": ORG_TYPES,
        "user": _user,
        "msg": msg,
    })


@router.post("/nueva")
async def create_org(request: Request, db: Session = Depends(get_db),
                     _user: dict = Depends(require_admin)):
    form = await request.form()
    name = form.get("name", "").strip()
    org_type = form.get("org_type", "flat")
    parent_id = form.get("parent_id", "").strip()
    description = form.get("description", "").strip()

    if not name:
        return RedirectResponse(url="/admin/orgs?msg=name_required", status_code=303)

    # Generate unique slug
    base_slug = _slugify(name)
    slug = base_slug
    counter = 1
    while db.query(Organization).filter(Organization.slug == slug).first():
        slug = f"{base_slug}-{counter}"
        counter += 1

    parent_id_int = int(parent_id) if parent_id and parent_id.isdigit() else None

    # Non-super_admin can only create children under their visible orgs
    if _user.get("role") != "super_admin" and parent_id_int:
        visible = get_descendant_org_ids(db, _user.get("org_id") or 0)
        if parent_id_int not in visible:
            raise HTTPException(status_code=403, detail="No tiene acceso a esa organización padre")

    org = Organization(
        name=name,
        slug=slug,
        org_type=org_type,
        parent_id=parent_id_int,
        description=description or None,
    )
    db.add(org)
    db.flush()

    audit(db, _user["username"], "org_created",
          target=f"org/{org.id}",
          details=f"Nombre: {name}, Tipo: {org_type}, Padre: {parent_id_int}",
          org_id=_user.get("org_id"))
    db.commit()
    return RedirectResponse(url="/admin/orgs?msg=org_created", status_code=303)


@router.post("/{org_id}/editar")
async def edit_org(org_id: int, request: Request, db: Session = Depends(get_db),
                   _user: dict = Depends(require_admin)):
    org = db.query(Organization).filter(Organization.id == org_id).first()
    if not org:
        raise HTTPException(status_code=404)

    # Access control: super_admin or within visible orgs
    if _user.get("role") != "super_admin":
        visible = get_descendant_org_ids(db, _user.get("org_id") or 0)
        if org_id not in visible:
            raise HTTPException(status_code=403)

    form = await request.form()
    old_name = org.name

    org.name = form.get("name", org.name).strip() or org.name
    org.org_type = form.get("org_type", org.org_type)
    org.description = form.get("description", "").strip() or None

    # Only super_admin can change parent
    if _user.get("role") == "super_admin":
        parent_id = form.get("parent_id", "").strip()
        new_parent = int(parent_id) if parent_id and parent_id.isdigit() else None
        # Prevent circular reference
        if new_parent and new_parent != org.id:
            descendants = get_descendant_org_ids(db, org_id)
            if new_parent not in descendants:
                org.parent_id = new_parent
        elif not parent_id:
            org.parent_id = None

    audit(db, _user["username"], "org_edited",
          target=f"org/{org_id}",
          details=f"{old_name} → {org.name}",
          org_id=_user.get("org_id"))
    db.commit()
    return RedirectResponse(url="/admin/orgs?msg=org_updated", status_code=303)


@router.post("/{org_id}/toggle-active")
async def toggle_org(org_id: int, request: Request, db: Session = Depends(get_db),
                     _user: dict = Depends(require_super_admin)):
    org = db.query(Organization).filter(Organization.id == org_id).first()
    if not org:
        raise HTTPException(status_code=404)

    # Prevent deactivating default org
    if org.slug == "default":
        return RedirectResponse(url="/admin/orgs?msg=cannot_deactivate_default", status_code=303)

    org.is_active = not org.is_active
    audit(db, _user["username"], "org_toggled",
          target=f"org/{org_id}",
          details=f"is_active → {org.is_active}",
          org_id=_user.get("org_id"))
    db.commit()
    return RedirectResponse(url="/admin/orgs?msg=org_toggled", status_code=303)


@router.get("/{org_id}/stats", response_class=JSONResponse)
async def org_stats(org_id: int, db: Session = Depends(get_db),
                    _user: dict = Depends(require_admin)):
    if _user.get("role") != "super_admin":
        visible = get_descendant_org_ids(db, _user.get("org_id") or 0)
        if org_id not in visible:
            raise HTTPException(status_code=403)

    # Include descendants in stats
    all_ids = get_descendant_org_ids(db, org_id)
    return {
        "org_id": org_id,
        "users": db.query(User).filter(User.organization_id.in_(all_ids)).count(),
        "incidents": db.query(Incident).filter(Incident.organization_id.in_(all_ids)).count(),
        "assets": db.query(Asset).filter(Asset.organization_id.in_(all_ids)).count(),
    }
