"""
SOC Assist — Admin: Gestión de usuarios.
Rutas: /admin/usuarios, /admin/users/{id}/*, recovery codes.
"""
import secrets
import string
from datetime import datetime

from fastapi import Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models.database import get_db, User, Incident, audit
from app.core.engine import engine_instance
from app.core.auth import require_admin, hash_password

from ._base import router, templates


# ─── Página de gestión de usuarios ───────────────────────────────────────────

@router.get("/usuarios", response_class=HTMLResponse)
async def usuarios_page(
    request: Request,
    db: Session = Depends(get_db),
    _user: dict = Depends(require_admin),
):
    """Página de gestión de usuarios con trazabilidad completa."""
    users = db.query(User).order_by(User.username).all()

    # Último incidente por usuario (coincidencia por nombre de analista)
    last_incidents: dict[int, object] = {}
    for u in users:
        inc = (
            db.query(Incident)
            .filter(func.lower(Incident.analyst_name) == u.username.lower())
            .order_by(Incident.timestamp.desc())
            .first()
        )
        if inc:
            last_incidents[u.id] = inc

    total   = len(users)
    active  = sum(1 for u in users if u.is_active)
    admins  = sum(1 for u in users if u.role == "admin")
    with_rc = sum(1 for u in users if u.recovery_code_hash)

    recovery_flash = request.session.pop("_recovery_flash", None)
    msg            = request.query_params.get("msg", "")

    return templates.TemplateResponse("users.html", {
        "request":        request,
        "users":          users,
        "last_incidents": last_incidents,
        "stats":          {"total": total, "active": active, "admins": admins, "with_rc": with_rc},
        "current_user":   _user,
        "recovery_flash": recovery_flash,
        "msg":            msg,
        "thresholds":     engine_instance.thresholds,
    })


# ─── CRUD de usuarios ─────────────────────────────────────────────────────────

@router.post("/users/add")
async def add_user(
    request: Request,
    db: Session = Depends(get_db),
    _user: dict = Depends(require_admin),
):
    """Crea un nuevo usuario con rol y contraseña."""
    form     = await request.form()
    username = form.get("username", "").strip()
    password = form.get("password", "").strip()
    role     = form.get("role", "analyst")

    if not username or not password:
        return RedirectResponse(url="/admin?msg=user_error&tab=users", status_code=303)

    allowed_roles = (
        ("analyst", "admin", "super_admin")
        if _user.get("role") == "super_admin"
        else ("analyst", "admin")
    )
    if role not in allowed_roles:
        role = "analyst"
    if db.query(User).filter(User.username == username).first():
        return RedirectResponse(url="/admin?msg=user_exists&tab=users", status_code=303)

    db.add(User(username=username, password_hash=hash_password(password), role=role))
    audit(db, _user.get("username", "?"), "user_created",
          target=username, details=f"Rol: {role}",
          ip=request.client.host if request.client else None)
    db.commit()
    return RedirectResponse(url="/admin?msg=user_added&tab=users", status_code=303)


@router.post("/users/{user_id}/password")
async def change_user_password(
    user_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_admin),
):
    """Cambia la contraseña de un usuario."""
    form         = await request.form()
    new_password = form.get("new_password", "").strip()
    if not new_password:
        return RedirectResponse(url="/admin?msg=user_error&tab=users", status_code=303)

    user = db.query(User).filter(User.id == user_id).first()
    if user:
        user.password_hash       = hash_password(new_password)
        user.password_changed_at = datetime.utcnow()
        audit(db, current_user.get("username", "?"), "user_password_changed",
              target=user.username, ip=request.client.host if request.client else None)
        db.commit()
    return RedirectResponse(url="/admin/usuarios?msg=password_changed", status_code=303)


@router.post("/users/{user_id}/delete")
async def delete_user(
    user_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_admin),
):
    """Elimina un usuario. No permite auto-eliminación."""
    if user_id == current_user.get("id"):
        return RedirectResponse(url="/admin?msg=user_self_delete&tab=users", status_code=303)

    user = db.query(User).filter(User.id == user_id).first()
    if user:
        deleted_username = user.username
        db.delete(user)
        audit(db, current_user.get("username", "?"), "user_deleted",
              target=deleted_username, ip=request.client.host if request.client else None)
        db.commit()
    return RedirectResponse(url="/admin?msg=user_deleted&tab=users", status_code=303)


@router.post("/users/{user_id}/toggle-active")
async def toggle_user_active(
    user_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_admin),
):
    """Activa o desactiva una cuenta de usuario."""
    if user_id == current_user.get("id"):
        return RedirectResponse(url="/admin/usuarios?msg=user_self_deactivate", status_code=303)

    user = db.query(User).filter(User.id == user_id).first()
    if user:
        user.is_active = not user.is_active
        action = "user_activated" if user.is_active else "user_deactivated"
        audit(db, current_user.get("username", "?"), action,
              target=user.username, ip=request.client.host if request.client else None)
        db.commit()
    return RedirectResponse(url="/admin/usuarios?msg=status_changed", status_code=303)


@router.post("/users/{user_id}/role")
async def change_user_role(
    user_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_admin),
):
    """Cambia el rol de un usuario (analyst / admin / super_admin)."""
    if user_id == current_user.get("id"):
        return RedirectResponse(url="/admin/usuarios?msg=user_self_role", status_code=303)

    form     = await request.form()
    new_role = form.get("role", "analyst")
    allowed_roles = (
        ("analyst", "admin", "super_admin")
        if current_user.get("role") == "super_admin"
        else ("analyst", "admin")
    )
    if new_role not in allowed_roles:
        new_role = "analyst"

    user = db.query(User).filter(User.id == user_id).first()
    if user:
        old_role  = user.role
        user.role = new_role
        audit(db, current_user.get("username", "?"), "user_role_changed",
              target=user.username, details=f"{old_role} → {new_role}",
              ip=request.client.host if request.client else None)
        db.commit()
    return RedirectResponse(url="/admin/usuarios?msg=role_changed", status_code=303)


@router.post("/users/{user_id}/notes")
async def update_user_notes(
    user_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_admin),
):
    """Actualiza las notas administrativas de un usuario."""
    form  = await request.form()
    notes = (form.get("notes") or "").strip()[:1000]

    user = db.query(User).filter(User.id == user_id).first()
    if user:
        user.notes = notes or None
        audit(db, current_user.get("username", "?"), "user_notes_updated",
              target=user.username, ip=request.client.host if request.client else None)
        db.commit()
    return RedirectResponse(url="/admin/usuarios?msg=notes_saved", status_code=303)


# ─── Códigos de recuperación ──────────────────────────────────────────────────

@router.post("/users/{user_id}/generate-recovery")
async def generate_recovery_code(
    user_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_admin),
):
    """Genera un código de recuperación de un solo uso. Se muestra UNA VEZ."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        return RedirectResponse(url="/admin/usuarios?msg=user_not_found", status_code=303)

    code = "-".join(
        "".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(6))
        for _ in range(4)
    )
    user.recovery_code_hash = hash_password(code)
    user.recovery_set_at    = datetime.utcnow()
    audit(db, current_user.get("username", "?"), "user_recovery_generated",
          target=user.username, ip=request.client.host if request.client else None)
    db.commit()

    request.session["_recovery_flash"] = {
        "username": user.username,
        "code":     code,
        "set_at":   datetime.utcnow().strftime("%d/%m/%Y %H:%M"),
    }
    return RedirectResponse(url="/admin/usuarios?msg=recovery_generated", status_code=303)


@router.post("/users/{user_id}/revoke-recovery")
async def revoke_recovery_code(
    user_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_admin),
):
    """Revoca un código de recuperación existente."""
    user = db.query(User).filter(User.id == user_id).first()
    if user and user.recovery_code_hash:
        user.recovery_code_hash = None
        user.recovery_set_at    = None
        audit(db, current_user.get("username", "?"), "user_recovery_revoked",
              target=user.username, ip=request.client.host if request.client else None)
        db.commit()
    return RedirectResponse(url="/admin/usuarios?msg=recovery_revoked", status_code=303)
