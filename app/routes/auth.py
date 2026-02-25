"""
SOC Assist — Authentication routes
Login / logout / account recovery.
"""
from datetime import datetime
from fastapi import APIRouter, Request, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from app.models.database import get_db, User
from app.core.auth import verify_password, hash_password

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


@router.get("/login", response_class=HTMLResponse)
async def login_form(request: Request):
    if request.session.get("user"):
        return RedirectResponse(url="/", status_code=302)
    return templates.TemplateResponse("login.html", {"request": request, "error": None})


@router.post("/login")
async def login(request: Request, db: Session = Depends(get_db)):
    form = await request.form()
    username = form.get("username", "").strip()
    password = form.get("password", "")

    user = db.query(User).filter(
        User.username == username,
        User.is_active == True
    ).first()

    if not user or not verify_password(password, user.password_hash):
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Usuario o contraseña incorrectos.",
        }, status_code=401)

    user.last_login = datetime.utcnow()
    user.login_count = (user.login_count or 0) + 1
    db.commit()

    request.session["user"] = {
        "id": user.id,
        "username": user.username,
        "role": user.role,
    }

    next_url = request.query_params.get("next", "/")
    # Basic safety: only redirect to relative paths
    if not next_url.startswith("/"):
        next_url = "/"
    return RedirectResponse(url=next_url, status_code=302)


@router.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login", status_code=302)


@router.get("/recuperar", response_class=HTMLResponse)
async def recovery_form(request: Request):
    """Account recovery page — use admin-generated recovery code to reset password."""
    if request.session.get("user"):
        return RedirectResponse(url="/", status_code=302)
    return templates.TemplateResponse("recover.html", {
        "request": request,
        "error": None,
        "success": False,
    })


@router.post("/recuperar", response_class=HTMLResponse)
async def recovery_submit(request: Request, db: Session = Depends(get_db)):
    """Verify recovery code and set a new password (single-use code)."""
    form = await request.form()
    username      = form.get("username", "").strip()
    recovery_code = form.get("recovery_code", "").strip()
    new_password  = form.get("new_password", "").strip()
    confirm_pwd   = form.get("confirm_password", "").strip()

    def _err(msg: str):
        return templates.TemplateResponse("recover.html", {
            "request": request,
            "error": msg,
            "success": False,
            "prefill_username": username,
        }, status_code=422)

    if not username or not recovery_code or not new_password:
        return _err("Todos los campos son obligatorios.")
    if new_password != confirm_pwd:
        return _err("Las contraseñas no coinciden.")
    if len(new_password) < 8:
        return _err("La contraseña debe tener al menos 8 caracteres.")

    user = db.query(User).filter(User.username == username, User.is_active == True).first()
    if not user or not user.recovery_code_hash:
        return _err("Usuario no encontrado o sin código de recuperación activo.")

    if not verify_password(recovery_code, user.recovery_code_hash):
        return _err("Código de recuperación incorrecto.")

    # Apply new password + invalidate recovery code (single-use)
    user.password_hash      = hash_password(new_password)
    user.password_changed_at = datetime.utcnow()
    user.recovery_code_hash = None
    user.recovery_set_at    = None
    db.commit()

    return templates.TemplateResponse("recover.html", {
        "request": request,
        "error": None,
        "success": True,
    })
