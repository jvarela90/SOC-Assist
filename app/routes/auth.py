"""
SOC Assist — Authentication routes
Login / logout / account recovery / 2FA TOTP verify.
"""
from datetime import datetime
from fastapi import APIRouter, Request, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
import pyotp
from app.models.database import get_db, User
from app.core.auth import verify_password, hash_password, require_auth

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

    # If 2FA is enabled, redirect to TOTP verification before granting session
    if user.totp_enabled and user.totp_secret:
        next_url = request.query_params.get("next", "/")
        if not next_url.startswith("/"):
            next_url = "/"
        request.session["totp_pending"] = {
            "user_id": user.id,
            "next": next_url,
        }
        return RedirectResponse(url="/verify-2fa", status_code=302)

    user.last_login = datetime.utcnow()
    user.login_count = (user.login_count or 0) + 1
    db.commit()

    request.session["user"] = {
        "id": user.id,
        "username": user.username,
        "role": user.role,
        "org_id": user.organization_id,
    }

    next_url = request.query_params.get("next", "/")
    # Basic safety: only redirect to relative paths
    if not next_url.startswith("/"):
        next_url = "/"
    return RedirectResponse(url=next_url, status_code=302)


@router.get("/verify-2fa", response_class=HTMLResponse)
async def verify_2fa_form(request: Request):
    """Step 2 of login: TOTP code entry."""
    if not request.session.get("totp_pending"):
        return RedirectResponse(url="/login", status_code=302)
    if request.session.get("user"):
        return RedirectResponse(url="/", status_code=302)
    return templates.TemplateResponse("verify_2fa.html", {"request": request, "error": None})


@router.post("/verify-2fa", response_class=HTMLResponse)
async def verify_2fa_submit(request: Request, db: Session = Depends(get_db)):
    """Verify TOTP code and complete login."""
    pending = request.session.get("totp_pending")
    if not pending:
        return RedirectResponse(url="/login", status_code=302)

    form = await request.form()
    code = form.get("totp_code", "").strip().replace(" ", "")

    user = db.query(User).filter(User.id == pending["user_id"], User.is_active == True).first()
    if not user or not user.totp_secret:
        request.session.pop("totp_pending", None)
        return RedirectResponse(url="/login", status_code=302)

    totp = pyotp.TOTP(user.totp_secret)
    if not totp.verify(code, valid_window=1):
        return templates.TemplateResponse("verify_2fa.html", {
            "request": request,
            "error": "Código incorrecto o expirado. Inténtalo de nuevo.",
        }, status_code=401)

    # Code valid — complete login
    user.last_login = datetime.utcnow()
    user.login_count = (user.login_count or 0) + 1
    db.commit()

    request.session.pop("totp_pending", None)
    request.session["user"] = {
        "id": user.id,
        "username": user.username,
        "role": user.role,
        "org_id": user.organization_id,
    }

    next_url = pending.get("next", "/")
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


# ── 2FA TOTP Setup (N3) ───────────────────────────────────────────────────────

@router.get("/cuenta/2fa", response_class=HTMLResponse)
async def totp_setup_page(
    request: Request,
    db: Session = Depends(get_db),
    _user: dict = Depends(require_auth),
):
    """Show 2FA setup page with QR code provisioning URI."""
    user = db.query(User).filter(User.id == _user["id"]).first()
    if not user:
        return RedirectResponse(url="/login", status_code=302)

    # Generate a new temp secret if user doesn't have one yet (pre-enable)
    # Stored in session temporarily until confirmed
    if not user.totp_secret:
        temp_secret = pyotp.random_base32()
        request.session["totp_setup_secret"] = temp_secret
    else:
        temp_secret = request.session.get("totp_setup_secret") or user.totp_secret

    totp = pyotp.TOTP(temp_secret)
    otp_uri = totp.provisioning_uri(
        name=user.username,
        issuer_name="SOC Assist",
    )

    return templates.TemplateResponse("totp_setup.html", {
        "request": request,
        "user": user,
        "otp_uri": otp_uri,
        "secret": temp_secret,
        "totp_enabled": user.totp_enabled,
        "error": None,
        "msg": request.query_params.get("msg", ""),
    })


@router.post("/cuenta/2fa/enable")
async def totp_enable(
    request: Request,
    db: Session = Depends(get_db),
    _user: dict = Depends(require_auth),
):
    """Confirm TOTP code from authenticator app to activate 2FA."""
    form = await request.form()
    code = str(form.get("totp_code", "")).strip().replace(" ", "")

    temp_secret = request.session.get("totp_setup_secret")
    if not temp_secret:
        return RedirectResponse("/cuenta/2fa?msg=session_expired", status_code=303)

    totp = pyotp.TOTP(temp_secret)
    if not totp.verify(code, valid_window=1):
        user = db.query(User).filter(User.id == _user["id"]).first()
        otp_uri = totp.provisioning_uri(name=user.username, issuer_name="SOC Assist")
        return templates.TemplateResponse("totp_setup.html", {
            "request": request,
            "user": user,
            "otp_uri": otp_uri,
            "secret": temp_secret,
            "totp_enabled": user.totp_enabled,
            "error": "Código incorrecto. Asegúrate de que el reloj de tu dispositivo esté sincronizado.",
            "msg": "",
        }, status_code=422)

    user = db.query(User).filter(User.id == _user["id"]).first()
    user.totp_secret  = temp_secret
    user.totp_enabled = True
    db.commit()
    request.session.pop("totp_setup_secret", None)

    return RedirectResponse("/cuenta/2fa?msg=enabled", status_code=303)


@router.post("/cuenta/2fa/disable")
async def totp_disable(
    request: Request,
    db: Session = Depends(get_db),
    _user: dict = Depends(require_auth),
):
    """Disable 2FA for the current user (requires password confirmation)."""
    form = await request.form()
    password = str(form.get("password", ""))

    user = db.query(User).filter(User.id == _user["id"]).first()
    if not user or not verify_password(password, user.password_hash):
        otp_uri = ""
        if user and user.totp_secret:
            otp_uri = pyotp.TOTP(user.totp_secret).provisioning_uri(
                name=user.username, issuer_name="SOC Assist"
            )
        return templates.TemplateResponse("totp_setup.html", {
            "request": request,
            "user": user,
            "otp_uri": otp_uri,
            "secret": user.totp_secret if user else "",
            "totp_enabled": True,
            "error": "Contraseña incorrecta. No se puede desactivar el 2FA.",
            "msg": "",
        }, status_code=422)

    user.totp_enabled = False
    user.totp_secret  = None
    db.commit()
    return RedirectResponse("/cuenta/2fa?msg=disabled", status_code=303)
