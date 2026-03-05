"""
SOC Assist — Authentication helpers
Session-based auth with bcrypt passwords.
Roles: analyst | admin | super_admin

Includes `api_auth` dependency for REST API routes (session cookie | Bearer token | HTTP Basic).
"""
import bcrypt
import bcrypt as _bcrypt
from datetime import datetime as _dt
from typing import Optional

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from sqlalchemy.orm import Session

# Deferred to avoid potential circular import issues at startup
def _get_db():  # noqa: ANN202
    from app.models.database import get_db as _real_get_db
    yield from _real_get_db()


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())


class NotAuthenticatedException(Exception):
    pass


class NotAdminException(Exception):
    pass


class NotSuperAdminException(Exception):
    pass


async def require_auth(request: Request) -> dict:
    """FastAPI dependency: requires any authenticated user."""
    user = request.session.get("user")
    if not user:
        raise NotAuthenticatedException()
    return user


async def require_admin(request: Request) -> dict:
    """FastAPI dependency: requires admin or super_admin role."""
    user = request.session.get("user")
    if not user:
        raise NotAuthenticatedException()
    if user.get("role") not in ("admin", "super_admin"):
        raise NotAdminException()
    return user


async def require_super_admin(request: Request) -> dict:
    """FastAPI dependency: requires super_admin role only."""
    user = request.session.get("user")
    if not user:
        raise NotAuthenticatedException()
    if user.get("role") != "super_admin":
        raise NotAdminException()
    return user


# ─── REST API auth (shared by api.py and chatbot_api.py) ─────────────────────

_api_security = HTTPBasic(auto_error=False)


async def api_auth(
    request: Request,
    credentials: Optional[HTTPBasicCredentials] = Depends(_api_security),
    db: Session = Depends(_get_db),
) -> dict:
    """FastAPI dependency for REST API routes.

    Accepts authentication via (in priority order):
      1. Session cookie (browser already logged in)
      2. Authorization: Bearer <token>  (API tokens issued via /admin)
      3. HTTP Basic Auth (SIEM / scripts — username + password)

    Raises HTTP 401 if none of the above succeed.
    """
    from app.models.database import User as _User, APIToken as _APIToken  # avoid circular import

    # 1) Browser session
    user = request.session.get("user")
    if user:
        return user

    # 2) Bearer token (Authorization: Bearer soc_xxxx...)
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        raw_token = auth_header[7:].strip()
        prefix = raw_token[:8]
        candidates = db.query(_APIToken).filter(
            _APIToken.token_prefix == prefix,
            _APIToken.is_active == True,
        ).all()
        for tok in candidates:
            if (tok.expires_at is None or tok.expires_at > _dt.utcnow()) and \
               _bcrypt.checkpw(raw_token.encode(), tok.token_hash.encode()):
                db.query(_APIToken).filter(_APIToken.id == tok.id).update(
                    {"last_used_at": _dt.utcnow()}, synchronize_session=False
                )
                db.commit()
                db_user = db.query(_User).filter(
                    _User.id == tok.user_id, _User.is_active == True
                ).first()
                if db_user:
                    return {"id": db_user.id, "username": db_user.username,
                            "role": db_user.role, "org_id": db_user.organization_id}

    # 3) HTTP Basic Auth (SIEM / scripts)
    if credentials:
        db_user = (
            db.query(_User)
            .filter(_User.username == credentials.username, _User.is_active == True)
            .first()
        )
        if db_user and verify_password(credentials.password, db_user.password_hash):
            return {"id": db_user.id, "username": db_user.username,
                    "role": db_user.role, "org_id": db_user.organization_id}

    raise HTTPException(
        status_code=401,
        detail="Credenciales requeridas. Usa session cookie, Bearer token, o HTTP Basic.",
        headers={"WWW-Authenticate": "Bearer, Basic realm='SOC Assist API'"},
    )
