"""
SOC Assist — Authentication helpers
Session-based auth with bcrypt passwords.
Roles: analyst | admin | super_admin
"""
import bcrypt
from fastapi import Request


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
