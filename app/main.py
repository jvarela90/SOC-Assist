"""
SOC Assist — Plataforma de Alerta Temprana en Ciberseguridad
Main FastAPI application entry point.
"""
from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from app.models.database import init_db
from app.routes import form, dashboard, admin, ti, auth, api
from app.routes import orgs, assets, attachments
from app.core.auth import NotAuthenticatedException, NotAdminException, NotSuperAdminException

# Initialize database tables (creates default admin on first run)
init_db()

app = FastAPI(
    title="SOC Assist",
    description="Plataforma de Alerta Temprana en Ciberseguridad",
    version="1.10.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# Session middleware (signed cookies via itsdangerous)
import os
import logging as _logging
_SECRET = os.environ.get("SOC_SECRET_KEY", "")
if not _SECRET:
    _SECRET = "soc-assist-change-this-in-production-2026"
    _logging.getLogger("soc_assist").warning(
        "SOC_SECRET_KEY no está configurada. Usando clave por defecto — "
        "INSEGURO en producción. Configurar con: "
        "export SOC_SECRET_KEY=$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
    )
app.add_middleware(SessionMiddleware, secret_key=_SECRET)

# Static files
app.mount("/static", StaticFiles(directory="app/static"), name="static")


# ── Exception handlers ───────────────────────────────────────────────────────

@app.exception_handler(NotAuthenticatedException)
async def not_authenticated(request: Request, exc: NotAuthenticatedException):
    return RedirectResponse(url=f"/login?next={request.url.path}", status_code=302)


@app.exception_handler(NotAdminException)
async def not_admin(request: Request, exc: NotAdminException):
    return RedirectResponse(url="/", status_code=302)


@app.exception_handler(NotSuperAdminException)
async def not_super_admin(request: Request, exc: NotSuperAdminException):
    return RedirectResponse(url="/", status_code=302)


# ── Routers ──────────────────────────────────────────────────────────────────

app.include_router(auth.router)
app.include_router(form.router)
app.include_router(dashboard.router)
app.include_router(admin.router)
app.include_router(ti.router)
app.include_router(api.router)          # REST API v1 — /api/v1/...
app.include_router(orgs.router)         # Org management — /admin/orgs/...
app.include_router(assets.router)       # Asset inventory — /activos/...
app.include_router(attachments.router)  # Evidence attachments — /incidentes/{id}/adjuntar, /adjuntos/...


# ── Startup: run review check once on startup ────────────────────────────────

@app.on_event("startup")
async def startup_tasks():
    """Run asset review check on startup to populate notifications."""
    import asyncio
    from app.services.scheduler import check_asset_reviews
    loop = asyncio.get_event_loop()
    loop.run_in_executor(None, check_asset_reviews)


# ── Health check (used by Docker HEALTHCHECK) ────────────────────────────────

@app.get("/health", include_in_schema=False)
async def health():
    return JSONResponse({"status": "ok", "version": app.version})
