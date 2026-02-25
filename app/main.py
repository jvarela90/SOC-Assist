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
from app.core.auth import NotAuthenticatedException, NotAdminException

# Initialize database tables (creates default admin on first run)
init_db()

app = FastAPI(
    title="SOC Assist",
    description="Plataforma de Alerta Temprana en Ciberseguridad",
    version="1.8.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# Session middleware (signed cookies via itsdangerous)
# In production, set SECRET_KEY from environment variable
import os
_SECRET = os.environ.get("SOC_SECRET_KEY", "soc-assist-change-this-in-production-2026")
app.add_middleware(SessionMiddleware, secret_key=_SECRET)

# Static files
app.mount("/static", StaticFiles(directory="app/static"), name="static")


# ── Exception handlers ───────────────────────────────────────────────────────

@app.exception_handler(NotAuthenticatedException)
async def not_authenticated(request: Request, exc: NotAuthenticatedException):
    return RedirectResponse(url=f"/login?next={request.url.path}", status_code=302)


@app.exception_handler(NotAdminException)
async def not_admin(request: Request, exc: NotAdminException):
    # Authenticated but not admin — redirect to home
    return RedirectResponse(url="/", status_code=302)


# ── Routers ──────────────────────────────────────────────────────────────────

app.include_router(auth.router)
app.include_router(form.router)
app.include_router(dashboard.router)
app.include_router(admin.router)
app.include_router(ti.router)
app.include_router(api.router)          # REST API v1 — /api/v1/...


# ── Health check (used by Docker HEALTHCHECK) ────────────────────────────────

@app.get("/health", include_in_schema=False)
async def health():
    return JSONResponse({"status": "ok", "version": app.version})
