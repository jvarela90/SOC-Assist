"""
SOC Assist — Plataforma de Alerta Temprana en Ciberseguridad
Main FastAPI application entry point.
"""
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from app.models.database import init_db
from app.routes import form, dashboard, admin, ti

# Initialize database tables
init_db()

app = FastAPI(
    title="SOC Assist",
    description="Plataforma de Alerta Temprana en Ciberseguridad",
    version="1.2.0",
)

# Static files
app.mount("/static", StaticFiles(directory="app/static"), name="static")

# Register routers
app.include_router(form.router)
app.include_router(dashboard.router)
app.include_router(admin.router)
app.include_router(ti.router)
