"""
SOC Assist — Panel de Administración (paquete).
Importa todos los sub-módulos para registrar sus rutas en el router compartido.

El router se define en _base.py y cada sub-módulo agrega sus rutas directamente.
app/main.py importa: from app.routes import admin  → usa admin.router
"""
from ._base import router  # noqa: F401 — re-exportado para main.py

# Importar sub-módulos para activar los decoradores de rutas
from . import config        # /admin (home), /admin/module-weights, /thresholds, /calibrate
from . import integrations  # /admin/ti-keys, /webhooks, /smtp, /thehive
from . import users         # /admin/usuarios, /admin/users/*
from . import security      # /admin/backup, /admin/audit-log, /admin/api-tokens

__all__ = ["router"]
