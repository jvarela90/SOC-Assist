"""
SOC Assist — Recursos compartidos del panel de administración.
Define el router principal, plantillas y rutas de configuración.
Este módulo es importado por todos los sub-módulos del panel admin.
"""
import json
from pathlib import Path

from fastapi import APIRouter
from fastapi.templating import Jinja2Templates

# ─── Router compartido (prefix="/admin") ──────────────────────────────────────
router = APIRouter(prefix="/admin")
templates = Jinja2Templates(directory="app/templates")

# ─── Rutas de archivos de configuración ───────────────────────────────────────
BASE_DIR       = Path(__file__).resolve().parent.parent.parent.parent
CONFIG_PATH    = BASE_DIR / "config_engine.json"
QUESTIONS_PATH = BASE_DIR / "questions.json"


def save_json(path: Path, data: dict) -> None:
    """Serializa `data` a JSON indentado y lo escribe en `path`."""
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
