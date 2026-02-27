"""
SOC Assist — Utilidad centralizada para carga de archivos de configuración JSON.

Todos los archivos JSON del proyecto usan comentarios estilo JavaScript (//).
Esta función es la única fuente de verdad para leer y parsear esos archivos.
"""
import json
import re
from pathlib import Path


# ── Constantes compartidas ────────────────────────────────────────────────────

# Orden canónico de clasificaciones, de menor a mayor severidad.
# Fuente única de verdad — importar desde aquí, no redefinir en cada módulo.
CLASSIFICATION_ORDER: list[str] = [
    "informativo",
    "sospechoso",
    "incidente",
    "critico",
    "brecha",
]


# ── Carga de JSON ─────────────────────────────────────────────────────────────

def load_json_file(path: Path) -> dict:
    """
    Carga un archivo JSON strippeando comentarios estilo // antes de parsear.

    Args:
        path: Ruta absoluta al archivo JSON.

    Returns:
        Diccionario parseado. Devuelve {} si el archivo no existe.

    Raises:
        json.JSONDecodeError: Si el contenido no es JSON válido.
    """
    if not path.exists():
        return {}
    raw = path.read_text(encoding="utf-8")
    clean = re.sub(r'//[^\n]*', '', raw)
    return json.loads(clean)
