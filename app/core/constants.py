"""
SOC Assist — Constantes globales del proyecto.
Editar aquí para cambiar límites, timeouts y clasificaciones sin buscar en el código.
"""

# ─── Paginación ───────────────────────────────────────────────────────────────
PAGINATION_SIZE: int = 50  # registros por página en /incidentes y otras listas

# ─── Threat Intelligence ──────────────────────────────────────────────────────
TI_TIMEOUT: int = 8               # segundos para asyncio.wait_for en lookups paralelos
TI_MULTIPLIER_MALICIOUS: float  = 1.5   # multiplicador de score cuando TI confirma malicioso
TI_MULTIPLIER_SUSPICIOUS: float = 1.2   # multiplicador de score cuando TI marca sospechoso

# ─── Clasificaciones ─────────────────────────────────────────────────────────
CLASSIFICATION_LEVELS: list[str] = [
    "informativo", "sospechoso", "incidente", "critico", "brecha"
]
CLASSIFICATION_COLORS: dict[str, str] = {
    "informativo": "secondary",
    "sospechoso":  "info",
    "incidente":   "warning",
    "critico":     "danger",
    "brecha":      "dark",
}

# ─── Rate limiting ────────────────────────────────────────────────────────────
RATE_LIMIT_WINDOW_SECONDS: int = 60   # ventana deslizante
RATE_LIMIT_MAX_REQUESTS:   int = 20   # máximo de peticiones por IP por ventana

# ─── Adjuntos de evidencia ────────────────────────────────────────────────────
MAX_UPLOAD_SIZE_BYTES: int = 10 * 1024 * 1024   # 10 MB
ALLOWED_EXTENSIONS: frozenset[str] = frozenset({
    ".jpg", ".png", ".pdf", ".txt", ".log",
    ".csv", ".json", ".xml", ".zip", ".pcap", ".pcapng",
})
