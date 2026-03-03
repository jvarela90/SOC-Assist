"""
SOC Assist — Chatbot Engine
Gestiona el flujo de preguntas: gateway questions → inferencia de categoría → cola dirigida.
Reduce de 66 preguntas a 13-24 según la amenaza detectada.
"""
from __future__ import annotations
import json
from pathlib import Path
from typing import Any

from app.core.engine import engine_instance
from app.services.config_loader import CLASSIFICATION_ORDER

_BASE_DIR = Path(__file__).resolve().parent.parent.parent

# ─── Constantes ──────────────────────────────────────────────────────────────

# 8 preguntas con mayor poder discriminante — siempre se preguntan primero
GATEWAY_QUESTIONS: list[str] = [
    "q_002",  # Fuente de alerta → EDR=malware, usuario=phishing, SIEM_high=APT, ráfaga=DDoS
    "q_008",  # Malware confirmado → rama malware/ransomware
    "q_057",  # Phishing confirmado → rama ingeniería social
    "q_038",  # Frecuencia masiva → rama DDoS
    "q_029",  # Cuenta zombie/inactiva → rama insider/credential
    "q_046",  # C2 confirmado → rama APT
    "q_048",  # Cifrado masivo → ransomware confirmado
    "q_027",  # Nivel de privilegio → peso en todas las ramas
]

# Subconjuntos de preguntas por categoría (se excluyen las ya respondidas en gateway)
CATEGORY_ROUTES: dict[str, list[str]] = {
    "ransomware": [
        "q_039", "q_040", "q_042", "q_011", "q_015", "q_018",
        "q_019", "q_024", "q_023", "q_049", "q_051", "q_041",
        "q_064", "q_065", "q_066", "q_047", "q_016", "q_001", "q_004",
    ],
    "phishing": [
        "q_054", "q_055", "q_056", "q_058", "q_031", "q_030", "q_033",
        "q_053", "q_032", "q_006", "q_003", "q_023", "q_024",
        "q_047", "q_016", "q_001",
    ],
    "apt_intrusion": [
        "q_062", "q_063", "q_003", "q_006", "q_039", "q_040", "q_041",
        "q_043", "q_044", "q_045", "q_047", "q_059", "q_060", "q_061",
        "q_019", "q_024", "q_028", "q_033", "q_052",
    ],
    "ddos": [
        "q_017", "q_011", "q_012", "q_013", "q_014",
        "q_018", "q_051", "q_064",
    ],
    "insider": [
        "q_028", "q_030", "q_033", "q_043", "q_044", "q_016",
        "q_047", "q_023", "q_024", "q_052", "q_034", "q_035",
    ],
    "credential_theft": [
        "q_031", "q_030", "q_028", "q_053", "q_032",
        "q_059", "q_061", "q_047", "q_016", "q_006", "q_003", "q_001",
    ],
    "unknown": [],  # se llena dinámicamente con todas las preguntas restantes
}

# Tabla de inferencia: (q_id, value) → {category: delta_confianza}
INFERENCE_TABLE: dict[tuple[str, str], dict[str, float]] = {
    # Ransomware
    ("q_048", "yes"):              {"ransomware": 0.70},
    ("q_048", "partial"):          {"ransomware": 0.40},
    # APT / C2
    ("q_046", "yes"):              {"apt_intrusion": 0.65},
    ("q_046", "confirmed"):        {"apt_intrusion": 0.65},
    ("q_046", "suspicious"):       {"apt_intrusion": 0.30},
    # Phishing
    ("q_057", "yes"):              {"phishing": 0.65},
    ("q_057", "confirmed"):        {"phishing": 0.65},
    ("q_057", "suspicious"):       {"phishing": 0.30},
    # Malware genérico (ambiguo)
    ("q_008", "yes"):              {"ransomware": 0.35, "apt_intrusion": 0.25},
    ("q_008", "behavior"):         {"ransomware": 0.20, "apt_intrusion": 0.15},
    # DDoS
    ("q_038", "burst"):            {"ddos": 0.70},
    ("q_038", "very_high"):        {"ddos": 0.35},
    # Insider / credential theft
    ("q_029", "disabled_active"):  {"insider": 0.45, "credential_theft": 0.35},
    ("q_029", "inactive"):         {"insider": 0.25, "credential_theft": 0.20},
    # Tipo de alerta
    ("q_002", "manual"):           {"phishing": 0.20},
    ("q_002", "edr_av"):           {"ransomware": 0.25, "apt_intrusion": 0.15},
    ("q_002", "siem_high"):        {"apt_intrusion": 0.30},
    ("q_002", "confirmed"):        {"apt_intrusion": 0.20, "ransomware": 0.20},
    # Privilegios (amplifica riesgo de cuentas)
    ("q_027", "domain_admin"):     {"apt_intrusion": 0.15, "insider": 0.15},
    ("q_027", "enterprise_admin"): {"apt_intrusion": 0.20, "insider": 0.20},
}

# Mapeo de categorías TI → categorías del chatbot
TI_CATEGORY_MAP: dict[str, str] = {
    "c&c":                 "apt_intrusion",
    "command and control": "apt_intrusion",
    "botnet":              "apt_intrusion",
    "botnet c&c":          "apt_intrusion",
    "ransomware":          "ransomware",
    "phishing":            "phishing",
    "fraud":               "phishing",
    "malware":             "ransomware",
    "trojan":              "apt_intrusion",
    "scanner":             "apt_intrusion",
    "brute-force":         "credential_theft",
    "ssh":                 "credential_theft",
    "cryptomining":        "unknown",
}

CATEGORY_THRESHOLD = 0.45   # confianza mínima para usar ruta dirigida
TI_CONFIDENCE_DELTA = 0.30  # peso de cada categoría TI detectada

CATEGORY_LABELS: dict[str, str] = {
    "ransomware":       "Ransomware",
    "phishing":         "Phishing / BEC",
    "apt_intrusion":    "APT / Intrusión",
    "ddos":             "DDoS / Disponibilidad",
    "insider":          "Insider Threat",
    "credential_theft": "Robo de Credenciales",
    "unknown":          "Sin categoría definida",
}

# ─── Acceso a preguntas ───────────────────────────────────────────────────────

def get_question(q_id: str) -> dict | None:
    return engine_instance.questions_map.get(q_id)


def build_question_data(q_id: str) -> dict | None:
    """Retorna pregunta en formato chatbot: {id, text, help, module, options}."""
    q = get_question(q_id)
    if not q:
        return None
    return {
        "id":      q["id"],
        "text":    q.get("text", ""),
        "help":    q.get("help", ""),
        "module":  q.get("module", ""),
        "options": [{"value": o["value"], "label": o["label"]} for o in q.get("options", [])],
    }


def _all_question_ids() -> list[str]:
    """Todos los q_ids ordenados por bloque + posición."""
    qs = engine_instance.questions_map.values()
    sorted_qs = sorted(qs, key=lambda q: (q.get("display_block", 99), q.get("display_position", 99)))
    return [q["id"] for q in sorted_qs]


# ─── Inferencia de categoría ──────────────────────────────────────────────────

def infer_category(
    answers: dict[str, str],
    ti_results: list[dict],
) -> tuple[str, float, dict[str, float]]:
    """
    Infiere la categoría más probable a partir de respuestas + TI.
    Retorna: (category, confidence, probabilities_dict)
    """
    categories = [c for c in CATEGORY_ROUTES if c != "unknown"]
    scores: dict[str, float] = {c: 0.0 for c in categories}

    # Contribución desde respuestas del analista
    for q_id, value in answers.items():
        for cat, delta in INFERENCE_TABLE.get((q_id, value), {}).items():
            if cat in scores:
                scores[cat] = min(1.0, scores[cat] + delta)

    # Contribución desde TI results
    for r in ti_results:
        if not isinstance(r, dict):
            continue
        cats_ti = r.get("categories", [])
        if isinstance(cats_ti, str):
            cats_ti = [cats_ti]
        for ti_cat in cats_ti:
            mapped = TI_CATEGORY_MAP.get(ti_cat.lower())
            if mapped and mapped in scores:
                scores[mapped] = min(1.0, scores[mapped] + TI_CONFIDENCE_DELTA)
        if r.get("summary_verdict") == "MALICIOSO":
            for cat in ("apt_intrusion", "ransomware"):
                scores[cat] = min(1.0, scores[cat] + 0.10)

    best_cat = max(scores, key=lambda c: scores[c])
    best_score = scores[best_cat]

    total = sum(scores.values()) or 1.0
    probs = {c: round(s / total, 3) for c, s in scores.items() if s > 0}

    if best_score < CATEGORY_THRESHOLD:
        return "unknown", 0.0, probs

    confidence = round(min(best_score / total, 0.97), 2)
    return best_cat, confidence, probs


# ─── TI → Auto-answers ───────────────────────────────────────────────────────

def ti_to_auto_answers(ti_results: list[dict]) -> dict[str, str]:
    """
    Convierte resultados TI → respuestas automáticas para preguntas del Bloque 2.
    Auto-responde: q_003, q_006, q_062, q_046 (parcial).
    """
    if not ti_results:
        return {}

    auto: dict[str, str] = {}
    verdicts: list[str] = []
    categories: list[str] = []
    has_c2 = False

    for r in ti_results:
        if not isinstance(r, dict):
            continue
        v = r.get("summary_verdict", "")
        if v:
            verdicts.append(v)
        cats = r.get("categories", [])
        if isinstance(cats, str):
            cats = [cats]
        for c in cats:
            cl = c.lower()
            categories.append(cl)
            if any(k in cl for k in ("c&c", "command", "botnet")):
                has_c2 = True

    # q_003: ¿Coincide con IOC?
    if "MALICIOSO" in verdicts:
        auto["q_003"] = "yes"
    elif "SOSPECHOSO" in verdicts:
        auto["q_003"] = "partial"
    elif verdicts:
        auto["q_003"] = "no"

    # q_006: Reputación IP/dominio
    if "MALICIOSO" in verdicts:
        auto["q_006"] = "malicious"
    elif "SOSPECHOSO" in verdicts:
        auto["q_006"] = "suspicious"
    elif verdicts:
        auto["q_006"] = "clean"

    # q_062: Categoría de amenaza
    if has_c2:
        auto["q_062"] = "c2"
    elif any("ransomware" in c for c in categories):
        auto["q_062"] = "ransomware"
    elif any("phishing" in c or "fraud" in c for c in categories):
        auto["q_062"] = "phishing"
    elif any("botnet" in c for c in categories):
        auto["q_062"] = "botnet"

    # q_046: C2 (conservador — sólo suspicious si TI indica C2)
    if has_c2 and "q_046" not in auto:
        auto["q_046"] = "suspicious"

    return auto


# ─── Cola de preguntas ────────────────────────────────────────────────────────

def get_question_queue(
    category: str,
    already_asked: list[str],
    ti_auto_answered: list[str] | None = None,
) -> list[str]:
    """Retorna q_ids a preguntar para la categoría, sin los ya respondidos."""
    already = set(already_asked) | set(ti_auto_answered or [])

    if category == "unknown":
        return [q_id for q_id in _all_question_ids() if q_id not in already]

    route = CATEGORY_ROUTES.get(category, [])
    return [q_id for q_id in route if q_id not in already]


# ─── Score preview (anti-anchoring) ──────────────────────────────────────────

def calculate_score_preview(answers: dict[str, str]) -> dict[str, Any]:
    """Evalúa el score parcial. Retorna clasificación y color, NO el número."""
    if not answers:
        return {"classification": "informativo", "label": "Informativo", "color": "success", "emoji": "🟢"}
    try:
        result = engine_instance.evaluate(answers)
        cls = result["classification"]
        info = engine_instance.thresholds.get(cls, {})
        return {
            "classification": cls,
            "label":  info.get("label", cls.title()),
            "color":  info.get("color", "secondary"),
            "emoji":  info.get("emoji", ""),
        }
    except Exception:
        return {"classification": "informativo", "label": "Informativo", "color": "secondary", "emoji": "🟢"}


# ─── Clasificación multidimensional ──────────────────────────────────────────

def build_threat_classification(
    answers: dict[str, str],
    category: str,
    ti_results: list[dict],
    result: dict,
) -> dict[str, Any]:
    """Construye la clasificación multidimensional para almacenamiento y API."""
    cls = result.get("classification", "informativo")

    # Vector de entrada
    vector: list[str] = []
    if answers.get("q_057") in ("yes", "confirmed"):
        vector.append("Email / Phishing")
    if answers.get("q_061") in ("vpn_anon", "rdp_exposed"):
        vector.append("RDP / Acceso remoto")
    if answers.get("q_046") in ("yes", "confirmed"):
        vector.append("C2 Network")
    if not vector:
        src = answers.get("q_002", "")
        if src in ("edr_av", "siem_high"):
            vector.append("Endpoint")
        elif src == "ids_ips":
            vector.append("Network")

    # Kill chain
    kill_chain: list[str] = []
    if answers.get("q_039") == "yes":
        kill_chain.append("Installation")
    if answers.get("q_040") == "yes":
        kill_chain.append("Lateral Movement")
    if answers.get("q_046") in ("yes", "confirmed", "suspicious"):
        kill_chain.append("Command & Control")
    if answers.get("q_047") in ("yes", "confirmed"):
        kill_chain.append("Actions on Objectives")
    if not kill_chain:
        kill_chain.append("Delivery / Exploitation")

    # Actor probable
    actor_map = {
        "insider":          "Insider / Interno",
        "apt_intrusion":    "APT / Amenaza persistente",
        "ransomware":       "Ciberdelincuencia organizada",
        "phishing":         "Ciberdelincuencia organizada",
        "credential_theft": "Ciberdelincuencia organizada",
        "ddos":             "DDoS / Hacktivismo",
    }
    actor = actor_map.get(category, "Desconocido")

    # Datos comprometidos
    data_types: list[str] = []
    if answers.get("q_023") in ("yes", "sensitive"):
        data_types.append("Datos sensibles / Regulados")
    if answers.get("q_024") in ("yes", "crown"):
        data_types.append("Activo Crown Jewel")
    if answers.get("q_047") in ("yes", "confirmed"):
        data_types.append("Exfiltración confirmada")

    priority_map = {
        "brecha": "P1", "critico": "P1",
        "incidente": "P2", "sospechoso": "P3", "informativo": "P4",
    }

    return {
        "naturaleza":          [CATEGORY_LABELS.get(category, category)],
        "vector":              vector or ["No determinado"],
        "severidad_nivel":     cls,
        "prioridad":           priority_map.get(cls, "P3"),
        "datos_comprometidos": data_types or ["No determinado"],
        "actor_probable":      actor,
        "fase_kill_chain":     kill_chain,
        "uso_ia":              False,
        "final_score":         result.get("final_score", 0),
        "category_label":      CATEGORY_LABELS.get(category, category),
    }
