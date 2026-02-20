"""
SOC Assist — Sistema de Calibración Automática
Ajusta los pesos de preguntas basándose en el historial de incidentes resueltos.
"""
import json
import re
from pathlib import Path
from datetime import datetime
from sqlalchemy.orm import Session
from app.models.database import Incident, IncidentAnswer, CalibrationLog, WeightHistory

BASE_DIR = Path(__file__).resolve().parent.parent.parent
CONFIG_PATH = BASE_DIR / "config_engine.json"
QUESTIONS_PATH = BASE_DIR / "questions.json"

LEARNING_RATE = 0.08
MIN_SAMPLES = 5


def _load_json(path: Path) -> dict:
    raw = path.read_text(encoding="utf-8")
    clean = re.sub(r'//[^\n]*', '', raw)
    return json.loads(clean)


def _save_json(path: Path, data: dict):
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def run_calibration(db: Session) -> dict:
    """
    Run auto-calibration based on resolved incidents.
    Returns a summary of what was done.
    """
    # Fetch resolved incidents
    resolved = db.query(Incident).filter(
        Incident.resolution.in_(["fp", "tp_resolved", "tp_escalated"])
    ).all()

    if len(resolved) < MIN_SAMPLES:
        return {
            "status": "skipped",
            "reason": f"Se necesitan mínimo {MIN_SAMPLES} incidentes resueltos (hay {len(resolved)})",
            "adjustments": 0
        }

    # Count FP and TP
    fp_count = sum(1 for i in resolved if i.resolution == "fp")
    tp_count = len(resolved) - fp_count

    fp_rate = fp_count / len(resolved) if resolved else 0
    fn_rate = 0.0  # Simplified: we cannot easily measure FN without ground truth

    # Compute per-question impact stats
    question_stats: dict[str, dict] = {}

    for incident in resolved:
        is_tp = incident.resolution in ("tp_resolved", "tp_escalated")
        for ans in incident.answers:
            qid = ans.question_id
            if qid not in question_stats:
                question_stats[qid] = {"tp_total": 0, "fp_total": 0, "contrib_sum": 0.0, "count": 0}
            question_stats[qid]["count"] += 1
            question_stats[qid]["contrib_sum"] += ans.contribution
            if is_tp:
                question_stats[qid]["tp_total"] += 1
            else:
                question_stats[qid]["fp_total"] += 1

    # Load current config and questions
    config = _load_json(CONFIG_PATH)
    q_data = _load_json(QUESTIONS_PATH)
    questions_map = {q["id"]: q for q in q_data["questions"]}

    adjustments = 0

    # Adjust question weights
    for qid, stats in question_stats.items():
        if stats["count"] < MIN_SAMPLES:
            continue
        if qid not in questions_map:
            continue

        q = questions_map[qid]
        tp_rate = stats["tp_total"] / stats["count"]
        fp_q_rate = stats["fp_total"] / stats["count"]

        # If question appears often in FP → reduce weight
        # If question appears often in TP → increase weight
        error_rate = tp_rate - fp_q_rate  # positive = good predictor, negative = noisy
        old_weight = float(q.get("weight", 1.0))
        adjustment = LEARNING_RATE * error_rate
        new_weight = round(max(0.1, min(3.0, old_weight + adjustment)), 3)

        if abs(new_weight - old_weight) > 0.005:
            q["weight"] = new_weight
            db.add(WeightHistory(
                question_id=qid,
                module=q["module"],
                change_type="question_weight",
                old_value=old_weight,
                new_value=new_weight,
                reason=f"Auto-calibración: tp_rate={tp_rate:.2f}, fp_rate={fp_q_rate:.2f}"
            ))
            adjustments += 1

    # Save updated questions
    _save_json(QUESTIONS_PATH, q_data)

    # Log the calibration run
    log = CalibrationLog(
        run_at=datetime.utcnow(),
        total_incidents=len(resolved),
        true_positives=tp_count,
        false_positives=fp_count,
        false_negatives=0,
        adjustments_made=adjustments,
        notes=f"FP rate: {fp_rate:.1%}. Ajustes realizados: {adjustments}"
    )
    db.add(log)
    db.commit()

    return {
        "status": "completed",
        "total_resolved": len(resolved),
        "true_positives": tp_count,
        "false_positives": fp_count,
        "fp_rate": round(fp_rate * 100, 1),
        "adjustments": adjustments,
        "timestamp": datetime.utcnow().isoformat()
    }
