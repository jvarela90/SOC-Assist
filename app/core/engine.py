"""
SOC Assist — Motor de Evaluación de Incidentes
Motor ponderado multidimensional con reglas duras y multiplicadores.
"""
import json
import os
from pathlib import Path
from typing import Any
from app.services.config_loader import load_json_file

BASE_DIR = Path(__file__).resolve().parent.parent.parent


def _load_json(filename: str) -> dict:
    """Load JSON file from the project root. Delegates to shared loader."""
    return load_json_file(BASE_DIR / filename)


class IncidentEngine:
    """
    Core evaluation engine.

    Flow:
      1. Calculate base_score  = Σ (answer_raw_score × q_weight × module_weight)
      2. Check hard rules       → may override final classification
      3. Apply multipliers      → final_score = base_score × Π(multiplier_i)
      4. Classify by thresholds
      5. Generate explanation
    """

    def __init__(self):
        self._config = _load_json("config_engine.json")
        q_data = _load_json("questions.json")

        self.module_weights: dict[str, float] = self._config["module_weights"]
        self.thresholds: dict = self._config["thresholds"]
        self.multiplier_rules: list = self._config["multipliers"]
        self.hard_rules: list = self._config["hard_rules"]
        self.recommendations: dict[str, str] = self._config["recommendations"]

        self.modules: list[dict] = q_data["modules"]
        self.questions: list[dict] = q_data["questions"]
        self.questions_map: dict[str, dict] = {q["id"]: q for q in self.questions}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def evaluate(self, answers: dict[str, str]) -> dict[str, Any]:
        """
        Evaluate a set of answers and return a full result dict.

        answers: { "q_001": "yes", "q_002": "auto_high", ... }
        """
        # Step 1 — base score
        module_scores: dict[str, float] = {}
        answer_details: list[dict] = []

        for qid, value in answers.items():
            if qid not in self.questions_map:
                continue
            q = self.questions_map[qid]
            raw = self._get_raw_score(q, value)
            if raw == 0:
                continue

            mod = q["module"]
            mod_w = self.module_weights.get(mod, 1.0)
            q_w = q.get("weight", 1.0)
            contribution = round(raw * mod_w * q_w, 2)

            module_scores[mod] = module_scores.get(mod, 0.0) + contribution
            answer_details.append({
                "question_id":   qid,
                "question_text": q["text"],
                "module":        mod,
                "value":         value,
                "value_label":   self._get_option_label(q, value),
                "raw_score":     raw,
                "contribution":  contribution,
            })

        base_score = round(sum(module_scores.values()), 2)

        # Step 2 — hard rules
        hard_rule_hit = self._check_hard_rules(answers)

        # Step 3 — multipliers
        multiplier = self._calculate_multiplier(answers)
        final_score = round(base_score * multiplier, 2)

        # Step 4 — classification
        score_classification = self._classify(final_score)
        if hard_rule_hit:
            hr_class = hard_rule_hit["classification"]
            # Hard rule acts as MINIMUM floor — take the more severe of the two
            order = list(self.thresholds.keys())
            hr_idx = order.index(hr_class) if hr_class in order else 0
            sc_idx = order.index(score_classification) if score_classification in order else 0
            classification = order[max(hr_idx, sc_idx)]
            override_msg = hard_rule_hit.get("override_message", "")
        else:
            classification = score_classification
            override_msg = None

        threshold_info = self.thresholds[classification]
        recommendation = self.recommendations[classification]

        # Sort details by contribution desc
        answer_details.sort(key=lambda x: x["contribution"], reverse=True)

        return {
            "base_score":      base_score,
            "final_score":     final_score,
            "multiplier":      multiplier,
            "classification":  classification,
            "threshold_info":  threshold_info,
            "recommendation":  recommendation,
            "module_scores":   module_scores,
            "answer_details":  answer_details,
            "hard_rule":       hard_rule_hit,
            "override_msg":    override_msg,
            "active_multipliers": self._get_active_multipliers(answers),
        }

    def get_module_info(self) -> list[dict]:
        return sorted(self.modules, key=lambda m: m["order"])

    def get_questions_by_module(self) -> dict[str, list[dict]]:
        result: dict[str, list] = {}
        for q in self.questions:
            mod = q["module"]
            result.setdefault(mod, [])
            result[mod].append(q)
        for mod in result:
            result[mod].sort(key=lambda q: q["order"])
        return result

    def get_config(self) -> dict:
        return self._config

    def reload(self):
        """Reload config and questions from disk (after admin edits)."""
        self.__init__()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_raw_score(self, question: dict, value: str) -> float:
        for opt in question.get("options", []):
            if opt["value"] == value:
                return float(opt.get("score", 0))
        return 0.0

    def _get_option_label(self, question: dict, value: str) -> str:
        for opt in question.get("options", []):
            if opt["value"] == value:
                return opt.get("label", value)
        return value

    def _check_hard_rules(self, answers: dict) -> dict | None:
        for rule in self.hard_rules:
            if all(
                answers.get(c["question_id"]) == c["value"]
                for c in rule["conditions"]
            ):
                return rule
        return None

    def _calculate_multiplier(self, answers: dict) -> float:
        total = 1.0
        for rule in self.multiplier_rules:
            if all(
                answers.get(c["question_id"]) == c["value"]
                for c in rule["conditions"]
            ):
                total *= rule["multiplier"]
        return round(total, 3)

    def _get_active_multipliers(self, answers: dict) -> list[dict]:
        active = []
        for rule in self.multiplier_rules:
            if all(
                answers.get(c["question_id"]) == c["value"]
                for c in rule["conditions"]
            ):
                active.append(rule)
        return active

    def _classify(self, score: float) -> str:
        for key, t in self.thresholds.items():
            if t["min"] <= score <= t["max"]:
                return key
        return "brecha"


# Singleton instance shared across the app
engine_instance = IncidentEngine()
