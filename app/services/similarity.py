"""
SOC Assist — Incident Similarity Engine (#43/#44)
Cosine similarity on module-score vectors derived from incident answers.
"""
import math
from collections import defaultdict


def _build_vector(answers) -> dict[str, float]:
    """Aggregate contribution per module into a sparse vector."""
    vec: dict[str, float] = defaultdict(float)
    for ans in answers:
        vec[ans.module] += ans.contribution
    return dict(vec)


def _cosine_similarity(v1: dict, v2: dict) -> float:
    if not v1 or not v2:
        return 0.0
    keys = set(v1) | set(v2)
    dot = sum(v1.get(k, 0.0) * v2.get(k, 0.0) for k in keys)
    norm1 = math.sqrt(sum(x * x for x in v1.values()))
    norm2 = math.sqrt(sum(x * x for x in v2.values()))
    if norm1 == 0.0 or norm2 == 0.0:
        return 0.0
    return dot / (norm1 * norm2)


def find_similar_incidents(
    incident,
    all_incidents,
    top_n: int = 5,
    min_similarity: float = 0.40,
) -> list[dict]:
    """
    Find the most similar incidents to *incident* using cosine similarity.

    Args:
        incident: The reference Incident ORM object (must have .answers loaded).
        all_incidents: Iterable of candidate Incident objects (can include *incident*).
        top_n: Maximum number of results to return.
        min_similarity: Minimum cosine similarity threshold (0.0–1.0).

    Returns:
        List of {"score": int (0–100), "incident": <Incident>} dicts,
        sorted descending by score.
    """
    vec = _build_vector(incident.answers)
    if not vec:
        return []

    results = []
    for other in all_incidents:
        if other.id == incident.id:
            continue
        other_vec = _build_vector(other.answers)
        if not other_vec:
            continue
        sim = _cosine_similarity(vec, other_vec)
        if sim >= min_similarity:
            results.append({"score": round(sim * 100), "incident": other})

    results.sort(key=lambda x: x["score"], reverse=True)
    return results[:top_n]
