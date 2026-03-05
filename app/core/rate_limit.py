"""
SOC Assist — In-memory rate limiter (#56)
No external dependencies. Limits POST /evaluar to prevent abuse.
Límites configurables en app/core/constants.py (RATE_LIMIT_WINDOW_SECONDS, RATE_LIMIT_MAX_REQUESTS).
"""
import time
from collections import defaultdict
from fastapi import Request, HTTPException
from app.core.constants import RATE_LIMIT_WINDOW_SECONDS as _WINDOW_SECONDS, RATE_LIMIT_MAX_REQUESTS as _MAX_REQUESTS

_buckets: dict[str, list[float]] = defaultdict(list)


async def rate_limit_evaluar(request: Request) -> None:
    """FastAPI dependency — raises HTTP 429 if IP exceeds the request limit."""
    ip = request.client.host if request.client else "unknown"
    now = time.monotonic()
    window_start = now - _WINDOW_SECONDS

    # Evict timestamps outside the current window
    _buckets[ip] = [t for t in _buckets[ip] if t > window_start]

    if len(_buckets[ip]) >= _MAX_REQUESTS:
        retry_after = max(1, int(_WINDOW_SECONDS - (now - _buckets[ip][0])))
        raise HTTPException(
            status_code=429,
            detail=f"Demasiadas evaluaciones. Reintenta en {retry_after} segundos.",
            headers={"Retry-After": str(retry_after)},
        )

    _buckets[ip].append(now)
