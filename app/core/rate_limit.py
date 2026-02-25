"""
SOC Assist — In-memory rate limiter (#56)
No external dependencies. Limits POST /evaluar to prevent abuse.
"""
import time
from collections import defaultdict
from fastapi import Request, HTTPException

# Window configuration
_WINDOW_SECONDS: int = 60
_MAX_REQUESTS: int = 20  # per IP per window

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
