"""Rate limiter for FastAPI. Uses Redis when REDIS_URL is set for global limits across instances."""
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.core.config import get_settings


def _storage_uri() -> str | None:
    """Return Redis URI for rate limit storage, or None for in-memory (per-process)."""
    url = (get_settings().redis_url or "").strip()
    if not url or not url.startswith("redis://"):
        return None
    # Use sync redis (limits lib async+redis requires coredis). Sync is acceptable for rate checks.
    return url


_uri = _storage_uri()
limiter = (
    Limiter(key_func=get_remote_address, storage_uri=_uri)
    if _uri
    else Limiter(key_func=get_remote_address)
)
