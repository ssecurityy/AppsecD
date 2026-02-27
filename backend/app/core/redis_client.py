"""Redis client for caching and sessions."""
import redis.asyncio as redis
from .config import get_settings

_settings = get_settings()
_redis: redis.Redis | None = None


async def get_redis() -> redis.Redis:
    global _redis
    if _redis is None:
        _redis = redis.from_url(_settings.redis_url, decode_responses=True)
    return _redis
