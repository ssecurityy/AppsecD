"""Redis cache service — enterprise-grade caching with TTL and invalidation.

Cache-aside pattern. Keys are namespaced by org/user for multi-tenant isolation.
"""
import json
from typing import Any, Optional
from app.core.redis_client import get_redis
from app.core.config import get_settings

_settings = get_settings()

# TTLs in seconds (enterprise: balance freshness vs load)
TTL_PROJECT_LIST = 60  # 1 min — projects change frequently
TTL_PROJECT_DETAIL = 120  # 2 min
TTL_ORG_SETTINGS = 300  # 5 min — settings change rarely
TTL_TEST_CASE_COUNT = 300  # 5 min

PREFIX = "appsecd"


def _key(*parts: str) -> str:
    return f"{PREFIX}:{':'.join(str(p) for p in parts)}"


async def cache_get(key: str) -> Optional[str]:
    """Get raw value from cache. Returns None if miss or error."""
    try:
        r = await get_redis()
        return await r.get(key)
    except Exception:
        return None


async def cache_set(key: str, value: str, ttl: int = 300) -> bool:
    """Set value with TTL. Returns False on error."""
    try:
        r = await get_redis()
        await r.setex(key, ttl, value)
        return True
    except Exception:
        return False


async def cache_delete(key: str) -> bool:
    """Delete key. Returns False on error."""
    try:
        r = await get_redis()
        await r.delete(key)
        return True
    except Exception:
        return False


async def cache_delete_pattern(pattern: str) -> int:
    """Delete all keys matching pattern. Returns count deleted."""
    try:
        r = await get_redis()
        keys = []
        async for k in r.scan_iter(match=pattern):
            keys.append(k)
        if keys:
            await r.delete(*keys)
        return len(keys)
    except Exception:
        return 0


async def get_cached_json(key: str) -> Optional[Any]:
    """Get and parse JSON from cache."""
    raw = await cache_get(key)
    if raw is None:
        return None
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return None


async def set_cached_json(key: str, value: Any, ttl: int = 300) -> bool:
    """Serialize and set JSON with TTL."""
    try:
        return await cache_set(key, json.dumps(value, default=str), ttl)
    except (TypeError, ValueError):
        return False


# --- Project cache ---

def project_list_key(user_id: str) -> str:
    return _key("projects", "list", user_id)


def project_detail_key(project_id: str) -> str:
    return _key("project", project_id)


def project_progress_key(project_id: str) -> str:
    return _key("project", project_id, "progress")


async def invalidate_project(project_id: str) -> None:
    """Invalidate all caches for a project."""
    await cache_delete(project_detail_key(project_id))
    await cache_delete(project_progress_key(project_id))
    await cache_delete_pattern(_key("projects", "list", "*"))


async def invalidate_project_list(user_id: Optional[str] = None) -> None:
    """Invalidate project list cache. If user_id given, only that user; else all users."""
    if user_id:
        await cache_delete(project_list_key(user_id))
    else:
        await cache_delete_pattern(_key("projects", "list", "*"))


# --- Org settings cache ---

def org_settings_key(org_id: str) -> str:
    return _key("org", org_id, "settings")


async def invalidate_org_settings(org_id: str) -> None:
    await cache_delete(org_settings_key(org_id))
