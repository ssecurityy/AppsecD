"""JWT and password security utilities."""
import uuid as uuid_mod
from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
from .config import get_settings

settings = get_settings()
pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")

SECRET_KEY = "vapt-navigator-secret-key-change-in-production-2026"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 8  # 8 hours


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    now = datetime.utcnow()
    expire = now + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({
        "exp": expire,
        "iat": now,
        "jti": str(uuid_mod.uuid4()),
        "iss": getattr(settings, "app_name", None) or "AppSecD",
    })
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def create_mfa_pending_token(user_id: str) -> str:
    """Short-lived token for MFA completion. 5 min expiry."""
    return create_access_token(
        {"sub": user_id, "purpose": "mfa_pending"},
        expires_delta=timedelta(minutes=5),
    )


def decode_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None


async def is_token_revoked(jti: str) -> bool:
    """Check if token JTI is in Redis blocklist."""
    if not jti:
        return False
    try:
        from app.core.redis_client import get_redis
        r = await get_redis()
        return await r.exists(f"jti_revoked:{jti}") > 0
    except Exception:
        return False


async def revoke_token(jti: str, exp_ts: Optional[int] = None) -> None:
    """Add JTI to Redis blocklist. TTL = min(exp - now, 86400)."""
    if not jti:
        return
    try:
        from app.core.redis_client import get_redis
        import time
        r = await get_redis()
        key = f"jti_revoked:{jti}"
        ttl = 86400  # 24h default
        if exp_ts and exp_ts > int(time.time()):
            ttl = min(exp_ts - int(time.time()), 86400)
        await r.set(key, "1", ex=max(ttl, 60))
    except Exception:
        pass
