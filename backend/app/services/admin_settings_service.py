"""Admin settings service — LLM config storage with encrypted API key."""
import base64
import hashlib
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.admin_setting import AdminSetting
from app.core.config import get_settings
from app.core.security import SECRET_KEY

# Fernet-compatible key from SECRET_KEY (32 bytes, base64url)
def _fernet_key() -> bytes:
    digest = hashlib.sha256(SECRET_KEY.encode()).digest()
    return base64.urlsafe_b64encode(digest)


def _encrypt(plain: str) -> str:
    from cryptography.fernet import Fernet
    f = Fernet(_fernet_key())
    return f.encrypt(plain.encode()).decode()


def _decrypt(cipher: str) -> str:
    from cryptography.fernet import Fernet
    f = Fernet(_fernet_key())
    return f.decrypt(cipher.encode()).decode()


async def get_llm_config(db: AsyncSession) -> tuple[str, Optional[str]]:
    """
    Returns (model, api_key). api_key is None if not set.
    Falls back to env OPENAI_API_KEY if no DB config.
    """
    s = get_settings()
    row = await db.execute(
        select(AdminSetting).where(AdminSetting.key == "llm_model")
    )
    model_row = row.scalar_one_or_none()
    row2 = await db.execute(
        select(AdminSetting).where(AdminSetting.key == "llm_api_key")
    )
    key_row = row2.scalar_one_or_none()

    model = (model_row.value if model_row else None) or "gpt-4o-mini"
    api_key: Optional[str] = None
    if key_row and key_row.value:
        try:
            api_key = _decrypt(key_row.value)
        except Exception:
            pass
    if not api_key and s.openai_api_key:
        api_key = s.openai_api_key  # env fallback
    return model, api_key


async def update_llm_config(
    db: AsyncSession,
    model: str,
    api_key: Optional[str] = None,  # None = keep existing, "" = clear
) -> None:
    """Update LLM model and optionally API key. api_key=None keeps current, '' clears."""
    # Upsert model
    row = await db.execute(select(AdminSetting).where(AdminSetting.key == "llm_model"))
    r = row.scalar_one_or_none()
    if r:
        r.value = model
    else:
        db.add(AdminSetting(key="llm_model", value=model))

    if api_key is not None:
        row2 = await db.execute(select(AdminSetting).where(AdminSetting.key == "llm_api_key"))
        r2 = row2.scalar_one_or_none()
        if api_key:
            enc = _encrypt(api_key)
            if r2:
                r2.value = enc
            else:
                db.add(AdminSetting(key="llm_api_key", value=enc))
        else:
            if r2:
                await db.delete(r2)
