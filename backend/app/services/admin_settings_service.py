"""Admin settings service — LLM config storage with encrypted API key."""
import base64
import hashlib
import json
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.admin_setting import AdminSetting
from app.core.config import get_settings
from app.core.security import SECRET_KEY
from app.core.llm_models import get_provider_for_model

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


def _get_env_key(provider: str, s) -> Optional[str]:
    if provider == "openai":
        return s.openai_api_key or None
    if provider == "anthropic":
        return s.anthropic_api_key or None
    if provider == "google":
        return s.google_api_key or None
    return None


async def get_llm_config(db: AsyncSession) -> tuple[str, str, Optional[str]]:
    """
    Returns (provider, model, api_key). api_key is None if not set.
    Falls back to env keys if no DB config.
    """
    s = get_settings()
    row = await db.execute(
        select(AdminSetting).where(AdminSetting.key == "llm_model")
    )
    model_row = row.scalar_one_or_none()
    row_p = await db.execute(
        select(AdminSetting).where(AdminSetting.key == "llm_provider")
    )
    provider_row = row_p.scalar_one_or_none()
    row2 = await db.execute(
        select(AdminSetting).where(AdminSetting.key == "llm_api_key")
    )
    key_row = row2.scalar_one_or_none()

    model = (model_row.value if model_row else None) or "gpt-4o-mini"
    provider = (provider_row.value if provider_row else None) or "openai"
    provider = get_provider_for_model(provider, model)

    api_key: Optional[str] = None
    if key_row and key_row.value:
        try:
            api_key = _decrypt(key_row.value)
        except Exception:
            pass
    if not api_key:
        api_key = _get_env_key(provider, s)
    return provider, model, api_key


async def update_llm_config(
    db: AsyncSession,
    provider: str,
    model: str,
    api_key: Optional[str] = None,  # None = keep existing, "" = clear
) -> None:
    """Update LLM provider, model, and optionally API key."""
    # Upsert provider
    row_p = await db.execute(select(AdminSetting).where(AdminSetting.key == "llm_provider"))
    rp = row_p.scalar_one_or_none()
    if rp:
        rp.value = provider
    else:
        db.add(AdminSetting(key="llm_provider", value=provider))

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


async def get_custom_models(db: AsyncSession) -> list[tuple[str, str, str]]:
    """Return custom models [(provider, model, label), ...] from DB."""
    row = await db.execute(
        select(AdminSetting).where(AdminSetting.key == "llm_custom_models")
    )
    r = row.scalar_one_or_none()
    if not r or not r.value:
        return []
    try:
        data = json.loads(r.value)
        return [(x["provider"], x["model"], x.get("label", x["model"])) for x in data]
    except Exception:
        return []


async def add_custom_model(
    db: AsyncSession,
    provider: str,
    model: str,
    label: str,
) -> None:
    """Add a custom model for future/prospective use."""
    custom = await get_custom_models(db)
    if any((p, m) == (provider, model) for p, m, _ in custom):
        return  # already exists
    custom.append((provider, model, label or model))
    data = [{"provider": p, "model": m, "label": l} for p, m, l in custom]
    row = await db.execute(select(AdminSetting).where(AdminSetting.key == "llm_custom_models"))
    r = row.scalar_one_or_none()
    if r:
        r.value = json.dumps(data)
    else:
        db.add(AdminSetting(key="llm_custom_models", value=json.dumps(data)))


async def remove_custom_model(db: AsyncSession, provider: str, model: str) -> None:
    """Remove a custom model."""
    custom = await get_custom_models(db)
    custom = [(p, m, l) for p, m, l in custom if (p, m) != (provider, model)]
    data = [{"provider": p, "model": m, "label": l} for p, m, l in custom]
    row = await db.execute(select(AdminSetting).where(AdminSetting.key == "llm_custom_models"))
    r = row.scalar_one_or_none()
    if r:
        r.value = json.dumps(data)
    elif data:
        db.add(AdminSetting(key="llm_custom_models", value=json.dumps(data)))
