"""Admin settings service — global platform settings with encrypted secrets."""
import base64
import hashlib
import json
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.admin_setting import AdminSetting
from app.core.config import get_settings
from app.core.security import get_fernet_key
from app.core.llm_models import get_provider_for_model

# Fernet-compatible key from SECRET_KEY (32 bytes, base64url)
def _fernet_key() -> bytes:
    return get_fernet_key()


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


async def _get_admin_setting(db: AsyncSession, key: str) -> Optional[str]:
    row = await db.execute(select(AdminSetting).where(AdminSetting.key == key))
    setting = row.scalar_one_or_none()
    return setting.value if setting else None


async def _upsert_admin_setting(db: AsyncSession, key: str, value: str) -> None:
    row = await db.execute(select(AdminSetting).where(AdminSetting.key == key))
    setting = row.scalar_one_or_none()
    if setting:
        setting.value = value
    else:
        db.add(AdminSetting(key=key, value=value))


async def _delete_admin_setting(db: AsyncSession, key: str) -> None:
    row = await db.execute(select(AdminSetting).where(AdminSetting.key == key))
    setting = row.scalar_one_or_none()
    if setting:
        await db.delete(setting)


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


async def get_github_platform_config(db: AsyncSession) -> dict:
    """Return platform-wide GitHub App/OAuth config with DB values overriding env."""
    s = get_settings()

    def _dec(value: Optional[str]) -> str:
        if not value:
            return ""
        try:
            return _decrypt(value)
        except Exception:
            return ""

    app_id = (await _get_admin_setting(db, "github_app_id")) or s.github_app_id or ""
    app_slug = (await _get_admin_setting(db, "github_app_slug")) or s.github_app_slug or ""
    app_name = (await _get_admin_setting(db, "github_app_name")) or s.github_app_name or ""
    app_client_id = (await _get_admin_setting(db, "github_app_client_id")) or s.github_app_client_id or ""
    app_client_secret = _dec(await _get_admin_setting(db, "github_app_client_secret")) or s.github_app_client_secret or ""
    app_private_key = _dec(await _get_admin_setting(db, "github_app_private_key")) or s.github_app_private_key or ""
    app_webhook_secret = _dec(await _get_admin_setting(db, "github_app_webhook_secret")) or s.github_app_webhook_secret or ""
    oauth_client_id = (await _get_admin_setting(db, "github_oauth_client_id")) or s.github_oauth_client_id or ""
    oauth_client_secret = _dec(await _get_admin_setting(db, "github_oauth_client_secret")) or s.github_oauth_client_secret or ""
    oauth_redirect_uri = (await _get_admin_setting(db, "github_oauth_redirect_uri")) or s.github_oauth_redirect_uri or ""

    return {
        "github_app_id": app_id,
        "github_app_slug": app_slug,
        "github_app_name": app_name,
        "github_app_client_id": app_client_id,
        "github_app_client_secret": app_client_secret,
        "github_app_private_key": app_private_key,
        "github_app_webhook_secret": app_webhook_secret,
        "github_oauth_client_id": oauth_client_id,
        "github_oauth_client_secret": oauth_client_secret,
        "github_oauth_redirect_uri": oauth_redirect_uri,
    }


async def update_github_platform_app_config(
    db: AsyncSession,
    *,
    app_id: Optional[str] = None,
    app_slug: Optional[str] = None,
    app_name: Optional[str] = None,
    client_id: Optional[str] = None,
    client_secret: Optional[str] = None,
    private_key: Optional[str] = None,
    webhook_secret: Optional[str] = None,
) -> None:
    """Upsert platform-wide GitHub App config. `None` keeps existing, empty string clears."""
    plain_values = {
        "github_app_id": app_id,
        "github_app_slug": app_slug,
        "github_app_name": app_name,
        "github_app_client_id": client_id,
    }
    secret_values = {
        "github_app_client_secret": client_secret,
        "github_app_private_key": private_key,
        "github_app_webhook_secret": webhook_secret,
    }

    for key, value in plain_values.items():
        if value is None:
            continue
        if value == "":
            await _delete_admin_setting(db, key)
        else:
            await _upsert_admin_setting(db, key, value)

    for key, value in secret_values.items():
        if value is None:
            continue
        if value == "":
            await _delete_admin_setting(db, key)
        else:
            await _upsert_admin_setting(db, key, _encrypt(value))


async def update_github_oauth_platform_config(
    db: AsyncSession,
    *,
    client_id: Optional[str] = None,
    client_secret: Optional[str] = None,
    redirect_uri: Optional[str] = None,
) -> None:
    """Upsert platform-wide GitHub OAuth config. `None` keeps existing, empty string clears."""
    plain_values = {
        "github_oauth_client_id": client_id,
        "github_oauth_redirect_uri": redirect_uri,
    }
    secret_values = {
        "github_oauth_client_secret": client_secret,
    }
    for key, value in plain_values.items():
        if value is None:
            continue
        if value == "":
            await _delete_admin_setting(db, key)
        else:
            await _upsert_admin_setting(db, key, value)
    for key, value in secret_values.items():
        if value is None:
            continue
        if value == "":
            await _delete_admin_setting(db, key)
        else:
            await _upsert_admin_setting(db, key, _encrypt(value))
