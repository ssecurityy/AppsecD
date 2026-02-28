"""Org-scoped settings — JIRA, LLM per organization. Enterprise multi-tenant."""
import base64
import hashlib
import json
from typing import Optional
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.org_setting import OrgSetting
from app.models.admin_setting import AdminSetting
from app.core.config import get_settings
from app.core.security import SECRET_KEY
from app.core.llm_models import get_provider_for_model


def _fernet_key() -> bytes:
    digest = hashlib.sha256(SECRET_KEY.encode()).digest()
    return base64.urlsafe_b64encode(digest)


def _encrypt(plain: str) -> str:
    from cryptography.fernet import Fernet
    return Fernet(_fernet_key()).encrypt(plain.encode()).decode()


def _decrypt(cipher: str) -> str:
    from cryptography.fernet import Fernet
    return Fernet(_fernet_key()).decrypt(cipher.encode()).decode()


def _get_env_key(provider: str, s) -> Optional[str]:
    if provider == "openai":
        return s.openai_api_key or None
    if provider == "anthropic":
        return s.anthropic_api_key or None
    if provider == "google":
        return s.google_api_key or None
    return None


async def _get_org_setting(db: AsyncSession, org_id: UUID, key: str) -> Optional[str]:
    r = await db.execute(
        select(OrgSetting).where(
            OrgSetting.organization_id == org_id,
            OrgSetting.key == key,
        )
    )
    row = r.scalar_one_or_none()
    return row.value if row else None


async def _get_global_setting(db: AsyncSession, key: str) -> Optional[str]:
    r = await db.execute(select(AdminSetting).where(AdminSetting.key == key))
    row = r.scalar_one_or_none()
    return row.value if row else None


async def get_llm_config(db: AsyncSession, organization_id: Optional[UUID] = None) -> tuple[str, str, Optional[str]]:
    """
    Returns (provider, model, api_key). Org-scoped when org_id given.
    Fallback: global admin_settings, then env.
    """
    s = get_settings()
    model = "gpt-4o-mini"
    provider = "openai"
    api_key: Optional[str] = None

    if organization_id:
        model = await _get_org_setting(db, organization_id, "llm_model") or model
        provider = await _get_org_setting(db, organization_id, "llm_provider") or provider
        provider = get_provider_for_model(provider, model)
        enc_key = await _get_org_setting(db, organization_id, "llm_api_key")
        if enc_key:
            try:
                api_key = _decrypt(enc_key)
            except Exception:
                pass

    if not api_key:
        model = await _get_global_setting(db, "llm_model") or model
        provider = await _get_global_setting(db, "llm_provider") or provider
        provider = get_provider_for_model(provider, model)
        enc_key = await _get_global_setting(db, "llm_api_key")
        if enc_key:
            try:
                api_key = _decrypt(enc_key)
            except Exception:
                pass

    if not api_key:
        api_key = _get_env_key(provider, s)
    return provider, model, api_key


async def update_llm_config(
    db: AsyncSession,
    provider: str,
    model: str,
    api_key: Optional[str] = None,
    organization_id: Optional[UUID] = None,
) -> None:
    """Update LLM config. Org-scoped when org_id given, else global."""
    if organization_id:
        await _upsert_org_setting(db, organization_id, "llm_provider", provider)
        await _upsert_org_setting(db, organization_id, "llm_model", model)
        if api_key is not None:
            if api_key:
                await _upsert_org_setting(db, organization_id, "llm_api_key", _encrypt(api_key))
            else:
                await _delete_org_setting(db, organization_id, "llm_api_key")
    else:
        from app.services.admin_settings_service import update_llm_config as update_global
        await update_global(db, provider, model, api_key)


async def _upsert_org_setting(db: AsyncSession, org_id: UUID, key: str, value: str) -> None:
    r = await db.execute(
        select(OrgSetting).where(
            OrgSetting.organization_id == org_id,
            OrgSetting.key == key,
        )
    )
    row = r.scalar_one_or_none()
    if row:
        row.value = value
    else:
        db.add(OrgSetting(organization_id=org_id, key=key, value=value))


async def _delete_org_setting(db: AsyncSession, org_id: UUID, key: str) -> None:
    r = await db.execute(
        select(OrgSetting).where(
            OrgSetting.organization_id == org_id,
            OrgSetting.key == key,
        )
    )
    row = r.scalar_one_or_none()
    if row:
        await db.delete(row)


async def get_jira_config(db: AsyncSession, organization_id: Optional[UUID] = None) -> tuple[str, str, str, str]:
    """Returns (base_url, email, token, project_key). Empty strings if not configured."""
    s = get_settings()
    base_url = email = token = project_key = ""

    if organization_id:
        base_url = await _get_org_setting(db, organization_id, "jira_base_url") or ""
        email = await _get_org_setting(db, organization_id, "jira_email") or ""
        enc = await _get_org_setting(db, organization_id, "jira_api_token")
        if enc:
            try:
                token = _decrypt(enc)
            except Exception:
                pass
        project_key = await _get_org_setting(db, organization_id, "jira_project_key") or ""

    if not (base_url and email and token and project_key):
        base_url = s.jira_base_url or ""
        email = s.jira_email or ""
        token = s.jira_api_token or ""
        project_key = s.jira_project_key or ""

    return base_url, email, token, project_key


async def update_jira_config(
    db: AsyncSession,
    base_url: str,
    email: str,
    api_token: str,
    project_key: str,
    organization_id: Optional[UUID] = None,
) -> None:
    """Update JIRA config. Org-scoped when org_id given."""
    if organization_id:
        await _upsert_org_setting(db, organization_id, "jira_base_url", base_url)
        await _upsert_org_setting(db, organization_id, "jira_email", email)
        await _upsert_org_setting(db, organization_id, "jira_api_token", _encrypt(api_token) if api_token else "")
        await _upsert_org_setting(db, organization_id, "jira_project_key", project_key)
    else:
        raise ValueError("JIRA must be configured per organization")


async def get_custom_models(db: AsyncSession, organization_id: Optional[UUID] = None) -> list[tuple[str, str, str]]:
    """Return custom models. Org-scoped or global."""
    if organization_id:
        val = await _get_org_setting(db, organization_id, "llm_custom_models")
    else:
        val = await _get_global_setting(db, "llm_custom_models")
    if not val:
        return []
    try:
        data = json.loads(val)
        return [(x["provider"], x["model"], x.get("label", x["model"])) for x in data]
    except Exception:
        return []


async def add_custom_model(
    db: AsyncSession,
    provider: str,
    model: str,
    label: str,
    organization_id: Optional[UUID] = None,
) -> None:
    """Add custom model. Org-scoped or global."""
    custom = await get_custom_models(db, organization_id)
    if any((p, m) == (provider, model) for p, m, _ in custom):
        return
    custom.append((provider, model, label or model))
    data = [{"provider": p, "model": m, "label": l} for p, m, l in custom]
    val = json.dumps(data)
    if organization_id:
        await _upsert_org_setting(db, organization_id, "llm_custom_models", val)
    else:
        r = await db.execute(select(AdminSetting).where(AdminSetting.key == "llm_custom_models"))
        row = r.scalar_one_or_none()
        if row:
            row.value = val
        else:
            db.add(AdminSetting(key="llm_custom_models", value=val))


async def remove_custom_model(
    db: AsyncSession,
    provider: str,
    model: str,
    organization_id: Optional[UUID] = None,
) -> None:
    """Remove custom model."""
    custom = await get_custom_models(db, organization_id)
    custom = [(p, m, l) for p, m, l in custom if (p, m) != (provider, model)]
    val = json.dumps([{"provider": p, "model": m, "label": l} for p, m, l in custom])
    if organization_id:
        await _upsert_org_setting(db, organization_id, "llm_custom_models", val)
    else:
        r = await db.execute(select(AdminSetting).where(AdminSetting.key == "llm_custom_models"))
        row = r.scalar_one_or_none()
        if row:
            row.value = val
