"""Admin settings API — org-scoped JIRA, LLM. Enterprise multi-tenant."""
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.api.auth import require_admin
from app.core.database import get_db
from app.core.config import get_settings
from app.models.user import User
from app.models.organization import Organization
from app.services.audit_service import log_audit
from app.services.org_settings_service import (
    get_llm_config,
    update_llm_config,
    get_jira_config,
    update_jira_config,
    get_custom_models,
    add_custom_model,
    remove_custom_model,
)
from app.services.llm_models_service import fetch_latest_models, is_valid_provider_model

router = APIRouter(prefix="/admin/settings", tags=["admin-settings"])


async def _resolve_org_id(current_user: User, org_id: str | None, db: AsyncSession) -> tuple[UUID | None, Organization | None]:
    """Resolve organization for settings. Super_admin can pick any org; admin auto-scoped to their org."""
    if current_user.role == "admin":
        # Admin is always scoped to their own org
        if not current_user.organization_id:
            raise HTTPException(400, "Admin must belong to an organization")
        org_result = await db.execute(select(Organization).where(Organization.id == current_user.organization_id))
        org = org_result.scalar_one_or_none()
        return current_user.organization_id, org

    # Super admin — use provided org_id or None
    if org_id:
        try:
            oid = UUID(org_id)
        except ValueError:
            raise HTTPException(400, "Invalid org_id")
        org_result = await db.execute(select(Organization).where(Organization.id == oid))
        org = org_result.scalar_one_or_none()
        if not org:
            raise HTTPException(404, "Organization not found")
        return oid, org
    return None, None


@router.get("")
async def get_settings_status(
    org_id: str | None = Query(None, description="Organization ID (super_admin only)"),
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """
    Return integration status. Admin: auto-scoped to their org. Super_admin: can pass org_id.
    """
    org_uuid, org = await _resolve_org_id(current_user, org_id, db)
    s = get_settings()
    provider, model, api_key = await get_llm_config(db, org_uuid)
    custom = await get_custom_models(db, org_uuid)
    jira_base, jira_email, jira_token, jira_key = await get_jira_config(db, org_uuid)

    openai_k = s.openai_api_key or (api_key if provider == "openai" else None)
    google_k = s.google_api_key or (api_key if provider == "google" else None)
    models = fetch_latest_models(
        openai_key=openai_k,
        google_key=google_k,
        custom_models=custom,
    )
    return {
        "organization_id": str(org_uuid) if org_uuid else None,
        "organization_name": org.name if org else None,
        "jira": {
            "configured": bool(jira_base and jira_email and jira_token and jira_key),
            "base_url": jira_base or "",
            "email": jira_email or "",
            "project_key": jira_key or "",
            "hint": "Configure JIRA below for this organization, or set in backend/.env as fallback.",
        },
        "ai": {
            "mode": "llm" if api_key else "rule_based",
            "provider": provider,
            "model": model,
            "hint": "Configure provider, model and API key below. Env fallback when not set.",
        },
        "llm_models": [{"provider": p, "value": m, "label": l} for p, m, l in models],
    }


@router.get("/llm/models")
async def refresh_llm_models(
    org_id: str | None = Query(None),
    refresh: bool = False,
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Refresh and return latest models from provider APIs."""
    org_uuid, _ = await _resolve_org_id(current_user, org_id, db)
    s = get_settings()
    provider, _, api_key = await get_llm_config(db, org_uuid)
    custom = await get_custom_models(db, org_uuid)
    openai_k = s.openai_api_key or (api_key if provider == "openai" else None)
    google_k = s.google_api_key or (api_key if provider == "google" else None)
    models = fetch_latest_models(
        openai_key=openai_k,
        google_key=google_k,
        custom_models=custom,
        force_refresh=refresh,
    )
    return {"llm_models": [{"provider": p, "value": m, "label": l} for p, m, l in models]}


class LlmSettingsUpdate(BaseModel):
    provider: str = "openai"
    model: str = "gpt-4o-mini"
    api_key: str | None = None


@router.put("/llm")
async def update_llm_settings(
    payload: LlmSettingsUpdate,
    org_id: str | None = Query(None),
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Update LLM config. Admin: auto-scoped to org. Super_admin: must select org."""
    org_uuid, _ = await _resolve_org_id(current_user, org_id, db)
    if not org_uuid:
        raise HTTPException(400, "Select an organization to configure.")
    if not is_valid_provider_model(payload.provider, payload.model):
        raise HTTPException(400, "Invalid provider or model.")
    await update_llm_config(db, payload.provider, payload.model, payload.api_key, org_uuid)
    await log_audit(db, "update_llm_settings", user_id=str(current_user.id), resource_type="settings", details={"provider": payload.provider, "model": payload.model, "org_id": str(org_uuid) if org_uuid else None})
    return {"ok": True}


class JiraSettingsUpdate(BaseModel):
    base_url: str = ""
    email: str = ""
    api_token: str = ""
    project_key: str = ""


@router.put("/jira")
async def update_jira_settings(
    payload: JiraSettingsUpdate,
    org_id: str | None = Query(None),
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Update JIRA config for organization. Admin: auto-scoped. Super_admin: per-org."""
    org_uuid, _ = await _resolve_org_id(current_user, org_id, db)
    if not org_uuid:
        raise HTTPException(400, "Organization required for JIRA config. Select an organization.")
    await update_jira_config(
        db,
        payload.base_url,
        payload.email,
        payload.api_token,
        payload.project_key,
        org_uuid,
    )
    await log_audit(db, "update_jira_settings", user_id=str(current_user.id), resource_type="settings", details={"org_id": str(org_uuid) if org_uuid else None})
    return {"ok": True}


class CustomModelAdd(BaseModel):
    provider: str
    model: str
    label: str = ""


@router.post("/llm/custom-model")
async def add_llm_custom_model(
    payload: CustomModelAdd,
    org_id: str | None = Query(None),
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Add a custom/future model. Org-scoped."""
    org_uuid, _ = await _resolve_org_id(current_user, org_id, db)
    if not is_valid_provider_model(payload.provider, payload.model):
        raise HTTPException(400, "Invalid provider or model.")
    await add_custom_model(db, payload.provider, payload.model, payload.label or payload.model, org_uuid)
    return {"ok": True}


@router.delete("/llm/custom-model")
async def delete_llm_custom_model(
    provider: str,
    model: str,
    org_id: str | None = Query(None),
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Remove a custom model."""
    org_uuid, _ = await _resolve_org_id(current_user, org_id, db)
    await remove_custom_model(db, provider, model, org_uuid)
    return {"ok": True}
