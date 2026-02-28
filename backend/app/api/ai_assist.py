"""AI Assist API — suggest CWE, CVSS, impact, remediation for findings."""
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.api.auth import get_current_user
from app.core.database import get_db
from app.services.ai_assist_service import suggest_finding
from app.services.org_settings_service import get_llm_config
from app.models.project import Project

router = APIRouter(prefix="/ai-assist", tags=["ai-assist"])


class SuggestRequest(BaseModel):
    title: str
    description: str = ""
    severity: str = "medium"
    project_id: str | None = None  # For org-scoped LLM config


@router.post("/suggest")
async def suggest(
    payload: SuggestRequest,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get AI-assisted suggestions for a finding (CWE, CVSS, impact, remediation)."""
    org_id = None
    if payload.project_id:
        proj = await db.execute(select(Project).where(Project.id == payload.project_id))
        p = proj.scalar_one_or_none()
        if p and p.organization_id:
            org_id = p.organization_id
    if not org_id and current_user.organization_id:
        org_id = current_user.organization_id
    provider, model, api_key = await get_llm_config(db, org_id)
    return suggest_finding(
        payload.title,
        payload.description,
        payload.severity,
        provider=provider,
        model=model,
        api_key=api_key,
    )
