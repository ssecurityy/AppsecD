"""AI Assist API — suggest CWE, CVSS, impact, remediation for findings."""
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from app.api.auth import get_current_user
from app.core.database import get_db
from app.services.ai_assist_service import suggest_finding
from app.services.admin_settings_service import get_llm_config

router = APIRouter(prefix="/ai-assist", tags=["ai-assist"])


class SuggestRequest(BaseModel):
    title: str
    description: str = ""
    severity: str = "medium"


@router.post("/suggest")
async def suggest(
    payload: SuggestRequest,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get AI-assisted suggestions for a finding (CWE, CVSS, impact, remediation)."""
    model, api_key = await get_llm_config(db)
    return suggest_finding(
        payload.title,
        payload.description,
        payload.severity,
        model=model,
        api_key=api_key,
    )
