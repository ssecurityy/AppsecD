"""AI Assist API — suggest CWE, CVSS, impact, remediation for findings."""
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from app.api.auth import get_current_user
from app.services.ai_assist_service import suggest_finding

router = APIRouter(prefix="/ai-assist", tags=["ai-assist"])


class SuggestRequest(BaseModel):
    title: str
    description: str = ""
    severity: str = "medium"


@router.post("/suggest")
async def suggest(
    payload: SuggestRequest,
    current_user=Depends(get_current_user),
):
    """Get AI-assisted suggestions for a finding (CWE, CVSS, impact, remediation)."""
    return suggest_finding(payload.title, payload.description, payload.severity)
