"""Admin settings API — integration status, no sensitive data."""
from fastapi import APIRouter, Depends
from app.api.auth import get_current_user, require_admin
from app.models.user import User
from app.core.config import get_settings

router = APIRouter(prefix="/admin/settings", tags=["admin-settings"])


@router.get("")
async def get_settings_status(
    current_user: User = Depends(require_admin),
):
    """
    Return integration status for admin. Never returns actual API keys.
    Used by admin Settings page to show what's configured.
    """
    s = get_settings()
    return {
        "jira": {
            "configured": bool(s.jira_base_url and s.jira_email and s.jira_api_token and s.jira_project_key),
            "hint": "Set JIRA_BASE_URL, JIRA_EMAIL, JIRA_API_TOKEN, JIRA_PROJECT_KEY in backend/.env",
        },
        "ai": {
            "mode": "llm" if s.openai_api_key else "rule_based",
            "hint": "Set OPENAI_API_KEY in backend/.env for LLM-powered suggestions (OpenAI). Without it, rule-based mode works.",
        },
    }
