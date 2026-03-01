"""Admin settings API — integration status, LLM config (model, key)."""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.auth import require_admin
from app.core.database import get_db
from app.core.config import get_settings
from app.models.user import User
from app.services.admin_settings_service import get_llm_config, update_llm_config

router = APIRouter(prefix="/admin/settings", tags=["admin-settings"])


@router.get("")
async def get_settings_status(
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """
    Return integration status for admin. Never returns actual API keys.
    Includes LLM model from DB. Used by admin Settings page.
    """
    s = get_settings()
    model, api_key = await get_llm_config(db)
    return {
        "jira": {
            "configured": bool(s.jira_base_url and s.jira_email and s.jira_api_token and s.jira_project_key),
            "hint": "Set JIRA_BASE_URL, JIRA_EMAIL, JIRA_API_TOKEN, JIRA_PROJECT_KEY in backend/.env",
        },
        "ai": {
            "mode": "llm" if api_key else "rule_based",
            "model": model,
            "hint": "Configure model and API key below, or set OPENAI_API_KEY in backend/.env as fallback.",
        },
    }


class LlmSettingsUpdate(BaseModel):
    model: str = "gpt-4o-mini"
    api_key: str | None = None  # None = keep existing, "" = clear


@router.put("/llm")
async def update_llm_settings(
    payload: LlmSettingsUpdate,
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """
    Update LLM model and optionally API key.
    - model: one of gpt-4o-mini, gpt-4o, gpt-4-turbo, etc.
    - api_key: new key to save (omit/None = keep current, "" = clear)
    """
    valid_models = ["gpt-4o-mini", "gpt-4o", "gpt-4-turbo", "gpt-4", "gpt-3.5-turbo"]
    if payload.model not in valid_models:
        raise HTTPException(400, f"Model must be one of: {', '.join(valid_models)}")
    await update_llm_config(db, payload.model, payload.api_key)
    return {"ok": True}


@router.post("/llm/test")
async def test_llm_connection(
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Test the configured LLM API key by making a small API call."""
    model, api_key = await get_llm_config(db)
    if not api_key:
        return {"ok": False, "error": "No API key configured", "mode": "rule_based"}
    try:
        from openai import OpenAI
        client = OpenAI(api_key=api_key)
        response = client.chat.completions.create(
            model=model or "gpt-4o-mini",
            messages=[{"role": "user", "content": "Say 'ok' in one word."}],
            max_tokens=5,
            temperature=0,
        )
        text = (response.choices[0].message.content or "").strip()
        return {"ok": True, "model": model, "response": text, "mode": "llm"}
    except Exception as e:
        return {"ok": False, "error": str(e), "model": model, "mode": "llm"}


@router.post("/jira/test")
async def test_jira_connection(
    current_user: User = Depends(require_admin),
):
    """Test the configured JIRA connection."""
    s = get_settings()
    if not (s.jira_base_url and s.jira_email and s.jira_api_token):
        return {"ok": False, "error": "JIRA not configured. Set env variables."}
    try:
        import httpx
        base = s.jira_base_url.rstrip("/")
        with httpx.Client(timeout=10) as client:
            r = client.get(
                f"{base}/rest/api/3/myself",
                auth=(s.jira_email, s.jira_api_token),
            )
            if r.status_code == 200:
                data = r.json()
                return {"ok": True, "user": data.get("displayName", "Unknown"), "email": data.get("emailAddress", "")}
            else:
                return {"ok": False, "error": f"JIRA returned {r.status_code}: {r.text[:200]}"}
    except Exception as e:
        return {"ok": False, "error": str(e)}
