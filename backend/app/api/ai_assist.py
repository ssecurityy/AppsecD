"""AI Assist API — suggest CWE, CVSS, impact, remediation for findings; craft payloads."""
import json
import logging
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.api.auth import get_current_user
from app.core.database import get_db
from app.services.ai_assist_service import suggest_finding
from app.services.org_settings_service import get_llm_config
from app.models.project import Project

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ai-assist", tags=["ai-assist"])


class SuggestRequest(BaseModel):
    title: str
    description: str = ""
    severity: str = "medium"
    project_id: str | None = None  # For org-scoped LLM config


class CraftPayloadRequest(BaseModel):
    test_title: str
    test_description: str = ""
    existing_payloads: list[str] = []
    target_url: str | None = None
    context: str | None = None
    project_id: str | None = None  # For org-scoped LLM config


CRAFT_PAYLOAD_PROMPT = """You are an expert penetration tester and security researcher. Analyze the following test case and existing payloads, then generate 5 enhanced, obfuscated, and context-aware payloads.

Test Case Title: {test_title}
Test Case Description: {test_description}
Target URL: {target_url}
Context: {context}

Existing Payloads:
{existing_payloads}

Your task:
1. Analyze the test case context and understand what vulnerability type is being tested
2. Generate 5 enhanced/obfuscated versions of the provided payloads (or new ones if none provided)
3. Include WAF bypass techniques (e.g., encoding, case variation, comment injection, chunked encoding)
4. Include encoding variations (URL encoding, double encoding, Unicode, HTML entities, Base64)
5. Include latest techniques relevant to the vulnerability type
6. Each payload should be distinct and target different bypass scenarios

Respond in JSON only, no markdown fences:
{{"payloads": [{{"payload": "the actual payload string", "technique": "short technique name (e.g. Double URL Encoding, Unicode Bypass)", "description": "brief explanation of why this payload works and what it bypasses"}}]}}"""


def _parse_payload_json(text: str) -> list[dict]:
    """Parse LLM response into payload list."""
    text = (text or "").strip()
    if text.startswith("```"):
        text = text.split("```")[1]
        if text.startswith("json"):
            text = text[4:]
    data = json.loads(text)
    payloads = data.get("payloads", [])
    result = []
    for p in payloads:
        result.append({
            "payload": p.get("payload", ""),
            "technique": p.get("technique", ""),
            "description": p.get("description", ""),
        })
    return result


def _call_llm_for_payloads(provider: str, model: str, api_key: str, prompt: str) -> list[dict] | None:
    """Call LLM to craft payloads. Returns list of payload dicts or None on failure."""
    try:
        if provider == "openai":
            from openai import OpenAI
            client = OpenAI(api_key=api_key)
            r = client.chat.completions.create(
                model=model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.7,
            )
            text = (r.choices[0].message.content or "").strip()
            return _parse_payload_json(text)
        elif provider == "anthropic":
            from anthropic import Anthropic
            client = Anthropic(api_key=api_key)
            r = client.messages.create(
                model=model,
                max_tokens=2048,
                messages=[{"role": "user", "content": prompt}],
            )
            text = (r.content[0].text if r.content else "").strip()
            return _parse_payload_json(text)
        elif provider == "google":
            import google.generativeai as genai
            genai.configure(api_key=api_key)
            m = genai.GenerativeModel(model)
            r = m.generate_content(prompt)
            text = (r.text or "").strip()
            return _parse_payload_json(text)
    except Exception as e:
        logger.warning("LLM payload crafting failed: %s", e)
    return None


def _fallback_payloads(existing_payloads: list[str]) -> list[dict]:
    """Return original payloads as fallback when no LLM is configured."""
    if not existing_payloads:
        return [{"payload": "", "technique": "none", "description": "No LLM configured and no existing payloads provided."}]
    return [
        {
            "payload": p,
            "technique": "original",
            "description": "Original payload (no LLM configured for enhancement).",
        }
        for p in existing_payloads
    ]


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


@router.post("/craft-payload")
async def craft_payload(
    payload: CraftPayloadRequest,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Use LLM to craft enhanced, obfuscated, context-aware payloads based on existing ones."""
    # Resolve org-scoped LLM config
    org_id = None
    if payload.project_id:
        proj = await db.execute(select(Project).where(Project.id == payload.project_id))
        p = proj.scalar_one_or_none()
        if p and p.organization_id:
            org_id = p.organization_id
    if not org_id and current_user.organization_id:
        org_id = current_user.organization_id

    provider, model, api_key = await get_llm_config(db, org_id)

    # Fallback if no LLM configured
    if not api_key or not model:
        return {
            "payloads": _fallback_payloads(payload.existing_payloads),
            "source": "fallback",
            "message": "No LLM configured. Returning original payloads.",
        }

    # Build prompt
    existing_str = "\n".join(f"  - {p}" for p in payload.existing_payloads) if payload.existing_payloads else "  (none provided)"
    prompt = CRAFT_PAYLOAD_PROMPT.format(
        test_title=payload.test_title,
        test_description=payload.test_description or "(not provided)",
        target_url=payload.target_url or "(not provided)",
        context=payload.context or "(not provided)",
        existing_payloads=existing_str,
    )

    result = _call_llm_for_payloads(provider, model, api_key, prompt)
    if result:
        return {
            "payloads": result,
            "source": "llm",
            "provider": provider,
            "model": model,
        }

    # LLM call failed — return fallback
    return {
        "payloads": _fallback_payloads(payload.existing_payloads),
        "source": "fallback",
        "message": "LLM call failed. Returning original payloads.",
    }
