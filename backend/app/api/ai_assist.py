"""AI Assist API — suggest CWE, CVSS, impact, remediation for findings; craft payloads."""
import json
import logging
from fastapi import APIRouter, Depends, HTTPException
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

    from app.api.security_intel import check_feature_enabled
    if not await check_feature_enabled(db, org_id, "ai_finding_suggest"):
        raise HTTPException(403, "AI Finding Suggestions is disabled for your organization. Contact your admin to enable it.")

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

    from app.api.security_intel import check_feature_enabled
    if not await check_feature_enabled(db, org_id, "ai_payload_crafting"):
        raise HTTPException(403, "AI Payload Crafting is disabled for your organization. Contact your admin to enable it.")

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


# ─── Helper: resolve org_id from project or user ───

async def _resolve_org_id(project_id: str | None, current_user, db: AsyncSession) -> str | None:
    """Resolve organization ID from project or user."""
    org_id = None
    if project_id:
        proj = await db.execute(select(Project).where(Project.id == project_id))
        p = proj.scalar_one_or_none()
        if p and p.organization_id:
            org_id = p.organization_id
    if not org_id and current_user.organization_id:
        org_id = current_user.organization_id
    return org_id


# ─── Request Models for LLM-enhanced endpoints ───

class AnalyzeEndpointRequest(BaseModel):
    endpoint: str
    method: str = "GET"
    parameters: str = ""
    request_sample: str = ""
    response_sample: str = ""
    framework: str = ""
    project_id: str | None = None

class GenerateSimilarTestsRequest(BaseModel):
    existing_test: dict
    target_context: str
    project_id: str | None = None

class MissingTestsRequest(BaseModel):
    project_id: str

class FrameworkTestsRequest(BaseModel):
    framework: str
    version: str = ""
    features: list[str] = []
    project_id: str | None = None

class EnrichRemediationRequest(BaseModel):
    finding_title: str
    finding_description: str = ""
    current_remediation: str = ""
    app_framework: str = ""
    app_language: str = ""
    project_id: str | None = None

class DeduplicateFindingsRequest(BaseModel):
    project_id: str

class QueryFindingsRequest(BaseModel):
    query: str
    project_id: str | None = None

class VulnerabilityTrendsRequest(BaseModel):
    project_ids: list[str] | None = None

class CvePayloadsRequest(BaseModel):
    cve_id: str
    cve_description: str = ""
    affected_product: str = ""
    project_id: str | None = None

class GenerateCommandsRequest(BaseModel):
    test_title: str
    test_description: str = ""
    target_url: str = ""
    parameters: str = ""
    vuln_type: str = ""
    project_id: str | None = None

class InterpretResultsRequest(BaseModel):
    tool_name: str
    raw_output: str
    test_context: str = ""
    project_id: str | None = None

class FullReportSummaryRequest(BaseModel):
    project_id: str


# ─── 1. Analyze Endpoint ───

@router.post("/analyze-endpoint")
async def analyze_endpoint_api(
    payload: AnalyzeEndpointRequest,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Analyze an endpoint for potential vulnerabilities."""
    from app.services.llm_enhanced_service import analyze_endpoint
    org_id = await _resolve_org_id(payload.project_id, current_user, db)
    from app.api.security_intel import check_feature_enabled
    if not await check_feature_enabled(db, org_id, "ai_finding_suggest"):
        raise HTTPException(403, "AI features are disabled for your organization.")
    provider, model, api_key = await get_llm_config(db, org_id)
    return analyze_endpoint(
        payload.endpoint, payload.method, payload.parameters,
        payload.request_sample, payload.response_sample, payload.framework,
        provider=provider or "", model=model or "", api_key=api_key or "",
    )


# ─── 2. Generate Similar Tests ───

@router.post("/generate-similar-tests")
async def generate_similar_tests_api(
    payload: GenerateSimilarTestsRequest,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Generate similar test cases from an existing one."""
    from app.services.llm_enhanced_service import generate_similar_tests
    org_id = await _resolve_org_id(payload.project_id, current_user, db)
    from app.api.security_intel import check_feature_enabled
    if not await check_feature_enabled(db, org_id, "ai_finding_suggest"):
        raise HTTPException(403, "AI features are disabled for your organization.")
    provider, model, api_key = await get_llm_config(db, org_id)
    return {
        "test_cases": generate_similar_tests(
            payload.existing_test, payload.target_context,
            provider=provider or "", model=model or "", api_key=api_key or "",
        )
    }


# ─── 3. Missing Tests ───

@router.post("/missing-tests")
async def missing_tests_api(
    payload: MissingTestsRequest,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Suggest tests that are missing from the current scope."""
    from app.services.llm_enhanced_service import suggest_missing_tests
    from app.models.result import ProjectTestResult
    import uuid
    org_id = await _resolve_org_id(payload.project_id, current_user, db)
    from app.api.security_intel import check_feature_enabled
    if not await check_feature_enabled(db, org_id, "ai_finding_suggest"):
        raise HTTPException(403, "AI features are disabled for your organization.")
    provider, model, api_key = await get_llm_config(db, org_id)
    proj = await db.execute(select(Project).where(Project.id == uuid.UUID(payload.project_id)))
    project = proj.scalar_one_or_none()
    if not project:
        raise HTTPException(404, "Project not found")
    results = await db.execute(select(ProjectTestResult).where(ProjectTestResult.project_id == uuid.UUID(payload.project_id)))
    tested_phases = list(set())
    return suggest_missing_tests(
        project.stack_profile or {}, tested_phases, project.tested_count or 0, project.total_test_cases or 0,
        provider=provider or "", model=model or "", api_key=api_key or "",
    )


# ─── 4. Framework Tests ───

@router.post("/framework-tests")
async def framework_tests_api(
    payload: FrameworkTestsRequest,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Generate framework-specific security tests."""
    from app.services.llm_enhanced_service import generate_framework_tests
    org_id = await _resolve_org_id(payload.project_id, current_user, db)
    from app.api.security_intel import check_feature_enabled
    if not await check_feature_enabled(db, org_id, "ai_finding_suggest"):
        raise HTTPException(403, "AI features are disabled for your organization.")
    provider, model, api_key = await get_llm_config(db, org_id)
    return {
        "test_cases": generate_framework_tests(
            payload.framework, payload.version, payload.features,
            provider=provider or "", model=model or "", api_key=api_key or "",
        )
    }


# ─── 5. Enrich Remediation ───

@router.post("/enrich-remediation")
async def enrich_remediation_api(
    payload: EnrichRemediationRequest,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Enrich remediation with app-specific, actionable guidance."""
    from app.services.llm_enhanced_service import enrich_remediation
    org_id = await _resolve_org_id(payload.project_id, current_user, db)
    from app.api.security_intel import check_feature_enabled
    if not await check_feature_enabled(db, org_id, "ai_finding_suggest"):
        raise HTTPException(403, "AI features are disabled for your organization.")
    provider, model, api_key = await get_llm_config(db, org_id)
    return enrich_remediation(
        payload.finding_title, payload.finding_description, payload.current_remediation,
        payload.app_framework, payload.app_language,
        provider=provider or "", model=model or "", api_key=api_key or "",
    )


# ─── 6. Deduplicate Findings ───

@router.post("/deduplicate-findings")
async def deduplicate_findings_api(
    payload: DeduplicateFindingsRequest,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Analyze findings for duplicates and suggest merges."""
    from app.services.llm_enhanced_service import deduplicate_findings
    from app.models.finding import Finding
    import uuid
    org_id = await _resolve_org_id(payload.project_id, current_user, db)
    from app.api.security_intel import check_feature_enabled
    if not await check_feature_enabled(db, org_id, "ai_finding_suggest"):
        raise HTTPException(403, "AI features are disabled for your organization.")
    provider, model, api_key = await get_llm_config(db, org_id)
    result = await db.execute(select(Finding).where(Finding.project_id == uuid.UUID(payload.project_id)))
    findings = [{"title": f.title, "severity": f.severity, "cwe_id": f.cwe_id, "affected_url": f.affected_url, "description": f.description} for f in result.scalars().all()]
    return deduplicate_findings(findings, provider=provider or "", model=model or "", api_key=api_key or "")


# ─── 7. Query Findings (Natural Language) ───

@router.post("/query-findings")
async def query_findings_api(
    payload: QueryFindingsRequest,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Convert natural language to structured finding filters."""
    from app.services.llm_enhanced_service import query_findings_nl
    org_id = await _resolve_org_id(payload.project_id, current_user, db)
    from app.api.security_intel import check_feature_enabled
    if not await check_feature_enabled(db, org_id, "ai_finding_suggest"):
        raise HTTPException(403, "AI features are disabled for your organization.")
    provider, model, api_key = await get_llm_config(db, org_id)
    return query_findings_nl(
        payload.query,
        available_severities=["critical", "high", "medium", "low", "info"],
        available_statuses=["open", "confirmed", "mitigated", "fixed", "accepted_risk", "fp"],
        available_cwes=[],
        provider=provider or "", model=model or "", api_key=api_key or "",
    )


# ─── 8. Vulnerability Trends ───

@router.post("/vulnerability-trends")
async def vulnerability_trends_api(
    payload: VulnerabilityTrendsRequest,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Analyze vulnerability trends across projects."""
    from app.services.llm_enhanced_service import analyze_vulnerability_trends
    from app.models.finding import Finding
    org_id = current_user.organization_id
    provider, model, api_key = await get_llm_config(db, org_id)
    projects = await db.execute(select(Project))
    projects_data = []
    for p in projects.scalars().all():
        findings = await db.execute(select(Finding).where(Finding.project_id == p.id))
        all_f = findings.scalars().all()
        projects_data.append({
            "name": p.application_name,
            "finding_count": len(all_f),
            "critical": sum(1 for f in all_f if (f.severity or "").lower() == "critical"),
            "high": sum(1 for f in all_f if (f.severity or "").lower() == "high"),
            "top_cwes": list(set(f.cwe_id for f in all_f if f.cwe_id))[:5],
        })
    return analyze_vulnerability_trends(projects_data, provider=provider or "", model=model or "", api_key=api_key or "")


# ─── 9. CVE Payloads ───

@router.post("/cve-payloads")
async def cve_payloads_api(
    payload: CvePayloadsRequest,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Generate proof-of-concept payloads from a CVE."""
    from app.services.llm_enhanced_service import generate_cve_payloads
    org_id = await _resolve_org_id(payload.project_id, current_user, db)
    from app.api.security_intel import check_feature_enabled
    if not await check_feature_enabled(db, org_id, "ai_finding_suggest"):
        raise HTTPException(403, "AI features are disabled for your organization.")
    provider, model, api_key = await get_llm_config(db, org_id)
    return generate_cve_payloads(
        payload.cve_id, payload.cve_description, payload.affected_product,
        provider=provider or "", model=model or "", api_key=api_key or "",
    )


# ─── 10. Generate Tool Commands ───

@router.post("/generate-commands")
async def generate_commands_api(
    payload: GenerateCommandsRequest,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Generate ready-to-run tool commands for a test case."""
    from app.services.llm_enhanced_service import generate_tool_commands
    org_id = await _resolve_org_id(payload.project_id, current_user, db)
    from app.api.security_intel import check_feature_enabled
    if not await check_feature_enabled(db, org_id, "ai_finding_suggest"):
        raise HTTPException(403, "AI features are disabled for your organization.")
    provider, model, api_key = await get_llm_config(db, org_id)
    return generate_tool_commands(
        payload.test_title, payload.test_description, payload.target_url,
        payload.parameters, payload.vuln_type,
        provider=provider or "", model=model or "", api_key=api_key or "",
    )


# ─── 11. Interpret Tool Results ───

@router.post("/interpret-results")
async def interpret_results_api(
    payload: InterpretResultsRequest,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Interpret tool output and suggest pass/fail + finding."""
    from app.services.llm_enhanced_service import interpret_tool_results
    org_id = await _resolve_org_id(payload.project_id, current_user, db)
    from app.api.security_intel import check_feature_enabled
    if not await check_feature_enabled(db, org_id, "ai_finding_suggest"):
        raise HTTPException(403, "AI features are disabled for your organization.")
    provider, model, api_key = await get_llm_config(db, org_id)
    return interpret_tool_results(
        payload.tool_name, payload.raw_output, payload.test_context,
        provider=provider or "", model=model or "", api_key=api_key or "",
    )


# ─── 12. Full Report Summary ───

@router.post("/full-report-summary")
async def full_report_summary_api(
    payload: FullReportSummaryRequest,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Generate a comprehensive report narrative."""
    from app.services.llm_enhanced_service import summarize_full_report
    from app.models.finding import Finding
    from app.models.result import ProjectTestResult
    import uuid
    org_id = await _resolve_org_id(payload.project_id, current_user, db)
    from app.api.security_intel import check_feature_enabled
    if not await check_feature_enabled(db, org_id, "ai_finding_suggest"):
        raise HTTPException(403, "AI features are disabled for your organization.")
    provider, model, api_key = await get_llm_config(db, org_id)
    proj = await db.execute(select(Project).where(Project.id == uuid.UUID(payload.project_id)))
    project = proj.scalar_one_or_none()
    if not project:
        raise HTTPException(404, "Project not found")
    findings_result = await db.execute(select(Finding).where(Finding.project_id == uuid.UUID(payload.project_id)))
    findings = [{"title": f.title, "severity": f.severity, "description": f.description, "cwe_id": f.cwe_id} for f in findings_result.scalars().all()]
    project_dict = {
        "application_name": project.application_name,
        "application_url": project.application_url,
        "testing_type": project.testing_type,
        "environment": project.environment,
    }
    return summarize_full_report(
        project_dict, findings, [],
        provider=provider or "", model=model or "", api_key=api_key or "",
    )
