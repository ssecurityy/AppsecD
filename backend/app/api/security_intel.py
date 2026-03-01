"""Security Intelligence API — CVE feeds, LLM-generated test cases, dashboard aggregations."""
import json
import logging
from datetime import datetime, timedelta
from typing import Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.auth import get_current_user, require_admin
from app.core.database import get_db
from app.models.finding import Finding
from app.models.project import Project
from app.models.user import User
from app.services.org_settings_service import get_llm_config

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/security-intel", tags=["security-intel"])

NVD_CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


# ---------------------------------------------------------------------------
# Request / Response schemas
# ---------------------------------------------------------------------------

class GenerateTestCasesRequest(BaseModel):
    app_type: str = ""  # e.g., "web application", "REST API", "mobile app"
    tech_stack: list[str] = []  # e.g., ["React", "Node.js", "PostgreSQL"]
    recent_cves: list[str] = []  # e.g., ["CVE-2024-1234"]
    focus_areas: list[str] = []  # e.g., ["authentication", "file upload"]
    context: str = ""  # Additional freeform context
    project_id: str | None = None  # For org-scoped LLM config


# ---------------------------------------------------------------------------
# LLM prompt for test case generation
# ---------------------------------------------------------------------------

GENERATE_TEST_CASES_PROMPT = """You are a senior application security engineer. Based on the following context, generate a comprehensive list of security test cases.

Application Type: {app_type}
Technology Stack: {tech_stack}
Recent/Relevant CVEs to consider: {recent_cves}
Focus Areas: {focus_areas}
Additional Context: {context}

Generate 10-15 detailed security test cases. For each test case include:
- A clear title
- OWASP category (e.g., A01:2021-Broken Access Control)
- Severity (critical, high, medium, low, info)
- Step-by-step testing procedure
- Expected result if vulnerable
- Recommended remediation

Respond in JSON only, no markdown fences:
{{"test_cases": [{{"title": "...", "owasp_category": "...", "severity": "...", "procedure": "...", "expected_result": "...", "remediation": "..."}}]}}"""


def _parse_test_cases_json(text: str) -> list[dict]:
    """Parse LLM response into test cases list."""
    text = (text or "").strip()
    if text.startswith("```"):
        text = text.split("```")[1]
        if text.startswith("json"):
            text = text[4:]
    data = json.loads(text)
    cases = data.get("test_cases", [])
    result = []
    for c in cases:
        result.append({
            "title": c.get("title", ""),
            "owasp_category": c.get("owasp_category", ""),
            "severity": c.get("severity", "medium"),
            "procedure": c.get("procedure", ""),
            "expected_result": c.get("expected_result", ""),
            "remediation": c.get("remediation", ""),
        })
    return result


def _call_llm_for_test_cases(provider: str, model: str, api_key: str, prompt: str) -> list[dict] | None:
    """Call LLM to generate test cases. Returns list of test case dicts or None on failure."""
    try:
        if provider == "openai":
            from openai import OpenAI
            client = OpenAI(api_key=api_key)
            r = client.chat.completions.create(
                model=model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.5,
            )
            text = (r.choices[0].message.content or "").strip()
            return _parse_test_cases_json(text)
        elif provider == "anthropic":
            from anthropic import Anthropic
            client = Anthropic(api_key=api_key)
            r = client.messages.create(
                model=model,
                max_tokens=4096,
                messages=[{"role": "user", "content": prompt}],
            )
            text = (r.content[0].text if r.content else "").strip()
            return _parse_test_cases_json(text)
        elif provider == "google":
            import google.generativeai as genai
            genai.configure(api_key=api_key)
            m = genai.GenerativeModel(model)
            r = m.generate_content(prompt)
            text = (r.text or "").strip()
            return _parse_test_cases_json(text)
    except Exception as e:
        logger.warning("LLM test case generation failed: %s", e)
    return None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/generate-test-cases")
async def generate_test_cases(
    payload: GenerateTestCasesRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Use LLM to generate security test cases for a given app context."""
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

    if not api_key or not model:
        raise HTTPException(
            400,
            "No LLM configured. Please configure an LLM provider in admin settings to use AI-powered test case generation.",
        )

    prompt = GENERATE_TEST_CASES_PROMPT.format(
        app_type=payload.app_type or "(not specified)",
        tech_stack=", ".join(payload.tech_stack) if payload.tech_stack else "(not specified)",
        recent_cves=", ".join(payload.recent_cves) if payload.recent_cves else "(none specified)",
        focus_areas=", ".join(payload.focus_areas) if payload.focus_areas else "(general security assessment)",
        context=payload.context or "(none)",
    )

    result = _call_llm_for_test_cases(provider, model, api_key, prompt)
    if result:
        return {
            "test_cases": result,
            "count": len(result),
            "source": "llm",
            "provider": provider,
            "model": model,
        }

    raise HTTPException(500, "LLM call failed. Please try again or check your LLM configuration.")


@router.get("/cve-feed")
async def get_cve_feed(
    results_per_page: int = Query(default=20, ge=1, le=100),
    keyword: str = Query(default="", description="Optional keyword to filter CVEs"),
    current_user: User = Depends(get_current_user),
):
    """Fetch recent CVEs from NVD API and return them formatted."""
    params = {
        "resultsPerPage": results_per_page,
    }
    if keyword:
        params["keywordSearch"] = keyword

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(NVD_CVE_API_URL, params=params)
            response.raise_for_status()
            data = response.json()
    except httpx.TimeoutException:
        raise HTTPException(504, "NVD API request timed out. Please try again later.")
    except httpx.HTTPStatusError as e:
        raise HTTPException(502, f"NVD API returned error: {e.response.status_code}")
    except Exception as e:
        logger.warning("NVD API call failed: %s", e)
        raise HTTPException(502, "Failed to fetch CVE data from NVD API.")

    # Parse and format CVE data
    vulnerabilities = data.get("vulnerabilities", [])
    formatted_cves = []
    for vuln in vulnerabilities:
        cve = vuln.get("cve", {})
        cve_id = cve.get("id", "")
        descriptions = cve.get("descriptions", [])
        description = ""
        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break
        if not description and descriptions:
            description = descriptions[0].get("value", "")

        # Extract CVSS scores
        metrics = cve.get("metrics", {})
        cvss_score = None
        cvss_severity = None
        # Try CVSS v3.1 first, then v3.0, then v2.0
        for version_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            metric_list = metrics.get(version_key, [])
            if metric_list:
                cvss_data = metric_list[0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                cvss_severity = cvss_data.get("baseSeverity", "").lower()
                break

        # Extract references
        references = []
        for ref in cve.get("references", [])[:5]:  # Limit to 5 references
            references.append({
                "url": ref.get("url", ""),
                "source": ref.get("source", ""),
            })

        # Extract CWE weaknesses
        weaknesses = cve.get("weaknesses", [])
        cwes = []
        for w in weaknesses:
            for wd in w.get("description", []):
                cwe_val = wd.get("value", "")
                if cwe_val and cwe_val != "NVD-CWE-noinfo" and cwe_val != "NVD-CWE-Other":
                    cwes.append(cwe_val)

        published = cve.get("published", "")
        last_modified = cve.get("lastModified", "")

        formatted_cves.append({
            "cve_id": cve_id,
            "description": description,
            "cvss_score": cvss_score,
            "severity": cvss_severity,
            "cwes": cwes,
            "references": references,
            "published": published,
            "last_modified": last_modified,
        })

    return {
        "cves": formatted_cves,
        "total_results": data.get("totalResults", 0),
        "results_per_page": data.get("resultsPerPage", results_per_page),
    }


@router.get("/dashboard")
async def get_security_dashboard(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Aggregate security intelligence dashboard: findings by severity, recent CVEs, trends."""
    org_id = getattr(current_user, "organization_id", None)

    # --- Findings by severity across all accessible projects ---
    severity_query = select(
        Finding.severity,
        func.count(Finding.id).label("count"),
    )
    if current_user.role == "super_admin":
        # Super admin sees all findings
        pass
    elif org_id:
        # Filter findings to projects in the user's organization
        severity_query = severity_query.join(
            Project, Finding.project_id == Project.id
        ).where(Project.organization_id == org_id)
    else:
        # No org — show nothing
        severity_query = severity_query.where(False)

    severity_query = severity_query.group_by(Finding.severity)
    severity_result = await db.execute(severity_query)
    findings_by_severity = {row.severity: row.count for row in severity_result}

    # Ensure all severities are present
    for sev in ("critical", "high", "medium", "low", "info"):
        findings_by_severity.setdefault(sev, 0)

    total_findings = sum(findings_by_severity.values())

    # --- Findings by status ---
    status_query = select(
        Finding.status,
        func.count(Finding.id).label("count"),
    )
    if current_user.role == "super_admin":
        pass
    elif org_id:
        status_query = status_query.join(
            Project, Finding.project_id == Project.id
        ).where(Project.organization_id == org_id)
    else:
        status_query = status_query.where(False)

    status_query = status_query.group_by(Finding.status)
    status_result = await db.execute(status_query)
    findings_by_status = {row.status: row.count for row in status_result}

    # --- Vulnerability trends (findings created in the last 30 days, grouped by week) ---
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    trend_query = select(
        func.date_trunc("week", Finding.created_at).label("week"),
        Finding.severity,
        func.count(Finding.id).label("count"),
    ).where(Finding.created_at >= thirty_days_ago)

    if current_user.role == "super_admin":
        pass
    elif org_id:
        trend_query = trend_query.join(
            Project, Finding.project_id == Project.id
        ).where(Project.organization_id == org_id)
    else:
        trend_query = trend_query.where(False)

    trend_query = trend_query.group_by("week", Finding.severity).order_by("week")
    trend_result = await db.execute(trend_query)
    trends = []
    for row in trend_result:
        trends.append({
            "week": row.week.isoformat() if row.week else "",
            "severity": row.severity,
            "count": row.count,
        })

    # --- Project summary ---
    project_count_query = select(func.count(Project.id))
    if current_user.role == "super_admin":
        pass
    elif org_id:
        project_count_query = project_count_query.where(Project.organization_id == org_id)
    else:
        project_count_query = project_count_query.where(False)

    project_count_result = await db.execute(project_count_query)
    total_projects = project_count_result.scalar() or 0

    # --- Fetch recent CVEs (lightweight call, limited to 10) ---
    recent_cves = []
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.get(NVD_CVE_API_URL, params={"resultsPerPage": 10})
            if response.status_code == 200:
                cve_data = response.json()
                for vuln in cve_data.get("vulnerabilities", [])[:10]:
                    cve = vuln.get("cve", {})
                    cve_id = cve.get("id", "")
                    descriptions = cve.get("descriptions", [])
                    description = ""
                    for desc in descriptions:
                        if desc.get("lang") == "en":
                            description = desc.get("value", "")
                            break
                    if not description and descriptions:
                        description = descriptions[0].get("value", "")

                    metrics = cve.get("metrics", {})
                    cvss_score = None
                    cvss_severity = None
                    for version_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                        metric_list = metrics.get(version_key, [])
                        if metric_list:
                            cvss_data = metric_list[0].get("cvssData", {})
                            cvss_score = cvss_data.get("baseScore")
                            cvss_severity = cvss_data.get("baseSeverity", "").lower()
                            break

                    recent_cves.append({
                        "cve_id": cve_id,
                        "description": description[:200] + ("..." if len(description) > 200 else ""),
                        "cvss_score": cvss_score,
                        "severity": cvss_severity,
                        "published": cve.get("published", ""),
                    })
    except Exception as e:
        logger.warning("Failed to fetch recent CVEs for dashboard: %s", e)
        # Non-fatal — dashboard still returns other data

    return {
        "findings_by_severity": findings_by_severity,
        "findings_by_status": findings_by_status,
        "total_findings": total_findings,
        "total_projects": total_projects,
        "vulnerability_trends": trends,
        "recent_cves": recent_cves,
    }
