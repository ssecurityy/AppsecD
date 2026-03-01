"""Security Intelligence API — CVE feeds (multi-source), LLM test cases, assistant with history, dashboard."""
import json
import logging
from datetime import datetime, timedelta
from typing import Optional
from uuid import UUID

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select, func, or_, desc, and_, String
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.api.auth import get_current_user, require_admin
from app.core.database import get_db
from app.models.finding import Finding
from app.models.project import Project
from app.models.test_case import TestCase
from app.models.category import Category
from app.models.result import ProjectTestResult
from app.models.stored_cve import StoredCVE
from app.models.org_feature_flag import OrgFeatureFlag
from app.models.user import User
from app.services.org_settings_service import get_llm_config

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/security-intel", tags=["security-intel"])

NVD_CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
GITHUB_ADVISORY_API = "https://api.github.com/advisories"
CIRCL_CVE_API = "https://cve.circl.lu/api"
NIST_CVE_SEARCH = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Feature flag keys for AI features
AI_FEATURES = {
    "ai_test_generation": "AI Test Case Generation",
    "ai_payload_crafting": "AI Payload Crafting",
    "ai_finding_suggest": "AI Finding Suggestions",
    "ai_report_summary": "AI Report Summary",
    "ai_security_assistant": "AI Security Assistant",
    "ai_remediation_enrichment": "AI Remediation Enrichment",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def check_feature_enabled(db: AsyncSession, org_id: Optional[UUID], feature_key: str) -> bool:
    """Check if a feature is enabled for an org. Returns True if no org or no flag set (default enabled)."""
    if not org_id:
        return True
    result = await db.execute(
        select(OrgFeatureFlag).where(
            OrgFeatureFlag.organization_id == org_id,
            OrgFeatureFlag.feature_key == feature_key,
        )
    )
    flag = result.scalar_one_or_none()
    if flag is None:
        return True  # Default: enabled
    return flag.enabled


def _parse_nvd_cve(vuln: dict) -> dict:
    """Parse a single NVD vulnerability entry into our storage format."""
    cve = vuln.get("cve", {})
    cve_id = cve.get("id", "")
    descriptions = cve.get("descriptions", [])
    description = ""
    for d in descriptions:
        if d.get("lang") == "en":
            description = d.get("value", "")
            break
    if not description and descriptions:
        description = descriptions[0].get("value", "")

    metrics = cve.get("metrics", {})
    cvss_score = None
    cvss_severity = None
    for vk in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        ml = metrics.get(vk, [])
        if ml:
            cd = ml[0].get("cvssData", {})
            cvss_score = cd.get("baseScore")
            cvss_severity = cd.get("baseSeverity", "").lower()
            break

    refs = []
    for ref in cve.get("references", []):
        refs.append({
            "url": ref.get("url", ""),
            "source": ref.get("source", ""),
            "tags": ref.get("tags", []),
        })

    cwes = []
    for w in cve.get("weaknesses", []):
        for wd in w.get("description", []):
            cv = wd.get("value", "")
            if cv and cv not in ("NVD-CWE-noinfo", "NVD-CWE-Other"):
                cwes.append(cv)

    published = None
    if cve.get("published"):
        try:
            published = datetime.fromisoformat(cve["published"].replace("Z", "+00:00")).replace(tzinfo=None)
        except Exception:
            pass

    last_modified = None
    if cve.get("lastModified"):
        try:
            last_modified = datetime.fromisoformat(cve["lastModified"].replace("Z", "+00:00")).replace(tzinfo=None)
        except Exception:
            pass

    # Extract affected products/configurations
    affected_products = []
    configurations = cve.get("configurations", [])
    for config in configurations:
        for node in config.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                criteria = cpe_match.get("criteria", "")
                if criteria:
                    parts = criteria.split(":")
                    if len(parts) >= 5:
                        affected_products.append({
                            "vendor": parts[3] if len(parts) > 3 else "",
                            "product": parts[4] if len(parts) > 4 else "",
                            "version": parts[5] if len(parts) > 5 else "*",
                            "vulnerable": cpe_match.get("vulnerable", True),
                        })

    return {
        "cve_id": cve_id,
        "description": description,
        "cvss_score": cvss_score,
        "severity": cvss_severity or "",
        "cwes": cwes,
        "references": refs,
        "published": published,
        "last_modified": last_modified,
        "source_data": {
            **cve,
            "affected_products": affected_products[:20],
        },
    }


def _parse_github_advisory(advisory: dict) -> dict:
    """Parse a GitHub Advisory into our storage format."""
    cve_id = advisory.get("cve_id") or advisory.get("ghsa_id", "")
    if not cve_id:
        return {}

    description = advisory.get("description", "") or advisory.get("summary", "")
    severity = (advisory.get("severity") or "medium").lower()
    cvss_score = None
    cvss = advisory.get("cvss", {})
    if cvss:
        cvss_score = cvss.get("score")

    cwes = []
    for cwe in advisory.get("cwes", []):
        cwe_id = cwe.get("cwe_id", "") if isinstance(cwe, dict) else str(cwe)
        if cwe_id:
            cwes.append(cwe_id)

    refs = []
    for ref in advisory.get("references", []):
        url = ref if isinstance(ref, str) else ref.get("url", "")
        if url:
            refs.append({"url": url, "source": "GitHub Advisory", "tags": []})

    # Add GitHub advisory URL itself
    html_url = advisory.get("html_url", "")
    if html_url:
        refs.insert(0, {"url": html_url, "source": "GitHub Advisory", "tags": ["advisory"]})

    published = None
    pub_str = advisory.get("published_at") or advisory.get("created_at")
    if pub_str:
        try:
            published = datetime.fromisoformat(pub_str.replace("Z", "+00:00")).replace(tzinfo=None)
        except Exception:
            pass

    last_modified = None
    mod_str = advisory.get("updated_at")
    if mod_str:
        try:
            last_modified = datetime.fromisoformat(mod_str.replace("Z", "+00:00")).replace(tzinfo=None)
        except Exception:
            pass

    return {
        "cve_id": cve_id,
        "description": description,
        "cvss_score": cvss_score,
        "severity": severity,
        "cwes": cwes,
        "references": refs,
        "published": published,
        "last_modified": last_modified,
        "source_data": {"source": "github_advisory", "ghsa_id": advisory.get("ghsa_id", ""), "html_url": html_url},
    }


def _parse_circl_cve(cve_data: dict) -> dict:
    """Parse a CIRCL CVE entry into our storage format."""
    cve_id = cve_data.get("id", "")
    if not cve_id:
        return {}

    description = ""
    descriptions = cve_data.get("containers", {}).get("cna", {}).get("descriptions", [])
    for d in descriptions:
        if d.get("lang") == "en":
            description = d.get("value", "")
            break
    if not description and descriptions:
        description = descriptions[0].get("value", "")
    if not description:
        description = cve_data.get("summary", "") or cve_data.get("description", "")

    cvss_score = cve_data.get("cvss")
    severity = ""
    if cvss_score:
        try:
            cvss_score = float(cvss_score)
            if cvss_score >= 9.0:
                severity = "critical"
            elif cvss_score >= 7.0:
                severity = "high"
            elif cvss_score >= 4.0:
                severity = "medium"
            else:
                severity = "low"
        except (ValueError, TypeError):
            cvss_score = None

    refs = []
    for ref in cve_data.get("references", []):
        url = ref if isinstance(ref, str) else ref.get("url", "")
        if url:
            refs.append({"url": url, "source": "CIRCL CVE", "tags": []})

    cwes = []
    cwe_str = cve_data.get("cwe")
    if cwe_str:
        cwes.append(cwe_str)

    published = None
    pub_str = cve_data.get("Published") or cve_data.get("datePublic")
    if pub_str:
        try:
            published = datetime.fromisoformat(pub_str.replace("Z", "+00:00")).replace(tzinfo=None)
        except Exception:
            try:
                published = datetime.strptime(pub_str[:19], "%Y-%m-%dT%H:%M:%S")
            except Exception:
                pass

    return {
        "cve_id": cve_id,
        "description": description,
        "cvss_score": cvss_score,
        "severity": severity,
        "cwes": cwes,
        "references": refs,
        "published": published,
        "last_modified": None,
        "source_data": {"source": "circl_cve"},
    }


# ---------------------------------------------------------------------------
# Request schemas
# ---------------------------------------------------------------------------

class GenerateTestCasesRequest(BaseModel):
    app_type: str = ""
    tech_stack: list[str] = []
    recent_cves: list[str] = []
    focus_areas: list[str] = []
    context: str = ""
    project_id: str | None = None


class SaveTestCasesRequest(BaseModel):
    project_id: str
    test_cases: list[dict]


class AssistantRequest(BaseModel):
    question: str
    project_id: str | None = None
    context: str = ""
    chat_history: list[dict] = []
    add_test_cases: bool = False


class AssistantAddTestCaseRequest(BaseModel):
    project_id: str
    test_cases: list[dict]


# ---------------------------------------------------------------------------
# LLM helpers
# ---------------------------------------------------------------------------

GENERATE_TEST_CASES_PROMPT = """You are a senior application security engineer. Based on the following context, generate a comprehensive list of security test cases.

Application Type: {app_type}
Technology Stack: {tech_stack}
Recent/Relevant CVEs to consider: {recent_cves}
Focus Areas: {focus_areas}
Additional Context: {context}

Generate 10-15 detailed security test cases. Each test case must follow this exact JSON format:
{{"test_cases": [{{
  "title": "...",
  "owasp_category": "...",
  "severity": "critical|high|medium|low|info",
  "description": "What this test verifies",
  "how_to_test": "Step-by-step testing procedure",
  "payloads": ["payload1", "payload2"],
  "pass_indicators": "What to look for when the app is secure",
  "fail_indicators": "What to look for when the app is vulnerable",
  "remediation": "How to fix if vulnerable",
  "cwe_id": "CWE-XXX"
}}]}}

Respond in JSON only, no markdown fences."""


ASSISTANT_PROMPT = """You are an expert application security assistant embedded in a VAPT (Vulnerability Assessment & Penetration Testing) platform called AppSecD. You have access to the organization's test case library, CVE database, and project data.

{context_section}

{chat_history_section}

User Question: {question}

Provide a detailed, actionable answer. If relevant, include:
- Step-by-step testing procedures
- Example payloads or commands
- Relevant CVEs or CWEs
- Tool recommendations
- Remediation guidance

When suggesting test cases, format them clearly so they can be added to the project.
If the user asks to add test cases or suggests specific tests, respond with them in a structured format.

Be specific and practical. Format your response clearly with markdown."""


def _parse_test_cases_json(text: str) -> list[dict]:
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
            "description": c.get("description", ""),
            "how_to_test": c.get("how_to_test", c.get("procedure", "")),
            "payloads": c.get("payloads", []),
            "pass_indicators": c.get("pass_indicators", c.get("expected_result", "")),
            "fail_indicators": c.get("fail_indicators", ""),
            "remediation": c.get("remediation", ""),
            "cwe_id": c.get("cwe_id", ""),
        })
    return result


def _call_llm(provider: str, model: str, api_key: str, prompt: str, max_tokens: int = 4096) -> str | None:
    """Call LLM and return raw text response."""
    try:
        if provider == "openai":
            from openai import OpenAI
            client = OpenAI(api_key=api_key)
            r = client.chat.completions.create(
                model=model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.5,
                max_tokens=max_tokens,
            )
            return (r.choices[0].message.content or "").strip()
        elif provider == "anthropic":
            from anthropic import Anthropic
            client = Anthropic(api_key=api_key)
            r = client.messages.create(
                model=model,
                max_tokens=max_tokens,
                messages=[{"role": "user", "content": prompt}],
            )
            return (r.content[0].text if r.content else "").strip()
        elif provider == "google":
            import google.generativeai as genai
            genai.configure(api_key=api_key)
            m = genai.GenerativeModel(model)
            r = m.generate_content(prompt)
            return (r.text or "").strip()
    except Exception as e:
        logger.warning("LLM call failed: %s", e)
    return None


def _call_llm_with_history(provider: str, model: str, api_key: str, messages: list[dict], max_tokens: int = 4096) -> str | None:
    """Call LLM with conversation history."""
    try:
        if provider == "openai":
            from openai import OpenAI
            client = OpenAI(api_key=api_key)
            r = client.chat.completions.create(
                model=model,
                messages=messages,
                temperature=0.5,
                max_tokens=max_tokens,
            )
            return (r.choices[0].message.content or "").strip()
        elif provider == "anthropic":
            from anthropic import Anthropic
            client = Anthropic(api_key=api_key)
            # Anthropic needs system message separate
            system_msg = ""
            user_messages = []
            for m in messages:
                if m["role"] == "system":
                    system_msg = m["content"]
                else:
                    user_messages.append(m)
            kwargs = {"model": model, "max_tokens": max_tokens, "messages": user_messages}
            if system_msg:
                kwargs["system"] = system_msg
            r = client.messages.create(**kwargs)
            return (r.content[0].text if r.content else "").strip()
        elif provider == "google":
            import google.generativeai as genai
            genai.configure(api_key=api_key)
            m = genai.GenerativeModel(model)
            # Combine all messages into one prompt for Google
            combined = "\n\n".join(f"[{msg['role']}]: {msg['content']}" for msg in messages)
            r = m.generate_content(combined)
            return (r.text or "").strip()
    except Exception as e:
        logger.warning("LLM call with history failed: %s", e)
    return None


async def _resolve_org_id(user, project_id: str | None, db: AsyncSession) -> Optional[UUID]:
    """Resolve org_id from project or user."""
    if project_id:
        proj = await db.execute(select(Project).where(Project.id == project_id))
        p = proj.scalar_one_or_none()
        if p and p.organization_id:
            return p.organization_id
    if user.organization_id:
        return user.organization_id
    return None


# ---------------------------------------------------------------------------
# CVE Endpoints — Multi-source sync
# ---------------------------------------------------------------------------

@router.post("/cve-sync")
async def sync_cves(
    keyword: str = Query(default="", description="Optional keyword filter"),
    days: int = Query(default=120, ge=1, le=365, description="Days back to fetch"),
    source: str = Query(default="all", description="Source: all, nvd, github, circl"),
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Fetch CVEs from multiple sources and store in PostgreSQL. Admin only."""
    total_stored = 0
    errors = []
    sources_used = []

    # --- Source 1: NVD API ---
    if source in ("all", "nvd"):
        try:
            nvd_count = await _sync_from_nvd(db, keyword, days)
            total_stored += nvd_count
            sources_used.append(f"NVD ({nvd_count})")
        except Exception as e:
            logger.warning("NVD sync error: %s", e)
            errors.append(f"NVD: {str(e)[:100]}")

    # --- Source 2: GitHub Advisory Database ---
    if source in ("all", "github"):
        try:
            gh_count = await _sync_from_github(db, keyword, days)
            total_stored += gh_count
            sources_used.append(f"GitHub ({gh_count})")
        except Exception as e:
            logger.warning("GitHub Advisory sync error: %s", e)
            errors.append(f"GitHub: {str(e)[:100]}")

    # --- Source 3: CIRCL CVE ---
    if source in ("all", "circl"):
        try:
            circl_count = await _sync_from_circl(db, keyword, days)
            total_stored += circl_count
            sources_used.append(f"CIRCL ({circl_count})")
        except Exception as e:
            logger.warning("CIRCL sync error: %s", e)
            errors.append(f"CIRCL: {str(e)[:100]}")

    msg = f"Synced {total_stored} CVEs from: {', '.join(sources_used) if sources_used else 'no sources'}"
    if errors:
        msg += f". Errors: {'; '.join(errors)}"

    return {
        "synced": total_stored,
        "sources": sources_used,
        "errors": errors,
        "message": msg,
    }


async def _sync_from_nvd(db: AsyncSession, keyword: str, days: int) -> int:
    """Fetch CVEs from NVD API."""
    start_date = (datetime.utcnow() - timedelta(days=days)).strftime("%Y-%m-%dT00:00:00.000")
    end_date = datetime.utcnow().strftime("%Y-%m-%dT23:59:59.999")
    total_stored = 0
    start_index = 0
    batch_size = 200

    while True:
        params = {
            "resultsPerPage": batch_size,
            "startIndex": start_index,
            "pubStartDate": start_date,
            "pubEndDate": end_date,
        }
        if keyword:
            params["keywordSearch"] = keyword

        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.get(NVD_CVE_API_URL, params=params)
                response.raise_for_status()
                data = response.json()
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 403:
                logger.info("NVD API rate limited, fetched %d so far", total_stored)
                break
            raise
        except Exception as e:
            logger.warning("NVD API fetch failed at index %d: %s", start_index, e)
            break

        vulns = data.get("vulnerabilities", [])
        if not vulns:
            break

        for vuln in vulns:
            parsed = _parse_nvd_cve(vuln)
            if not parsed["cve_id"]:
                continue
            await _upsert_cve(db, parsed)
            total_stored += 1

        await db.commit()

        total_results = data.get("totalResults", 0)
        start_index += batch_size
        if start_index >= total_results:
            break

        # NVD rate limit: 5 requests per 30 seconds without API key
        import asyncio
        await asyncio.sleep(6)

    return total_stored


async def _sync_from_github(db: AsyncSession, keyword: str, days: int) -> int:
    """Fetch CVEs from GitHub Advisory Database."""
    total_stored = 0
    try:
        params = {
            "type": "reviewed",
            "per_page": 100,
        }
        if keyword:
            params["cve_id"] = keyword if keyword.upper().startswith("CVE-") else None

        async with httpx.AsyncClient(timeout=30.0) as client:
            headers = {"Accept": "application/vnd.github+json"}
            response = await client.get(GITHUB_ADVISORY_API, params=params, headers=headers)
            if response.status_code != 200:
                logger.info("GitHub Advisory API returned %d", response.status_code)
                return 0
            advisories = response.json()

        for advisory in advisories:
            parsed = _parse_github_advisory(advisory)
            if not parsed or not parsed.get("cve_id"):
                continue
            await _upsert_cve(db, parsed)
            total_stored += 1

        await db.commit()
    except Exception as e:
        logger.warning("GitHub Advisory sync error: %s", e)

    return total_stored


async def _sync_from_circl(db: AsyncSession, keyword: str, days: int) -> int:
    """Fetch recent CVEs from CIRCL CVE API."""
    total_stored = 0
    try:
        # CIRCL provides last 30 CVEs
        url = f"{CIRCL_CVE_API}/last/30"
        if keyword and keyword.upper().startswith("CVE-"):
            url = f"{CIRCL_CVE_API}/cve/{keyword.upper()}"

        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(url)
            if response.status_code != 200:
                return 0
            data = response.json()

        if isinstance(data, dict):
            data = [data]

        for cve_data in data:
            parsed = _parse_circl_cve(cve_data)
            if not parsed or not parsed.get("cve_id"):
                continue
            await _upsert_cve(db, parsed)
            total_stored += 1

        await db.commit()
    except Exception as e:
        logger.warning("CIRCL sync error: %s", e)

    return total_stored


async def _upsert_cve(db: AsyncSession, parsed: dict):
    """Insert or update a CVE record."""
    existing = await db.execute(
        select(StoredCVE).where(StoredCVE.cve_id == parsed["cve_id"])
    )
    row = existing.scalar_one_or_none()
    if row:
        # Only update if we have better data
        if parsed["description"] and (not row.description or len(parsed["description"]) > len(row.description or "")):
            row.description = parsed["description"]
        if parsed["cvss_score"] and not row.cvss_score:
            row.cvss_score = parsed["cvss_score"]
        if parsed["severity"] and not row.severity:
            row.severity = parsed["severity"]
        if parsed["cwes"] and (not row.cwes or len(parsed["cwes"]) > len(row.cwes or [])):
            row.cwes = parsed["cwes"]
        # Merge references
        existing_urls = {r.get("url") for r in (row.references or [])}
        new_refs = list(row.references or [])
        for ref in (parsed["references"] or []):
            if ref.get("url") and ref["url"] not in existing_urls:
                new_refs.append(ref)
                existing_urls.add(ref["url"])
        row.references = new_refs
        if parsed["published"] and not row.published:
            row.published = parsed["published"]
        if parsed["last_modified"]:
            row.last_modified = parsed["last_modified"]
        # Merge source data
        if isinstance(row.source_data, dict) and isinstance(parsed.get("source_data"), dict):
            merged = {**row.source_data, **parsed["source_data"]}
            row.source_data = merged
    else:
        db.add(StoredCVE(**parsed))


@router.get("/cve-feed")
async def get_cve_feed(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    keyword: str = Query(default="", description="Search CVE ID, description, or CWE"),
    severity: str = Query(default="", description="Filter by severity"),
    cwe: str = Query(default="", description="Filter by CWE ID"),
    date_from: str = Query(default="", description="Filter from date (YYYY-MM-DD)"),
    date_to: str = Query(default="", description="Filter to date (YYYY-MM-DD)"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Fetch CVEs from local DB with advanced search. Falls back to NVD API if DB is empty."""
    # Check if we have stored CVEs
    count_q = select(func.count(StoredCVE.id))
    total_count = (await db.execute(count_q)).scalar() or 0

    if total_count == 0:
        # Fallback: fetch from NVD API directly
        params = {"resultsPerPage": min(page_size, 50)}
        if keyword:
            params["keywordSearch"] = keyword
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(NVD_CVE_API_URL, params=params)
                response.raise_for_status()
                data = response.json()
            vulns = data.get("vulnerabilities", [])
            formatted = []
            for vuln in vulns:
                parsed = _parse_nvd_cve(vuln)
                formatted.append({
                    "cve_id": parsed["cve_id"],
                    "description": parsed["description"],
                    "cvss_score": parsed["cvss_score"],
                    "severity": parsed["severity"],
                    "cwes": parsed["cwes"],
                    "references": parsed["references"],
                    "published": parsed["published"].isoformat() if parsed["published"] else "",
                    "last_modified": parsed["last_modified"].isoformat() if parsed["last_modified"] else "",
                    "affected_products": parsed["source_data"].get("affected_products", []),
                })
            return {
                "cves": formatted,
                "total": data.get("totalResults", 0),
                "page": 1,
                "page_size": page_size,
                "source": "nvd_api",
                "needs_sync": True,
            }
        except Exception as e:
            logger.warning("NVD API fallback failed: %s", e)
            return {"cves": [], "total": 0, "page": 1, "page_size": page_size, "source": "error", "needs_sync": True}

    # Query from DB with advanced filters
    query = select(StoredCVE)
    count_query = select(func.count(StoredCVE.id))

    filters = []
    if keyword:
        kw = f"%{keyword}%"
        filters.append(or_(
            StoredCVE.cve_id.ilike(kw),
            StoredCVE.description.ilike(kw),
            StoredCVE.cwes.cast(String).ilike(kw),
        ))

    if severity:
        filters.append(StoredCVE.severity == severity.lower())

    if cwe:
        filters.append(StoredCVE.cwes.cast(String).ilike(f"%{cwe}%"))

    if date_from:
        try:
            dt_from = datetime.strptime(date_from, "%Y-%m-%d")
            filters.append(StoredCVE.published >= dt_from)
        except ValueError:
            pass

    if date_to:
        try:
            dt_to = datetime.strptime(date_to, "%Y-%m-%d")
            filters.append(StoredCVE.published <= dt_to)
        except ValueError:
            pass

    if filters:
        for f in filters:
            query = query.where(f)
            count_query = count_query.where(f)

    total = (await db.execute(count_query)).scalar() or 0
    query = query.order_by(desc(StoredCVE.published)).offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(query)
    cves = result.scalars().all()

    formatted = []
    for c in cves:
        source_data = c.source_data or {}
        formatted.append({
            "cve_id": c.cve_id,
            "description": c.description or "",
            "cvss_score": c.cvss_score,
            "severity": c.severity or "",
            "cwes": c.cwes or [],
            "references": c.references or [],
            "published": c.published.isoformat() if c.published else "",
            "last_modified": c.last_modified.isoformat() if c.last_modified else "",
            "affected_products": source_data.get("affected_products", []),
        })

    return {
        "cves": formatted,
        "total": total,
        "page": page,
        "page_size": page_size,
        "source": "database",
        "needs_sync": False,
    }


@router.get("/cve/{cve_id}")
async def get_cve_detail(
    cve_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get full CVE details including all references and affected products."""
    result = await db.execute(
        select(StoredCVE).where(StoredCVE.cve_id == cve_id)
    )
    cve = result.scalar_one_or_none()

    if not cve:
        # Try fetching from NVD API directly
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(NVD_CVE_API_URL, params={"cveId": cve_id})
                response.raise_for_status()
                data = response.json()
            vulns = data.get("vulnerabilities", [])
            if vulns:
                parsed = _parse_nvd_cve(vulns[0])
                # Store it for future use
                db.add(StoredCVE(**parsed))
                await db.commit()
                source_data = parsed.get("source_data", {})
                return {
                    "cve_id": parsed["cve_id"],
                    "description": parsed["description"],
                    "cvss_score": parsed["cvss_score"],
                    "severity": parsed["severity"],
                    "cwes": parsed["cwes"],
                    "references": parsed["references"],
                    "published": parsed["published"].isoformat() if parsed["published"] else "",
                    "last_modified": parsed["last_modified"].isoformat() if parsed["last_modified"] else "",
                    "affected_products": source_data.get("affected_products", []),
                    "source_data": source_data,
                    "source": "nvd_api_live",
                }
        except Exception as e:
            logger.warning("CVE detail fetch failed: %s", e)
        raise HTTPException(404, f"CVE {cve_id} not found")

    source_data = cve.source_data or {}
    return {
        "cve_id": cve.cve_id,
        "description": cve.description or "",
        "cvss_score": cve.cvss_score,
        "severity": cve.severity or "",
        "cwes": cve.cwes or [],
        "references": cve.references or [],
        "published": cve.published.isoformat() if cve.published else "",
        "last_modified": cve.last_modified.isoformat() if cve.last_modified else "",
        "affected_products": source_data.get("affected_products", []),
        "source_data": source_data,
        "source": "database",
    }


@router.get("/cve-search/{cve_id}")
async def search_cve_by_id(
    cve_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Search for a specific CVE by ID. Fetches from NVD if not in DB."""
    # First check local DB
    result = await db.execute(
        select(StoredCVE).where(StoredCVE.cve_id.ilike(f"%{cve_id}%"))
    )
    local_results = result.scalars().all()

    if local_results:
        return {
            "cves": [{
                "cve_id": c.cve_id,
                "description": c.description or "",
                "cvss_score": c.cvss_score,
                "severity": c.severity or "",
                "cwes": c.cwes or [],
                "references": c.references or [],
                "published": c.published.isoformat() if c.published else "",
                "source": "database",
            } for c in local_results[:20]],
            "total": len(local_results),
            "source": "database",
        }

    # Fetch from NVD API
    try:
        params = {}
        if cve_id.upper().startswith("CVE-"):
            params["cveId"] = cve_id.upper()
        else:
            params["keywordSearch"] = cve_id
            params["resultsPerPage"] = 20

        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(NVD_CVE_API_URL, params=params)
            response.raise_for_status()
            data = response.json()

        vulns = data.get("vulnerabilities", [])
        results = []
        for vuln in vulns:
            parsed = _parse_nvd_cve(vuln)
            if parsed["cve_id"]:
                # Store for future
                await _upsert_cve(db, parsed)
                results.append({
                    "cve_id": parsed["cve_id"],
                    "description": parsed["description"],
                    "cvss_score": parsed["cvss_score"],
                    "severity": parsed["severity"],
                    "cwes": parsed["cwes"],
                    "references": parsed["references"],
                    "published": parsed["published"].isoformat() if parsed["published"] else "",
                    "source": "nvd_api",
                })
        await db.commit()

        return {
            "cves": results,
            "total": len(results),
            "source": "nvd_api",
        }
    except Exception as e:
        logger.warning("CVE search failed: %s", e)
        return {"cves": [], "total": 0, "source": "error", "error": str(e)[:200]}


# ---------------------------------------------------------------------------
# Test Case Generation
# ---------------------------------------------------------------------------

@router.post("/generate-test-cases")
async def generate_test_cases(
    payload: GenerateTestCasesRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Use LLM to generate security test cases."""
    org_id = await _resolve_org_id(current_user, payload.project_id, db)

    if not await check_feature_enabled(db, org_id, "ai_test_generation"):
        raise HTTPException(403, "AI Test Case Generation is disabled for your organization. Contact your admin to enable it.")

    provider, model, api_key = await get_llm_config(db, org_id)
    if not api_key or not model:
        raise HTTPException(400, "No LLM configured. Please configure an LLM provider in admin settings.")

    prompt = GENERATE_TEST_CASES_PROMPT.format(
        app_type=payload.app_type or "(not specified)",
        tech_stack=", ".join(payload.tech_stack) if payload.tech_stack else "(not specified)",
        recent_cves=", ".join(payload.recent_cves) if payload.recent_cves else "(none specified)",
        focus_areas=", ".join(payload.focus_areas) if payload.focus_areas else "(general security assessment)",
        context=payload.context or "(none)",
    )

    text = _call_llm(provider, model, api_key, prompt)
    if text:
        try:
            result = _parse_test_cases_json(text)
            return {
                "test_cases": result,
                "count": len(result),
                "source": "llm",
                "provider": provider,
                "model": model,
            }
        except Exception as e:
            logger.warning("Failed to parse test cases: %s", e)

    raise HTTPException(500, "LLM call failed. Please try again or check your LLM configuration.")


@router.post("/save-test-cases")
async def save_test_cases_to_project(
    payload: SaveTestCasesRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Save AI-generated test cases to a project. Deduplicates by title."""
    from app.services.project_permissions import user_can_write_project

    if not await user_can_write_project(db, current_user, payload.project_id):
        raise HTTPException(403, "Write access denied to this project")

    # Get the "Custom/AI Generated" category, or create it
    cat_result = await db.execute(
        select(Category).where(Category.slug == "ai-generated")
    )
    category = cat_result.scalar_one_or_none()
    if not category:
        import uuid
        category = Category(
            id=uuid.uuid4(),
            name="AI Generated Tests",
            slug="ai-generated",
            phase="ai_generated",
            icon="robot",
            description="Security test cases generated by AI",
            order_index=999,
            is_active=True,
        )
        db.add(category)
        await db.flush()

    # Get existing test case titles in this project to deduplicate
    existing_q = await db.execute(
        select(TestCase.title)
        .join(ProjectTestResult, ProjectTestResult.test_case_id == TestCase.id)
        .where(ProjectTestResult.project_id == payload.project_id)
    )
    existing_titles = {row[0].lower().strip() for row in existing_q.all()}

    saved = 0
    skipped = 0
    import uuid

    for tc_data in payload.test_cases:
        title = tc_data.get("title", "").strip()
        if not title:
            continue

        # Dedup check
        if title.lower() in existing_titles:
            skipped += 1
            continue

        # Create TestCase
        tc = TestCase(
            id=uuid.uuid4(),
            category_id=category.id,
            title=title,
            description=tc_data.get("description", ""),
            owasp_ref=tc_data.get("owasp_category", ""),
            cwe_id=tc_data.get("cwe_id", ""),
            severity=tc_data.get("severity", "medium"),
            phase="ai_generated",
            where_to_test=tc_data.get("where_to_test", ""),
            what_to_test=tc_data.get("what_to_test", ""),
            how_to_test=tc_data.get("how_to_test", ""),
            payloads=tc_data.get("payloads", []),
            tool_commands=tc_data.get("tool_commands", []),
            pass_indicators=tc_data.get("pass_indicators", ""),
            fail_indicators=tc_data.get("fail_indicators", ""),
            remediation=tc_data.get("remediation", ""),
            references=tc_data.get("references", []),
            tags=["ai-generated"],
            is_active=True,
        )
        db.add(tc)
        await db.flush()

        # Create ProjectTestResult
        ptr = ProjectTestResult(
            id=uuid.uuid4(),
            project_id=uuid.UUID(payload.project_id),
            test_case_id=tc.id,
            tester_id=current_user.id,
            status="not_started",
            is_applicable=True,
        )
        db.add(ptr)
        existing_titles.add(title.lower())
        saved += 1

    # Update project test counts
    proj_result = await db.execute(select(Project).where(Project.id == payload.project_id))
    project = proj_result.scalar_one_or_none()
    if project:
        total_q = await db.execute(
            select(func.count(ProjectTestResult.id))
            .where(ProjectTestResult.project_id == payload.project_id)
        )
        project.total_test_cases = total_q.scalar() or 0

    await db.commit()
    return {"saved": saved, "skipped": skipped, "message": f"Saved {saved} test cases, skipped {skipped} duplicates"}


# ---------------------------------------------------------------------------
# Security Assistant — with chat history and DB integration
# ---------------------------------------------------------------------------

@router.post("/assistant")
async def security_assistant(
    payload: AssistantRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """AI Security Assistant — answer security questions with context, history, and DB access."""
    org_id = await _resolve_org_id(current_user, payload.project_id, db)

    if not await check_feature_enabled(db, org_id, "ai_security_assistant"):
        raise HTTPException(403, "AI Security Assistant is disabled for your organization. Contact your admin to enable it.")

    provider, model, api_key = await get_llm_config(db, org_id)
    if not api_key or not model:
        raise HTTPException(400, "No LLM configured. Please configure an LLM provider in admin settings.")

    # Build context
    context_parts = []

    # Add relevant test cases from library
    q_kw = payload.question.lower()
    tc_result = await db.execute(
        select(TestCase).where(TestCase.is_active == True).limit(200)
    )
    all_tcs = tc_result.scalars().all()
    relevant_tcs = []
    for tc in all_tcs:
        combined = f"{tc.title} {tc.description or ''} {' '.join(tc.tags or [])}".lower()
        words = q_kw.split()
        if any(w in combined for w in words if len(w) > 3):
            relevant_tcs.append(tc)
            if len(relevant_tcs) >= 5:
                break

    if relevant_tcs:
        context_parts.append("**Relevant Test Cases from Library:**")
        for tc in relevant_tcs:
            context_parts.append(f"- {tc.title}: {(tc.description or '')[:200]}")
            if tc.how_to_test:
                context_parts.append(f"  How to test: {tc.how_to_test[:300]}")
            if tc.payloads:
                payloads_str = ", ".join(str(p) for p in (tc.payloads or [])[:5])
                context_parts.append(f"  Payloads: {payloads_str}")

    # Add relevant CVEs
    cve_result = await db.execute(
        select(StoredCVE)
        .where(or_(StoredCVE.description.ilike(f"%{q_kw[:50]}%"), StoredCVE.cve_id.ilike(f"%{q_kw[:20]}%")))
        .order_by(desc(StoredCVE.published))
        .limit(5)
    )
    relevant_cves = cve_result.scalars().all()
    if relevant_cves:
        context_parts.append("\n**Relevant CVEs:**")
        for cve in relevant_cves:
            context_parts.append(f"- {cve.cve_id} (CVSS: {cve.cvss_score}): {(cve.description or '')[:200]}")

    # Add project context if available
    project_context = None
    if payload.project_id:
        proj_result = await db.execute(select(Project).where(Project.id == payload.project_id))
        project_context = proj_result.scalar_one_or_none()
        if project_context:
            context_parts.append(f"\n**Project Context:**")
            context_parts.append(f"- App: {project_context.application_name} ({project_context.application_url or 'no URL'})")
            context_parts.append(f"- Stack: {json.dumps(project_context.stack_profile) if project_context.stack_profile else 'unknown'}")

            # Add project test results summary
            test_results = await db.execute(
                select(
                    ProjectTestResult.status,
                    func.count(ProjectTestResult.id),
                ).where(
                    ProjectTestResult.project_id == payload.project_id
                ).group_by(ProjectTestResult.status)
            )
            status_counts = {row[0]: row[1] for row in test_results}
            if status_counts:
                context_parts.append(f"- Test Status: {json.dumps(status_counts)}")

            # Add project findings summary
            findings_result = await db.execute(
                select(Finding.severity, func.count(Finding.id))
                .where(Finding.project_id == payload.project_id)
                .group_by(Finding.severity)
            )
            findings_counts = {row[0]: row[1] for row in findings_result}
            if findings_counts:
                context_parts.append(f"- Findings: {json.dumps(findings_counts)}")

    if payload.context:
        context_parts.append(f"\n**Additional Context:** {payload.context}")

    context_section = "\n".join(context_parts) if context_parts else "No additional context available."

    # Build chat history section
    chat_history_section = ""
    if payload.chat_history:
        history_parts = ["**Previous conversation:**"]
        for msg in payload.chat_history[-10:]:  # Last 10 messages for context
            role = msg.get("role", "user")
            content = msg.get("content", "")[:500]
            history_parts.append(f"[{role}]: {content}")
        chat_history_section = "\n".join(history_parts)

    prompt = ASSISTANT_PROMPT.format(
        context_section=context_section,
        question=payload.question,
        chat_history_section=chat_history_section,
    )

    # Use history-aware LLM call
    messages = [{"role": "system", "content": prompt}]
    for msg in (payload.chat_history or [])[-6:]:
        messages.append({
            "role": msg.get("role", "user"),
            "content": msg.get("content", ""),
        })
    messages.append({"role": "user", "content": payload.question})

    text = _call_llm_with_history(provider, model, api_key, messages, max_tokens=4096)
    if not text:
        # Fallback to simple call
        text = _call_llm(provider, model, api_key, prompt, max_tokens=4096)

    if text:
        # Check if the response suggests test cases that can be auto-extracted
        suggested_test_cases = []
        if any(kw in payload.question.lower() for kw in ["add test", "create test", "generate test", "test case"]):
            # Try to extract test case suggestions from the response
            try:
                tc_prompt = f"""From the following security assistant response, extract any suggested test cases into JSON format.
Response: {text[:2000]}

If test cases are mentioned, return them as:
{{"test_cases": [{{"title": "...", "severity": "medium", "description": "...", "how_to_test": "...", "cwe_id": "..."}}]}}

If no test cases are mentioned, return: {{"test_cases": []}}
JSON only, no markdown."""
                tc_text = _call_llm(provider, model, api_key, tc_prompt, max_tokens=2000)
                if tc_text:
                    suggested_test_cases = _parse_test_cases_json(tc_text)
            except Exception:
                pass

        return {
            "answer": text,
            "source": "llm",
            "provider": provider,
            "model": model,
            "suggested_test_cases": suggested_test_cases,
            "context_used": {
                "test_cases": len(relevant_tcs),
                "cves": len(relevant_cves),
                "project": project_context.application_name if project_context else None,
            },
        }

    raise HTTPException(500, "LLM call failed. Please try again.")


@router.post("/assistant/add-test-cases")
async def assistant_add_test_cases(
    payload: AssistantAddTestCaseRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Add test cases suggested by the assistant to a project."""
    from app.services.project_permissions import user_can_write_project

    if not await user_can_write_project(db, current_user, payload.project_id):
        raise HTTPException(403, "Write access denied to this project")

    save_payload = SaveTestCasesRequest(
        project_id=payload.project_id,
        test_cases=payload.test_cases,
    )
    return await save_test_cases_to_project(save_payload, current_user, db)


# ---------------------------------------------------------------------------
# Feature Flags
# ---------------------------------------------------------------------------

@router.get("/feature-flags")
async def get_feature_flags(
    org_id: str = Query(default="", description="Organization ID"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get AI feature flags for an organization."""
    target_org_id = None
    if org_id:
        target_org_id = org_id
    elif current_user.organization_id:
        target_org_id = str(current_user.organization_id)

    flags = {}
    for key, label in AI_FEATURES.items():
        flags[key] = {"label": label, "enabled": True}

    if target_org_id:
        result = await db.execute(
            select(OrgFeatureFlag).where(
                OrgFeatureFlag.organization_id == target_org_id,
            )
        )
        for flag in result.scalars().all():
            if flag.feature_key in flags:
                flags[flag.feature_key]["enabled"] = flag.enabled

    return {"flags": flags, "org_id": target_org_id}


@router.put("/feature-flags")
async def update_feature_flags(
    payload: dict,
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Update AI feature flags for an organization. Admin/SuperAdmin only."""
    org_id = payload.get("org_id")
    flags = payload.get("flags", {})

    if not org_id:
        raise HTTPException(400, "org_id is required")

    import uuid as uuid_mod
    for key, enabled in flags.items():
        if key not in AI_FEATURES:
            continue
        result = await db.execute(
            select(OrgFeatureFlag).where(
                OrgFeatureFlag.organization_id == org_id,
                OrgFeatureFlag.feature_key == key,
            )
        )
        row = result.scalar_one_or_none()
        if row:
            row.enabled = bool(enabled)
        else:
            db.add(OrgFeatureFlag(
                id=uuid_mod.uuid4(),
                organization_id=uuid_mod.UUID(org_id) if isinstance(org_id, str) else org_id,
                feature_key=key,
                enabled=bool(enabled),
            ))

    await db.commit()
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

@router.get("/dashboard")
async def get_security_dashboard(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Aggregate security intelligence dashboard."""
    org_id = getattr(current_user, "organization_id", None)

    # Findings by severity
    severity_query = select(Finding.severity, func.count(Finding.id).label("count"))
    if current_user.role == "super_admin":
        pass
    elif org_id:
        severity_query = severity_query.join(Project, Finding.project_id == Project.id).where(Project.organization_id == org_id)
    else:
        severity_query = severity_query.where(False)
    severity_query = severity_query.group_by(Finding.severity)
    severity_result = await db.execute(severity_query)
    findings_by_severity = {row.severity: row.count for row in severity_result}
    for sev in ("critical", "high", "medium", "low", "info"):
        findings_by_severity.setdefault(sev, 0)
    total_findings = sum(findings_by_severity.values())

    # Findings by status
    status_query = select(Finding.status, func.count(Finding.id).label("count"))
    if current_user.role == "super_admin":
        pass
    elif org_id:
        status_query = status_query.join(Project, Finding.project_id == Project.id).where(Project.organization_id == org_id)
    else:
        status_query = status_query.where(False)
    status_query = status_query.group_by(Finding.status)
    status_result = await db.execute(status_query)
    findings_by_status = {row.status: row.count for row in status_result}

    # Trends (last 30 days)
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    trend_query = select(
        func.date_trunc("week", Finding.created_at).label("week"),
        Finding.severity,
        func.count(Finding.id).label("count"),
    ).where(Finding.created_at >= thirty_days_ago)
    if current_user.role == "super_admin":
        pass
    elif org_id:
        trend_query = trend_query.join(Project, Finding.project_id == Project.id).where(Project.organization_id == org_id)
    else:
        trend_query = trend_query.where(False)
    trend_query = trend_query.group_by("week", Finding.severity).order_by("week")
    trend_result = await db.execute(trend_query)
    trends = [{"week": row.week.isoformat() if row.week else "", "severity": row.severity, "count": row.count} for row in trend_result]

    # Project count
    project_count_query = select(func.count(Project.id))
    if current_user.role == "super_admin":
        pass
    elif org_id:
        project_count_query = project_count_query.where(Project.organization_id == org_id)
    else:
        project_count_query = project_count_query.where(False)
    total_projects = (await db.execute(project_count_query)).scalar() or 0

    # Recent CVEs from DB
    recent_cves = []
    cve_result = await db.execute(
        select(StoredCVE).order_by(desc(StoredCVE.published)).limit(10)
    )
    for c in cve_result.scalars().all():
        recent_cves.append({
            "cve_id": c.cve_id,
            "description": (c.description or "")[:200] + ("..." if len(c.description or "") > 200 else ""),
            "cvss_score": c.cvss_score,
            "severity": c.severity,
            "published": c.published.isoformat() if c.published else "",
        })

    # CVE count in DB
    cve_count = (await db.execute(select(func.count(StoredCVE.id)))).scalar() or 0

    return {
        "findings_by_severity": findings_by_severity,
        "findings_by_status": findings_by_status,
        "total_findings": total_findings,
        "total_projects": total_projects,
        "vulnerability_trends": trends,
        "recent_cves": recent_cves,
        "cve_count": cve_count,
    }
