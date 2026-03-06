"""DAST Automation API — run automated security scans."""
import asyncio
import uuid
import re
import hashlib
import logging
from urllib.parse import urlparse
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

from app.api.auth import get_current_user
from app.services.project_permissions import user_can_read_project
from app.core.database import get_db, AsyncSessionLocal
from app.models.project import Project
from app.models.finding import Finding
from app.models.dast_scan_result import DastScanResult
from app.models.test_case import TestCase
from app.models.result import ProjectTestResult
from app.models.crawl_session import CrawlSession

logger = logging.getLogger(__name__)


def _finding_fingerprint(cwe_id: str, affected_url: str, parameter: str, title: str) -> str:
    """Generate a dedup fingerprint from normalized attributes."""
    # Strip prefix [DAST] / [Claude DAST], lowercase, strip whitespace
    norm_title = re.sub(r'^\[(Claude )?DAST\]\s*', '', title).strip().lower()
    # Use URL path only (ignore query params, fragments, host differences)
    parsed = urlparse(affected_url or "")
    url_path = parsed.path.rstrip("/").lower() or "/"
    raw = f"{(cwe_id or '').strip()}|{url_path}|{(parameter or '').strip().lower()}|{norm_title}"
    return hashlib.sha256(raw.encode()).hexdigest()[:32]

router = APIRouter(prefix="/dast", tags=["dast"])


async def _resolve_claude_api_key(db: AsyncSession, project) -> str:
    """Resolve Claude API key: org-level first, then global fallback."""
    from app.core.config import get_settings
    settings = get_settings()
    api_key = settings.anthropic_api_key or ""

    # Try org-level API key first
    try:
        org_id = getattr(project, "organization_id", None)
        if org_id:
            from app.models.organization import Organization
            org_row = (await db.execute(
                select(Organization).where(Organization.id == org_id)
            )).scalar_one_or_none()
            if org_row and getattr(org_row, "claude_dast_api_key", None):
                api_key = org_row.claude_dast_api_key
    except Exception:
        pass

    return api_key


class DastScanRequest(BaseModel):
    project_id: str
    target_url: str | None = None  # Override project URL
    checks: list[str] | None = None  # Specific checks or all


class DastSingleCheckRequest(BaseModel):
    target_url: str
    check: str  # security_headers, ssl_tls, etc.


class DastFfufScanRequest(BaseModel):
    target_url: str
    base_path: str = "/"  # e.g. /api, /admin
    wordlist: str = "small"  # small, medium, dirbuster-dirs, api-common


class DastFfufExhaustiveRequest(BaseModel):
    project_id: str
    target_url: str
    base_path: str = "/"  # e.g. /api, /


class CrawlRequest(BaseModel):
    project_id: str
    target_url: str | None = None
    auth_config: dict | None = None  # {type, name?, value?, headers?}
    max_depth: int = 3
    crawl_scope: str = "host"  # host, subdomain, all
    run_param_discovery: bool = True
    use_playwright: bool = False  # JS/SPA deepening (requires playwright)


class RecursiveDirScanRequest(BaseModel):
    project_id: str
    target_url: str
    base_path: str = "/"
    max_depth: int = 3
    wordlist: str = "small"
    auth_config: dict | None = None


class FetchUrlRequest(BaseModel):
    url: str
    auth_config: dict | None = None


async def _run_scan_background(
    scan_id: str,
    project_id: str,
    target_url: str,
    checks: list[str] | None,
    user_id: uuid.UUID,
):
    """Run DAST scan in thread, update progress, create findings when done."""
    from app.services.dast_service import run_dast_scan, _dast_progress_get, _dast_progress_set

    try:
        result = await asyncio.to_thread(
            run_dast_scan,
            target_url,
            checks,
            progress_scan_id=scan_id,
            progress_meta={"project_id": project_id, "target_url": target_url},
        )
    except Exception as e:
        logger.exception("DAST scan %s failed", scan_id)
        from app.services.dast_service import _dast_progress_set
        _dast_progress_set(scan_id, {
                "project_id": project_id,
                "target_url": target_url,
                "status": "error",
                "error": str(e),
                "results": [],
                "last_updated": __import__("time").time(),
            })
        return

    findings_created = []
    project_uuid = uuid.UUID(project_id)
    async with AsyncSessionLocal() as db:
        try:
            from datetime import datetime as _dt
            for check in result["results"]:
                title = f"[DAST] {check['title']}"
                if check["status"] == "failed":
                    # Smart dedup: fingerprint-based first, then fallback to exact match
                    fp = _finding_fingerprint(
                        check.get("cwe_id", ""), target_url,
                        check.get("affected_parameter", ""), title,
                    )
                    existing_row = None
                    # Try fingerprint match
                    existing_q = await db.execute(
                        select(Finding).where(
                            Finding.project_id == project_uuid,
                            Finding.dedup_fingerprint == fp,
                            Finding.status.in_(["open", "confirmed"]),
                        )
                    )
                    existing_row = existing_q.scalar_one_or_none()
                    # Fallback: legacy exact-match
                    if not existing_row:
                        existing_q2 = await db.execute(
                            select(Finding).where(
                                Finding.project_id == project_uuid,
                                Finding.title == title,
                                Finding.affected_url == target_url,
                                Finding.status.in_(["open", "confirmed"]),
                            )
                        )
                        existing_row = existing_q2.scalar_one_or_none()
                    if existing_row:
                        # Update existing finding with latest evidence
                        existing_row.last_seen_at = _dt.utcnow()
                        existing_row.scan_count = (existing_row.scan_count or 1) + 1
                        existing_row.dedup_fingerprint = fp
                        if check.get("request_raw"):
                            existing_row.request = check["request_raw"]
                        if check.get("response_raw"):
                            existing_row.response = check["response_raw"]
                        if check.get("evidence"):
                            existing_row.description = check["description"] + f"\n\nEvidence:\n{check['evidence']}"
                        continue
                    finding = Finding(
                        project_id=project_uuid,
                        title=title,
                        dedup_fingerprint=fp,
                        last_seen_at=_dt.utcnow(),
                        description=check["description"],
                        severity=check.get("severity", "medium"),
                        cwe_id=check.get("cwe_id", ""),
                        owasp_category=check.get("owasp_ref", ""),
                        affected_url=target_url,
                        reproduction_steps=check.get("reproduction_steps", ""),
                        impact=check["description"],
                        recommendation=check.get("remediation", ""),
                        status="open",
                        created_by=user_id,
                    )
                    if check.get("evidence"):
                        finding.description += f"\n\nEvidence:\n{check['evidence']}"
                    if check.get("request_raw"):
                        finding.request = check["request_raw"]
                    if check.get("response_raw"):
                        finding.response = check["response_raw"]

                    # AI-enrich finding with Gemini interpretation
                    try:
                        from app.services.dast.ai_analysis import interpret_scan_result
                        from app.services.admin_settings_service import get_llm_config as _get_llm
                        provider, model, api_key = await _get_llm(db)
                        if not api_key:
                            from app.core.config import get_settings
                            s = get_settings()
                            if s.google_api_key:
                                provider, model, api_key = "google", "gemini-2.5-flash", s.google_api_key
                        if api_key:
                            enriched = interpret_scan_result(
                                check, target_url,
                                provider=provider, model=model, api_key=api_key,
                            )
                            ai = enriched.get("ai_analysis", {})
                            if ai.get("interpretation"):
                                finding.description += f"\n\n**AI Analysis:**\n{ai['interpretation']}"
                            if ai.get("remediation_steps"):
                                finding.recommendation += "\n\n**AI Remediation:**\n" + "\n".join(f"- {s}" for s in ai["remediation_steps"])
                    except Exception as ai_err:
                        logger.debug("AI enrichment skipped for %s: %s", check.get("title", ""), ai_err)

                    db.add(finding)
                    findings_created.append(check["title"])
                elif check["status"] == "passed":
                    # Auto-close: if this check now passes, close related open findings for same target
                    from datetime import datetime
                    existing = await db.execute(
                        select(Finding).where(
                            Finding.project_id == project_uuid,
                            Finding.title == title,
                            Finding.affected_url == target_url,
                            Finding.status.in_(["open", "confirmed"]),
                        )
                    )
                    for f in existing.scalars().all():
                        f.status = "fixed"
                        f.recheck_status = "resolved"
                        f.recheck_notes = "DAST scan passed — vulnerability no longer detected"
                        f.recheck_date = datetime.utcnow()
                        f.recheck_by = user_id

            # Sync DAST results to ProjectTestResult only for checks that ran (single or subset)
            # Map check_id -> module_id (WSTG or MOD from seed). Auto-mark test cases when automated.
            # Comprehensive DAST check → TestCase module_id mapping
            # Covers all 61 checks where a matching test case exists
            DAST_CHECK_TO_MODULE = {
                # SSL/TLS & Transport
                "DAST-SSL-01": "WSTG-CRYP-01",
                "DAST-CRYP-02": "WSTG-CRYP-02",
                "DAST-REDIR-02": "WSTG-CONF-07",
                "DAST-HSTS-01": "WSTG-CONF-07",
                "DAST-HSTS-02": "WSTG-CONF-07",
                # Headers & Security Config
                "DAST-HDR-01": "WSTG-CONF-07",
                "DAST-FRAME-01": "WSTG-CLNT-09",
                "DAST-CT-01": "WSTG-CONF-07",
                "DAST-PERM-01": "WSTG-CONF-07",
                "DAST-XSSP-01": "WSTG-CONF-07",
                "DAST-CSPR-01": "WSTG-CONF-07",
                "DAST-ECT-01": "WSTG-CONF-07",
                "DAST-VER-01": "WSTG-INFO-02",
                "DAST-COOP-01": "WSTG-CONF-07",
                "DAST-CACHE-01": "WSTG-ATHN-06",
                # Cookies
                "DAST-COOK-01": "WSTG-SESS-02",
                "DAST-COOKP-01": "WSTG-SESS-02",
                # Information Disclosure
                "DAST-INFO-01": "WSTG-INFO-02",
                "DAST-RECON-01": "WSTG-INFO-02",
                "DAST-DEBUG-01": "WSTG-ERRH-01",
                "DAST-PII-01": "WSTG-INFO-05",
                # Recon & Discovery
                "DAST-ROBO-01": "WSTG-INFO-03",
                "DAST-RECON-02": "WSTG-INFO-03",
                "DAST-DIR-01": "WSTG-CONF-04",
                "DAST-DIR-02": "MOD-RECON-04",
                "DAST-BACKUP-01": "WSTG-CONF-04",
                "DAST-API-01": "WSTG-INFO-10",
                "DAST-SECTXT-01": "WSTG-INFO-03",
                "DAST-ENV-01": "WSTG-CONF-04",
                # Injection & Attack
                "DAST-CORS-01": "WSTG-CLNT-07",
                "DAST-REDIR-01": "WSTG-CLNT-04",
                "DAST-HOST-01": "WSTG-INPV-17",
                "DAST-CRLF-01": "WSTG-INPV-15",
                "DAST-XSS-01": "WSTG-INPV-01",
                "DAST-SQLI-01": "WSTG-INPV-05",
                # HTTP Methods
                "DAST-METH-01": "WSTG-CONF-06",
                "DAST-TRACE-01": "WSTG-CONF-06",
                "DAST-ALLOW-01": "WSTG-CONF-06",
                # Forms & Auth
                "DAST-FORM-01": "WSTG-ATHN-06",
                "DAST-RATE-01": "WSTG-ATHN-03",
                # Misc
                "DAST-SRI-01": "WSTG-CLNT-13",
                "DAST-REF-01": "WSTG-CONF-07",
                "DAST-UIR-01": "WSTG-CONF-07",
                "DAST-REDIR-03": "WSTG-CLNT-04",
                "DAST-ST-01": "WSTG-INFO-02",
                "DAST-VIA-01": "WSTG-INFO-02",
                "DAST-XFF-01": "WSTG-INFO-02",
                "DAST-CORP-01": "WSTG-CONF-07",
                "DAST-CSD-01": "WSTG-CONF-07",
                "DAST-AGE-01": "WSTG-CONF-07",
                # Advanced checks
                "DAST-JWT-01": "WSTG-SESS-01",
                "DAST-CSRF-01": "WSTG-SESS-05",
                "DAST-CSP-01": "WSTG-CONF-07",
                "DAST-LFI-01": "WSTG-INPV-12",
                "DAST-SSRF-01": "WSTG-INPV-19",
                "DAST-CMDI-01": "WSTG-INPV-12",
                "DAST-CORS-02": "WSTG-CLNT-07",
                "DAST-SMUGGLE-01": "WSTG-CONF-07",
                # Modern OWASP 2021-2025 checks
                "DAST-DESER-01": "WSTG-INPV-12",
                "DAST-SSRF-02": "WSTG-INPV-19",
                "DAST-BAC-01": "WSTG-ATHZ-02",
                "DAST-MASS-01": "WSTG-INPV-11",
                "DAST-APIMISC-01": "WSTG-CONF-07",
                "DAST-SSTI-01": "WSTG-INPV-18",
                "DAST-PROTO-01": "WSTG-INPV-01",
                "DAST-DNSR-01": "WSTG-INPV-19",
                "DAST-CACHEP-01": "WSTG-ATHN-06",
                "DAST-CORSNULL-01": "WSTG-CLNT-07",
                # Exposure checks
                "DAST-CLOUD-01": "WSTG-CONF-04",
                "DAST-GIT-01": "WSTG-CONF-04",
                "DAST-ENVF-01": "WSTG-CONF-04",
                "DAST-DOCKER-01": "WSTG-CONF-04",
                "DAST-CICD-01": "WSTG-CONF-04",
                "DAST-SECRET-01": "WSTG-INFO-05",
                "DAST-GQL-01": "WSTG-INFO-10",
                "DAST-SRCMAP-01": "WSTG-INFO-05",
                # Network/Infrastructure checks
                "DAST-ADMIN-01": "WSTG-CONF-04",
                "DAST-DBEXP-01": "WSTG-CONF-04",
                "DAST-WS-01": "WSTG-CLNT-10",
                "DAST-SW-01": "WSTG-CLNT-13",
                "DAST-CSPBY-01": "WSTG-CONF-07",
                "DAST-SUBTO-01": "WSTG-CONF-10",
            }
            from datetime import datetime as dt
            for check in result["results"]:
                check_id = check.get("check_id", "")
                module_id = DAST_CHECK_TO_MODULE.get(check_id)
                if not module_id:
                    continue
                status_map = {"passed": "passed", "failed": "failed", "error": "failed"}
                new_status = status_map.get((check.get("status") or "").lower())
                if not new_status:
                    continue
                ptr_q = (
                    select(ProjectTestResult, TestCase)
                    .join(TestCase, ProjectTestResult.test_case_id == TestCase.id)
                    .where(
                        ProjectTestResult.project_id == project_uuid,
                        TestCase.module_id == module_id,
                        ProjectTestResult.is_applicable == True,
                    )
                    .limit(1)
                )
                ptr_rows = (await db.execute(ptr_q)).all()
                for ptr, tc in ptr_rows:
                    ptr.status = new_status
                    ptr.tester_id = user_id
                    ptr.completed_at = dt.utcnow()
                    if check.get("evidence"):
                        ptr.evidence = [{"filename": "dast_evidence", "url": "", "description": check["evidence"]}]
                    if check.get("request_raw"):
                        ptr.request_captured = check["request_raw"]
                    if check.get("response_raw"):
                        ptr.response_captured = check["response_raw"]
                    if check.get("reproduction_steps"):
                        ptr.reproduction_steps = check["reproduction_steps"]
                    ptr.tool_used = "DAST (Navigator)"
                    ptr.payload_used = check.get("evidence", "")
                    break  # Only update first match to avoid touching duplicates

            await db.commit()
        except Exception as e:
            logger.exception("DAST findings creation failed for %s", scan_id)
            await db.rollback()

        # Persist scan result to DB (survives tab close, refresh, offline)
        try:
            scan_record = DastScanResult(
                project_id=project_uuid,
                scan_id=scan_id,
                target_url=target_url,
                status="completed",
                results=result["results"],
                passed=result["passed"],
                failed=result["failed"],
                errors_count=result["errors"],
                duration_seconds=int(result.get("duration_seconds", 0) or 0),
                findings_created=len(findings_created),
                finding_titles=findings_created,
                created_by=user_id,
            )
            db.add(scan_record)
            await db.commit()
        except Exception as e:
            logger.warning("DAST scan result persist failed: %s", e)
            await db.rollback()

    cur = _dast_progress_get(scan_id)
    if cur:
        cur["findings_created"] = len(findings_created)
        cur["finding_titles"] = findings_created
        _dast_progress_set(scan_id, cur)


@router.post("/scan")
async def run_scan(
    payload: DastScanRequest,
    background_tasks: BackgroundTasks,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Start DAST scan in background. Returns scan_id for progress polling."""
    project_result = await db.execute(select(Project).where(Project.id == uuid.UUID(payload.project_id)))
    project = project_result.scalar_one_or_none()
    if not project:
        raise HTTPException(404, "Project not found")

    target_url = payload.target_url or project.application_url
    if not target_url:
        raise HTTPException(400, "No target URL configured for this project")
    from app.core.ssrf import is_ssrf_blocked_url
    if is_ssrf_blocked_url(target_url):
        raise HTTPException(400, "Target URL is not allowed (internal/private addresses are blocked for security)")

    scan_id = str(uuid.uuid4())
    # Seed progress in Redis immediately so first poll finds it (multi-worker safe)
    from app.services.dast_service import _dast_progress_set, ALL_CHECKS
    total = len(ALL_CHECKS) if not payload.checks else len(payload.checks)
    _dast_progress_set(scan_id, {
        "status": "running",
        "current_check": "Starting...",
        "completed_count": 0,
        "total": total,
        "results": [],
        "last_updated": __import__("time").time(),
        "project_id": payload.project_id,
        "target_url": target_url,
    })
    background_tasks.add_task(
        _run_scan_background,
        scan_id,
        payload.project_id,
        target_url,
        payload.checks,
        current_user.id,
    )
    return {"scan_id": scan_id, "project_id": payload.project_id, "target_url": target_url}


@router.get("/project/{project_id}/history")
async def get_scan_history(
    project_id: str,
    limit: int = 20,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return scan history for this project (last N scans)."""
    if not await user_can_read_project(db, current_user, project_id):
        raise HTTPException(403, "Access denied to this project")
    from sqlalchemy import desc
    r = await db.execute(
        select(DastScanResult)
        .where(DastScanResult.project_id == uuid.UUID(project_id), DastScanResult.status == "completed")
        .order_by(desc(DastScanResult.created_at))
        .limit(min(limit, 50))
    )
    rows = r.scalars().all()
    return {
        "scans": [
            {
                "id": str(row.id),
                "scan_id": row.scan_id,
                "target_url": row.target_url,
                "passed": row.passed,
                "failed": row.failed,
                "errors_count": row.errors_count,
                "total_checks": (row.passed or 0) + (row.failed or 0) + (row.errors_count or 0),
                "duration_seconds": row.duration_seconds,
                "findings_created": row.findings_created,
                "created_at": row.created_at.isoformat() if row.created_at else None,
            }
            for row in rows
        ],
    }


@router.get("/project/{project_id}/scan/{scan_id}")
async def get_scan_by_id(
    project_id: str,
    scan_id: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return a specific historical scan by scan_id. Used when user clicks on scan history."""
    if not await user_can_read_project(db, current_user, project_id):
        raise HTTPException(403, "Access denied")
    r = await db.execute(
        select(DastScanResult)
        .where(
            DastScanResult.project_id == uuid.UUID(project_id),
            DastScanResult.scan_id == scan_id,
            DastScanResult.status == "completed",
        )
    )
    row = r.scalar_one_or_none()
    if not row:
        raise HTTPException(404, "Scan not found")
    return {
        "scan_id": row.scan_id,
        "target_url": row.target_url,
        "total_checks": len(row.results or []),
        "passed": row.passed,
        "failed": row.failed,
        "errors": row.errors_count,
        "duration_seconds": row.duration_seconds,
        "results": row.results or [],
        "findings_created": row.findings_created or 0,
        "finding_titles": row.finding_titles or [],
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


@router.get("/project/{project_id}/latest")
async def get_latest_scan(
    project_id: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return the most recent completed DAST scan for this project. Used when user returns after scan ran in background."""
    if not await user_can_read_project(db, current_user, project_id):
        raise HTTPException(403, "Access denied to this project")
    from sqlalchemy import desc
    r = await db.execute(
        select(DastScanResult)
        .where(DastScanResult.project_id == uuid.UUID(project_id), DastScanResult.status == "completed")
        .order_by(desc(DastScanResult.created_at))
        .limit(1)
    )
    row = r.scalar_one_or_none()
    if not row:
        raise HTTPException(404, "No completed DAST scan found for this project")
    return {
        "target_url": row.target_url,
        "total_checks": len(row.results or []),
        "passed": row.passed,
        "failed": row.failed,
        "errors": row.errors_count,
        "duration_seconds": row.duration_seconds,
        "results": row.results or [],
        "findings_created": row.findings_created or 0,
        "finding_titles": row.finding_titles or [],
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


@router.get("/scans")
async def list_scans(current_user=Depends(get_current_user)):
    """List active and recent DAST scans for dashboard visibility."""
    from app.services.dast_service import list_dast_progress

    return {"scans": list_dast_progress()}


@router.get("/scan/{scan_id}")
async def get_scan_progress(
    scan_id: str,
    current_user=Depends(get_current_user),
):
    """Return scan progress or completed result. Poll every 1.5-2s while running."""
    from app.services.dast_service import get_dast_progress

    prog = get_dast_progress(scan_id)
    if not prog:
        raise HTTPException(404, "Scan not found or expired")
    return prog


@router.post("/check")
async def run_single_check(
    payload: DastSingleCheckRequest,
    current_user=Depends(get_current_user),
):
    """Run a single DAST check against any URL."""
    from app.services.dast_service import run_dast_scan
    result = run_dast_scan(payload.target_url, [payload.check])
    return result


@router.get("/checks")
async def list_available_checks(current_user=Depends(get_current_user)):
    """List available DAST checks."""
    from app.services.dast_service import ALL_CHECKS
    return {
        "checks": [
            {"id": name, "title": fn.__doc__.strip().split("\n")[0] if fn.__doc__ else name, "is_automated": True}
            for name, fn in ALL_CHECKS
        ]
    }


@router.post("/ffuf-scan")
async def run_ffuf_scan(
    payload: DastFfufScanRequest,
    current_user=Depends(get_current_user),
):
    """Run full ffuf wordlist scan on a base path (e.g. /api). For Directories Run Full Wordlist button."""
    from app.services.dast_service import run_ffuf_full_scan
    result = await asyncio.to_thread(
        run_ffuf_full_scan,
        payload.target_url,
        payload.base_path,
        payload.wordlist,
        300,
    )
    return result


def _ffuf_job_set(job_id: str, data: dict) -> None:
    try:
        import redis
        import json
        from app.core.config import get_settings
        r = redis.from_url(get_settings().redis_url, decode_responses=True)
        r.setex(f"dast:ffufjob:{job_id}", 3600, json.dumps(data, default=str))
    except Exception as e:
        logger.warning("ffuf job set failed: %s", e)


def _ffuf_job_get(job_id: str) -> dict | None:
    try:
        import redis
        import json
        from app.core.config import get_settings
        r = redis.from_url(get_settings().redis_url, decode_responses=True)
        raw = r.get(f"dast:ffufjob:{job_id}")
        if raw:
            return json.loads(raw)
    except Exception as e:
        logger.warning("ffuf job get failed: %s", e)
    return None


async def _run_ffuf_exhaustive_background(job_id: str, project_id: str, target_url: str, base_path: str, user_id: uuid.UUID):
    """Run exhaustive ffuf (all wordlists), update ProjectTestResult for MOD-RECON-04."""
    from app.services.dast_service import run_ffuf_exhaustive_scan
    _ffuf_job_set(job_id, {"status": "running", "current": "Starting exhaustive scan...", "last_updated": __import__("time").time()})
    try:
        result = await asyncio.to_thread(run_ffuf_exhaustive_scan, target_url, base_path, 300)
        discovered = result.get("discovered", [])
        evidence = ", ".join(f"{d['path']} (HTTP {d['status']})" for d in discovered[:20])
        if len(discovered) > 20:
            evidence += f" ... +{len(discovered) - 20} more"
        status = "failed" if discovered else "passed"
        ptr_updated = False
        async with AsyncSessionLocal() as db:
            from datetime import datetime as dt
            ptr_q = (
                select(ProjectTestResult, TestCase)
                .join(TestCase, ProjectTestResult.test_case_id == TestCase.id)
                .where(
                    ProjectTestResult.project_id == uuid.UUID(project_id),
                    TestCase.module_id == "MOD-RECON-04",
                    ProjectTestResult.is_applicable == True,
                )
                .limit(1)
            )
            ptr_rows = (await db.execute(ptr_q)).all()
            for ptr, _ in ptr_rows:
                ptr_updated = True
                ptr.status = status
                ptr.tester_id = user_id
                ptr.completed_at = dt.utcnow()
                ptr.evidence = [{"filename": "dast_ffuf_exhaustive", "url": "", "description": evidence or "No paths discovered", "discovered": discovered}]
                ptr.request_captured = f"Exhaustive ffuf: {target_url}{base_path or '/'}"
                ptr.response_captured = f"Discovered {len(discovered)} path(s)"
                ptr.reproduction_steps = f"1. Run exhaustive directory bruteforce on {target_url}{base_path or '/'}\n2. Wordlists: {result.get('wordlists_used', [])}\n3. Paths: {evidence}"
                ptr.tool_used = "DAST (Navigator) ffuf exhaustive"
                ptr.payload_used = evidence
                break
            await db.commit()
        _ffuf_job_set(job_id, {
            "status": "completed",
            "discovered": discovered,
            "wordlists_used": result.get("wordlists_used", []),
            "test_case_updated": ptr_updated,
            "last_updated": __import__("time").time(),
        })
    except Exception as e:
        logger.exception("ffuf exhaustive failed: %s", e)
        _ffuf_job_set(job_id, {"status": "error", "error": str(e)[:200], "last_updated": __import__("time").time()})


@router.post("/ffuf-exhaustive")
async def run_ffuf_exhaustive(
    payload: DastFfufExhaustiveRequest,
    background_tasks: BackgroundTasks,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Run exhaustive directory bruteforce (all wordlists) in background. Auto-marks MOD-RECON-04 (Directory Discovery) test case."""
    if not await user_can_read_project(db, current_user, payload.project_id):
        raise HTTPException(403, "Access denied")
    job_id = str(uuid.uuid4())
    background_tasks.add_task(
        _run_ffuf_exhaustive_background,
        job_id,
        payload.project_id,
        payload.target_url,
        payload.base_path or "/",
        current_user.id,
    )
    return {"job_id": job_id, "status": "running", "message": "Exhaustive scan started in background"}


@router.get("/ffuf-exhaustive/{job_id}")
async def get_ffuf_exhaustive_progress(
    job_id: str,
    current_user=Depends(get_current_user),
):
    """Poll exhaustive ffuf job status. Returns status, discovered, test_case_updated when complete."""
    data = _ffuf_job_get(job_id)
    if not data:
        raise HTTPException(404, "Job not found or expired")
    return data


@router.get("/project/{project_id}/last-discovered-paths")
async def get_last_discovered_paths(
    project_id: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return last exhaustive/discovery paths from ProjectTestResult (MOD-RECON-04). Survives page reload."""
    if not await user_can_read_project(db, current_user, project_id):
        raise HTTPException(403, "Access denied")
    ptr_q = (
        select(ProjectTestResult)
        .join(TestCase, ProjectTestResult.test_case_id == TestCase.id)
        .where(
            ProjectTestResult.project_id == uuid.UUID(project_id),
            TestCase.module_id == "MOD-RECON-04",
            ProjectTestResult.is_applicable == True,
        )
        .order_by(ProjectTestResult.completed_at.desc().nullslast())
        .limit(1)
    )
    ptr = (await db.execute(ptr_q)).scalar_one_or_none()
    discovered = []
    wordlists_used = []
    if ptr and ptr.evidence:
        for ev in ptr.evidence if isinstance(ptr.evidence, list) else []:
            if isinstance(ev, dict) and ev.get("discovered"):
                discovered = ev["discovered"]
                break
    return {"discovered": discovered, "wordlists_used": wordlists_used}


@router.get("/project/{project_id}/last-dir-scan")
async def get_last_dir_scan(
    project_id: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return last recursive directory scan from CrawlSession (crawl_type=directory). Survives reload/logout."""
    if not await user_can_read_project(db, current_user, project_id):
        raise HTTPException(403, "Access denied")
    q = (
        select(CrawlSession)
        .where(CrawlSession.project_id == uuid.UUID(project_id), CrawlSession.crawl_type == "directory")
        .order_by(desc(CrawlSession.created_at))
        .limit(1)
    )
    row = (await db.execute(q)).scalar_one_or_none()
    if not row:
        return {"flat": [], "total_found": 0, "target_url": ""}
    flat = list(row.directory_flat or [])
    # Normalize to {path, status} for frontend tree
    normalized = [{"path": x.get("path", x) if isinstance(x, dict) else str(x), "status": x.get("status", 200) if isinstance(x, dict) else 200} for x in flat if (isinstance(x, dict) and x.get("path")) or (isinstance(x, str) and x)]
    return {"flat": normalized, "total_found": len(normalized), "target_url": row.target_url or ""}


# ──────────────────────────────────────────────────────────
#  Spider / Crawler Endpoints
# ──────────────────────────────────────────────────────────

async def _run_crawl_background(
    crawl_id: str, project_id: str, target_url: str,
    auth_config: dict | None, max_depth: int, crawl_scope: str,
    run_param_discovery: bool, use_playwright: bool, user_id: uuid.UUID,
):
    """Run crawler in background, persist results to CrawlSession."""
    from app.services.dast.crawler import run_crawl, _crawl_progress_set
    _crawl_progress_set(crawl_id, {
        "status": "running", "phase": "starting", "pct": 0,
        "message": "Initializing crawler...", "last_updated": __import__("time").time(),
        "project_id": project_id,
    })
    try:
        result = await asyncio.to_thread(
            run_crawl, target_url, auth_config, max_depth, crawl_scope,
            None, crawl_id, 600, run_param_discovery, use_playwright,
        )
    except Exception as e:
        logger.exception("Crawl %s failed", crawl_id)
        _crawl_progress_set(crawl_id, {
            "status": "error", "error": str(e)[:300],
            "last_updated": __import__("time").time(), "project_id": project_id,
        })
        return

    # Persist to DB
    project_uuid = uuid.UUID(project_id)
    async with AsyncSessionLocal() as db:
        try:
            stats = result.get("stats", {})
            session = CrawlSession(
                project_id=project_uuid,
                crawl_id=crawl_id,
                target_url=target_url,
                status="completed",
                crawl_type="authenticated" if auth_config else "full",
                auth_type=(auth_config or {}).get("type", "none"),
                urls=result.get("urls", []),
                api_endpoints=result.get("api_endpoints", []),
                parameters=result.get("parameters", []),
                forms=result.get("forms", []),
                js_files=result.get("js_files", []),
                pages=result.get("pages", []),
                deeplinks=result.get("deeplinks", []),
                js_sca=result.get("js_sca"),
                retire_results=result.get("retire_results"),
                crawler_used=stats.get("crawler_used"),
                total_urls=stats.get("total_urls", 0),
                total_endpoints=stats.get("api_endpoints", 0),
                total_parameters=stats.get("parameters", 0),
                total_forms=stats.get("forms", 0),
                total_js_files=stats.get("js_files", 0),
                duration_seconds=int(stats.get("duration_seconds", 0)),
                max_depth=max_depth,
                crawl_scope=crawl_scope,
                created_by=user_id,
            )
            db.add(session)
            await db.commit()
        except Exception as e:
            logger.warning("Crawl session persist failed: %s", e)
            await db.rollback()

    # Update progress with final results
    _crawl_progress_set(crawl_id, {
        "status": "completed",
        "phase": "done",
        "pct": 100,
        "message": f"Crawl complete — {stats.get('total_urls', 0)} URLs discovered",
        "last_updated": __import__("time").time(),
        "project_id": project_id,
        "stats": stats,
        "urls": result.get("urls", [])[:500],
        "api_endpoints": result.get("api_endpoints", [])[:200],
        "parameters": result.get("parameters", [])[:200],
        "forms": result.get("forms", [])[:100],
        "js_files": result.get("js_files", [])[:100],
        "pages": result.get("pages", [])[:200],
        "deeplinks": result.get("deeplinks", []),
        "js_sca": result.get("js_sca"),
        "retire_results": result.get("retire_results"),
    })


@router.post("/crawl")
async def start_crawl(
    payload: CrawlRequest,
    background_tasks: BackgroundTasks,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Start spider/crawler in background. Returns crawl_id for progress polling."""
    project = (await db.execute(select(Project).where(Project.id == uuid.UUID(payload.project_id)))).scalar_one_or_none()
    if not project:
        raise HTTPException(404, "Project not found")
    target_url = payload.target_url or project.application_url
    if not target_url:
        raise HTTPException(400, "No target URL configured")
    from app.core.ssrf import is_ssrf_blocked_url
    if is_ssrf_blocked_url(target_url):
        raise HTTPException(400, "Target URL is not allowed (internal/private addresses are blocked for security)")

    crawl_id = str(uuid.uuid4())
    background_tasks.add_task(
        _run_crawl_background, crawl_id, payload.project_id, target_url,
        payload.auth_config, payload.max_depth, payload.crawl_scope,
        payload.run_param_discovery, payload.use_playwright, current_user.id,
    )
    return {"crawl_id": crawl_id, "project_id": payload.project_id, "target_url": target_url}


@router.get("/crawl/{crawl_id}")
async def get_crawl_progress(
    crawl_id: str,
    current_user=Depends(get_current_user),
):
    """Poll crawl progress. Returns live stats and discovered URLs."""
    from app.services.dast.crawler import get_crawl_progress as _get_progress
    prog = _get_progress(crawl_id)
    if not prog:
        raise HTTPException(404, "Crawl not found or expired")
    return prog


@router.get("/crawl/project/{project_id}/history")
async def get_crawl_history(
    project_id: str,
    limit: int = 20,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return crawl session history for a project."""
    if not await user_can_read_project(db, current_user, project_id):
        raise HTTPException(403, "Access denied")
    from sqlalchemy import desc
    r = await db.execute(
        select(CrawlSession)
        .where(CrawlSession.project_id == uuid.UUID(project_id))
        .order_by(desc(CrawlSession.created_at))
        .limit(min(limit, 50))
    )
    rows = r.scalars().all()
    return {
        "sessions": [
            {
                "id": str(row.id),
                "crawl_id": row.crawl_id,
                "target_url": row.target_url,
                "status": row.status,
                "crawl_type": row.crawl_type,
                "auth_type": row.auth_type,
                "crawler_used": getattr(row, "crawler_used", None),
                "total_urls": row.total_urls,
                "total_endpoints": row.total_endpoints,
                "total_parameters": row.total_parameters,
                "total_forms": row.total_forms,
                "total_js_files": row.total_js_files,
                "duration_seconds": row.duration_seconds,
                "max_depth": row.max_depth,
                "created_at": row.created_at.isoformat() if row.created_at else None,
            }
            for row in rows
        ]
    }


@router.get("/crawl/project/{project_id}/latest")
async def get_latest_crawl(
    project_id: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return the most recent completed crawl session for this project."""
    if not await user_can_read_project(db, current_user, project_id):
        raise HTTPException(403, "Access denied")
    from sqlalchemy import desc
    r = await db.execute(
        select(CrawlSession)
        .where(CrawlSession.project_id == uuid.UUID(project_id), CrawlSession.status == "completed")
        .order_by(desc(CrawlSession.created_at))
        .limit(1)
    )
    row = r.scalar_one_or_none()
    if not row:
        raise HTTPException(404, "No completed crawl found")
    return {
        "crawl_id": row.crawl_id,
        "target_url": row.target_url,
        "crawl_type": row.crawl_type,
        "auth_type": row.auth_type,
        "urls": row.urls or [],
        "api_endpoints": row.api_endpoints or [],
        "parameters": row.parameters or [],
        "forms": row.forms or [],
        "js_files": row.js_files or [],
        "pages": row.pages or [],
        "deeplinks": getattr(row, "deeplinks", None) or [],
        "js_sca": getattr(row, "js_sca", None),
        "retire_results": getattr(row, "retire_results", None),
        "crawler_used": getattr(row, "crawler_used", None),
        "total_urls": row.total_urls,
        "total_endpoints": row.total_endpoints,
        "total_parameters": row.total_parameters,
        "duration_seconds": row.duration_seconds,
        "max_depth": row.max_depth,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


@router.get("/crawl/project/{project_id}/session/{crawl_id}")
async def get_crawl_session(
    project_id: str,
    crawl_id: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return a specific crawl session by crawl_id."""
    if not await user_can_read_project(db, current_user, project_id):
        raise HTTPException(403, "Access denied")
    r = await db.execute(
        select(CrawlSession).where(
            CrawlSession.project_id == uuid.UUID(project_id),
            CrawlSession.crawl_id == crawl_id,
        )
    )
    row = r.scalar_one_or_none()
    if not row:
        raise HTTPException(404, "Crawl session not found")
    return {
        "crawl_id": row.crawl_id,
        "target_url": row.target_url,
        "status": row.status,
        "crawl_type": row.crawl_type,
        "auth_type": row.auth_type,
        "urls": row.urls or [],
        "api_endpoints": row.api_endpoints or [],
        "parameters": row.parameters or [],
        "forms": row.forms or [],
        "js_files": row.js_files or [],
        "pages": row.pages or [],
        "deeplinks": getattr(row, "deeplinks", None) or [],
        "js_sca": getattr(row, "js_sca", None),
        "retire_results": getattr(row, "retire_results", None),
        "crawler_used": getattr(row, "crawler_used", None),
        "directory_tree": row.directory_tree or [],
        "directory_flat": row.directory_flat or [],
        "total_urls": row.total_urls,
        "total_endpoints": row.total_endpoints,
        "total_parameters": row.total_parameters,
        "total_forms": row.total_forms,
        "total_js_files": row.total_js_files,
        "duration_seconds": row.duration_seconds,
        "max_depth": row.max_depth,
        "error": row.error,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


# ──────────────────────────────────────────────────────────
#  Recursive Directory Scanning
# ──────────────────────────────────────────────────────────

def _dir_job_set(job_id: str, data: dict) -> None:
    try:
        import redis, json
        from app.core.config import get_settings
        r = redis.from_url(get_settings().redis_url, decode_responses=True)
        r.setex(f"dast:dirjob:{job_id}", 7200, json.dumps(data, default=str))
    except Exception as e:
        logger.warning("dir job set failed: %s", e)


def _dir_job_get(job_id: str) -> dict | None:
    try:
        import redis, json
        from app.core.config import get_settings
        r = redis.from_url(get_settings().redis_url, decode_responses=True)
        raw = r.get(f"dast:dirjob:{job_id}")
        return json.loads(raw) if raw else None
    except Exception as e:
        logger.warning("dir job get failed: %s", e)
    return None


async def _run_recursive_dir_background(
    job_id: str, project_id: str, target_url: str, base_path: str,
    max_depth: int, wordlist_key: str, auth_config: dict | None, user_id: uuid.UUID,
):
    """Run recursive directory scan in background."""
    from app.services.dast.crawler import run_recursive_directory_scan
    _dir_job_set(job_id, {
        "status": "running", "message": f"Scanning {base_path} (depth 0/{max_depth})...",
        "last_updated": __import__("time").time(),
    })
    try:
        def on_progress(info):
            _dir_job_set(job_id, {
                "status": "running",
                "message": info.get("message", "Scanning..."),
                "current_depth": info.get("depth", 0),
                "paths_found": info.get("paths_found", 0),
                "last_updated": __import__("time").time(),
            })

        result = await asyncio.to_thread(
            run_recursive_directory_scan, target_url, base_path, max_depth,
            wordlist_key, auth_config, on_progress, job_id,
        )

        # Persist to CrawlSession
        async with AsyncSessionLocal() as db:
            session = CrawlSession(
                project_id=uuid.UUID(project_id),
                crawl_id=job_id,
                target_url=target_url,
                status="completed",
                crawl_type="directory",
                auth_type=(auth_config or {}).get("type", "none"),
                directory_tree=result.get("tree", []),
                directory_flat=result.get("flat", []),
                total_urls=len(result.get("flat", [])),
                duration_seconds=int(result.get("duration_seconds", 0)),
                max_depth=max_depth,
                created_by=user_id,
            )
            db.add(session)
            await db.commit()

        _dir_job_set(job_id, {
            "status": "completed",
            "tree": result.get("tree", []),
            "flat": result.get("flat", []),
            "total_found": len(result.get("flat", [])),
            "duration_seconds": result.get("duration_seconds", 0),
            "depths_scanned": result.get("depths_scanned", 0),
            "last_updated": __import__("time").time(),
        })
    except Exception as e:
        logger.exception("Recursive dir scan failed: %s", e)
        _dir_job_set(job_id, {"status": "error", "error": str(e)[:300], "last_updated": __import__("time").time()})


@router.post("/dir-scan")
async def start_recursive_dir_scan(
    payload: RecursiveDirScanRequest,
    background_tasks: BackgroundTasks,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Start recursive directory scan with depth control. Returns job_id for polling."""
    if not await user_can_read_project(db, current_user, payload.project_id):
        raise HTTPException(403, "Access denied")
    from app.core.ssrf import is_ssrf_blocked_url
    if is_ssrf_blocked_url(payload.target_url or ""):
        raise HTTPException(400, "Target URL is not allowed (internal/private addresses are blocked for security)")
    job_id = str(uuid.uuid4())
    background_tasks.add_task(
        _run_recursive_dir_background, job_id, payload.project_id,
        payload.target_url, payload.base_path, min(payload.max_depth, 5),
        payload.wordlist, payload.auth_config, current_user.id,
    )
    return {"job_id": job_id, "status": "running"}


@router.get("/dir-scan/{job_id}")
async def get_dir_scan_progress(
    job_id: str,
    current_user=Depends(get_current_user),
):
    """Poll recursive directory scan progress."""
    data = _dir_job_get(job_id)
    if not data:
        raise HTTPException(404, "Job not found or expired")
    return data


@router.post("/fetch-url")
async def fetch_url_content_endpoint(
    payload: FetchUrlRequest,
    current_user=Depends(get_current_user),
):
    """Fetch URL content with request/response for viewing file contents in directory tree."""
    from app.services.dast.crawler import fetch_url_content
    result = await asyncio.to_thread(fetch_url_content, payload.url, payload.auth_config)
    return result


# ──────────────────────────────────────────────────────────
#  AI-Powered DAST Analysis Endpoints
# ──────────────────────────────────────────────────────────

class AIScanSummaryRequest(BaseModel):
    project_id: str
    scan_id: str | None = None


class AICrawlAnalysisRequest(BaseModel):
    project_id: str
    crawl_id: str | None = None


class AISuggestChecksRequest(BaseModel):
    project_id: str
    target_url: str | None = None


class AICategorizePaths(BaseModel):
    project_id: str
    paths: list[dict] = []
    target_url: str = ""


class AIInterpretResultRequest(BaseModel):
    check_result: dict
    target_url: str


async def _get_llm_config(db: AsyncSession) -> tuple[str, str, str]:
    """Get LLM config, defaulting to Gemini if available."""
    from app.services.admin_settings_service import get_llm_config
    provider, model, api_key = await get_llm_config(db)
    if not api_key:
        from app.core.config import get_settings
        s = get_settings()
        if s.google_api_key:
            return "google", "gemini-2.5-flash", s.google_api_key
    return provider, model, api_key or ""


@router.post("/ai/summarize-scan")
async def ai_summarize_scan(
    payload: AIScanSummaryRequest,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Generate AI summary of DAST scan results."""
    if not await user_can_read_project(db, current_user, payload.project_id):
        raise HTTPException(403, "Access denied")
    from app.services.dast.ai_analysis import summarize_scan

    if payload.scan_id:
        r = await db.execute(
            select(DastScanResult).where(
                DastScanResult.project_id == uuid.UUID(payload.project_id),
                DastScanResult.scan_id == payload.scan_id,
            )
        )
    else:
        r = await db.execute(
            select(DastScanResult)
            .where(DastScanResult.project_id == uuid.UUID(payload.project_id), DastScanResult.status == "completed")
            .order_by(desc(DastScanResult.created_at))
            .limit(1)
        )
    row = r.scalar_one_or_none()
    if not row or not row.results:
        raise HTTPException(404, "No scan results found")

    provider, model, api_key = await _get_llm_config(db)
    result = await asyncio.to_thread(
        summarize_scan, row.results, row.target_url,
        provider=provider, model=model, api_key=api_key,
    )
    return result


@router.post("/ai/analyze-crawl")
async def ai_analyze_crawl(
    payload: AICrawlAnalysisRequest,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """AI analysis of crawl output — attack surface, high-value targets, parameter risks."""
    if not await user_can_read_project(db, current_user, payload.project_id):
        raise HTTPException(403, "Access denied")
    from app.services.dast.ai_analysis import analyze_crawl_output

    if payload.crawl_id:
        r = await db.execute(
            select(CrawlSession).where(
                CrawlSession.project_id == uuid.UUID(payload.project_id),
                CrawlSession.crawl_id == payload.crawl_id,
            )
        )
    else:
        r = await db.execute(
            select(CrawlSession)
            .where(CrawlSession.project_id == uuid.UUID(payload.project_id), CrawlSession.status == "completed")
            .order_by(desc(CrawlSession.created_at))
            .limit(1)
        )
    row = r.scalar_one_or_none()
    if not row:
        raise HTTPException(404, "No crawl session found")

    provider, model, api_key = await _get_llm_config(db)
    result = await asyncio.to_thread(
        analyze_crawl_output,
        row.urls or [], row.api_endpoints or [], row.parameters or [],
        row.forms or [], row.js_files or [], row.target_url,
        provider=provider, model=model, api_key=api_key,
    )
    return result


@router.post("/ai/suggest-checks")
async def ai_suggest_checks(
    payload: AISuggestChecksRequest,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """AI-powered check suggestion based on project context."""
    if not await user_can_read_project(db, current_user, payload.project_id):
        raise HTTPException(403, "Access denied")
    from app.services.dast.ai_analysis import suggest_checks

    project = (await db.execute(select(Project).where(Project.id == uuid.UUID(payload.project_id)))).scalar_one_or_none()
    if not project:
        raise HTTPException(404, "Project not found")

    target_url = payload.target_url or project.application_url
    stack_profile = project.stack_profile if hasattr(project, "stack_profile") else {}

    crawl_stats = None
    latest_crawl = await db.execute(
        select(CrawlSession)
        .where(CrawlSession.project_id == uuid.UUID(payload.project_id), CrawlSession.status == "completed")
        .order_by(desc(CrawlSession.created_at))
        .limit(1)
    )
    crawl_row = latest_crawl.scalar_one_or_none()
    if crawl_row:
        crawl_stats = {
            "total_urls": crawl_row.total_urls,
            "total_endpoints": crawl_row.total_endpoints,
            "total_parameters": crawl_row.total_parameters,
            "total_forms": crawl_row.total_forms,
        }

    provider, model, api_key = await _get_llm_config(db)
    result = await asyncio.to_thread(
        suggest_checks, target_url, stack_profile, crawl_stats,
        provider=provider, model=model, api_key=api_key,
    )
    return result


@router.post("/ai/categorize-paths")
async def ai_categorize_paths(
    payload: AICategorizePaths,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """AI categorization of discovered directory paths."""
    if not await user_can_read_project(db, current_user, payload.project_id):
        raise HTTPException(403, "Access denied")
    from app.services.dast.ai_analysis import categorize_paths

    provider, model, api_key = await _get_llm_config(db)
    result = await asyncio.to_thread(
        categorize_paths, payload.paths, payload.target_url,
        provider=provider, model=model, api_key=api_key,
    )
    return result


@router.post("/ai/interpret-result")
async def ai_interpret_result(
    payload: AIInterpretResultRequest,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """AI interpretation of a single DAST check result."""
    from app.services.dast.ai_analysis import interpret_scan_result

    provider, model, api_key = await _get_llm_config(db)
    result = await asyncio.to_thread(
        interpret_scan_result, payload.check_result, payload.target_url,
        provider=provider, model=model, api_key=api_key,
    )
    return result


class AICoverageGapsRequest(BaseModel):
    project_id: str
    target_url: str | None = None


@router.post("/ai/coverage-gaps")
async def ai_coverage_gaps(
    payload: AICoverageGapsRequest,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Analyze test coverage gaps: compare crawl output vs existing test results."""
    if not await user_can_read_project(db, current_user, payload.project_id):
        raise HTTPException(403, "Access denied")

    project_uuid = uuid.UUID(payload.project_id)
    project = (await db.execute(select(Project).where(Project.id == project_uuid))).scalar_one_or_none()
    if not project:
        raise HTTPException(404, "Project not found")

    latest_crawl = await db.execute(
        select(CrawlSession)
        .where(CrawlSession.project_id == project_uuid, CrawlSession.status == "completed")
        .order_by(desc(CrawlSession.created_at)).limit(1)
    )
    crawl = latest_crawl.scalar_one_or_none()

    tested_q = await db.execute(
        select(ProjectTestResult)
        .where(ProjectTestResult.project_id == project_uuid, ProjectTestResult.status.in_(["passed", "failed"]))
    )
    tested_count = len(tested_q.scalars().all())

    total_q = await db.execute(
        select(ProjectTestResult).where(ProjectTestResult.project_id == project_uuid, ProjectTestResult.is_applicable == True)
    )
    total_applicable = len(total_q.scalars().all())

    latest_scan = await db.execute(
        select(DastScanResult)
        .where(DastScanResult.project_id == project_uuid, DastScanResult.status == "completed")
        .order_by(desc(DastScanResult.created_at)).limit(1)
    )
    scan = latest_scan.scalar_one_or_none()
    checks_run = len(scan.results) if scan and scan.results else 0

    from app.services.dast_service import ALL_CHECKS
    total_checks = len(ALL_CHECKS)

    crawl_stats = {}
    if crawl:
        crawl_stats = {
            "total_urls": crawl.total_urls or 0,
            "api_endpoints": crawl.total_endpoints or 0,
            "parameters": crawl.total_parameters or 0,
            "forms": crawl.total_forms or 0,
            "js_files": crawl.total_js_files or 0,
        }

    provider, model, api_key = await _get_llm_config(db)
    if not api_key:
        return {
            "test_coverage_pct": round((tested_count / total_applicable * 100) if total_applicable else 0, 1),
            "dast_coverage_pct": round((checks_run / total_checks * 100) if total_checks else 0, 1),
            "tested": tested_count,
            "total_applicable": total_applicable,
            "checks_run": checks_run,
            "total_checks": total_checks,
            "crawl_stats": crawl_stats,
            "gaps": [],
            "recommendations": ["Run a full DAST scan", "Complete manual test cases"],
        }

    from app.services.dast.ai_analysis import _call_llm, _parse_json
    import json
    prompt = f"""You are a security testing expert. Analyze the test coverage gaps for this project.

Project: {project.application_name} ({project.application_url})
Test Coverage: {tested_count}/{total_applicable} test cases completed ({round((tested_count/total_applicable*100) if total_applicable else 0)}%)
DAST Coverage: {checks_run}/{total_checks} automated checks run ({round((checks_run/total_checks*100) if total_checks else 0)}%)
Crawl Stats: {json.dumps(crawl_stats)}
Has Crawl Data: {"Yes" if crawl else "No"}
Has DAST Scan: {"Yes" if scan else "No"}

Identify coverage gaps and prioritize what should be tested next.
Respond in JSON:
{{"gaps": [{{"area": "area name", "severity": "critical|high|medium", "description": "what is missing"}}], "recommendations": ["specific action 1", "specific action 2"], "priority_tests": ["test_type_1", "test_type_2"], "overall_coverage_assessment": "brief assessment"}}"""

    raw = await asyncio.to_thread(_call_llm, provider, model, api_key, prompt)
    parsed = _parse_json(raw)

    base = {
        "test_coverage_pct": round((tested_count / total_applicable * 100) if total_applicable else 0, 1),
        "dast_coverage_pct": round((checks_run / total_checks * 100) if total_checks else 0, 1),
        "tested": tested_count,
        "total_applicable": total_applicable,
        "checks_run": checks_run,
        "total_checks": total_checks,
        "crawl_stats": crawl_stats,
    }
    if parsed and isinstance(parsed, dict):
        return {**base, **parsed}
    return {**base, "gaps": [], "recommendations": ["Run full DAST scan", "Complete manual test cases"]}


# ─── Claude AI DAST Endpoints ─────────────────────────────────────────────────


class ClaudeScanRequest(BaseModel):
    project_id: str
    target_url: str | None = None
    scan_mode: str = "standard"  # quick, standard, deep
    include_subdomains: bool = False
    max_cost_usd: float | None = None  # Override per-scan limit
    auth_config: dict | None = None  # Grey-box auth: {type, token, cookie_string, username, password, ...}
    proxy_url: str | None = None  # HTTP/SOCKS5 proxy for internal targets (e.g., socks5://127.0.0.1:1080)


class ClaudeRetestRequest(BaseModel):
    project_id: str
    finding_ids: list[str]  # UUIDs of findings to retest
    target_url: str | None = None


class ClaudeCrawlOnlyRequest(BaseModel):
    project_id: str
    target_url: str | None = None
    include_subdomains: bool = False


class ClaudeGenerateChecksRequest(BaseModel):
    project_id: str
    target_url: str | None = None


class ClaudePentestOptionRequest(BaseModel):
    option_id: str
    selected_action: str  # The action the user selected


class ClaudeCostEstimateRequest(BaseModel):
    scan_mode: str = "standard"
    target_url: str = ""
    include_subdomains: bool = False


async def _run_claude_scan_background(
    scan_id: str,
    project_id: str,
    target_url: str,
    scan_mode: str,
    include_subdomains: bool,
    max_cost_usd: float,
    user_id: uuid.UUID,
    auth_config: dict | None = None,
    proxy_url: str | None = None,
):
    """Run Claude AI DAST scan as background task."""
    import time
    import json
    from datetime import datetime
    from app.core.config import get_settings
    from app.services.dast.runner import _dast_progress_set
    from app.models.claude_scan_session import ClaudeScanSession
    from app.models.claude_crawl_result import ClaudeCrawlResult

    settings = get_settings()
    api_key = settings.anthropic_api_key

    # Try org-level API key first
    try:
        from app.models.organization import Organization
        async with AsyncSessionLocal() as _db:
            project_row = (await _db.execute(
                select(Project).where(Project.id == uuid.UUID(project_id))
            )).scalar_one_or_none()
            if project_row and hasattr(project_row, "organization_id") and project_row.organization_id:
                org_row = (await _db.execute(
                    select(Organization).where(Organization.id == project_row.organization_id)
                )).scalar_one_or_none()
                if org_row and org_row.claude_dast_api_key:
                    api_key = org_row.claude_dast_api_key
    except Exception:
        pass  # Fall back to global key

    if not api_key:
        _dast_progress_set(scan_id, {
            "status": "error",
            "error": "Anthropic API key not configured. Set it in Admin > AI Usage > Per-Organization settings.",
            "last_updated": time.time(),
        })
        return

    # Build project context
    project_context = {}
    async with AsyncSessionLocal() as db:
        try:
            project = (await db.execute(
                select(Project).where(Project.id == uuid.UUID(project_id))
            )).scalar_one_or_none()
            if not project:
                _dast_progress_set(scan_id, {"status": "error", "error": "Project not found"})
                return

            if not target_url:
                target_url = project.application_url
            if not target_url:
                _dast_progress_set(scan_id, {"status": "error", "error": "No target URL"})
                return

            # Load existing findings for dedup / FP awareness
            existing_findings_q = await db.execute(
                select(Finding).where(
                    Finding.project_id == uuid.UUID(project_id),
                    Finding.affected_url == target_url,
                ).limit(50)
            )
            existing_findings = [
                {
                    "title": f.title, "severity": f.severity, "status": f.status,
                    "affected_url": f.affected_url, "cwe_id": f.cwe_id,
                }
                for f in existing_findings_q.scalars().all()
            ]

            project_context = {
                "project_name": project.application_name,
                "testing_scope": f"{target_url} and same-origin resources",
                "include_subdomains": include_subdomains,
                "stack_profile": project.technology_stack if hasattr(project, "technology_stack") else {},
                "existing_findings": existing_findings,
            }
        except Exception as e:
            logger.exception("Claude scan context build failed: %s", e)
            _dast_progress_set(scan_id, {"status": "error", "error": str(e)[:300]})
            return

    # Load session context from Redis
    session_context = None
    try:
        import redis as redis_lib
        r = redis_lib.from_url(settings.redis_url, decode_responses=True)
        session_key = f"claude:session:{project_id}"
        raw = r.get(session_key)
        if raw:
            session_context = json.loads(raw)
    except Exception:
        pass

    # Resolve auth config if provided
    resolved_auth = {"headers": {}, "cookies": {}, "auth_type": "none"}
    if auth_config:
        try:
            from app.services.dast.auth_resolver import resolve_auth
            resolved_auth = await resolve_auth(auth_config)
        except Exception as e:
            logger.warning("Auth resolution failed: %s", e)

    # Get organization_id for RAG
    org_id = ""
    try:
        async with AsyncSessionLocal() as _db2:
            _proj = (await _db2.execute(select(Project).where(Project.id == uuid.UUID(project_id)))).scalar_one_or_none()
            if _proj and _proj.organization_id:
                org_id = str(_proj.organization_id)
    except Exception:
        pass

    # Create and run the agent
    try:
        from app.services.dast.claude_agent import ClaudeDastAgent
        from app.services.dast.claude_executor import ClaudeToolExecutor

        agent = ClaudeDastAgent(
            anthropic_api_key=api_key,
            project_id=project_id,
            scan_id=scan_id,
            scan_mode=scan_mode,
            max_cost_usd=max_cost_usd,
            max_api_calls=settings.claude_dast_max_api_calls,
            auth_headers=resolved_auth.get("headers", {}),
            auth_type=resolved_auth.get("auth_type", "none"),
            organization_id=org_id,
        )

        executor = ClaudeToolExecutor(
            project_id=project_id,
            scan_id=scan_id,
            target_url=target_url,
            scope_domain=target_url,
            auth_headers=resolved_auth.get("headers", {}),
            organization_id=org_id,
            proxy_url=proxy_url,
        )
        agent.set_executor(executor)

        # Progress callback → Redis (also update session context periodically)
        _last_session_update = [0.0]
        def _progress_cb(data: dict):
            _dast_progress_set(scan_id, {**data, "project_id": project_id, "target_url": target_url})
            # Update session context every 30s so Session tab shows live info
            now = time.time()
            if now - _last_session_update[0] > 30:
                _last_session_update[0] = now
                try:
                    import redis as redis_lib
                    _r = redis_lib.from_url(settings.redis_url, decode_responses=True)
                    _r.setex(f"claude:session:{project_id}", settings.claude_dast_session_ttl_days * 86400, json.dumps({
                        "project_id": project_id, "target_url": target_url,
                        "summary": f"Scanning... {data.get('findings_so_far', 0)} findings, {data.get('pages_crawled', 0)} pages crawled",
                        "last_scan_id": scan_id, "last_scan_at": now, "status": "running",
                        "scan_count": 1, "discovered_endpoints_count": data.get("pages_crawled", 0),
                    }, default=str))
                except Exception:
                    pass
        agent.set_progress_callback(_progress_cb)

        result = await agent.run_intelligent_scan(
            target_url=target_url,
            project_context=project_context,
            session_context=session_context,
        )
    except Exception as e:
        logger.exception("Claude scan %s failed: %s", scan_id, e)
        _dast_progress_set(scan_id, {
            "status": "error", "error": str(e)[:500],
            "project_id": project_id, "target_url": target_url,
            "last_updated": time.time(),
        })
        return

    # Persist findings using the same pipeline as regular DAST
    project_uuid = uuid.UUID(project_id)
    findings_created = []
    async with AsyncSessionLocal() as db:
        try:
            for finding_data in result.get("findings", []):
                title = f"[Claude DAST] {finding_data.get('title', 'Unknown')}"
                affected = finding_data.get("affected_url", target_url)
                # Smart dedup: fingerprint-based first, then fallback to exact match
                fp = _finding_fingerprint(
                    finding_data.get("cwe_id", ""), affected,
                    finding_data.get("affected_parameter", ""), title,
                )
                existing_row = None
                # Try fingerprint match
                fp_q = await db.execute(
                    select(Finding).where(
                        Finding.project_id == project_uuid,
                        Finding.dedup_fingerprint == fp,
                        Finding.status.in_(["open", "confirmed"]),
                    )
                )
                existing_row = fp_q.scalar_one_or_none()
                # Fallback: legacy exact-match
                if not existing_row:
                    legacy_q = await db.execute(
                        select(Finding).where(
                            Finding.project_id == project_uuid,
                            Finding.title == title,
                            Finding.affected_url == affected,
                            Finding.status.in_(["open", "confirmed"]),
                        )
                    )
                    existing_row = legacy_q.scalar_one_or_none()
                if existing_row:
                    # Update existing finding with latest evidence instead of skipping
                    existing_row.last_seen_at = datetime.utcnow()
                    existing_row.scan_count = (existing_row.scan_count or 1) + 1
                    existing_row.dedup_fingerprint = fp
                    if finding_data.get("request_raw"):
                        existing_row.request = finding_data["request_raw"]
                    if finding_data.get("response_raw"):
                        existing_row.response = finding_data["response_raw"]
                    if finding_data.get("description"):
                        existing_row.description = finding_data["description"]
                    if finding_data.get("reproduction_steps"):
                        existing_row.reproduction_steps = finding_data["reproduction_steps"]
                    continue

                finding = Finding(
                    project_id=project_uuid,
                    title=title,
                    dedup_fingerprint=fp,
                    last_seen_at=datetime.utcnow(),
                    description=finding_data.get("description", ""),
                    severity=finding_data.get("severity", "medium"),
                    cvss_score=finding_data.get("cvss_score", ""),
                    cwe_id=finding_data.get("cwe_id", ""),
                    owasp_category=finding_data.get("owasp_category", ""),
                    affected_url=affected,
                    affected_parameter=finding_data.get("affected_parameter", ""),
                    request=finding_data.get("request_raw", ""),
                    response=finding_data.get("response_raw", ""),
                    reproduction_steps=finding_data.get("reproduction_steps", ""),
                    impact=finding_data.get("impact", ""),
                    recommendation=finding_data.get("recommendation", ""),
                    status="open",
                    created_by=user_id,
                )
                db.add(finding)
                findings_created.append(finding_data.get("title", ""))

            await db.commit()

            # Auto-mark test cases based on Claude findings
            try:
                from datetime import datetime as dt
                # CWE to WSTG module mapping for Claude findings
                CWE_TO_MODULE = {
                    "CWE-79": "WSTG-INPV-01",   # XSS
                    "CWE-89": "WSTG-INPV-05",   # SQLi
                    "CWE-78": "WSTG-INPV-12",   # OS Command Injection
                    "CWE-22": "WSTG-INPV-12",   # Path Traversal
                    "CWE-918": "WSTG-INPV-19",  # SSRF
                    "CWE-352": "WSTG-SESS-05",  # CSRF
                    "CWE-287": "WSTG-ATHN-01",  # Improper Auth
                    "CWE-862": "WSTG-ATHZ-02",  # Missing Auth
                    "CWE-306": "WSTG-ATHN-01",  # Missing Critical Auth
                    "CWE-502": "WSTG-INPV-12",  # Deserialization
                    "CWE-434": "WSTG-BUSL-08",  # File Upload
                    "CWE-611": "WSTG-INPV-07",  # XXE
                    "CWE-200": "WSTG-INFO-05",  # Info Exposure
                    "CWE-522": "WSTG-ATHN-02",  # Insuff Protected Creds
                    "CWE-798": "WSTG-ATHN-02",  # Hardcoded Creds
                    "CWE-269": "WSTG-ATHZ-03",  # Priv Escalation
                    "CWE-639": "WSTG-ATHZ-04",  # IDOR
                    "CWE-601": "WSTG-CLNT-04",  # Open Redirect
                    "CWE-94": "WSTG-INPV-18",   # Code Injection / SSTI
                    "CWE-1021": "WSTG-CLNT-09", # Clickjacking
                    "CWE-326": "WSTG-CRYP-01",  # Weak Crypto
                    "CWE-327": "WSTG-CRYP-01",  # Broken Crypto
                    "CWE-614": "WSTG-SESS-02",  # Cookie not Secure
                    "CWE-384": "WSTG-SESS-03",  # Session Fixation
                    "CWE-346": "WSTG-CLNT-07",  # CORS
                    # Extended mappings for broader coverage
                    "CWE-77": "WSTG-INPV-12",   # Command Injection (alt)
                    "CWE-90": "WSTG-INPV-06",   # LDAP Injection
                    "CWE-91": "WSTG-INPV-07",   # XML Injection
                    "CWE-116": "WSTG-INPV-01",  # Improper Output Encoding
                    "CWE-285": "WSTG-ATHZ-01",  # Improper Authorization
                    "CWE-307": "WSTG-ATHN-03",  # Brute Force
                    "CWE-312": "WSTG-INFO-05",  # Cleartext Storage
                    "CWE-319": "WSTG-CRYP-03",  # Cleartext Transmission
                    "CWE-400": "WSTG-ATHN-03",  # Uncontrolled Resource
                    "CWE-548": "WSTG-CONF-04",  # Directory Listing
                    "CWE-613": "WSTG-SESS-07",  # Insufficient Session Expiration
                    "CWE-693": "WSTG-CONF-07",  # Protection Mechanism Failure
                    "CWE-732": "WSTG-CONF-04",  # Incorrect Permission
                    "CWE-829": "WSTG-CLNT-13",  # Untrusted Functionality
                    "CWE-942": "WSTG-CLNT-07",  # Overly Permissive CORS
                    "CWE-1004": "WSTG-SESS-02", # Cookie without HttpOnly
                    "CWE-1275": "WSTG-SESS-02", # Cookie with SameSite=None
                }
                # Title-based fallback mapping for findings without matching CWEs
                TITLE_TO_MODULE = {
                    "xss": "WSTG-INPV-01", "cross-site scripting": "WSTG-INPV-01",
                    "sql injection": "WSTG-INPV-05", "sqli": "WSTG-INPV-05",
                    "ssrf": "WSTG-INPV-19", "server-side request": "WSTG-INPV-19",
                    "csrf": "WSTG-SESS-05", "cross-site request forgery": "WSTG-SESS-05",
                    "open redirect": "WSTG-CLNT-04", "url redirect": "WSTG-CLNT-04",
                    "directory listing": "WSTG-CONF-04", "directory traversal": "WSTG-INPV-12",
                    "path traversal": "WSTG-INPV-12", "lfi": "WSTG-INPV-12",
                    "security header": "WSTG-CONF-07", "missing header": "WSTG-CONF-07",
                    "cookie": "WSTG-SESS-02", "session": "WSTG-SESS-01",
                    "cors": "WSTG-CLNT-07", "information disclosure": "WSTG-INFO-05",
                    "info leak": "WSTG-INFO-05", "sensitive data": "WSTG-INFO-05",
                    "command injection": "WSTG-INPV-12", "rce": "WSTG-INPV-12",
                    "authentication": "WSTG-ATHN-01", "brute force": "WSTG-ATHN-03",
                    "idor": "WSTG-ATHZ-04", "access control": "WSTG-ATHZ-02",
                    "jwt": "WSTG-SESS-01", "deserialization": "WSTG-INPV-12",
                    "ssti": "WSTG-INPV-18", "template injection": "WSTG-INPV-18",
                    "xxe": "WSTG-INPV-07", "xml external": "WSTG-INPV-07",
                }

                def _auto_mark_test_result(module_id, finding_data):
                    """Auto-mark a project test result as failed for the given module."""
                    return (
                        select(ProjectTestResult, TestCase)
                        .join(TestCase, ProjectTestResult.test_case_id == TestCase.id)
                        .where(
                            ProjectTestResult.project_id == project_uuid,
                            TestCase.module_id == module_id,
                            ProjectTestResult.is_applicable == True,
                        )
                        .limit(1)
                    )

                marked_modules = set()
                for finding_data in result.get("findings", []):
                    cwe = finding_data.get("cwe_id", "")
                    module_id = CWE_TO_MODULE.get(cwe)
                    # Fallback: title-based matching
                    if not module_id:
                        title_lower = finding_data.get("title", "").lower()
                        for keyword, mod_id in TITLE_TO_MODULE.items():
                            if keyword in title_lower:
                                module_id = mod_id
                                break
                    if not module_id or module_id in marked_modules:
                        continue
                    ptr_q = _auto_mark_test_result(module_id, finding_data)
                    ptr_rows = (await db.execute(ptr_q)).all()
                    for ptr, tc in ptr_rows:
                        ptr.status = "failed"
                        ptr.tester_id = user_id
                        ptr.completed_at = dt.utcnow()
                        ptr.evidence = [{"filename": "claude_dast_evidence", "url": "", "description": finding_data.get("description", "")[:500]}]
                        ptr.request_captured = finding_data.get("request_raw", "")[:3000]
                        ptr.response_captured = finding_data.get("response_raw", "")[:3000]
                        ptr.reproduction_steps = finding_data.get("reproduction_steps", "")
                        ptr.tool_used = "Claude AI DAST (Navigator)"
                        ptr.payload_used = finding_data.get("payload_used", finding_data.get("affected_parameter", ""))
                        marked_modules.add(module_id)
                        break
                await db.commit()
            except Exception as e:
                logger.warning("Claude auto-mark test cases failed: %s", e)
                await db.rollback()

        except Exception as e:
            logger.exception("Claude findings creation failed: %s", e)
            await db.rollback()

        # Persist ClaudeScanSession
        try:
            cost_data = result.get("cost", {})
            session_record = ClaudeScanSession(
                project_id=project_uuid,
                scan_id=scan_id,
                target_url=target_url,
                scan_mode=scan_mode,
                status="completed",
                total_input_tokens=cost_data.get("total_input_tokens", 0),
                total_output_tokens=cost_data.get("total_output_tokens", 0),
                total_cached_tokens=cost_data.get("total_cached_tokens", 0),
                total_api_calls=cost_data.get("total_api_calls", 0),
                total_cost_usd=cost_data.get("total_cost_usd", 0.0),
                cost_breakdown=cost_data.get("cost_per_model", {}),
                total_findings=len(result.get("findings", [])),
                findings_by_severity=result.get("findings_by_severity", {}),
                pages_crawled=len(result.get("crawl_results", [])),
                new_test_cases=len(result.get("new_test_cases", [])),
                pentest_options_offered=len(result.get("pentest_options", [])),
                duration_seconds=int(result.get("duration_seconds", 0)),
                activity_log=result.get("activity_log", [])[-50:],
                created_by=user_id,
                completed_at=datetime.utcnow(),
            )
            db.add(session_record)
            await db.commit()
        except Exception as e:
            logger.warning("Claude scan session persist failed: %s", e)
            await db.rollback()

        # Persist ClaudeCrawlResult with structured extraction
        try:
            crawl_results = result.get("crawl_results", [])
            if crawl_results:
                # Extract structured data from raw crawl results
                api_endpoints = []
                js_files = []
                forms_discovered = []
                hidden_paths = []
                subdomains_found = []
                technology_stack = {}
                secrets_found = []
                for cr in crawl_results:
                    # API endpoints
                    url = cr.get("url", "")
                    if any(p in url.lower() for p in ["/api/", "/graphql", "/rest/", "/v1/", "/v2/", "/v3/"]):
                        api_endpoints.append({"url": url, "method": cr.get("method", "GET"), "status_code": cr.get("status_code")})
                    # JS files
                    if url.endswith(".js") or url.endswith(".mjs"):
                        js_files.append({"url": url, "size": len(cr.get("response_body_preview", "")), "secrets": cr.get("secrets", []), "libraries": cr.get("libraries_detected", [])})
                    # Forms
                    for form in (cr.get("forms") or cr.get("forms_found") or []):
                        forms_discovered.append(form if isinstance(form, dict) else {"action": str(form)})
                    # Hidden/interesting paths
                    for finding in (cr.get("interesting_findings") or []):
                        if isinstance(finding, str):
                            hidden_paths.append({"path": finding, "source": url})
                        elif isinstance(finding, dict):
                            hidden_paths.append(finding)
                    # Technology detection
                    for tech in (cr.get("technology_detected") or []):
                        if isinstance(tech, str):
                            technology_stack[tech] = True
                        elif isinstance(tech, dict):
                            technology_stack.update(tech)
                    # Secrets
                    for secret in (cr.get("secrets_found") or cr.get("secrets") or []):
                        secrets_found.append(secret if isinstance(secret, dict) else {"type": "unknown", "value_preview": str(secret)[:50]})

                crawl_record = ClaudeCrawlResult(
                    project_id=project_uuid,
                    scan_id=scan_id,
                    crawled_pages=crawl_results,
                    api_endpoints=api_endpoints or [],
                    js_files=js_files or [],
                    forms_discovered=forms_discovered or [],
                    hidden_paths=hidden_paths or [],
                    subdomains=subdomains_found or [],
                    technology_stack=technology_stack or {},
                    secrets_found=secrets_found or [],
                    total_pages=len(crawl_results),
                    duration_seconds=int(result.get("duration_seconds", 0)),
                )
                db.add(crawl_record)
                await db.commit()
        except Exception as e:
            logger.warning("Claude crawl result persist failed: %s", e)
            await db.rollback()

    # Store RAG learnings from findings for future scans
    try:
        from app.services.dast.claude_rag import store_learning
        from urllib.parse import urlparse as _urlparse
        _domain = _urlparse(target_url).hostname or ""
        async with AsyncSessionLocal() as rag_db:
            for fd in result.get("findings", []):
                await store_learning(
                    rag_db,
                    finding_data={
                        "title": fd.get("title", ""),
                        "description": fd.get("description", ""),
                        "severity": fd.get("severity", "info"),
                        "owasp_category": fd.get("owasp_category", ""),
                        "cwe_id": fd.get("cwe_id", ""),
                        "affected_url": fd.get("affected_url", ""),
                        "parameter": fd.get("affected_parameter", ""),
                        "payload": fd.get("payload_used", ""),
                        "evidence": {"request": fd.get("request_raw", "")[:500], "response": fd.get("response_raw", "")[:500]},
                    },
                    scan_context={
                        "domain": _domain,
                        "technology_stack": project_context.get("stack_profile", {}),
                        "project_id": project_id,
                        "organization_id": org_id or None,
                    },
                )
            await rag_db.commit()
    except Exception as e:
        logger.debug("RAG learning storage skipped: %s", e)

    # Save session context for future retests
    try:
        import redis as redis_lib
        r = redis_lib.from_url(settings.redis_url, decode_responses=True)
        session_key = f"claude:session:{project_id}"
        session_data = {
            "project_id": project_id,
            "target_url": target_url,
            "messages": result.get("messages", [])[-30:],
            "summary": f"Last scan: {len(findings_created)} findings, {len(result.get('crawl_results', []))} pages crawled",
            "last_scan_id": scan_id,
            "last_scan_at": time.time(),
        }
        r.setex(session_key, settings.claude_dast_session_ttl_days * 86400, json.dumps(session_data, default=str))
    except Exception:
        pass

    # Update final progress
    _dast_progress_set(scan_id, {
        "status": "completed",
        "project_id": project_id,
        "target_url": target_url,
        "findings_created": len(findings_created),
        "finding_titles": findings_created,
        "total_findings": len(result.get("findings", [])),
        "cost": result.get("cost", {}),
        "duration_seconds": result.get("duration_seconds", 0),
        "last_updated": time.time(),
    })


@router.post("/claude/scan")
async def claude_scan(
    req: ClaudeScanRequest,
    background: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    user=Depends(get_current_user),
):
    """Start a Claude AI-powered DAST scan."""
    from app.core.config import get_settings
    settings = get_settings()

    if not settings.claude_dast_enabled:
        raise HTTPException(400, "Claude DAST is not enabled")

    project = (await db.execute(
        select(Project).where(Project.id == uuid.UUID(req.project_id))
    )).scalar_one_or_none()
    if not project:
        raise HTTPException(404, "Project not found")
    if not await user_can_read_project(db, user, req.project_id):
        raise HTTPException(403, "Access denied")

    # Check org-level or global API key
    resolved_key = await _resolve_claude_api_key(db, project)
    if not resolved_key:
        raise HTTPException(400, "Anthropic API key not configured. Ask your admin to set it in Organization Settings.")

    # ── Org-level budget enforcement ──
    org_id = getattr(project, "organization_id", None)
    if org_id:
        from app.models.organization import Organization
        org_result = await db.execute(select(Organization).where(Organization.id == org_id))
        org = org_result.scalar_one_or_none()
        if org:
            if not org.claude_enabled:
                raise HTTPException(403, "Claude DAST is disabled for this organization")
            # Check daily scan limit
            if org.claude_max_scans_per_day:
                from app.models.claude_scan_session import ClaudeScanSession
                from sqlalchemy import func
                from datetime import datetime, timedelta
                today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
                daily_count = (await db.execute(
                    select(func.count(ClaudeScanSession.id))
                    .where(ClaudeScanSession.project_id == project.id)
                    .where(ClaudeScanSession.created_at >= today_start)
                )).scalar() or 0
                if daily_count >= org.claude_max_scans_per_day:
                    raise HTTPException(429, f"Daily scan limit reached ({org.claude_max_scans_per_day} scans/day)")
            # Check deep scan approval
            if req.scan_mode == "deep" and org.claude_deep_scan_approval_required:
                if user.role not in ("super_admin", "admin"):
                    raise HTTPException(403, "Deep scan mode requires admin approval for this organization")
            # Check monthly budget
            if org.claude_monthly_budget_usd:
                from app.models.claude_usage import ClaudeUsageTracking
                from sqlalchemy import func
                from datetime import datetime, timedelta
                month_start = datetime.utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
                monthly_cost = (await db.execute(
                    select(func.sum(ClaudeUsageTracking.cost_usd))
                    .where(ClaudeUsageTracking.organization_id == org_id)
                    .where(ClaudeUsageTracking.created_at >= month_start)
                )).scalar() or 0
                if float(monthly_cost) >= float(org.claude_monthly_budget_usd):
                    raise HTTPException(429, f"Monthly AI budget exceeded (${float(org.claude_monthly_budget_usd):.2f})")

    target_url = req.target_url or project.application_url
    if not target_url:
        raise HTTPException(400, "No target URL specified")

    # Use org per-scan limit if set, otherwise global config
    org_scan_limit = None
    if org_id:
        try:
            org_scan_limit = float(org.claude_per_scan_limit_usd) if org and org.claude_per_scan_limit_usd else None
        except Exception:
            pass
    max_cost = req.max_cost_usd or org_scan_limit or settings.claude_dast_max_cost_per_scan
    scan_id = f"claude-{uuid.uuid4().hex[:16]}"

    # Seed initial progress
    from app.services.dast.runner import _dast_progress_set
    import time
    _dast_progress_set(scan_id, {
        "status": "starting",
        "project_id": req.project_id,
        "target_url": target_url,
        "scan_mode": req.scan_mode,
        "current_phase": "initializing",
        "current_activity": "Starting Claude AI scan...",
        "findings_so_far": 0,
        "last_updated": time.time(),
    })

    # Pre-seed session context in Redis so "No active session" isn't shown during scan
    try:
        import json as _json
        import redis as redis_lib
        _r = redis_lib.from_url(settings.redis_url, decode_responses=True)
        _session_key = f"claude:session:{req.project_id}"
        _r.setex(_session_key, settings.claude_dast_session_ttl_days * 86400, _json.dumps({
            "project_id": req.project_id,
            "target_url": target_url,
            "summary": f"Scan in progress (mode: {req.scan_mode})",
            "last_scan_id": scan_id,
            "last_scan_at": time.time(),
            "status": "running",
        }, default=str))
    except Exception:
        pass

    background.add_task(
        _run_claude_scan_background,
        scan_id=scan_id,
        project_id=req.project_id,
        target_url=target_url,
        scan_mode=req.scan_mode,
        include_subdomains=req.include_subdomains,
        max_cost_usd=max_cost,
        user_id=user.id,
        auth_config=req.auth_config,
        proxy_url=req.proxy_url,
    )

    return {"scan_id": scan_id, "status": "started", "target_url": target_url, "scan_mode": req.scan_mode}


@router.get("/claude/scan/{scan_id}")
async def claude_scan_progress(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    user=Depends(get_current_user),
):
    """Poll live progress for a Claude AI scan."""
    from app.services.dast.runner import _dast_progress_get
    progress = _dast_progress_get(scan_id)
    if not progress:
        raise HTTPException(404, "Scan not found or expired")
    return progress


@router.post("/claude/scan/{scan_id}/stop")
async def claude_scan_stop(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    user=Depends(get_current_user),
):
    """Gracefully stop a running Claude scan."""
    from app.services.dast.runner import _dast_progress_get, _dast_progress_set
    import time
    progress = _dast_progress_get(scan_id)
    if not progress:
        raise HTTPException(404, "Scan not found")
    progress["status"] = "stopped"
    progress["current_activity"] = "Scan stopped by user"
    progress["last_updated"] = time.time()
    _dast_progress_set(scan_id, progress)
    return {"status": "stopped", "scan_id": scan_id}


@router.post("/claude/scan/{scan_id}/pentest-option")
async def claude_pentest_option(
    scan_id: str,
    req: ClaudePentestOptionRequest,
    db: AsyncSession = Depends(get_db),
    user=Depends(get_current_user),
):
    """User selects a penetration option for deeper testing."""
    from app.services.dast.runner import _dast_progress_get, _dast_progress_set
    import time
    progress = _dast_progress_get(scan_id)
    if not progress:
        raise HTTPException(404, "Scan not found")

    # Store the user decision for the agent to pick up
    pending = progress.get("pending_pentest_options", [])
    for opt in pending:
        if opt.get("option_id") == req.option_id:
            opt["user_selected"] = req.selected_action
            opt["selected_at"] = time.time()
            break
    progress["pending_pentest_options"] = pending
    _dast_progress_set(scan_id, progress)
    return {"status": "option_recorded", "option_id": req.option_id, "action": req.selected_action}


@router.post("/claude/retest")
async def claude_retest(
    req: ClaudeRetestRequest,
    background: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    user=Depends(get_current_user),
):
    """Retest specific findings using Claude AI with session context."""
    from app.core.config import get_settings
    settings = get_settings()

    project = (await db.execute(
        select(Project).where(Project.id == uuid.UUID(req.project_id))
    )).scalar_one_or_none()
    if not project:
        raise HTTPException(404, "Project not found")
    if not await user_can_read_project(db, user, req.project_id):
        raise HTTPException(403, "Access denied")

    resolved_key = await _resolve_claude_api_key(db, project)
    if not resolved_key:
        raise HTTPException(400, "Anthropic API key not configured. Ask your admin to set it in Organization Settings.")

    # Load findings to retest
    findings_to_retest = []
    for fid in req.finding_ids:
        f = (await db.execute(
            select(Finding).where(Finding.id == uuid.UUID(fid))
        )).scalar_one_or_none()
        if f:
            findings_to_retest.append({
                "id": str(f.id), "title": f.title, "severity": f.severity,
                "affected_url": f.affected_url, "affected_parameter": f.affected_parameter or "",
                "description": f.description or "", "request": f.request or "",
                "response": f.response or "", "cwe_id": f.cwe_id or "",
            })

    if not findings_to_retest:
        raise HTTPException(400, "No valid findings to retest")

    target_url = req.target_url or project.application_url
    scan_id = f"claude-retest-{uuid.uuid4().hex[:12]}"

    from app.services.dast.runner import _dast_progress_set
    import time
    _dast_progress_set(scan_id, {
        "status": "starting",
        "project_id": req.project_id,
        "target_url": target_url,
        "current_phase": "verification",
        "current_activity": f"Retesting {len(findings_to_retest)} findings...",
        "last_updated": time.time(),
    })

    async def _retest_background():
        import json
        from app.services.dast.claude_agent import ClaudeDastAgent
        from app.services.dast.claude_executor import ClaudeToolExecutor
        from app.services.dast.runner import _dast_progress_set

        # Load session context
        session_context = None
        try:
            import redis as redis_lib
            r = redis_lib.from_url(settings.redis_url, decode_responses=True)
            raw = r.get(f"claude:session:{req.project_id}")
            if raw:
                session_context = json.loads(raw)
        except Exception:
            pass

        # Resolve org-level API key
        _retest_api_key = settings.anthropic_api_key
        try:
            from app.models.organization import Organization
            async with AsyncSessionLocal() as _rdb:
                _rproj = (await _rdb.execute(select(Project).where(Project.id == uuid.UUID(req.project_id)))).scalar_one_or_none()
                if _rproj and _rproj.organization_id:
                    _rorg = (await _rdb.execute(select(Organization).where(Organization.id == _rproj.organization_id))).scalar_one_or_none()
                    if _rorg and getattr(_rorg, "claude_dast_api_key", None):
                        _retest_api_key = _rorg.claude_dast_api_key
        except Exception:
            pass

        try:
            agent = ClaudeDastAgent(
                anthropic_api_key=_retest_api_key,
                project_id=req.project_id,
                scan_id=scan_id,
                scan_mode="standard",
                max_cost_usd=settings.claude_dast_max_cost_per_scan / 2,
                max_api_calls=settings.claude_dast_max_api_calls // 2,
            )
            executor = ClaudeToolExecutor(
                project_id=req.project_id,
                scan_id=scan_id,
                target_url=target_url,
                scope_domain=target_url,
            )
            agent.set_executor(executor)
            agent.set_progress_callback(lambda data: _dast_progress_set(scan_id, {
                **data, "project_id": req.project_id, "target_url": target_url,
            }))

            result = await agent.retest_findings(
                target_url=target_url,
                findings_to_retest=findings_to_retest,
                project_context={"project_name": project.application_name},
                session_context=session_context,
            )

            # Update original findings based on retest results
            async with AsyncSessionLocal() as db2:
                for finding_result in result.get("findings", []):
                    original_id = finding_result.get("original_finding_id")
                    if not original_id:
                        continue
                    try:
                        from datetime import datetime
                        f = (await db2.execute(
                            select(Finding).where(Finding.id == uuid.UUID(original_id))
                        )).scalar_one_or_none()
                        if f:
                            retest_status = finding_result.get("retest_status", "not_fixed")
                            f.recheck_status = retest_status
                            f.recheck_date = datetime.utcnow()
                            f.recheck_by = user.id
                            f.recheck_notes = finding_result.get("retest_notes", "Retested by Claude AI")
                            f.recheck_count = (f.recheck_count or 0) + 1
                            history = f.recheck_history or []
                            history.append({
                                "date": datetime.utcnow().isoformat(),
                                "status": retest_status,
                                "notes": finding_result.get("retest_notes", ""),
                                "by": "Claude AI",
                                "evidence": finding_result.get("evidence", ""),
                            })
                            f.recheck_history = history
                            if retest_status == "resolved":
                                f.status = "fixed"
                    except Exception as e:
                        logger.warning("Retest finding update failed: %s", e)
                await db2.commit()

            _dast_progress_set(scan_id, {
                "status": "completed",
                "findings": result.get("findings", []),
                "cost": result.get("cost", {}),
                "duration_seconds": result.get("duration_seconds", 0),
                "last_updated": time.time(),
            })
        except Exception as e:
            logger.exception("Claude retest %s failed: %s", scan_id, e)
            _dast_progress_set(scan_id, {"status": "error", "error": str(e)[:300], "last_updated": time.time()})

    background.add_task(_retest_background)
    return {"scan_id": scan_id, "status": "started", "findings_count": len(findings_to_retest)}


@router.post("/claude/crawl")
async def claude_crawl_only(
    req: ClaudeCrawlOnlyRequest,
    background: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    user=Depends(get_current_user),
):
    """Run Claude AI crawl only (no testing)."""
    from app.core.config import get_settings
    settings = get_settings()

    project = (await db.execute(
        select(Project).where(Project.id == uuid.UUID(req.project_id))
    )).scalar_one_or_none()
    if not project:
        raise HTTPException(404, "Project not found")
    if not await user_can_read_project(db, user, req.project_id):
        raise HTTPException(403, "Access denied")

    resolved_key = await _resolve_claude_api_key(db, project)
    if not resolved_key:
        raise HTTPException(400, "Anthropic API key not configured. Ask your admin to set it in Organization Settings.")

    target_url = req.target_url or project.application_url
    scan_id = f"claude-crawl-{uuid.uuid4().hex[:12]}"

    from app.services.dast.runner import _dast_progress_set
    import time
    _dast_progress_set(scan_id, {
        "status": "starting",
        "current_phase": "crawling",
        "current_activity": "Starting AI crawl...",
        "last_updated": time.time(),
    })

    async def _crawl_background():
        import json
        from app.services.dast.claude_agent import ClaudeDastAgent
        from app.services.dast.claude_executor import ClaudeToolExecutor
        from app.services.dast.claude_prompts import SYSTEM_PROMPT_CRAWL_ONLY
        from app.services.dast.runner import _dast_progress_set
        from app.models.claude_crawl_result import ClaudeCrawlResult

        # Resolve org-level API key
        _crawl_api_key = settings.anthropic_api_key
        try:
            from app.models.organization import Organization
            async with AsyncSessionLocal() as _cdb:
                _cproj = (await _cdb.execute(select(Project).where(Project.id == uuid.UUID(req.project_id)))).scalar_one_or_none()
                if _cproj and _cproj.organization_id:
                    _corg = (await _cdb.execute(select(Organization).where(Organization.id == _cproj.organization_id))).scalar_one_or_none()
                    if _corg and getattr(_corg, "claude_dast_api_key", None):
                        _crawl_api_key = _corg.claude_dast_api_key
        except Exception:
            pass

        try:
            agent = ClaudeDastAgent(
                anthropic_api_key=_crawl_api_key,
                project_id=req.project_id,
                scan_id=scan_id,
                scan_mode="standard",
                max_cost_usd=settings.claude_dast_max_cost_per_scan / 4,
                max_api_calls=settings.claude_dast_max_api_calls // 4,
            )
            executor = ClaudeToolExecutor(
                project_id=req.project_id,
                scan_id=scan_id,
                target_url=target_url,
                scope_domain=target_url,
            )
            agent.set_executor(executor)
            agent.set_progress_callback(lambda data: _dast_progress_set(scan_id, data))

            system_prompt = SYSTEM_PROMPT_CRAWL_ONLY.format(
                target_url=target_url,
                include_subdomains=req.include_subdomains,
            )
            messages = [{"role": "user", "content": f"Crawl {target_url} comprehensively. Discover all pages, APIs, forms, JS files, hidden paths, and parameters."}]
            messages = await agent._tool_use_loop(system_prompt, messages, max_iterations=100)

            # Persist crawl results
            async with AsyncSessionLocal() as db2:
                crawl_record = ClaudeCrawlResult(
                    project_id=uuid.UUID(req.project_id),
                    scan_id=scan_id,
                    crawled_pages=agent.crawl_results,
                    total_pages=len(agent.crawl_results),
                    duration_seconds=0,
                )
                db2.add(crawl_record)
                await db2.commit()

            _dast_progress_set(scan_id, {
                "status": "completed",
                "crawl_results": agent.crawl_results[:100],
                "total_pages": len(agent.crawl_results),
                "cost": agent.cost.to_dict(),
                "last_updated": time.time(),
            })
        except Exception as e:
            logger.exception("Claude crawl %s failed: %s", scan_id, e)
            _dast_progress_set(scan_id, {"status": "error", "error": str(e)[:300], "last_updated": time.time()})

    background.add_task(_crawl_background)
    return {"scan_id": scan_id, "status": "started", "target_url": target_url}


@router.get("/claude/crawl/{project_id}/results")
async def claude_crawl_results(
    project_id: str,
    db: AsyncSession = Depends(get_db),
    user=Depends(get_current_user),
):
    """Get AI crawl results for a project."""
    from app.models.claude_crawl_result import ClaudeCrawlResult

    project = (await db.execute(
        select(Project).where(Project.id == uuid.UUID(project_id))
    )).scalar_one_or_none()
    if not project:
        raise HTTPException(404, "Project not found")
    if not await user_can_read_project(db, user, project_id):
        raise HTTPException(403, "Access denied")

    results = (await db.execute(
        select(ClaudeCrawlResult)
        .where(ClaudeCrawlResult.project_id == uuid.UUID(project_id))
        .order_by(desc(ClaudeCrawlResult.created_at))
        .limit(5)
    )).scalars().all()

    db_results = [
        {
            "id": str(r.id),
            "scan_id": r.scan_id,
            "crawled_pages": r.crawled_pages or [],
            "api_endpoints": r.api_endpoints or [],
            "js_files": r.js_files or [],
            "subdomains": r.subdomains or [],
            "hidden_paths": r.hidden_paths or [],
            "hidden_parameters": r.hidden_parameters or [],
            "forms_discovered": r.forms_discovered or [],
            "technology_stack": r.technology_stack or {},
            "attack_surface_summary": r.attack_surface_summary,
            "sca_results": r.sca_results or [],
            "secrets_found": r.secrets_found or [],
            "total_pages": r.total_pages,
            "total_endpoints": r.total_endpoints,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in results
    ]

    # If there's an active scan, include live crawl data from progress
    try:
        from app.services.dast.runner import list_dast_progress
        for s in list_dast_progress():
            if s.get("project_id") == project_id and s.get("status") in ("running", "starting"):
                live_crawl = s.get("live_crawl_results", [])
                if live_crawl and (not db_results or not db_results[0].get("crawled_pages")):
                    # Insert live results as a virtual entry at the top
                    db_results.insert(0, {
                        "id": "live",
                        "scan_id": s.get("scan_id", ""),
                        "crawled_pages": live_crawl,
                        "api_endpoints": [cr for cr in live_crawl if any(p in (cr.get("url", "")).lower() for p in ["/api/", "/graphql", "/rest/", "/v1/", "/v2/"])],
                        "js_files": [cr for cr in live_crawl if (cr.get("url", "")).endswith((".js", ".mjs"))],
                        "subdomains": [],
                        "hidden_paths": [],
                        "hidden_parameters": [],
                        "forms_discovered": [],
                        "technology_stack": {},
                        "attack_surface_summary": None,
                        "sca_results": [],
                        "secrets_found": [],
                        "total_pages": len(live_crawl),
                        "total_endpoints": 0,
                        "created_at": None,
                        "_live": True,
                    })
                break
    except Exception:
        pass

    return db_results


@router.post("/claude/generate-checks")
async def claude_generate_checks(
    req: ClaudeGenerateChecksRequest,
    background: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    user=Depends(get_current_user),
):
    """Generate new test cases from Claude's analysis of the target."""
    from app.core.config import get_settings
    settings = get_settings()

    project = (await db.execute(
        select(Project).where(Project.id == uuid.UUID(req.project_id))
    )).scalar_one_or_none()
    if not project:
        raise HTTPException(404, "Project not found")
    if not await user_can_read_project(db, user, req.project_id):
        raise HTTPException(403, "Access denied")

    resolved_key = await _resolve_claude_api_key(db, project)
    if not resolved_key:
        raise HTTPException(400, "Anthropic API key not configured. Ask your admin to set it in Organization Settings.")

    target_url = req.target_url or project.application_url
    scan_id = f"claude-gen-{uuid.uuid4().hex[:12]}"

    from app.services.dast.runner import _dast_progress_set
    import time
    _dast_progress_set(scan_id, {"status": "starting", "last_updated": time.time()})

    async def _gen_background():
        import json
        from app.services.dast.claude_agent import ClaudeDastAgent
        from app.services.dast.claude_executor import ClaudeToolExecutor
        from app.services.dast.claude_prompts import SYSTEM_PROMPT_GENERATE_CHECKS
        from app.services.dast.runner import _dast_progress_set

        # Resolve org-level API key
        _gen_api_key = settings.anthropic_api_key
        try:
            from app.models.organization import Organization
            async with AsyncSessionLocal() as _gdb:
                _gproj = (await _gdb.execute(select(Project).where(Project.id == uuid.UUID(req.project_id)))).scalar_one_or_none()
                if _gproj and _gproj.organization_id:
                    _gorg = (await _gdb.execute(select(Organization).where(Organization.id == _gproj.organization_id))).scalar_one_or_none()
                    if _gorg and getattr(_gorg, "claude_dast_api_key", None):
                        _gen_api_key = _gorg.claude_dast_api_key
        except Exception:
            pass

        try:
            agent = ClaudeDastAgent(
                anthropic_api_key=_gen_api_key,
                project_id=req.project_id,
                scan_id=scan_id,
                scan_mode="quick",
                max_cost_usd=5.0,
                max_api_calls=50,
            )
            executor = ClaudeToolExecutor(
                project_id=req.project_id,
                scan_id=scan_id,
                target_url=target_url,
                scope_domain=target_url,
            )
            agent.set_executor(executor)
            agent.set_progress_callback(lambda data: _dast_progress_set(scan_id, data))

            system_prompt = SYSTEM_PROMPT_GENERATE_CHECKS.format(target_url=target_url)
            messages = [{"role": "user", "content": f"Analyze {target_url} and generate additional security test cases beyond our existing checks."}]
            messages = await agent._tool_use_loop(system_prompt, messages, max_iterations=50)

            _dast_progress_set(scan_id, {
                "status": "completed",
                "new_test_cases": agent.new_test_cases,
                "total_generated": len(agent.new_test_cases),
                "cost": agent.cost.to_dict(),
                "last_updated": time.time(),
            })
        except Exception as e:
            logger.exception("Claude generate checks %s failed: %s", scan_id, e)
            _dast_progress_set(scan_id, {"status": "error", "error": str(e)[:300], "last_updated": time.time()})

    background.add_task(_gen_background)
    return {"scan_id": scan_id, "status": "started"}


@router.get("/claude/session/{project_id}")
async def claude_session_info(
    project_id: str,
    db: AsyncSession = Depends(get_db),
    user=Depends(get_current_user),
):
    """Get Claude session info for a project (context summary, history)."""
    import json
    from app.core.config import get_settings
    from app.models.claude_scan_session import ClaudeScanSession

    project = (await db.execute(
        select(Project).where(Project.id == uuid.UUID(project_id))
    )).scalar_one_or_none()
    if not project:
        raise HTTPException(404, "Project not found")
    if not await user_can_read_project(db, user, project_id):
        raise HTTPException(403, "Access denied")

    # Redis session context
    session_context = None
    try:
        import redis as redis_lib
        settings = get_settings()
        r = redis_lib.from_url(settings.redis_url, decode_responses=True)
        raw = r.get(f"claude:session:{project_id}")
        if raw:
            session_context = json.loads(raw)
            # Don't expose raw messages to frontend
            session_context.pop("messages", None)
    except Exception:
        pass

    # Scan history from DB
    history = (await db.execute(
        select(ClaudeScanSession)
        .where(ClaudeScanSession.project_id == uuid.UUID(project_id))
        .order_by(desc(ClaudeScanSession.created_at))
        .limit(20)
    )).scalars().all()

    # Also check for active scan in progress (fallback if session wasn't seeded)
    active_scan = None
    try:
        from app.services.dast.runner import list_dast_progress
        for s in list_dast_progress():
            if s.get("project_id") == project_id and s.get("status") in ("running", "starting"):
                active_scan = s
                break
    except Exception:
        pass

    has_session = session_context is not None or active_scan is not None
    summary = None
    if session_context:
        summary = session_context.get("summary")
    elif active_scan:
        summary = f"Scan in progress: {active_scan.get('current_activity', 'Initializing...')}"

    scan_count = 0
    discovered_endpoints_count = 0
    technology_stack = {}
    waf_detected = None
    interesting_behaviors = []
    if session_context:
        scan_count = session_context.get("scan_count", len(history))
        discovered_endpoints_count = session_context.get("discovered_endpoints_count", 0)
        technology_stack = session_context.get("technology_stack", {})
        waf_detected = session_context.get("waf_detected")
        interesting_behaviors = session_context.get("interesting_behaviors", [])
    elif active_scan:
        discovered_endpoints_count = active_scan.get("pages_crawled", 0)

    return {
        "has_session": has_session,
        "session_summary": summary,
        "summary": summary,
        "last_scan_at": session_context.get("last_scan_at") if session_context else None,
        "active_scan": active_scan is not None,
        "active_scan_id": active_scan.get("scan_id") if active_scan else (session_context.get("last_scan_id") if session_context else None),
        "scan_count": scan_count or len(history),
        "discovered_endpoints_count": discovered_endpoints_count,
        "technology_stack": technology_stack,
        "waf_detected": waf_detected,
        "interesting_behaviors": interesting_behaviors,
        "scan_history": [
            {
                "scan_id": s.scan_id,
                "scan_mode": s.scan_mode,
                "status": s.status,
                "total_findings": s.total_findings,
                "findings_by_severity": s.findings_by_severity or {},
                "pages_crawled": s.pages_crawled,
                "total_cost_usd": s.total_cost_usd,
                "duration_seconds": s.duration_seconds,
                "created_at": s.created_at.isoformat() if s.created_at else None,
            }
            for s in history
        ],
    }


@router.delete("/claude/session/{project_id}")
async def claude_session_clear(
    project_id: str,
    db: AsyncSession = Depends(get_db),
    user=Depends(get_current_user),
):
    """Clear Claude session for a project (fresh start)."""
    from app.core.config import get_settings
    project = (await db.execute(
        select(Project).where(Project.id == uuid.UUID(project_id))
    )).scalar_one_or_none()
    if not project:
        raise HTTPException(404, "Project not found")
    if not await user_can_read_project(db, user, project_id):
        raise HTTPException(403, "Access denied")

    try:
        import redis as redis_lib
        settings = get_settings()
        r = redis_lib.from_url(settings.redis_url, decode_responses=True)
        r.delete(f"claude:session:{project_id}")
    except Exception:
        pass

    return {"status": "cleared", "project_id": project_id}


@router.post("/claude/cost-estimate")
async def claude_cost_estimate(
    req: ClaudeCostEstimateRequest,
    user=Depends(get_current_user),
):
    """Estimate cost before running a Claude scan."""
    from app.services.dast.claude_cost import estimate_scan_cost
    estimate = estimate_scan_cost(scan_mode=req.scan_mode)
    return estimate


@router.get("/claude/history/{project_id}")
async def claude_scan_history(
    project_id: str,
    db: AsyncSession = Depends(get_db),
    user=Depends(get_current_user),
):
    """All Claude DAST scan history for a project."""
    from app.models.claude_scan_session import ClaudeScanSession

    project = (await db.execute(
        select(Project).where(Project.id == uuid.UUID(project_id))
    )).scalar_one_or_none()
    if not project:
        raise HTTPException(404, "Project not found")
    if not await user_can_read_project(db, user, project_id):
        raise HTTPException(403, "Access denied")

    sessions = (await db.execute(
        select(ClaudeScanSession)
        .where(ClaudeScanSession.project_id == uuid.UUID(project_id))
        .order_by(desc(ClaudeScanSession.created_at))
        .limit(50)
    )).scalars().all()

    return [
        {
            "id": str(s.id),
            "scan_id": s.scan_id,
            "target_url": s.target_url,
            "scan_mode": s.scan_mode,
            "status": s.status,
            "models_used": s.models_used or [],
            "total_input_tokens": s.total_input_tokens,
            "total_output_tokens": s.total_output_tokens,
            "total_api_calls": s.total_api_calls,
            "total_cost_usd": s.total_cost_usd,
            "cost_breakdown": s.cost_breakdown or {},
            "total_findings": s.total_findings,
            "findings_by_severity": s.findings_by_severity or {},
            "pages_crawled": s.pages_crawled,
            "new_test_cases": s.new_test_cases,
            "duration_seconds": s.duration_seconds,
            "created_at": s.created_at.isoformat() if s.created_at else None,
            "completed_at": s.completed_at.isoformat() if s.completed_at else None,
        }
        for s in sessions
    ]


@router.get("/claude/admin/usage")
async def claude_admin_usage(
    db: AsyncSession = Depends(get_db),
    user=Depends(get_current_user),
):
    """Super admin: organization-wide Claude usage stats."""
    from app.models.claude_usage import ClaudeUsageTracking
    from sqlalchemy import func

    if user.role != "super_admin":
        raise HTTPException(403, "Super admin access required")

    # Aggregate usage by organization
    from datetime import datetime, timedelta
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)

    usage_q = await db.execute(
        select(
            ClaudeUsageTracking.organization_id,
            func.count(ClaudeUsageTracking.id).label("total_calls"),
            func.sum(ClaudeUsageTracking.input_tokens).label("total_input"),
            func.sum(ClaudeUsageTracking.output_tokens).label("total_output"),
            func.sum(ClaudeUsageTracking.cost_usd).label("total_cost"),
        )
        .where(ClaudeUsageTracking.created_at >= thirty_days_ago)
        .group_by(ClaudeUsageTracking.organization_id)
    )

    usage_rows = usage_q.all()
    by_org = []
    total_cost = 0.0
    for row in usage_rows:
        cost = float(row.total_cost or 0)
        total_cost += cost
        by_org.append({
            "organization_id": str(row.organization_id),
            "total_calls": row.total_calls or 0,
            "total_input_tokens": row.total_input or 0,
            "total_output_tokens": row.total_output or 0,
            "total_cost_usd": round(cost, 4),
        })

    # By model breakdown
    model_q = await db.execute(
        select(
            ClaudeUsageTracking.model,
            func.count(ClaudeUsageTracking.id).label("calls"),
            func.sum(ClaudeUsageTracking.cost_usd).label("cost"),
        )
        .where(ClaudeUsageTracking.created_at >= thirty_days_ago)
        .group_by(ClaudeUsageTracking.model)
    )
    by_model = {row.model: {"calls": row.calls, "cost": round(float(row.cost or 0), 4)} for row in model_q.all()}

    return {
        "period": "last_30_days",
        "total_cost_usd": round(total_cost, 4),
        "by_organization": by_org,
        "by_model": by_model,
    }


# ── Admin Claude Settings (global + per-org) ───────────────────────────

class ClaudeSettingsUpdate(BaseModel):
    claude_enabled: bool | None = None
    claude_monthly_budget_usd: float | None = None
    claude_per_scan_limit_usd: float | None = None
    claude_allowed_models: list[str] | None = None
    claude_max_scans_per_day: int | None = None
    claude_deep_scan_approval_required: bool | None = None
    claude_dast_api_key: str | None = None  # Per-org Anthropic API key


@router.get("/claude/admin/settings")
async def claude_admin_settings_global(
    db: AsyncSession = Depends(get_db),
    user=Depends(get_current_user),
):
    """Get global Claude DAST settings from app config."""
    if user.role != "super_admin":
        raise HTTPException(403, "Super admin access required")
    from app.core.config import get_settings
    s = get_settings()
    return {
        "claude_dast_enabled": s.claude_dast_enabled,
        "claude_dast_default_model": s.claude_dast_default_model,
        "claude_dast_max_cost_per_scan": s.claude_dast_max_cost_per_scan,
        "claude_dast_max_api_calls": s.claude_dast_max_api_calls,
        "claude_dast_max_daily_scans": s.claude_dast_max_daily_scans,
        "claude_dast_session_ttl_days": s.claude_dast_session_ttl_days,
        "claude_dast_allowed_models": s.claude_dast_allowed_models.split(",") if s.claude_dast_allowed_models else [],
    }


@router.get("/claude/admin/settings/{org_id}")
async def claude_admin_settings_org(
    org_id: str,
    db: AsyncSession = Depends(get_db),
    user=Depends(get_current_user),
):
    """Get per-org Claude DAST settings."""
    if user.role != "super_admin":
        raise HTTPException(403, "Super admin access required")
    from app.models.organization import Organization
    result = await db.execute(select(Organization).where(Organization.id == org_id))
    org = result.scalar_one_or_none()
    if not org:
        raise HTTPException(404, "Organization not found")
    return {
        "organization_id": str(org.id),
        "name": org.name,
        "claude_enabled": org.claude_enabled,
        "claude_monthly_budget_usd": float(org.claude_monthly_budget_usd) if org.claude_monthly_budget_usd is not None else None,
        "claude_per_scan_limit_usd": float(org.claude_per_scan_limit_usd) if org.claude_per_scan_limit_usd is not None else None,
        "claude_allowed_models": org.claude_allowed_models or ["claude-haiku-4-5", "claude-sonnet-4-6", "claude-opus-4-6"],
        "claude_max_scans_per_day": org.claude_max_scans_per_day,
        "claude_deep_scan_approval_required": org.claude_deep_scan_approval_required,
        "claude_dast_api_key_set": bool(org.claude_dast_api_key),
        "claude_dast_api_key_preview": f"sk-...{org.claude_dast_api_key[-6:]}" if org.claude_dast_api_key else None,
    }


@router.patch("/claude/admin/settings/{org_id}")
async def claude_admin_settings_org_update(
    org_id: str,
    req: ClaudeSettingsUpdate,
    db: AsyncSession = Depends(get_db),
    user=Depends(get_current_user),
):
    """Update per-org Claude DAST settings."""
    if user.role != "super_admin":
        raise HTTPException(403, "Super admin access required")
    from app.models.organization import Organization
    result = await db.execute(select(Organization).where(Organization.id == org_id))
    org = result.scalar_one_or_none()
    if not org:
        raise HTTPException(404, "Organization not found")
    if req.claude_enabled is not None:
        org.claude_enabled = req.claude_enabled
    if req.claude_monthly_budget_usd is not None:
        org.claude_monthly_budget_usd = req.claude_monthly_budget_usd
    if req.claude_per_scan_limit_usd is not None:
        org.claude_per_scan_limit_usd = req.claude_per_scan_limit_usd
    if req.claude_allowed_models is not None:
        org.claude_allowed_models = req.claude_allowed_models
    if req.claude_max_scans_per_day is not None:
        org.claude_max_scans_per_day = req.claude_max_scans_per_day
    if req.claude_deep_scan_approval_required is not None:
        org.claude_deep_scan_approval_required = req.claude_deep_scan_approval_required
    if req.claude_dast_api_key is not None:
        org.claude_dast_api_key = req.claude_dast_api_key if req.claude_dast_api_key else None
    await db.commit()
    return {"status": "updated", "organization_id": org_id}


# ── Export Endpoints ──────────────────────────────────────────────────────────


@router.get("/export/{project_id}/burp-xml")
async def export_burp_xml(
    project_id: str,
    db: AsyncSession = Depends(get_db),
    user=Depends(get_current_user),
):
    """Export findings as Burp Suite XML."""
    if not await user_can_read_project(db, user, project_id):
        raise HTTPException(403, "Access denied")
    findings_q = await db.execute(
        select(Finding).where(Finding.project_id == uuid.UUID(project_id))
    )
    findings = [
        {
            "title": f.title, "severity": f.severity, "description": f.description or "",
            "affected_url": f.affected_url or "", "affected_parameter": f.affected_parameter or "",
            "cwe_id": f.cwe_id or "", "request": f.request or "", "response": f.response or "",
            "remediation": f.recommendation or "", "reproduction_steps": f.reproduction_steps or "",
            "confidence": "certain" if f.status == "confirmed" else "tentative",
        }
        for f in findings_q.scalars().all()
    ]
    from app.services.dast.export_burp import export_findings_burp_xml
    xml_content = export_findings_burp_xml(findings)
    from fastapi.responses import Response
    return Response(content=xml_content, media_type="application/xml",
                    headers={"Content-Disposition": f"attachment; filename=dast-findings-{project_id[:8]}.xml"})


@router.get("/export/{project_id}/json")
async def export_json(
    project_id: str,
    db: AsyncSession = Depends(get_db),
    user=Depends(get_current_user),
):
    """Export findings as JSON."""
    if not await user_can_read_project(db, user, project_id):
        raise HTTPException(403, "Access denied")
    findings_q = await db.execute(
        select(Finding).where(Finding.project_id == uuid.UUID(project_id))
    )
    findings = [
        {
            "title": f.title, "severity": f.severity, "description": f.description or "",
            "affected_url": f.affected_url or "", "affected_parameter": f.affected_parameter or "",
            "cwe_id": f.cwe_id or "", "owasp_category": f.owasp_category or "",
            "request": f.request or "", "response": f.response or "",
            "remediation": f.recommendation or "", "reproduction_steps": f.reproduction_steps or "",
            "status": f.status or "", "cvss_score": f.cvss_score or "",
        }
        for f in findings_q.scalars().all()
    ]
    from app.services.dast.export_burp import export_findings_json
    json_content = export_findings_json(findings)
    from fastapi.responses import Response
    return Response(content=json_content, media_type="application/json",
                    headers={"Content-Disposition": f"attachment; filename=dast-findings-{project_id[:8]}.json"})


@router.get("/export/{project_id}/csv")
async def export_csv(
    project_id: str,
    db: AsyncSession = Depends(get_db),
    user=Depends(get_current_user),
):
    """Export findings as CSV."""
    if not await user_can_read_project(db, user, project_id):
        raise HTTPException(403, "Access denied")
    findings_q = await db.execute(
        select(Finding).where(Finding.project_id == uuid.UUID(project_id))
    )
    findings = [
        {
            "title": f.title, "severity": f.severity, "description": f.description or "",
            "affected_url": f.affected_url or "", "affected_parameter": f.affected_parameter or "",
            "cwe_id": f.cwe_id or "", "owasp_category": f.owasp_category or "",
            "request": f.request or "", "response": f.response or "",
            "remediation": f.recommendation or "", "status": f.status or "",
        }
        for f in findings_q.scalars().all()
    ]
    from app.services.dast.export_burp import export_findings_csv
    csv_content = export_findings_csv(findings)
    from fastapi.responses import Response
    return Response(content=csv_content, media_type="text/csv",
                    headers={"Content-Disposition": f"attachment; filename=dast-findings-{project_id[:8]}.csv"})


@router.get("/export/{project_id}/har")
async def export_har(
    project_id: str,
    db: AsyncSession = Depends(get_db),
    user=Depends(get_current_user),
):
    """Export crawl data as HAR (HTTP Archive)."""
    if not await user_can_read_project(db, user, project_id):
        raise HTTPException(403, "Access denied")
    from app.models.claude_crawl_result import ClaudeCrawlResult
    crawl_q = await db.execute(
        select(ClaudeCrawlResult).where(
            ClaudeCrawlResult.project_id == uuid.UUID(project_id)
        ).order_by(ClaudeCrawlResult.created_at.desc()).limit(1)
    )
    crawl = crawl_q.scalar_one_or_none()
    if not crawl or not crawl.crawled_pages:
        raise HTTPException(404, "No crawl data found")
    from app.services.dast.export_burp import export_har
    har_content = export_har(crawl.crawled_pages)
    from fastapi.responses import Response
    return Response(content=har_content, media_type="application/json",
                    headers={"Content-Disposition": f"attachment; filename=dast-crawl-{project_id[:8]}.har"})


# ── Learning Management Endpoints ────────────────────────────────────────────


@router.get("/learnings/{project_id}")
async def get_learnings(
    project_id: str,
    db: AsyncSession = Depends(get_db),
    user=Depends(get_current_user),
):
    """Get RAG learnings for a project."""
    if not await user_can_read_project(db, user, project_id):
        raise HTTPException(403, "Access denied")
    from app.services.dast.claude_rag import get_learnings_stats
    stats = await get_learnings_stats(db)
    from app.models.dast_learning import DastLearning
    learnings_q = await db.execute(
        select(DastLearning).where(
            DastLearning.project_id == uuid.UUID(project_id)
        ).order_by(DastLearning.confidence.desc()).limit(100)
    )
    learnings = [
        {
            "id": str(l.id), "domain": l.domain, "title": l.title,
            "severity": l.severity, "category": l.category,
            "confidence": float(l.confidence) if l.confidence else 0.8,
            "times_confirmed": l.times_confirmed or 1, "created_at": str(l.created_at),
        }
        for l in learnings_q.scalars().all()
    ]
    return {"stats": stats, "learnings": learnings}


@router.delete("/learnings/{project_id}")
async def delete_learnings(
    project_id: str,
    db: AsyncSession = Depends(get_db),
    user=Depends(get_current_user),
):
    """Delete all RAG learnings for a project."""
    if not await user_can_read_project(db, user, project_id):
        raise HTTPException(403, "Access denied")
    from app.services.dast.claude_rag import delete_learnings_for_project
    deleted = await delete_learnings_for_project(db, project_id=project_id)
    return {"status": "deleted", "count": deleted}
