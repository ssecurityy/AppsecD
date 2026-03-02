"""DAST Automation API — run automated security scans."""
import asyncio
import uuid
import logging
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

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

router = APIRouter(prefix="/dast", tags=["dast"])


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
            for check in result["results"]:
                title = f"[DAST] {check['title']}"
                if check["status"] == "failed":
                    # Deduplicate: skip if same finding already exists (open/confirmed)
                    existing = await db.execute(
                        select(Finding).where(
                            Finding.project_id == project_uuid,
                            Finding.title == title,
                            Finding.affected_url == target_url,
                            Finding.status.in_(["open", "confirmed"]),
                        )
                    )
                    if existing.scalar_one_or_none():
                        continue
                    finding = Finding(
                        project_id=project_uuid,
                        title=title,
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


# ──────────────────────────────────────────────────────────
#  Spider / Crawler Endpoints
# ──────────────────────────────────────────────────────────

async def _run_crawl_background(
    crawl_id: str, project_id: str, target_url: str,
    auth_config: dict | None, max_depth: int, crawl_scope: str,
    run_param_discovery: bool, user_id: uuid.UUID,
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
            None, crawl_id, 600, run_param_discovery,
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

    crawl_id = str(uuid.uuid4())
    background_tasks.add_task(
        _run_crawl_background, crawl_id, payload.project_id, target_url,
        payload.auth_config, payload.max_depth, payload.crawl_scope,
        payload.run_param_discovery, current_user.id,
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
