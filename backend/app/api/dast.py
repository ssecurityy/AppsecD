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

            # Sync DAST results to ProjectTestResult for mapped WSTG test cases
            DAST_CHECK_TO_WSTG = {"DAST-CRYP-02": "WSTG-CRYP-02"}
            from datetime import datetime as dt
            for check in result["results"]:
                check_id = check.get("check_id", "")
                wstg_id = DAST_CHECK_TO_WSTG.get(check_id)
                if not wstg_id:
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
                        TestCase.module_id == wstg_id,
                        ProjectTestResult.is_applicable == True,
                    )
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
