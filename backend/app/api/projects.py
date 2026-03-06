"""Projects API — with Redis caching and pagination for enterprise load."""
from fastapi import APIRouter, HTTPException, Depends, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, case, delete
from app.core.database import get_db
from app.api.auth import get_current_user, require_super_admin
from app.api.deps import validate_project_id
from app.core.rbac import require_roles
from app.services.project_permissions import (
    get_visible_project_ids,
    user_can_read_project,
    user_can_write_project,
    user_can_manage_members,
)
from app.models.user import User
from app.models.project import Project
from app.models.project_member import ProjectMember, PROJECT_ROLES, apply_role_defaults
from app.services.applicability_service import compute_applicability_score
from app.services.audit_service import log_audit
from app.api.auth import get_client_ip
from app.core.sanitize import sanitize_text
from app.models.test_case import TestCase
from app.models.result import ProjectTestResult
from app.models.category import Category
from app.models.finding import Finding
from app.models.dast_scan_result import DastScanResult
from app.models.phase_completion import UserPhaseCompletion
from app.schemas.project import ProjectCreate, ProjectOut, ProjectUpdate, ProjectMemberCreate, ProjectMemberUpdate, ProjectMemberOut

# Map DAST check_id to testing phase for progress overlay
DAST_CHECK_TO_PHASE = {
    "DAST-HDR-01": "pre_auth",   # Security Headers
    "DAST-SSL-01": "transport",  # SSL/TLS
    "DAST-COOK-01": "auth",      # Cookie security
    "DAST-CORS-01": "pre_auth",  # CORS
    "DAST-INFO-01": "recon",     # Info disclosure
    "DAST-METH-01": "pre_auth",  # HTTP methods
    "DAST-ROBO-01": "recon",     # robots.txt
    "DAST-DIR-01": "recon",      # Directory listing
    "DAST-REDIR-01": "pre_auth", # Open redirect
    "DAST-RATE-01": "auth",      # Rate limiting
    "DAST-XSS-01": "client",     # XSS
    "DAST-SQLI-01": "api",       # SQLi
    "DAST-API-01": "api",        # API docs
    "DAST-HOST-01": "pre_auth",  # Host header
    "DAST-CRLF-01": "pre_auth",  # CRLF
    "DAST-PII-01": "client",     # PII exposure
    "DAST-SRI-01": "client",     # SRI
    "DAST-CACHE-01": "pre_auth", # Cache control
    "DAST-FORM-01": "auth",      # Autocomplete
    "DAST-BACKUP-01": "recon",   # Backup files
    "DAST-DIR-02": "recon",      # Path discovery
    "DAST-SECTXT-01": "recon",   # security.txt
    "DAST-REDIR-02": "transport", # HTTP→HTTPS redirect
    "DAST-HSTS-01": "transport",  # HSTS preload
    "DAST-VER-01": "recon",      # Version headers
    "DAST-COOP-01": "pre_auth",  # COOP/COEP
    "DAST-REF-01": "pre_auth",   # Weak Referrer-Policy
    "DAST-DEBUG-01": "recon",    # Debug/stack trace
    "DAST-ENV-01": "recon",      # .env/.git exposure
    "DAST-CT-01": "pre_auth",    # Content-Type sniffing
    "DAST-FRAME-01": "pre_auth", # Clickjacking
    "DAST-TRACE-01": "pre_auth", "DAST-ECT-01": "transport", "DAST-PERM-01": "pre_auth",
    "DAST-XSSP-01": "client", "DAST-CSPR-01": "pre_auth", "DAST-ST-01": "recon",
    "DAST-VIA-01": "recon", "DAST-XFF-01": "recon", "DAST-ALLOW-01": "pre_auth",
    "DAST-CORP-01": "pre_auth", "DAST-CSD-01": "auth", "DAST-AGE-01": "pre_auth",
    "DAST-UIR-01": "transport", "DAST-COOKP-01": "auth", "DAST-REDIR-03": "pre_auth",
    "DAST-TAO-01": "recon", "DAST-ALTSVC-01": "transport", "DAST-HSTS-02": "transport",
    "DAST-CD-01": "pre_auth", "DAST-PRAGMA-01": "pre_auth",
    "DAST-CRYP-02": "transport",  # Padding Oracle (WSTG-CRYP-02)
}
from datetime import datetime, date
import uuid

require_tester_plus = require_roles(get_current_user, "super_admin", "admin", "lead", "tester")
router = APIRouter(prefix="/projects", tags=["projects"])


async def _get_dast_results_by_phase(db: AsyncSession, project_id: str) -> dict:
    """Aggregate DAST results across all scans, using latest result per check_id.
    Partial scans (single check) only add/update that check; they do not wipe others."""
    from sqlalchemy import desc
    r = await db.execute(
        select(DastScanResult)
        .where(DastScanResult.project_id == project_id, DastScanResult.status == "completed")
        .order_by(desc(DastScanResult.created_at))
        .limit(50)
    )
    scans = r.scalars().all()
    # Build: check_id -> latest result (first seen = most recent due to desc order)
    latest_per_check: dict[str, dict] = {}
    for scan in scans:
        if not scan.results:
            continue
        for res in scan.results:
            check_id = res.get("check_id", "")
            if not check_id or check_id in latest_per_check:
                continue
            latest_per_check[check_id] = res
    if not latest_per_check:
        return {}
    agg: dict[str, dict] = {}
    for res in latest_per_check.values():
        check_id = res.get("check_id", "")
        if check_id.startswith("DAST-ERR-"):
            phase = "recon"
        else:
            phase = DAST_CHECK_TO_PHASE.get(check_id, "pre_auth")
        if phase not in agg:
            agg[phase] = {"passed": 0, "failed": 0, "total": 0}
        agg[phase]["total"] += 1
        status = (res.get("status") or "").lower()
        if status == "passed":
            agg[phase]["passed"] += 1
        elif status == "failed":
            agg[phase]["failed"] += 1
    return agg


def project_to_dict(p: Project, organization_name: str | None = None, finding_count: int | None = None) -> dict:
    d = {
        "id": str(p.id),
        "organization_id": str(p.organization_id) if p.organization_id else None,
        "organization_name": organization_name,
        "name": p.name,
        "application_name": p.application_name,
        "application_version": p.application_version,
        "application_url": p.application_url,
        "app_owner_name": p.app_owner_name,
        "app_spoc_name": p.app_spoc_name,
        "app_spoc_email": p.app_spoc_email,
        "status": p.status,
        "testing_type": p.testing_type,
        "environment": p.environment,
        "testing_scope": p.testing_scope,
        "target_completion_date": p.target_completion_date.isoformat() if p.target_completion_date else None,
        "classification": p.classification,
        "lead_id": str(p.lead_id) if p.lead_id else None,
        "stack_profile": p.stack_profile or {},
        "applicable_categories": p.applicable_categories or [],
        "total_test_cases": p.total_test_cases or 0,
        "tested_count": p.tested_count or 0,
        "passed_count": p.passed_count or 0,
        "failed_count": p.failed_count or 0,
        "na_count": p.na_count or 0,
        "risk_rating": p.risk_rating or "medium",
        "created_at": p.created_at.isoformat() if p.created_at else "",
        "started_at": p.started_at.isoformat() if p.started_at else None,
        "completed_at": p.completed_at.isoformat() if p.completed_at else None,
    }
    if finding_count is not None:
        d["finding_count"] = finding_count
    return d


@router.post("/detect-tech", response_model=dict)
async def detect_technology(
    payload: dict,
    current_user: User = Depends(get_current_user),
):
    """Detect technology stack from URL. Returns stack_profile for project onboarding."""
    from app.core.ssrf import is_ssrf_blocked_url
    from app.services.tech_detection_service import detect_technology as _detect
    url = payload.get("url") or payload.get("application_url") or ""
    if not url:
        return {"stack_profile": {}, "_error": "URL required", "_detected": False}
    if is_ssrf_blocked_url(url):
        return {"stack_profile": {}, "_error": "Target URL is not allowed (internal/private addresses are blocked)", "_detected": False}
    result = _detect(url)
    stack_profile = {k: v for k, v in result.items() if k != "prefilled" and not k.startswith("_")}
    prefilled = result.get("prefilled") or {}
    return {
        "stack_profile": stack_profile,
        "prefilled": prefilled,
        "_detected": result.get("_detected", False),
        "_error": result.get("_error"),
    }


IDEMPOTENCY_TTL = 300  # 5 minutes


@router.post("", response_model=dict)
async def create_project(
    request: Request,
    payload: ProjectCreate,
    current_user: User = Depends(require_tester_plus),
    db: AsyncSession = Depends(get_db),
):
    idem_key = request.headers.get("X-Idempotency-Key", "").strip()
    if idem_key:
        try:
            from app.core.redis_client import get_redis
            import json
            r = await get_redis()
            stored = await r.get(f"idempotency:project:{idem_key}")
            if stored:
                try:
                    return json.loads(stored)
                except (ValueError, TypeError):
                    pass
        except Exception:
            pass

    target_date = None
    if payload.target_completion_date:
        try:
            target_date = datetime.fromisoformat(payload.target_completion_date.replace("Z", "")).date()
        except (ValueError, TypeError):
            pass

    org_id = getattr(current_user, "organization_id", None)
    project = Project(
        name=sanitize_text(payload.name, max_length=255),
        application_name=sanitize_text(payload.application_name, max_length=255),
        application_version=payload.application_version,
        application_url=payload.application_url,
        app_owner_name=payload.app_owner_name,
        app_spoc_name=payload.app_spoc_name,
        app_spoc_email=payload.app_spoc_email,
        testing_type=payload.testing_type,
        environment=payload.environment,
        testing_scope=payload.testing_scope,
        target_completion_date=target_date,
        classification=payload.classification,
        lead_id=payload.lead_id,
        stack_profile=payload.stack_profile,
        tester_id=current_user.id,
        created_by=current_user.id,
        organization_id=org_id,
        status="in_progress",
        started_at=datetime.utcnow(),
    )
    db.add(project)
    await db.flush()

    # Auto-add creator as manager so they have full access
    defaults = apply_role_defaults("manager")
    pm = ProjectMember(
        project_id=project.id,
        user_id=current_user.id,
        role="manager",
        can_read=defaults["can_read"],
        can_write=defaults["can_write"],
        can_download_report=defaults["can_download_report"],
        can_manage_members=defaults["can_manage_members"],
        created_by=current_user.id,
    )
    db.add(pm)

    # Add assigned testers as project members
    if payload.assigned_tester_ids:
        tester_defaults = apply_role_defaults("tester")
        for uid in payload.assigned_tester_ids:
            if uid != current_user.id:  # Don't duplicate creator
                db.add(ProjectMember(
                    project_id=project.id,
                    user_id=uid,
                    role="tester",
                    can_read=tester_defaults["can_read"],
                    can_write=tester_defaults["can_write"],
                    can_download_report=tester_defaults["can_download_report"],
                    can_manage_members=tester_defaults["can_manage_members"],
                    created_by=current_user.id,
                ))

    # Auto-apply test cases based on stack profile
    applicable = await _apply_test_cases(project, db)
    project.total_test_cases = applicable
    await log_audit(db, "create_project", user_id=str(current_user.id), resource_type="project", resource_id=str(project.id), details={"name": project.name}, ip_address=get_client_ip(request))
    from app.services.cache_service import invalidate_project_list
    await invalidate_project_list(str(current_user.id))
    await db.commit()
    await db.refresh(project)
    result = project_to_dict(project, finding_count=0)
    if idem_key:
        try:
            import json
            from app.core.redis_client import get_redis
            r = await get_redis()
            await r.setex(f"idempotency:project:{idem_key}", IDEMPOTENCY_TTL, json.dumps(result))
        except Exception:
            pass
    return result


async def _apply_test_cases(project: Project, db: AsyncSession) -> int:
    """Create ProjectTestResult rows with applicability scoring."""
    stack = project.stack_profile or {}
    result = await db.execute(select(TestCase).where(TestCase.is_active == True))
    all_cases = result.scalars().all()

    count = 0
    for tc in all_cases:
        tc_dict = {
            "applicability_conditions": tc.applicability_conditions,
            "tags": tc.tags or [],
            "title": tc.title,
            "description": tc.description,
            "severity": tc.severity,
        }
        score, tier = compute_applicability_score(tc_dict, stack)
        is_applicable = tier in ("applicable", "optional")
        ptr = ProjectTestResult(
            project_id=project.id,
            test_case_id=tc.id,
            status="not_started" if is_applicable else "na",
            is_applicable=is_applicable,
        )
        db.add(ptr)
        count += 1

    project.total_test_cases = count
    return count


@router.get("", response_model=dict)
async def list_projects(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    from app.models.organization import Organization
    from app.services.cache_service import get_cached_json, set_cached_json, project_list_key
    from app.core.config import get_settings

    cache_key = f"{project_list_key(str(current_user.id))}:{limit}:{offset}"
    settings = get_settings()
    if getattr(settings, "cache_enabled", True):
        cached = await get_cached_json(cache_key)
        if cached:
            return cached

    visible = await get_visible_project_ids(db, current_user)
    base = select(Project).order_by(Project.created_at.desc())
    if visible is not None:
        base = base.where(Project.id.in_(visible))
    count_q = select(func.count()).select_from(base.subquery())
    total = (await db.execute(count_q)).scalar() or 0
    query = base.limit(limit).offset(offset)
    result = await db.execute(query)
    projects = result.scalars().all()
    project_ids = [p.id for p in projects]
    finding_counts: dict = {}
    if project_ids:
        fc_result = await db.execute(
            select(Finding.project_id, func.count()).where(Finding.project_id.in_(project_ids)).group_by(Finding.project_id)
        )
        finding_counts = {str(row[0]): row[1] for row in fc_result.all()}
    org_ids = {p.organization_id for p in projects if p.organization_id}
    orgs = {}
    if org_ids:
        r = await db.execute(select(Organization).where(Organization.id.in_(org_ids)))
        orgs = {str(o.id): o.name for o in r.scalars().all()}
    items = [
        project_to_dict(
            p,
            orgs.get(str(p.organization_id)) if p.organization_id else None,
            finding_count=finding_counts.get(str(p.id), 0),
        )
        for p in projects
    ]
    out = {"items": items, "total": total, "limit": limit, "offset": offset}
    if getattr(settings, "cache_enabled", True):
        await set_cached_json(cache_key, out, ttl=60)
    return out


@router.get("/trend/findings", response_model=dict)
async def get_all_projects_findings_trend(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Findings trend across all visible projects (for dashboard)."""
    visible = await get_visible_project_ids(db, current_user)
    if visible is not None and len(visible) == 0:
        return {"by_date": [], "by_severity": {}}

    date_col = func.date(Finding.created_at)
    dast_case = case((Finding.title.like("[DAST]%"), 1), else_=0)
    manual_case = case((~Finding.title.like("[DAST]%"), 1), else_=0)

    by_date_q = (
        select(
            date_col.label("date"),
            func.count().label("total"),
            func.sum(dast_case).label("dast"),
            func.sum(manual_case).label("manual"),
        )
        .select_from(Finding)
        .group_by(date_col)
        .order_by(date_col)
    )
    if visible is not None:
        by_date_q = by_date_q.where(Finding.project_id.in_(visible))
    date_rows = (await db.execute(by_date_q)).all()

    by_date = [
        {"date": row.date.isoformat() if hasattr(row.date, "isoformat") else str(row.date), "total": row.total or 0, "dast": int(row.dast or 0), "manual": int(row.manual or 0)}
        for row in date_rows
    ]

    sev_q = select(Finding.severity, func.count()).select_from(Finding).group_by(Finding.severity)
    if visible is not None:
        sev_q = sev_q.where(Finding.project_id.in_(visible))
    sev_rows = (await db.execute(sev_q)).all()
    by_severity = {str(row[0] or "unknown"): row[1] for row in sev_rows}

    return {"by_date": by_date, "by_severity": by_severity}


@router.get("/{project_id}", response_model=dict)
async def get_project(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    project_id: uuid.UUID = Depends(validate_project_id),
):
    pid_str = str(project_id)
    result = await db.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(404, "Project not found")
    if not await user_can_read_project(db, current_user, pid_str):
        raise HTTPException(403, "Access denied to this project")
    fc_result = await db.execute(
        select(func.count()).where(Finding.project_id == project_id)
    )
    finding_count = fc_result.scalar() or 0
    return project_to_dict(project, finding_count=finding_count)


@router.patch("/{project_id}", response_model=dict)
async def update_project(
    payload: ProjectUpdate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    project_id: uuid.UUID = Depends(validate_project_id),
):
    result = await db.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(404, "Project not found")
    if not await user_can_write_project(db, current_user, str(project_id)):
        raise HTTPException(403, "Write access denied to this project")
    if payload.status:
        project.status = payload.status
    if payload.stack_profile is not None:
        project.stack_profile = payload.stack_profile
    if payload.risk_rating:
        project.risk_rating = payload.risk_rating
    await db.commit()
    await db.refresh(project)
    fc_result = await db.execute(select(func.count()).where(Finding.project_id == project_id))
    finding_count = fc_result.scalar() or 0
    return project_to_dict(project, finding_count=finding_count)


@router.get("/{project_id}/progress", response_model=dict)
async def get_project_progress(
    project_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get detailed progress breakdown per phase. Includes DAST scan results mapped to phases."""
    result = await db.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(404, "Project not found")
    if not await user_can_read_project(db, current_user, project_id):
        raise HTTPException(403, "Access denied to this project")

    results_q = await db.execute(
        select(ProjectTestResult, TestCase, Category)
        .join(TestCase, ProjectTestResult.test_case_id == TestCase.id)
        .join(Category, TestCase.category_id == Category.id)
        .where(ProjectTestResult.project_id == project_id)
    )
    rows = results_q.all()

    phases: dict = {}
    for ptr, tc, cat in rows:
        phase = cat.phase
        if phase not in phases:
            phases[phase] = {
                "phase": phase,
                "phase_name": cat.name if tc else phase,
                "icon": cat.icon or "🔍",
                "total": 0, "not_started": 0, "passed": 0,
                "failed": 0, "na": 0, "in_progress": 0,
                "dast_passed": 0, "dast_failed": 0,
            }
        phases[phase]["total"] += 1
        phases[phase][ptr.status] = phases[phase].get(ptr.status, 0) + 1

    # Overlay DAST scan results onto phases
    dast_by_phase = await _get_dast_results_by_phase(db, project_id)
    cats_q = await db.execute(select(Category).where(Category.is_active == True))
    all_cats = {c.phase: (c.name, c.icon or "🔍") for c in cats_q.scalars().all()}
    phase_names = {cat.phase: (cat.name, cat.icon or "🔍") for _, _, cat in rows}
    phase_names.update(all_cats)
    for dphase, dcounts in dast_by_phase.items():
        name, icon = phase_names.get(dphase, (dphase.replace("_", " ").title(), "🔍"))
        if dphase not in phases:
            phases[dphase] = {
                "phase": dphase,
                "phase_name": name,
                "icon": icon or "🔍",
                "total": 0, "not_started": 0, "passed": 0,
                "failed": 0, "na": 0, "in_progress": 0,
                "dast_passed": 0, "dast_failed": 0,
            }
        phases[dphase]["dast_passed"] = dcounts.get("passed", 0)
        phases[dphase]["dast_failed"] = dcounts.get("failed", 0)
        phases[dphase]["passed"] += dcounts.get("passed", 0)
        phases[dphase]["failed"] += dcounts.get("failed", 0)
        phases[dphase]["total"] += dcounts.get("total", 0)

    phase_list = sorted(phases.values(), key=lambda x: x["phase"])

    total_applicable = sum(1 for ptr, tc, cat in rows if ptr.is_applicable)
    manual_tested = sum(1 for ptr, tc, cat in rows if ptr.status in ("passed", "failed", "na"))
    manual_passed = sum(1 for ptr, tc, cat in rows if ptr.status == "passed")
    manual_failed = sum(1 for ptr, tc, cat in rows if ptr.status == "failed")
    dast_total = sum(d.get("total", 0) for d in dast_by_phase.values())
    dast_passed = sum(d.get("passed", 0) for d in dast_by_phase.values())
    dast_failed = sum(d.get("failed", 0) for d in dast_by_phase.values())
    tested = manual_tested + dast_total
    passed = manual_passed + dast_passed
    failed = manual_failed + dast_failed

    pct = round((tested / (total_applicable + dast_total) * 100) if (total_applicable + dast_total) > 0 else 0, 1)

    # Update project counts (include DAST in tested/passed/failed)
    project.tested_count = tested
    project.passed_count = passed
    project.failed_count = failed
    await db.commit()

    return {
        "project_id": project_id,
        "total_applicable": total_applicable + dast_total,  # manual + DAST for display
        "tested": tested,
        "passed": passed,
        "failed": failed,
        "na": sum(1 for ptr, tc, cat in rows if ptr.status == "na"),
        "not_started": sum(1 for ptr, tc, cat in rows if ptr.status == "not_started"),
        "completion_pct": pct,
        "phases": phase_list,
        "dast_tested": dast_total,
        "dast_passed": dast_passed,
        "dast_failed": dast_failed,
    }


@router.get("/{project_id}/findings/trend", response_model=dict)
async def get_project_findings_trend(
    project_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Findings trend: by date (with dast vs manual) and by severity. DAST findings have title starting with '[DAST]'."""
    if not await user_can_read_project(db, current_user, project_id):
        raise HTTPException(403, "Access denied to this project")

    # by_date: date, total, dast, manual
    date_col = func.date(Finding.created_at)
    dast_case = case((Finding.title.like("[DAST]%"), 1), else_=0)
    manual_case = case((~Finding.title.like("[DAST]%"), 1), else_=0)

    by_date_q = (
        select(
            date_col.label("date"),
            func.count().label("total"),
            func.sum(dast_case).label("dast"),
            func.sum(manual_case).label("manual"),
        )
        .where(Finding.project_id == project_id)
        .group_by(date_col)
        .order_by(date_col)
    )
    date_rows = (await db.execute(by_date_q)).all()

    by_date = [
        {
            "date": row.date.isoformat() if hasattr(row.date, "isoformat") else str(row.date),
            "total": row.total or 0,
            "dast": int(row.dast or 0),
            "manual": int(row.manual or 0),
        }
        for row in date_rows
    ]

    # by_severity
    sev_q = (
        select(Finding.severity, func.count())
        .where(Finding.project_id == project_id)
        .group_by(Finding.severity)
    )
    sev_rows = (await db.execute(sev_q)).all()
    by_severity = {str(row[0] or "unknown"): row[1] for row in sev_rows}

    return {"by_date": by_date, "by_severity": by_severity}


# --- Project members (admin or project manager) ---

@router.get("/{project_id}/members/available-users", response_model=list)
async def get_available_users_for_project(
    project_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Users not yet in project — for add-member dropdown. Admin or can_manage_members."""
    if not await user_can_read_project(db, current_user, project_id):
        raise HTTPException(403, "Access denied to this project")
    if not await user_can_manage_members(db, current_user, project_id):
        raise HTTPException(403, "Manage members permission required")
    # Get user IDs already in project
    r = await db.execute(select(ProjectMember.user_id).where(ProjectMember.project_id == project_id))
    member_ids = {row[0] for row in r.all()}
    # Get all active users not in project
    q = select(User).where(User.is_active == True)
    if member_ids:
        q = q.where(User.id.notin_(member_ids))
    result = await db.execute(q)
    users = result.scalars().all()
    return [{"id": str(u.id), "username": u.username, "full_name": u.full_name} for u in users]


@router.get("/{project_id}/members", response_model=list)
async def list_project_members(
    project_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List project members — admin or users with can_manage_members."""
    if not await user_can_read_project(db, current_user, project_id):
        raise HTTPException(403, "Access denied to this project")
    if not await user_can_manage_members(db, current_user, project_id):
        raise HTTPException(403, "Manage members permission required")
    r = await db.execute(
        select(ProjectMember, User).join(User, ProjectMember.user_id == User.id).where(ProjectMember.project_id == project_id)
    )
    out = []
    for pm, u in r.all():
        out.append({
            "id": str(pm.id),
            "project_id": str(pm.project_id),
            "user_id": str(pm.user_id),
            "username": u.username,
            "full_name": u.full_name,
            "role": pm.role,
            "can_read": pm.can_read,
            "can_write": pm.can_write,
            "can_download_report": pm.can_download_report,
            "can_manage_members": pm.can_manage_members,
        })
    return out


@router.post("/{project_id}/members", response_model=dict)
async def add_project_member(
    project_id: str,
    payload: ProjectMemberCreate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Add project member — admin or users with can_manage_members."""
    if not await user_can_read_project(db, current_user, project_id):
        raise HTTPException(403, "Access denied to this project")
    if not await user_can_manage_members(db, current_user, project_id):
        raise HTTPException(403, "Manage members permission required")
    if payload.role not in PROJECT_ROLES:
        raise HTTPException(400, f"Invalid role. Use: {PROJECT_ROLES}")
    existing = await db.execute(
        select(ProjectMember).where(
            ProjectMember.project_id == project_id,
            ProjectMember.user_id == payload.user_id,
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(400, "User already a member of this project")
    defaults = apply_role_defaults(payload.role)
    pm = ProjectMember(
        project_id=project_id,
        user_id=payload.user_id,
        role=payload.role,
        can_read=payload.can_read if payload.can_read is not None else defaults["can_read"],
        can_write=payload.can_write if payload.can_write is not None else defaults["can_write"],
        can_download_report=payload.can_download_report if payload.can_download_report is not None else defaults["can_download_report"],
        can_manage_members=payload.can_manage_members if payload.can_manage_members is not None else defaults["can_manage_members"],
        created_by=current_user.id,
    )
    db.add(pm)
    await db.commit()
    await db.refresh(pm)
    return {
        "id": str(pm.id),
        "project_id": str(pm.project_id),
        "user_id": str(pm.user_id),
        "role": pm.role,
        "can_read": pm.can_read,
        "can_write": pm.can_write,
        "can_download_report": pm.can_download_report,
        "can_manage_members": pm.can_manage_members,
    }


@router.patch("/{project_id}/members/{member_id}", response_model=dict)
async def update_project_member(
    project_id: str,
    member_id: str,
    payload: ProjectMemberUpdate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update project member — admin or users with can_manage_members."""
    if not await user_can_manage_members(db, current_user, project_id):
        raise HTTPException(403, "Manage members permission required")
    r = await db.execute(
        select(ProjectMember).where(
            ProjectMember.id == member_id,
            ProjectMember.project_id == project_id,
        )
    )
    pm = r.scalar_one_or_none()
    if not pm:
        raise HTTPException(404, "Member not found")
    if payload.role:
        if payload.role not in PROJECT_ROLES:
            raise HTTPException(400, f"Invalid role. Use: {PROJECT_ROLES}")
        pm.role = payload.role
        defaults = apply_role_defaults(payload.role)
        pm.can_read = defaults["can_read"]
        pm.can_write = defaults["can_write"]
        pm.can_download_report = defaults["can_download_report"]
        pm.can_manage_members = defaults["can_manage_members"]
    if payload.can_read is not None:
        pm.can_read = payload.can_read
    if payload.can_write is not None:
        pm.can_write = payload.can_write
    if payload.can_download_report is not None:
        pm.can_download_report = payload.can_download_report
    if payload.can_manage_members is not None:
        pm.can_manage_members = payload.can_manage_members
    await db.commit()
    await db.refresh(pm)
    return {
        "id": str(pm.id),
        "project_id": str(pm.project_id),
        "user_id": str(pm.user_id),
        "role": pm.role,
        "can_read": pm.can_read,
        "can_write": pm.can_write,
        "can_download_report": pm.can_download_report,
        "can_manage_members": pm.can_manage_members,
    }


@router.delete("/{project_id}/members/{member_id}")
async def remove_project_member(
    project_id: str,
    member_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Remove project member — admin or users with can_manage_members."""
    if not await user_can_manage_members(db, current_user, project_id):
        raise HTTPException(403, "Manage members permission required")
    r = await db.execute(
        select(ProjectMember).where(
            ProjectMember.id == member_id,
            ProjectMember.project_id == project_id,
        )
    )
    pm = r.scalar_one_or_none()
    if not pm:
        raise HTTPException(404, "Member not found")
    await db.delete(pm)
    await db.commit()
    return {"ok": True}


@router.delete("/{project_id}")
async def delete_project(
    request: Request,
    project_id: str,
    current_user: User = Depends(require_super_admin),
    db: AsyncSession = Depends(get_db),
):
    """Delete a project and all its data (findings, results, members, etc.). Super_admin only."""
    try:
        pid = uuid.UUID(project_id)
    except (ValueError, TypeError):
        raise HTTPException(400, "Invalid project ID")
    result = await db.execute(select(Project).where(Project.id == pid))
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(404, "Project not found")
    name = project.name
    await db.execute(delete(Finding).where(Finding.project_id == pid))
    await db.execute(delete(ProjectTestResult).where(ProjectTestResult.project_id == pid))
    await db.execute(delete(UserPhaseCompletion).where(UserPhaseCompletion.project_id == pid))
    await db.execute(delete(ProjectMember).where(ProjectMember.project_id == pid))
    await db.execute(delete(Project).where(Project.id == pid))
    await log_audit(db, "delete_project", user_id=str(current_user.id), resource_type="project", resource_id=project_id, details={"name": name}, ip_address=get_client_ip(request))
    await db.commit()
    try:
        from app.services.cache_service import invalidate_project_list
        await invalidate_project_list(str(current_user.id))
    except Exception:
        pass
    return {"ok": True}
