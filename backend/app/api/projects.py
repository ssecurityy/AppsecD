"""Projects API — with Redis caching and pagination for enterprise load."""
from fastapi import APIRouter, HTTPException, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from app.core.database import get_db
from app.api.auth import get_current_user
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
from app.models.test_case import TestCase
from app.models.result import ProjectTestResult
from app.models.category import Category
from app.schemas.project import ProjectCreate, ProjectOut, ProjectUpdate, ProjectMemberCreate, ProjectMemberUpdate, ProjectMemberOut
from datetime import datetime, date
import uuid

require_tester_plus = require_roles(get_current_user, "super_admin", "admin", "lead", "tester")
router = APIRouter(prefix="/projects", tags=["projects"])


def project_to_dict(p: Project, organization_name: str | None = None) -> dict:
    return {
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


@router.post("", response_model=dict)
async def create_project(
    payload: ProjectCreate,
    current_user: User = Depends(require_tester_plus),
    db: AsyncSession = Depends(get_db),
):
    target_date = None
    if payload.target_completion_date:
        try:
            target_date = datetime.fromisoformat(payload.target_completion_date.replace("Z", "")).date()
        except (ValueError, TypeError):
            pass

    org_id = getattr(current_user, "organization_id", None)
    project = Project(
        name=payload.name,
        application_name=payload.application_name,
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
    await log_audit(db, "create_project", user_id=str(current_user.id), resource_type="project", resource_id=str(project.id), details={"name": project.name})
    from app.services.cache_service import invalidate_project_list
    await invalidate_project_list(str(current_user.id))
    await db.commit()
    await db.refresh(project)
    return project_to_dict(project)


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
    org_ids = {p.organization_id for p in projects if p.organization_id}
    orgs = {}
    if org_ids:
        r = await db.execute(select(Organization).where(Organization.id.in_(org_ids)))
        orgs = {str(o.id): o.name for o in r.scalars().all()}
    items = [
        project_to_dict(p, orgs.get(str(p.organization_id)) if p.organization_id else None)
        for p in projects
    ]
    out = {"items": items, "total": total, "limit": limit, "offset": offset}
    if getattr(settings, "cache_enabled", True):
        await set_cached_json(cache_key, out, ttl=60)
    return out


@router.get("/{project_id}", response_model=dict)
async def get_project(
    project_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(404, "Project not found")
    if not await user_can_read_project(db, current_user, project_id):
        raise HTTPException(403, "Access denied to this project")
    return project_to_dict(project)


@router.patch("/{project_id}", response_model=dict)
async def update_project(
    project_id: str,
    payload: ProjectUpdate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(404, "Project not found")
    if not await user_can_write_project(db, current_user, project_id):
        raise HTTPException(403, "Write access denied to this project")
    if payload.status:
        project.status = payload.status
    if payload.stack_profile is not None:
        project.stack_profile = payload.stack_profile
    if payload.risk_rating:
        project.risk_rating = payload.risk_rating
    await db.commit()
    await db.refresh(project)
    return project_to_dict(project)


@router.get("/{project_id}/progress", response_model=dict)
async def get_project_progress(
    project_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get detailed progress breakdown per phase."""
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
            }
        phases[phase]["total"] += 1
        phases[phase][ptr.status] = phases[phase].get(ptr.status, 0) + 1

    phase_list = sorted(phases.values(), key=lambda x: x["phase"])

    total_applicable = sum(1 for ptr, tc, cat in rows if ptr.is_applicable)
    tested = sum(1 for ptr, tc, cat in rows if ptr.status in ("passed", "failed", "na"))
    passed = sum(1 for ptr, tc, cat in rows if ptr.status == "passed")
    failed = sum(1 for ptr, tc, cat in rows if ptr.status == "failed")

    pct = round((tested / total_applicable * 100) if total_applicable > 0 else 0, 1)

    # Update project counts
    project.tested_count = tested
    project.passed_count = passed
    project.failed_count = failed
    await db.commit()

    return {
        "project_id": project_id,
        "total_applicable": total_applicable,
        "tested": tested,
        "passed": passed,
        "failed": failed,
        "na": sum(1 for ptr, tc, cat in rows if ptr.status == "na"),
        "not_started": sum(1 for ptr, tc, cat in rows if ptr.status == "not_started"),
        "completion_pct": pct,
        "phases": phase_list,
    }


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
