"""Test cases API — library and per-project results."""
from fastapi import APIRouter, HTTPException, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, func
from app.core.database import get_db
from app.api.auth import get_current_user
from app.services.project_permissions import user_can_read_project, user_can_write_project
from app.models.user import User
from app.models.project import Project
from app.models.test_case import TestCase
from app.models.category import Category
from app.models.result import ProjectTestResult
from app.models.phase_completion import UserPhaseCompletion
from app.models.project import Project
from app.services.payload_intelligence import filter_payloads_for_stack
from app.schemas.result import ResultUpdate
import uuid

router = APIRouter(prefix="/testcases", tags=["testcases"])


def tc_to_dict(tc: TestCase, cat: Category) -> dict:
    return {
        "id": str(tc.id),
        "category_id": str(tc.category_id),
        "module_id": tc.module_id,
        "category_name": cat.name if cat else "",
        "category_icon": cat.icon if cat else "🔍",
        "phase": tc.phase,
        "title": tc.title,
        "description": tc.description,
        "owasp_ref": tc.owasp_ref,
        "cwe_id": tc.cwe_id,
        "severity": tc.severity,
        "where_to_test": tc.where_to_test,
        "what_to_test": tc.what_to_test,
        "how_to_test": tc.how_to_test,
        "payloads": tc.payloads or [],
        "tool_commands": tc.tool_commands or [],
        "pass_indicators": tc.pass_indicators,
        "fail_indicators": tc.fail_indicators,
        "remediation": tc.remediation,
        "references": tc.references or [],
        "tags": tc.tags or [],
        "applicability_conditions": tc.applicability_conditions or {},
    }


@router.get("/library", response_model=list)
async def get_test_library(
    phase: str = Query(None),
    severity: str = Query(None),
    q: str = Query(None),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    query = select(TestCase, Category).join(Category, TestCase.category_id == Category.id)
    filters = [TestCase.is_active == True]
    if phase:
        filters.append(TestCase.phase == phase)
    if severity:
        filters.append(TestCase.severity == severity)
    query = query.where(and_(*filters)).order_by(TestCase.phase)
    result = await db.execute(query)
    rows = result.all()
    out = []
    for tc, cat in rows:
        d = tc_to_dict(tc, cat)
        if q:
            combined = f"{tc.title} {tc.description or ''} {' '.join(tc.tags or [])}".lower()
            if q.lower() not in combined:
                continue
        out.append(d)
    return out


@router.get("/project/{project_id}", response_model=list)
async def get_project_test_cases(
    project_id: str,
    phase: str = Query(None),
    status: str = Query(None),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get test cases for a project with their current status."""
    if not await user_can_read_project(db, current_user, project_id):
        raise HTTPException(403, "Access denied to this project")
    query = (
        select(ProjectTestResult, TestCase, Category)
        .join(TestCase, ProjectTestResult.test_case_id == TestCase.id)
        .join(Category, TestCase.category_id == Category.id)
        .where(ProjectTestResult.project_id == project_id)
    )
    if phase:
        query = query.where(TestCase.phase == phase)
    if status:
        query = query.where(ProjectTestResult.status == status)
    query = query.order_by(Category.order_index, TestCase.phase)
    result = await db.execute(query)
    rows = result.all()
    # Get project stack for payload intelligence
    proj_result = await db.execute(select(Project).where(Project.id == project_id))
    project = proj_result.scalar_one_or_none()
    stack = project.stack_profile or {} if project else {}
    out = []
    for ptr, tc, cat in rows:
        d = tc_to_dict(tc, cat)
        # Stack-aware payload ordering
        if d.get("payloads") and stack:
            d["payloads"] = filter_payloads_for_stack(d["payloads"], stack)
        d["result_id"] = str(ptr.id)
        d["result_status"] = ptr.status
        d["is_applicable"] = ptr.is_applicable
        d["notes"] = ptr.notes
        d["evidence"] = ptr.evidence or []
        d["tool_used"] = ptr.tool_used
        d["payload_used"] = ptr.payload_used
        d["time_spent_seconds"] = ptr.time_spent_seconds or 0
        out.append(d)
    return out


@router.patch("/results/{result_id}", response_model=dict)
async def update_result(
    result_id: str,
    payload: ResultUpdate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update test case result."""
    result = await db.execute(
        select(ProjectTestResult).where(ProjectTestResult.id == result_id)
    )
    ptr = result.scalar_one_or_none()
    if not ptr:
        raise HTTPException(404, "Result not found")
    if not await user_can_write_project(db, current_user, str(ptr.project_id)):
        raise HTTPException(403, "Write access denied to this project")

    old_status = ptr.status
    if payload.status is not None:
        ptr.status = payload.status
    ptr.tester_id = current_user.id
    if payload.notes is not None:
        ptr.notes = payload.notes
    if payload.evidence is not None:
        ptr.evidence = payload.evidence
    if payload.request_captured is not None:
        ptr.request_captured = payload.request_captured
    if payload.response_captured is not None:
        ptr.response_captured = payload.response_captured
    if payload.reproduction_steps is not None:
        ptr.reproduction_steps = payload.reproduction_steps
    if payload.tool_used is not None:
        ptr.tool_used = payload.tool_used
    if payload.payload_used is not None:
        ptr.payload_used = payload.payload_used
    if payload.time_spent_seconds is not None:
        ptr.time_spent_seconds = payload.time_spent_seconds
    if payload.severity_override is not None:
        ptr.severity_override = payload.severity_override
    if payload.is_applicable is not None:
        ptr.is_applicable = payload.is_applicable
        if not payload.is_applicable:
            ptr.status = "na"

    from datetime import datetime
    if ptr.status in ("passed", "failed", "na") and not ptr.completed_at:
        ptr.completed_at = datetime.utcnow()

    # Award XP
    xp = 0
    if ptr.status == "passed" and old_status != "passed":
        xp = 10
    elif ptr.status == "failed" and old_status != "failed":
        xp = 50
    if xp > 0:
        from datetime import date
        today = date.today()
        # Update streak on activity
        last = getattr(current_user, "last_streak_date", None)
        if last is None:
            current_user.streak_days = 1
            current_user.last_streak_date = today
        elif last != today:
            if (today - last).days == 1:
                current_user.streak_days = (current_user.streak_days or 0) + 1
            else:
                current_user.streak_days = 1
            current_user.last_streak_date = today
        current_user.xp_points = (current_user.xp_points or 0) + xp
        level = max(1, (current_user.xp_points // 500) + 1)
        current_user.level = level

    # Check phase completion — award +100 XP if phase just completed
    phase_complete_xp = 0
    phase_name = None
    if ptr.status in ("passed", "failed", "na"):
        tc_result = await db.execute(select(TestCase).where(TestCase.id == ptr.test_case_id))
        tc = tc_result.scalar_one_or_none()
        if tc:
            phase = tc.phase
            done_q = await db.execute(
                select(func.count(ProjectTestResult.id))
                .join(TestCase, ProjectTestResult.test_case_id == TestCase.id)
                .where(
                    ProjectTestResult.project_id == ptr.project_id,
                    TestCase.phase == phase,
                    ProjectTestResult.is_applicable == True,
                    ProjectTestResult.status.in_(["passed", "failed", "na"]),
                )
            )
            total_q = await db.execute(
                select(func.count(ProjectTestResult.id))
                .join(TestCase, ProjectTestResult.test_case_id == TestCase.id)
                .where(
                    ProjectTestResult.project_id == ptr.project_id,
                    TestCase.phase == phase,
                    ProjectTestResult.is_applicable == True,
                )
            )
            done = done_q.scalar() or 0
            total = total_q.scalar() or 0
            if total > 0 and done >= total:
                existing = await db.execute(
                    select(UserPhaseCompletion).where(
                        UserPhaseCompletion.user_id == current_user.id,
                        UserPhaseCompletion.project_id == ptr.project_id,
                        UserPhaseCompletion.phase == phase,
                    )
                )
                if existing.scalar_one_or_none() is None:
                    db.add(UserPhaseCompletion(
                        user_id=current_user.id,
                        project_id=ptr.project_id,
                        phase=phase,
                    ))
                    phase_complete_xp = 100
                    phase_name = phase
                    current_user.xp_points = (current_user.xp_points or 0) + 100
                    current_user.level = max(1, (current_user.xp_points // 500) + 1)

    await db.commit()
    # Broadcast progress update to WebSocket clients
    try:
        from app.api.websocket import get_manager
        mgr = get_manager()
        await mgr.broadcast(str(ptr.project_id), {"type": "test_updated", "result_id": str(ptr.id), "status": ptr.status})
        await mgr.broadcast(str(ptr.project_id), {"type": "progress_update", "result_id": str(ptr.id), "status": ptr.status})
    except Exception:
        pass
    return {
        "id": str(ptr.id),
        "status": ptr.status,
        "xp_earned": xp + phase_complete_xp,
        "phase_completed": phase_name,
        "user_xp": current_user.xp_points,
        "user_level": current_user.level,
    }


@router.get("/phases", response_model=list)
async def get_phases(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Category).where(Category.is_active == True).order_by(Category.order_index)
    )
    cats = result.scalars().all()
    return [
        {
            "id": str(c.id),
            "name": c.name,
            "slug": c.slug,
            "phase": c.phase,
            "icon": c.icon,
            "description": c.description,
            "order_index": c.order_index,
        }
        for c in cats
    ]
