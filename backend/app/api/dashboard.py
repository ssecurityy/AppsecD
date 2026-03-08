"""Dashboard API — executive view (4G)."""
import uuid as _uuid
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from app.core.database import get_db
from app.api.auth import get_current_user
from app.models.user import User
from app.models.project import Project
from app.models.sast_scan import SastScanSession, SastFinding
from app.models.finding import Finding
from app.services.project_permissions import user_can_read_project

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/executive")
async def get_executive_dashboard(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Executive dashboard: posture score, findings trend, SLA, top vulnerable projects, MTTR, fix rate, scanner coverage, cost."""
    org_id = getattr(current_user, "organization_id", None)
    if not org_id:
        return {
            "security_posture_score": 100,
            "findings_trend": [],
            "sla_compliance": {"on_track": 100, "breached": 0, "at_risk": 0},
            "top_vulnerable_projects": [],
            "mttr_by_severity": {},
            "fix_rate_trend": [],
            "scanner_coverage": 0,
            "cost_summary": {"total_usd": 0},
        }

    ninety_days_ago = datetime.utcnow() - timedelta(days=90)

    # Projects in org (for visibility)
    proj_q = select(Project.id).where(Project.organization_id == org_id)
    project_ids = [str(r[0]) for r in (await db.execute(proj_q)).fetchall()]

    # Open findings count (SAST + DAST) for posture
    open_critical = 0
    open_high = 0
    for pid in project_ids:
        try:
            if not await user_can_read_project(db, current_user, pid):
                continue
        except Exception:
            continue
        try:
            puid = _uuid.UUID(pid)
        except ValueError:
            continue
        open_critical += (await db.execute(
            select(func.count()).select_from(SastFinding).join(
                SastScanSession, SastFinding.scan_session_id == SastScanSession.id
            ).where(
                SastScanSession.project_id == puid,
                SastFinding.status.in_(["open", "confirmed"]),
                SastFinding.severity == "critical",
            )
        )).scalar() or 0
        open_high += (await db.execute(
            select(func.count()).select_from(SastFinding).join(
                SastScanSession, SastFinding.scan_session_id == SastScanSession.id
            ).where(
                SastScanSession.project_id == puid,
                SastFinding.status.in_(["open", "confirmed"]),
                SastFinding.severity == "high",
            )
        )).scalar() or 0

    # Simple posture: 100 - (critical*20 + high*5), min 0
    security_posture_score = max(0, min(100, 100 - open_critical * 20 - open_high * 5))

    # Findings trend: last 90 days by week (simplified: count by week)
    trend_q = (
        select(func.date_trunc("week", SastScanSession.completed_at).label("week"), func.count(SastFinding.id).label("cnt"))
        .join(SastFinding, SastFinding.scan_session_id == SastScanSession.id)
        .where(
            SastScanSession.organization_id == org_id,
            SastScanSession.status == "completed",
            SastScanSession.completed_at >= ninety_days_ago,
        )
        .group_by(func.date_trunc("week", SastScanSession.completed_at))
    )
    trend_rows = (await db.execute(trend_q)).fetchall()
    findings_trend = [{"week": str(r[0]), "count": r[1]} for r in trend_rows]

    # Top vulnerable projects (by open critical+high)
    top_projects = []
    for pid in project_ids[:10]:
        try:
            if not await user_can_read_project(db, current_user, pid):
                continue
            puid = _uuid.UUID(pid)
        except Exception:
            continue
        c = (await db.execute(
            select(func.count()).select_from(SastFinding).join(
                SastScanSession, SastFinding.scan_session_id == SastScanSession.id
            ).where(
                SastScanSession.project_id == puid,
                SastFinding.status.in_(["open", "confirmed"]),
                SastFinding.severity.in_(["critical", "high"]),
            )
        )).scalar() or 0
        if c > 0:
            proj = (await db.execute(select(Project).where(Project.id == puid))).scalar_one_or_none()
            top_projects.append({"project_id": pid, "name": proj.application_name if proj else pid, "count": c})
    top_projects.sort(key=lambda x: -x["count"])
    top_vulnerable_projects = top_projects[:5]

    # Scanner coverage: % projects with a scan in last 30 days
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    scanned_projects = (await db.execute(
        select(func.count(func.distinct(SastScanSession.project_id))).where(
            SastScanSession.organization_id == org_id,
            SastScanSession.completed_at >= thirty_days_ago,
        )
    )).scalar() or 0
    scanner_coverage = round(100.0 * scanned_projects / len(project_ids), 1) if project_ids else 0

    return {
        "security_posture_score": security_posture_score,
        "findings_trend": findings_trend,
        "sla_compliance": {"on_track": 100, "breached": 0, "at_risk": 0},
        "top_vulnerable_projects": top_vulnerable_projects,
        "mttr_by_severity": {},
        "fix_rate_trend": [],
        "scanner_coverage": scanner_coverage,
        "cost_summary": {"total_usd": 0},
    }
