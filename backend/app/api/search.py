"""Global search API (4F)."""
import uuid
from fastapi import APIRouter, HTTPException, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, or_
from app.core.database import get_db
from app.api.auth import get_current_user
from app.models.user import User
from app.models.project import Project
from app.models.sast_scan import SastFinding
from app.models.finding import Finding
from app.models.stored_cve import StoredCVE
from app.services.project_permissions import user_can_read_project

router = APIRouter(prefix="/search", tags=["search"])


@router.get("")
async def global_search(
    q: str = Query(..., min_length=1),
    type: str = Query("all", regex="^(all|findings|projects|cves)$"),
    limit: int = Query(20, ge=1, le=50),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Search across findings, projects, and CVEs. Results grouped by type."""
    term = f"%{q.strip()}%"
    org_id = getattr(current_user, "organization_id", None)
    results = {"projects": [], "findings": [], "sast_findings": [], "cves": []}

    if type in ("all", "projects"):
        proj_q = select(Project).where(
            Project.organization_id == org_id,
            or_(
                Project.application_name.ilike(term),
                Project.name.ilike(term),
            ),
        ).limit(limit)
        projects = (await db.execute(proj_q)).scalars().all()
        for p in projects:
            if await user_can_read_project(db, current_user, str(p.id)):
                results["projects"].append({
                    "id": str(p.id),
                    "name": p.application_name or p.name,
                    "subtitle": getattr(p, "application_url", "") or "",
                })

    if type in ("all", "findings"):
        from app.models.sast_scan import SastScanSession
        sast_q = (
            select(SastFinding)
            .join(SastScanSession, SastFinding.scan_session_id == SastScanSession.id)
            .where(
                SastScanSession.organization_id == org_id,
                or_(
                    SastFinding.title.ilike(term),
                    SastFinding.file_path.ilike(term),
                    SastFinding.rule_id.ilike(term),
                ),
            )
            .limit(limit)
        )
        sast_rows = (await db.execute(sast_q)).scalars().all()
        for f in sast_rows:
            results["sast_findings"].append({
                "id": str(f.id),
                "title": f.title,
                "subtitle": f"{f.file_path}:{f.line_start}" if f.file_path else "",
                "severity": f.severity,
                "project_id": str(f.project_id),
            })

        # DAST findings
        find_q = select(Finding).join(Project, Finding.project_id == Project.id).where(
            Project.organization_id == org_id,
            or_(
                Finding.title.ilike(term),
                Finding.affected_url.ilike(term),
            ),
        ).limit(limit)
        dast_rows = (await db.execute(find_q)).scalars().all()
        for f in dast_rows:
            if await user_can_read_project(db, current_user, str(f.project_id)):
                results["findings"].append({
                    "id": str(f.id),
                    "title": f.title,
                    "subtitle": f.affected_url or "",
                    "severity": f.severity,
                    "project_id": str(f.project_id),
                })

    if type in ("all", "cves"):
        cve_q = select(StoredCVE).where(
            or_(
                StoredCVE.cve_id.ilike(term),
                (StoredCVE.description.isnot(None)) & (StoredCVE.description.ilike(term)),
            ),
        ).limit(limit)
        cve_rows = (await db.execute(cve_q)).scalars().all()
        results["cves"] = [
            {"id": c.cve_id, "title": c.cve_id, "subtitle": (c.description or "")[:120]}
            for c in cve_rows
        ]

    return results
