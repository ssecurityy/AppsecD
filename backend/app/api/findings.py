"""Findings API with Vulnerability Management."""
from fastapi import APIRouter, HTTPException, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from app.core.database import get_db
from app.api.auth import get_current_user
from app.core.rbac import require_roles
from app.services.project_permissions import user_can_read_project, user_can_write_project
from app.services.badge_service import check_and_award_badges
from app.services.audit_service import log_audit

require_tester_plus = require_roles(get_current_user, "super_admin", "admin", "lead", "tester")
from app.models.user import User
from app.models.finding import Finding
from app.schemas.result import FindingCreate
from datetime import datetime

router = APIRouter(prefix="/findings", tags=["findings"])

RECHECK_STATUSES = [
    "pending", "resolved", "not_fixed", "partially_fixed",
    "exception", "deferred", "retest_needed",
]


def f_to_dict(f: Finding) -> dict:
    return {
        "id": str(f.id),
        "project_id": str(f.project_id),
        "title": f.title,
        "description": f.description,
        "severity": f.severity,
        "cvss_score": f.cvss_score,
        "cvss_vector": f.cvss_vector,
        "status": f.status or "open",
        "assigned_to": str(f.assigned_to) if f.assigned_to else None,
        "due_date": f.due_date.isoformat() if f.due_date else None,
        "owasp_category": f.owasp_category,
        "cwe_id": f.cwe_id,
        "affected_url": f.affected_url,
        "affected_parameter": f.affected_parameter,
        "request": f.request,
        "response": f.response,
        "reproduction_steps": f.reproduction_steps,
        "impact": f.impact,
        "recommendation": f.recommendation,
        "created_at": f.created_at.isoformat() if f.created_at else "",
        # Vulnerability Management fields
        "recheck_status": getattr(f, "recheck_status", None) or "pending",
        "recheck_notes": getattr(f, "recheck_notes", None),
        "recheck_date": f.recheck_date.isoformat() if getattr(f, "recheck_date", None) else None,
        "recheck_by": str(f.recheck_by) if getattr(f, "recheck_by", None) else None,
        "recheck_evidence": getattr(f, "recheck_evidence", None) or [],
        "original_severity": getattr(f, "original_severity", None),
        "recheck_count": getattr(f, "recheck_count", None) or 0,
        "remediation_deadline": f.remediation_deadline.isoformat() if getattr(f, "remediation_deadline", None) else None,
        "remediation_owner": getattr(f, "remediation_owner", None),
        "recheck_history": getattr(f, "recheck_history", None) or [],
    }


@router.post("", response_model=dict)
async def create_finding(
    payload: FindingCreate,
    current_user: User = Depends(require_tester_plus),
    db: AsyncSession = Depends(get_db),
):
    if not await user_can_write_project(db, current_user, str(payload.project_id)):
        raise HTTPException(403, "Write access denied to this project")
    finding = Finding(
        project_id=payload.project_id,
        test_result_id=payload.test_result_id,
        title=payload.title,
        description=payload.description,
        severity=payload.severity,
        cvss_score=payload.cvss_score,
        owasp_category=payload.owasp_category,
        cwe_id=payload.cwe_id,
        affected_url=payload.affected_url,
        affected_parameter=payload.affected_parameter,
        request=payload.request,
        response=payload.response,
        reproduction_steps=payload.reproduction_steps,
        impact=payload.impact,
        recommendation=payload.recommendation,
        created_by=current_user.id,
        original_severity=payload.severity,
        recheck_status="pending",
    )
    db.add(finding)
    await db.flush()

    # Award XP for critical/high findings
    xp = {"critical": 200, "high": 100, "medium": 50, "low": 20, "info": 10}.get(payload.severity, 10)
    from datetime import date
    today = date.today()
    if getattr(current_user, "last_finding_date", None) != today:
        xp += 25  # First finding of the day bonus
        current_user.last_finding_date = today
    current_user.xp_points = (current_user.xp_points or 0) + xp

    # Check first finding in project
    count_result = await db.execute(
        select(func.count(Finding.id)).where(Finding.project_id == payload.project_id)
    )
    is_first = count_result.scalar() == 1

    # Count XSS findings by this user
    all_findings = await db.execute(
        select(Finding).where(
            Finding.project_id == payload.project_id,
            Finding.created_by == current_user.id,
        )
    )
    user_xss_count = sum(
        1 for f in all_findings.scalars().all()
        if f and ("xss" in ((f.title or "") + " " + (f.description or "")).lower()
                 or "cross-site scripting" in ((f.title or "") + " " + (f.description or "")).lower())
    )

    new_badges = check_and_award_badges(
        list(current_user.badges or []),
        "finding_created",
        {
            "title": payload.title,
            "description": payload.description,
            "is_first_finding_in_project": is_first,
            "user_xss_count": user_xss_count,
        },
    )
    if new_badges:
        current_user.badges = list(current_user.badges or []) + new_badges

    await log_audit(db, "create_finding", user_id=str(current_user.id), resource_type="finding", resource_id=str(finding.id), details={"project_id": str(payload.project_id), "severity": payload.severity})
    await db.commit()
    await db.refresh(finding)
    return {**f_to_dict(finding), "xp_earned": xp, "badges_earned": new_badges}


@router.get("/project/{project_id}", response_model=list)
async def get_findings(
    project_id: str,
    recheck_status: str = Query(None, description="Filter by recheck status"),
    severity: str = Query(None, description="Filter by severity"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    if not await user_can_read_project(db, current_user, project_id):
        raise HTTPException(403, "Access denied to this project")
    query = (
        select(Finding)
        .where(Finding.project_id == project_id)
        .order_by(Finding.created_at.desc())
    )
    if recheck_status:
        query = query.where(Finding.recheck_status == recheck_status)
    if severity:
        query = query.where(Finding.severity == severity)
    result = await db.execute(query)
    return [f_to_dict(f) for f in result.scalars().all()]


@router.get("/project/{project_id}/summary", response_model=dict)
async def get_vulnerability_summary(
    project_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get vulnerability management summary for a project."""
    if not await user_can_read_project(db, current_user, project_id):
        raise HTTPException(403, "Access denied to this project")
    result = await db.execute(
        select(Finding).where(Finding.project_id == project_id)
    )
    findings = result.scalars().all()
    total = len(findings)
    by_recheck = {}
    by_severity = {}
    for f in findings:
        rs = getattr(f, "recheck_status", None) or "pending"
        by_recheck[rs] = by_recheck.get(rs, 0) + 1
        sv = f.severity or "info"
        by_severity[sv] = by_severity.get(sv, 0) + 1
    resolved = by_recheck.get("resolved", 0)
    return {
        "total": total,
        "resolved": resolved,
        "not_fixed": by_recheck.get("not_fixed", 0),
        "partially_fixed": by_recheck.get("partially_fixed", 0),
        "pending": by_recheck.get("pending", 0),
        "exception": by_recheck.get("exception", 0),
        "deferred": by_recheck.get("deferred", 0),
        "retest_needed": by_recheck.get("retest_needed", 0),
        "by_recheck_status": by_recheck,
        "by_severity": by_severity,
        "resolution_rate": round((resolved / total * 100) if total > 0 else 0, 1),
    }


@router.patch("/{finding_id}", response_model=dict)
async def update_finding(
    finding_id: str,
    payload: dict,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(404, "Finding not found")
    if not await user_can_write_project(db, current_user, str(finding.project_id)):
        raise HTTPException(403, "Write access denied to this project")
    allowed = {
        "status", "assigned_to", "due_date", "title", "description", "severity",
        "impact", "recommendation", "reproduction_steps", "owasp_category",
        "cwe_id", "cvss_score", "remediation_deadline", "remediation_owner",
    }
    for key, val in payload.items():
        if key in allowed and hasattr(finding, key):
            if key in ("due_date", "remediation_deadline") and isinstance(val, str):
                try:
                    val = datetime.fromisoformat(val.replace("Z", "")).date()
                except (ValueError, TypeError):
                    pass
            setattr(finding, key, val)
    finding.updated_at = datetime.utcnow()
    await db.commit()
    await db.refresh(finding)
    return f_to_dict(finding)


@router.patch("/{finding_id}/recheck", response_model=dict)
async def update_recheck_status(
    finding_id: str,
    payload: dict,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update vulnerability recheck status with full audit trail."""
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(404, "Finding not found")
    if not await user_can_write_project(db, current_user, str(finding.project_id)):
        raise HTTPException(403, "Write access denied to this project")

    new_status = payload.get("recheck_status")
    if new_status and new_status not in RECHECK_STATUSES:
        raise HTTPException(400, f"Invalid recheck_status. Use: {RECHECK_STATUSES}")

    # Build history entry
    history_entry = {
        "date": datetime.utcnow().isoformat(),
        "old_status": getattr(finding, "recheck_status", None) or "pending",
        "new_status": new_status or getattr(finding, "recheck_status", "pending"),
        "notes": payload.get("recheck_notes", ""),
        "by": str(current_user.id),
        "by_name": current_user.full_name,
    }

    # Update fields
    if new_status:
        finding.recheck_status = new_status
    if "recheck_notes" in payload:
        finding.recheck_notes = payload["recheck_notes"]
    finding.recheck_date = datetime.utcnow()
    finding.recheck_by = current_user.id
    finding.recheck_count = (getattr(finding, "recheck_count", None) or 0) + 1
    if "recheck_evidence" in payload:
        finding.recheck_evidence = payload["recheck_evidence"]
    if "remediation_deadline" in payload and payload["remediation_deadline"]:
        try:
            finding.remediation_deadline = datetime.fromisoformat(
                payload["remediation_deadline"].replace("Z", "")
            ).date()
        except (ValueError, TypeError):
            pass
    if "remediation_owner" in payload:
        finding.remediation_owner = payload["remediation_owner"]

    # Append to history
    history = list(getattr(finding, "recheck_history", None) or [])
    history.append(history_entry)
    finding.recheck_history = history

    # If resolved, auto-update main status
    if new_status == "resolved":
        finding.status = "fixed"
    elif new_status == "not_fixed":
        finding.status = "confirmed"
    elif new_status == "exception":
        finding.status = "accepted_risk"

    finding.updated_at = datetime.utcnow()
    await log_audit(
        db, "recheck_finding",
        user_id=str(current_user.id),
        resource_type="finding",
        resource_id=str(finding.id),
        details={"recheck_status": new_status, "project_id": str(finding.project_id)},
    )
    await db.commit()
    await db.refresh(finding)
    return f_to_dict(finding)


@router.post("/{finding_id}/jira", response_model=dict)
async def create_jira_issue(
    finding_id: str,
    project_key: str | None = None,
    current_user: User = Depends(require_tester_plus),
    db: AsyncSession = Depends(get_db),
):
    """Create a JIRA issue from this finding."""
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(404, "Finding not found")
    if not await user_can_write_project(db, current_user, str(finding.project_id)):
        raise HTTPException(403, "Write access denied to this project")

    from app.services.jira_service import create_jira_issue_from_finding, _jira_configured
    if not _jira_configured():
        raise HTTPException(503, "JIRA integration not configured. Set JIRA_BASE_URL, JIRA_EMAIL, JIRA_API_TOKEN, JIRA_PROJECT_KEY.")

    f_dict = {
        "title": finding.title,
        "description": finding.description,
        "severity": finding.severity,
        "affected_url": finding.affected_url,
        "owasp_category": finding.owasp_category,
        "cwe_id": finding.cwe_id,
        "reproduction_steps": finding.reproduction_steps,
        "recommendation": finding.recommendation,
    }
    out = create_jira_issue_from_finding(f_dict, project_key)
    if not out:
        raise HTTPException(502, "Failed to create JIRA issue. Check JIRA configuration and connectivity.")
    return {"jira_key": out["key"], "jira_url": out["url"]}
