"""Findings API."""
from fastapi import APIRouter, HTTPException, Depends, Query, UploadFile, File
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from app.core.database import get_db
from app.api.auth import get_current_user
from app.core.rbac import require_roles
from app.services.project_permissions import user_can_read_project, user_can_write_project
from app.services.badge_service import check_and_award_badges
from app.services.audit_service import log_audit

require_tester_plus = require_roles(get_current_user, "admin", "lead", "tester")
from app.models.user import User
from app.models.finding import Finding
from app.schemas.result import FindingCreate
from datetime import datetime

router = APIRouter(prefix="/findings", tags=["findings"])


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

    # Count XSS findings by this user (title/description contains xss)
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
    try:
        from app.api.websocket import get_manager
        manager = get_manager()
        await manager.broadcast(str(finding.project_id), {"type": "finding_created", "finding_id": str(finding.id)})
    except Exception:
        pass
    return {**f_to_dict(finding), "xp_earned": xp, "badges_earned": new_badges}


@router.get("/project/{project_id}", response_model=list)
async def get_findings(
    project_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    if not await user_can_read_project(db, current_user, project_id):
        raise HTTPException(403, "Access denied to this project")
    result = await db.execute(
        select(Finding)
        .where(Finding.project_id == project_id)
        .order_by(Finding.created_at.desc())
    )
    return [f_to_dict(f) for f in result.scalars().all()]


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
    allowed = {"status", "assigned_to", "due_date", "title", "description", "severity", "impact", "recommendation", "reproduction_steps", "owasp_category", "cwe_id", "cvss_score"}
    for key, val in payload.items():
        if key in allowed and hasattr(finding, key):
            if key == "due_date" and isinstance(val, str):
                try:
                    from datetime import datetime
                    val = datetime.fromisoformat(val.replace("Z", "")).date()
                except (ValueError, TypeError):
                    pass
            setattr(finding, key, val)
    finding.updated_at = datetime.utcnow()
    await db.commit()
    await db.refresh(finding)
    try:
        from app.api.websocket import get_manager
        manager = get_manager()
        await manager.broadcast(str(finding.project_id), {"type": "finding_updated", "finding_id": str(finding.id)})
    except Exception:
        pass
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


@router.post("/auto-suggest")
async def auto_suggest_finding(
    payload: dict,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """When a test case fails, suggest a finding with pre-filled data."""
    from app.services.ai_assist_service import suggest_finding
    from app.services.admin_settings_service import get_llm_config

    title = payload.get("test_title", "")
    description = payload.get("test_description", "")
    fail_notes = payload.get("notes", "")
    combined_desc = f"{description}\n\nTester Notes: {fail_notes}" if fail_notes else description

    model, api_key = await get_llm_config(db)
    suggestion = suggest_finding(title, combined_desc, "medium", model=model, api_key=api_key)

    return {
        "title": title,
        "description": combined_desc,
        **suggestion,
    }


@router.post("/import/burp")
async def import_burp_xml(
    project_id: str = Query(...),
    file: UploadFile = File(...),
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Import findings from Burp Suite XML export."""
    from app.services.burp_import_service import parse_burp_xml
    
    if not file.filename or not file.filename.endswith(".xml"):
        raise HTTPException(400, "Only XML files are accepted")
    
    content = await file.read()
    if len(content) > 50 * 1024 * 1024:  # 50MB limit
        raise HTTPException(400, "File too large (max 50MB)")
    
    xml_str = content.decode("utf-8", errors="replace")
    parsed = parse_burp_xml(xml_str)
    
    if not parsed:
        raise HTTPException(400, "No findings found in XML. Ensure it is a valid Burp Suite XML export.")
    
    import uuid as _uuid
    created = []
    for f_data in parsed:
        finding = Finding(
            project_id=_uuid.UUID(project_id),
            title=f_data["title"],
            severity=f_data["severity"],
            description=f_data.get("description", ""),
            affected_url=f_data.get("affected_url", ""),
            recommendation=f_data.get("recommendation", ""),
            request=f_data.get("request", ""),
            response=f_data.get("response", ""),
            status="open",
            created_by=current_user.id,
        )
        db.add(finding)
        created.append(f_data["title"])
    
    await db.commit()
    return {"imported": len(created), "findings": created}
