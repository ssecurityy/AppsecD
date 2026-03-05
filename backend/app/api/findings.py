"""Findings API with Vulnerability Management."""
from fastapi import APIRouter, HTTPException, Depends, Query, Request, UploadFile, File
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from app.core.database import get_db
from app.api.auth import get_current_user, get_client_ip
from app.core.rbac import require_roles
from app.services.project_permissions import user_can_read_project, user_can_write_project
from app.services.badge_service import check_and_award_badges
from app.services.audit_service import log_audit

require_tester_plus = require_roles(get_current_user, "super_admin", "admin", "lead", "tester")
from app.models.user import User
from app.models.finding import Finding
from app.models.project import Project
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
        # JIRA integration fields
        "jira_key": getattr(f, "jira_key", None),
        "jira_url": getattr(f, "jira_url", None),
        "jira_status": getattr(f, "jira_status", None),
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
    request: Request,
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

    await log_audit(db, "create_finding", user_id=str(current_user.id), resource_type="finding", resource_id=str(finding.id), details={"project_id": str(payload.project_id), "severity": payload.severity}, ip_address=get_client_ip(request))
    await db.commit()
    await db.refresh(finding)

    # Fire notifications for critical/high (non-blocking)
    if payload.severity and payload.severity.lower() in ("critical", "high"):
        proj_result = await db.execute(select(Project).where(Project.id == payload.project_id))
        proj = proj_result.scalar_one_or_none()
        proj_name = proj.application_name or proj.name if proj else "Unknown"
        from app.services.notification_service import notify_critical_finding
        import asyncio
        asyncio.create_task(notify_critical_finding(
            project_name=proj_name,
            finding_title=payload.title or "Security Finding",
            severity=payload.severity,
            finding_id=str(finding.id),
            project_id=str(payload.project_id),
        ))

    return {**f_to_dict(finding), "xp_earned": xp, "badges_earned": new_badges}


@router.get("/project/{project_id}", response_model=dict)
async def get_findings(
    project_id: str,
    recheck_status: str = Query(None),
    severity: str = Query(None),
    status: str = Query(None, description="Filter by finding status (open, confirmed, mitigated, fixed)"),
    date_from: str = Query(None, description="YYYY-MM-DD"),
    date_to: str = Query(None, description="YYYY-MM-DD"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    if not await user_can_read_project(db, current_user, project_id):
        raise HTTPException(403, "Access denied to this project")
    from sqlalchemy import and_, func
    from datetime import datetime

    base = (
        select(Finding)
        .where(Finding.project_id == project_id)
        .order_by(Finding.created_at.desc())
    )
    conditions = []
    if recheck_status:
        conditions.append(Finding.recheck_status == recheck_status)
    if severity:
        conditions.append(Finding.severity == severity)
    if status:
        conditions.append(Finding.status == status)
    if date_from:
        try:
            conditions.append(Finding.created_at >= datetime.strptime(date_from, "%Y-%m-%d"))
        except ValueError:
            pass
    if date_to:
        try:
            from datetime import timedelta
            end = datetime.strptime(date_to, "%Y-%m-%d").replace(hour=23, minute=59, second=59) + timedelta(days=1)
            conditions.append(Finding.created_at < end)
        except ValueError:
            pass
    if conditions:
        base = base.where(and_(*conditions))

    count_q = select(func.count()).select_from(base.subquery())
    total = (await db.execute(count_q)).scalar() or 0
    query = base.limit(limit).offset(offset)
    result = await db.execute(query)
    items = [f_to_dict(f) for f in result.scalars().all()]
    return {"items": items, "total": total, "limit": limit, "offset": offset}


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
    request: Request,
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
        ip_address=get_client_ip(request),
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
    """Create a JIRA issue from this finding. Uses org-scoped JIRA config."""
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(404, "Finding not found")
    if not await user_can_write_project(db, current_user, str(finding.project_id)):
        raise HTTPException(403, "Write access denied to this project")

    # Get org-scoped JIRA config
    from app.services.org_settings_service import get_jira_config
    proj_result = await db.execute(select(Project).where(Project.id == finding.project_id))
    proj = proj_result.scalar_one_or_none()
    org_id = getattr(proj, "organization_id", None) or getattr(current_user, "organization_id", None)
    jira_base, jira_email, jira_token, jira_key = await get_jira_config(db, org_id)

    from app.services.jira_service import create_jira_issue_from_finding, _jira_configured
    if not _jira_configured(base_url=jira_base or "", email=jira_email or "", token=jira_token or "", project_key=jira_key or ""):
        raise HTTPException(503, "JIRA integration not configured. Configure JIRA in Admin Settings for your organization.")

    f_dict = {
        "title": finding.title,
        "description": finding.description,
        "severity": finding.severity,
        "affected_url": finding.affected_url,
        "owasp_category": finding.owasp_category,
        "cwe_id": finding.cwe_id,
        "cvss_score": finding.cvss_score,
        "reproduction_steps": finding.reproduction_steps,
        "impact": finding.impact,
        "recommendation": finding.recommendation,
    }
    out = create_jira_issue_from_finding(
        f_dict, project_key,
        base_url=jira_base, email=jira_email, api_token=jira_token, default_project_key=jira_key,
    )
    if not out:
        raise HTTPException(502, "Failed to create JIRA issue. Check JIRA configuration and connectivity.")

    # Store JIRA ticket info on the finding
    if hasattr(finding, "jira_key"):
        finding.jira_key = out.get("key")
    if hasattr(finding, "jira_url"):
        finding.jira_url = out.get("url")
    if hasattr(finding, "jira_status"):
        finding.jira_status = "Open"
    await db.commit()
    await db.refresh(finding)

    return {**f_to_dict(finding), "jira_key": out["key"], "jira_url": out["url"]}


@router.post("/bulk-jira", response_model=dict)
async def bulk_create_jira_issues(
    payload: dict,
    current_user: User = Depends(require_tester_plus),
    db: AsyncSession = Depends(get_db),
):
    """Bulk create JIRA issues for multiple findings."""
    finding_ids = payload.get("finding_ids", [])
    project_key_override = payload.get("project_key")
    if not finding_ids:
        raise HTTPException(400, "No finding IDs provided")

    from app.services.org_settings_service import get_jira_config
    from app.services.jira_service import create_jira_issue_from_finding, _jira_configured

    created = []
    failed = []
    for fid in finding_ids:
        result = await db.execute(select(Finding).where(Finding.id == fid))
        finding = result.scalar_one_or_none()
        if not finding:
            failed.append({"id": fid, "error": "Not found"})
            continue
        if not await user_can_write_project(db, current_user, str(finding.project_id)):
            failed.append({"id": fid, "error": "Access denied"})
            continue
        if getattr(finding, "jira_key", None):
            failed.append({"id": fid, "error": f"Already has JIRA ticket: {finding.jira_key}"})
            continue

        proj_result = await db.execute(select(Project).where(Project.id == finding.project_id))
        proj = proj_result.scalar_one_or_none()
        org_id = getattr(proj, "organization_id", None) or getattr(current_user, "organization_id", None)
        jira_base, jira_email, jira_token, jira_key = await get_jira_config(db, org_id)

        if not _jira_configured(base_url=jira_base or "", email=jira_email or "", token=jira_token or "", project_key=jira_key or ""):
            failed.append({"id": fid, "error": "JIRA not configured"})
            continue

        f_dict = {
            "title": finding.title, "description": finding.description,
            "severity": finding.severity, "affected_url": finding.affected_url,
            "owasp_category": finding.owasp_category, "cwe_id": finding.cwe_id,
            "cvss_score": finding.cvss_score, "reproduction_steps": finding.reproduction_steps,
            "impact": finding.impact, "recommendation": finding.recommendation,
        }
        out = create_jira_issue_from_finding(
            f_dict, project_key_override,
            base_url=jira_base, email=jira_email, api_token=jira_token, default_project_key=jira_key,
        )
        if out:
            if hasattr(finding, "jira_key"):
                finding.jira_key = out.get("key")
            if hasattr(finding, "jira_url"):
                finding.jira_url = out.get("url")
            if hasattr(finding, "jira_status"):
                finding.jira_status = "Open"
            created.append({"id": fid, "jira_key": out["key"], "jira_url": out["url"]})
        else:
            failed.append({"id": fid, "error": "Failed to create issue"})

    await db.commit()
    return {"created": len(created), "failed": len(failed), "results": created, "errors": failed}


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
    if len(content) > 50 * 1024 * 1024:
        raise HTTPException(400, "File too large (max 50MB)")

    xml_str = content.decode("utf-8", errors="replace")
    parsed = parse_burp_xml(xml_str)

    if not parsed:
        raise HTTPException(400, "No findings found in XML. Ensure it is a valid Burp Suite XML export.")

    # Optional LLM enhancement
    try:
        from app.services.llm_enhanced_service import enhance_burp_findings
        from app.services.org_settings_service import get_llm_config
        org_id = current_user.organization_id
        provider, model, api_key = await get_llm_config(db, org_id)
        if api_key:
            parsed = enhance_burp_findings(parsed, provider=provider or "", model=model or "", api_key=api_key or "")
    except Exception:
        pass  # LLM enhancement is optional

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

    provider, model, api_key = await get_llm_config(db)
    suggestion = suggest_finding(title, combined_desc, "medium", provider=provider, model=model, api_key=api_key)

    return {
        "title": title,
        "description": combined_desc,
        **suggestion,
    }
