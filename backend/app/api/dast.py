"""DAST Automation API — run automated security scans."""
import uuid
import logging
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.api.auth import get_current_user
from app.core.database import get_db
from app.models.project import Project
from app.models.finding import Finding
from app.models.result import ProjectTestResult
from app.models.test_case import TestCase

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/dast", tags=["dast"])


class DastScanRequest(BaseModel):
    project_id: str
    target_url: str | None = None  # Override project URL
    checks: list[str] | None = None  # Specific checks or all


class DastSingleCheckRequest(BaseModel):
    target_url: str
    check: str  # security_headers, ssl_tls, etc.


@router.post("/scan")
async def run_scan(
    payload: DastScanRequest,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Run DAST scan against project target URL. Auto-creates findings for failures."""
    from app.services.dast_service import run_dast_scan
    
    project_result = await db.execute(select(Project).where(Project.id == uuid.UUID(payload.project_id)))
    project = project_result.scalar_one_or_none()
    if not project:
        raise HTTPException(404, "Project not found")
    
    target_url = payload.target_url or project.application_url
    if not target_url:
        raise HTTPException(400, "No target URL configured for this project")
    
    # Run scan
    scan_result = run_dast_scan(target_url, payload.checks)
    
    # Auto-create findings for failed checks
    findings_created = []
    for check in scan_result["results"]:
        if check["status"] == "failed":
            finding = Finding(
                project_id=project.id,
                title=f"[DAST] {check['title']}",
                description=check["description"],
                severity=check.get("severity", "medium"),
                cwe_id=check.get("cwe_id", ""),
                owasp_category=check.get("owasp_ref", ""),
                affected_url=target_url,
                reproduction_steps=check.get("reproduction_steps", ""),
                impact=check["description"],
                recommendation=check.get("remediation", ""),
                status="open",
                created_by=current_user.id,
            )
            # Set evidence from check details
            if check.get("evidence"):
                finding.description += f"\n\nEvidence:\n{check['evidence']}"
            
            db.add(finding)
            findings_created.append(check["title"])
    
    if findings_created:
        await db.commit()
    
    scan_result["findings_created"] = len(findings_created)
    scan_result["finding_titles"] = findings_created
    return scan_result


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
            {"id": name, "title": fn.__doc__.strip().split("\n")[0] if fn.__doc__ else name}
            for name, fn in ALL_CHECKS
        ]
    }
