"""Reports API — generate and download project reports."""
import json
from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import HTMLResponse, Response
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.core.database import get_db
from app.api.auth import get_current_user
from app.services.project_permissions import user_can_download_report
from app.services.report_service import (
    build_report_data,
    generate_html,
    generate_docx,
    generate_pdf,
    generate_json,
    generate_csv,
)
from app.models.user import User
from app.models.project import Project
from app.models.finding import Finding
from app.models.result import ProjectTestResult
from app.models.category import Category

router = APIRouter(prefix="/projects", tags=["reports"])


def finding_to_dict(f, evidence_from_result=None):
    ev = evidence_from_result if evidence_from_result else []
    if not ev and getattr(f, "evidence_urls", None):
        ev = [{"url": u, "filename": u.split("/")[-1] if "/" in str(u) else str(u)} for u in (f.evidence_urls or [])]
    d = {
        "id": str(f.id),
        "title": f.title,
        "description": f.description,
        "severity": f.severity,
        "cvss_score": f.cvss_score,
        "owasp_category": f.owasp_category,
        "cwe_id": f.cwe_id,
        "affected_url": f.affected_url,
        "affected_parameter": f.affected_parameter,
        "reproduction_steps": f.reproduction_steps,
        "impact": f.impact,
        "recommendation": f.recommendation,
        "evidence": ev,
    }
    # Include request/response for automated findings (DAST, Burp import)
    if getattr(f, "request", None):
        d["request"] = f.request
    if getattr(f, "response", None):
        d["response"] = f.response
    return d


def project_to_dict(p):
    return {
        "id": str(p.id),
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
        "testing_scope": getattr(p, "testing_scope", None),
        "target_completion_date": p.target_completion_date.isoformat() if getattr(p, "target_completion_date", None) else None,
        "classification": getattr(p, "classification", None),
        "total_test_cases": p.total_test_cases or 0,
        "tested_count": p.tested_count or 0,
        "passed_count": p.passed_count or 0,
        "failed_count": p.failed_count or 0,
        "na_count": p.na_count or 0,
    }


@router.get("/{project_id}/report")
async def get_report(
    project_id: str,
    format: str = "html",
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Generate and download report. format: html, docx, pdf, json, csv"""
    if not await user_can_download_report(db, current_user, project_id):
        raise HTTPException(403, "Report download not permitted for this project")

    result = await db.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(404, "Project not found")

    findings_result = await db.execute(
        select(Finding).where(Finding.project_id == project_id).order_by(Finding.created_at.desc())
    )
    findings_raw = findings_result.scalars().all()
    result_ids = [f.test_result_id for f in findings_raw if f.test_result_id]
    evidence_by_result = {}
    if result_ids:
        ptr_result = await db.execute(
            select(ProjectTestResult.id, ProjectTestResult.evidence).where(ProjectTestResult.id.in_(result_ids))
        )
        for row in ptr_result.all():
            evidence_by_result[str(row.id)] = row.evidence or []
    findings = [
        finding_to_dict(f, evidence_from_result=evidence_by_result.get(str(f.test_result_id), []) if f.test_result_id else None)
        for f in findings_raw
    ]

    phases_result = await db.execute(
        select(Category).where(Category.is_active == True).order_by(Category.order_index)
    )
    phases = [
        {"id": str(c.id), "name": c.name, "phase": c.phase, "icon": c.icon}
        for c in phases_result.scalars().all()
    ]

    proj_dict = project_to_dict(project)
    data = build_report_data(proj_dict, findings, phases, project_id=project_id)

    fmt = format.lower()
    if fmt == "html":
        html = generate_html(data)
        return HTMLResponse(html)
    elif fmt == "docx":
        content = generate_docx(data)
        filename = f"VAPT_Report_{project.application_name.replace(' ', '_')}.docx"
        return Response(
            content=content,
            media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    elif fmt == "pdf":
        content = generate_pdf(data)
        filename = f"VAPT_Report_{project.application_name.replace(' ', '_')}.pdf"
        return Response(
            content=content,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    elif fmt == "json":
        return Response(
            content=generate_json(data),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="report_{project_id}.json"'},
        )
    elif fmt == "csv":
        return Response(
            content=generate_csv(data),
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="findings_{project_id}.csv"'},
        )
    else:
        raise HTTPException(400, f"Unsupported format: {format}. Use html, docx, pdf, json, csv")


@router.get("/{project_id}/report/data")
async def get_report_data(
    project_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get report data as JSON for live preview. Same data as report generation."""
    if not await user_can_download_report(db, current_user, project_id):
        raise HTTPException(403, "Report download not permitted for this project")

    result = await db.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(404, "Project not found")

    findings_result = await db.execute(
        select(Finding).where(Finding.project_id == project_id).order_by(Finding.created_at.desc())
    )
    findings_raw = findings_result.scalars().all()
    result_ids = [f.test_result_id for f in findings_raw if f.test_result_id]
    evidence_by_result = {}
    if result_ids:
        ptr_result = await db.execute(
            select(ProjectTestResult.id, ProjectTestResult.evidence).where(ProjectTestResult.id.in_(result_ids))
        )
        for row in ptr_result.all():
            evidence_by_result[str(row.id)] = row.evidence or []
    findings = [
        finding_to_dict(f, evidence_from_result=evidence_by_result.get(str(f.test_result_id), []) if f.test_result_id else None)
        for f in findings_raw
    ]
    phases_result = await db.execute(
        select(Category).where(Category.is_active == True).order_by(Category.order_index)
    )
    phases = [
        {"id": str(c.id), "name": c.name, "phase": c.phase, "icon": c.icon}
        for c in phases_result.scalars().all()
    ]
    proj_dict = project_to_dict(project)
    data = build_report_data(proj_dict, findings, phases, project_id=project_id)
    for f in data.get("findings", []):
        f.pop("compliance", None)
    return data


@router.post("/{project_id}/report/async")
async def start_async_report(
    project_id: str,
    format: str = "pdf",
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Queue async report generation. Returns task_id for polling."""
    if not await user_can_download_report(db, current_user, project_id):
        raise HTTPException(403, "Report download not permitted for this project")
    if format.lower() not in ("docx", "pdf"):
        raise HTTPException(400, "Async reports support docx and pdf only")

    result = await db.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(404, "Project not found")

    findings_result = await db.execute(
        select(Finding).where(Finding.project_id == project_id).order_by(Finding.created_at.desc())
    )
    findings_raw = findings_result.scalars().all()
    result_ids = [f.test_result_id for f in findings_raw if f.test_result_id]
    evidence_by_result = {}
    if result_ids:
        ptr_result = await db.execute(
            select(ProjectTestResult.id, ProjectTestResult.evidence).where(ProjectTestResult.id.in_(result_ids))
        )
        for row in ptr_result.all():
            evidence_by_result[str(row.id)] = row.evidence or []
    findings = [
        finding_to_dict(f, evidence_from_result=evidence_by_result.get(str(f.test_result_id), []) if f.test_result_id else None)
        for f in findings_raw
    ]
    phases_result = await db.execute(
        select(Category).where(Category.is_active == True).order_by(Category.order_index)
    )
    phases = [
        {"id": str(c.id), "name": c.name, "phase": c.phase, "icon": c.icon}
        for c in phases_result.scalars().all()
    ]
    proj_dict = project_to_dict(project)
    data = build_report_data(proj_dict, findings, phases, project_id=project_id)
    report_data_json = json.dumps(data, default=str)

    try:
        from app.tasks import generate_report_async
        task = generate_report_async.delay(project_id, format.lower(), report_data_json)
        return {"task_id": task.id, "format": format, "status": "queued"}
    except Exception as e:
        raise HTTPException(503, f"Async report queue unavailable: {e}")


@router.get("/{project_id}/report/async/{task_id}")
async def get_async_report_status(
    project_id: str,
    task_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Poll async report status. If ready, returns file; otherwise status."""
    if not await user_can_download_report(db, current_user, project_id):
        raise HTTPException(403, "Report download not permitted for this project")

    try:
        from app.celery_app import celery_app
        async_result = celery_app.AsyncResult(task_id)
        if async_result.ready():
            if async_result.failed():
                raise HTTPException(500, str(async_result.result))
            res = async_result.result
            if not res or "content_hex" not in res:
                raise HTTPException(500, "Report generation failed")
            content = bytes.fromhex(res["content_hex"])
            fmt = res.get("format", "pdf")
            proj_result = await db.execute(select(Project).where(Project.id == project_id))
            project = proj_result.scalar_one_or_none()
            app_name = (project.application_name or "Report").replace(" ", "_")
            filename = f"VAPT_Report_{app_name}.{fmt}"
            media = "application/vnd.openxmlformats-officedocument.wordprocessingml.document" if fmt == "docx" else "application/pdf"
            return Response(
                content=content,
                media_type=media,
                headers={"Content-Disposition": f'attachment; filename="{filename}"'},
            )
        return {"task_id": task_id, "status": "pending"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, str(e))


@router.post("/{project_id}/report/summarize")
async def summarize_report(
    project_id: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Generate an LLM-powered executive summary for the report."""
    from app.services.admin_settings_service import get_llm_config
    import uuid

    project_result = await db.execute(select(Project).where(Project.id == uuid.UUID(project_id)))
    project = project_result.scalar_one_or_none()
    if not project:
        raise HTTPException(404, "Project not found")

    findings_result = await db.execute(select(Finding).where(Finding.project_id == uuid.UUID(project_id)))
    findings = findings_result.scalars().all()

    _provider, model, api_key = await get_llm_config(db)

    if not api_key:
        finding_count = len(findings)
        critical_high = sum(1 for f in findings if (f.severity or "").lower() in ("critical", "high"))
        summary = f"Security assessment of {project.application_name} identified {finding_count} finding(s). "
        if critical_high:
            summary += f"{critical_high} are Critical/High severity requiring immediate attention. "
        summary += f"Testing covered {project.tested_count or 0} of {project.total_test_cases or 0} test cases."
        return {"summary": summary, "mode": "rule_based"}

    try:
        from openai import OpenAI
        client = OpenAI(api_key=api_key)

        findings_text = "\n".join([
            f"- [{f.severity}] {f.title}: {(f.description or '')[:100]}"
            for f in findings[:20]
        ])

        prompt = f"""Write a brief executive summary (3-4 sentences) for a security assessment report:
Application: {project.application_name}
URL: {project.application_url}
Test Cases: {project.tested_count or 0}/{project.total_test_cases or 0} executed
Findings:
{findings_text}
Be professional, concise, and actionable."""

        response = client.chat.completions.create(
            model=model or "gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.3,
            max_tokens=300,
        )
        summary = (response.choices[0].message.content or "").strip()
        return {"summary": summary, "mode": "llm"}
    except Exception as e:
        return {"summary": f"Failed to generate LLM summary: {str(e)}", "mode": "error"}
