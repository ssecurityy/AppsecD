"""SAST API — static application security testing endpoints."""
import asyncio
import json
import logging
import os
import shutil
import tempfile
import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, UploadFile, File, Form, Request
from pydantic import BaseModel
from sqlalchemy import select, desc, func, case
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.auth import get_current_user
from app.core.database import get_db, AsyncSessionLocal
from app.services.project_permissions import user_can_read_project, user_can_write_project
from app.models.sast_scan import SastScanSession, SastFinding, SastRepository, SastPolicy
from app.models.organization import Organization
from app.models.project import Project

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/sast", tags=["sast"])

MAX_UPLOAD_SIZE = 500 * 1024 * 1024  # 500MB


# ── Helpers ────────────────────────────────────────────────────────

async def _check_sast_enabled(db: AsyncSession, org_id) -> None:
    """Raise 403 if SAST is not enabled for this org."""
    org = (await db.execute(select(Organization).where(Organization.id == org_id))).scalar_one_or_none()
    if not org or not getattr(org, "sast_enabled", False):
        raise HTTPException(403, "SAST is not enabled for this organization. Contact your super admin.")


async def _check_feature_flag(db: AsyncSession, org_id, flag: str, feature_name: str = "") -> None:
    """Raise 403 if a specific SAST feature flag is disabled."""
    org = (await db.execute(select(Organization).where(Organization.id == org_id))).scalar_one_or_none()
    if org and not getattr(org, flag, True):
        raise HTTPException(403, f"{feature_name or flag} is not enabled for this organization.")


async def _resolve_api_key(db: AsyncSession, org_id) -> str:
    """Resolve Anthropic API key for AI analysis."""
    from app.core.config import get_settings
    settings = get_settings()
    api_key = settings.anthropic_api_key or ""
    try:
        org = (await db.execute(select(Organization).where(Organization.id == org_id))).scalar_one_or_none()
        if org and getattr(org, "claude_dast_api_key", None):
            api_key = org.claude_dast_api_key
    except Exception:
        pass
    return api_key


def _sast_progress_get(scan_id: str) -> dict | None:
    """Get SAST scan progress from Redis."""
    from app.services.sast.scanner import _progress_get
    return _progress_get(scan_id)


async def _resolve_repository_access_token(
    db: AsyncSession,
    organization_id,
    repo: SastRepository,
) -> tuple[str, str]:
    """Resolve an access token for a repository from org-scoped GitHub config."""
    from app.services.admin_settings_service import get_github_platform_config
    from app.services.org_settings_service import get_github_config
    from app.services.sast.github_client import get_installation_access_token, decrypt_token

    scan_cfg = repo.scan_config or {}
    auth_mode = (scan_cfg.get("auth_mode") or "pat").lower()
    github_cfg = await get_github_config(db, organization_id)

    if auth_mode == "github_app":
        installation = github_cfg.get("app_installation") or {}
        installation_id = installation.get("installation_id") or scan_cfg.get("installation_id")
        if not installation_id:
            raise HTTPException(400, "Organization GitHub App installation is missing")
        try:
            platform_github = await get_github_platform_config(db)
            return await get_installation_access_token(int(installation_id), platform_github), auth_mode
        except Exception:
            raise HTTPException(400, "Failed to create GitHub App installation token")

    if auth_mode == "oauth":
        token = github_cfg.get("oauth_token")
        if token:
            return token, auth_mode
        if repo.access_token_encrypted:
            try:
                return decrypt_token(repo.access_token_encrypted), auth_mode
            except Exception:
                pass
        raise HTTPException(400, "Organization GitHub OAuth connection is missing")

    if auth_mode == "pat":
        token = github_cfg.get("pat_token")
        if token:
            return token, auth_mode
        if repo.access_token_encrypted:
            try:
                return decrypt_token(repo.access_token_encrypted), auth_mode
            except Exception:
                pass
        raise HTTPException(400, "Organization GitHub PAT connection is missing")

    if repo.access_token_encrypted:
        try:
            return decrypt_token(repo.access_token_encrypted), auth_mode
        except Exception:
            pass
    raise HTTPException(400, "Repository authentication could not be resolved")


def _build_webhook_token(project_id: str) -> str:
    """Build a stable webhook token using the app secret."""
    import hashlib
    from app.core.security import get_secret_key

    return hashlib.sha256(
        f"sast-webhook:{project_id}:{get_secret_key()}".encode()
    ).hexdigest()[:32]


def _github_oauth_state_key(state: str) -> str:
    return f"github_oauth_state:{state}"


def _github_app_state_key(state: str) -> str:
    return f"github_app_state:{state}"


def _public_frontend_origin() -> str:
    from app.core.config import get_settings

    settings = get_settings()
    origins = [origin.strip() for origin in settings.allowed_origins.split(",") if origin.strip()]
    for origin in origins:
        if "localhost" in origin or "127.0.0.1" in origin:
            continue
        return origin.rstrip("/")
    return (origins[0] if origins else "https://appsecd.com").rstrip("/")


def _session_to_dict(s: SastScanSession) -> dict:
    """Serialize SastScanSession to dict."""
    return {
        "id": str(s.id),
        "project_id": str(s.project_id),
        "organization_id": str(s.organization_id),
        "scan_type": s.scan_type,
        "status": s.status,
        "source_info": s.source_info,
        "language_stats": s.language_stats,
        "total_files": s.total_files,
        "files_scanned": s.files_scanned,
        "total_issues": s.total_issues,
        "issues_by_severity": s.issues_by_severity,
        "issues_by_category": s.issues_by_category,
        "ai_analysis_enabled": s.ai_analysis_enabled,
        "ai_cost_usd": float(s.ai_cost_usd or 0),
        "semgrep_rules_used": s.semgrep_rules_used,
        "secrets_found": s.secrets_found,
        "dependency_issues": s.dependency_issues,
        "scan_duration_seconds": s.scan_duration_seconds,
        "scan_config": s.scan_config,
        "error_message": s.error_message,
        "policy_result": s.policy_result,
        "created_at": s.created_at.isoformat() if s.created_at else None,
        "completed_at": s.completed_at.isoformat() if s.completed_at else None,
        # Code Security Platform extended fields
        "claude_review_enabled": getattr(s, "claude_review_enabled", False),
        "claude_review_cost_usd": float(getattr(s, "claude_review_cost_usd", 0) or 0),
        "claude_review_findings_count": getattr(s, "claude_review_findings_count", 0) or 0,
        "sca_issues": getattr(s, "sca_issues", 0) or 0,
        "iac_issues": getattr(s, "iac_issues", 0) or 0,
        "container_issues": getattr(s, "container_issues", 0) or 0,
        "js_deep_issues": getattr(s, "js_deep_issues", 0) or 0,
        "license_issues": getattr(s, "license_issues", 0) or 0,
    }


def _finding_to_dict(f: SastFinding) -> dict:
    """Serialize SastFinding to dict."""
    return {
        "id": str(f.id),
        "scan_session_id": str(f.scan_session_id),
        "project_id": str(f.project_id),
        "rule_id": f.rule_id,
        "rule_source": f.rule_source,
        "severity": f.severity,
        "confidence": f.confidence,
        "title": f.title,
        "description": f.description,
        "message": f.message,
        "file_path": f.file_path,
        "line_start": f.line_start,
        "line_end": f.line_end,
        "column_start": f.column_start,
        "column_end": f.column_end,
        "code_snippet": f.code_snippet,
        "fix_suggestion": f.fix_suggestion,
        "fixed_code": f.fixed_code,
        "ai_analysis": f.ai_analysis,
        "cwe_id": f.cwe_id,
        "owasp_category": f.owasp_category,
        "references": f.references,
        "fingerprint": f.fingerprint,
        "status": f.status,
        "created_at": f.created_at.isoformat() if f.created_at else None,
    }


# ── Scan Endpoints ─────────────────────────────────────────────────

def _parse_scan_config_form(scan_config_json: str | None) -> dict:
    """Parse optional scan_config JSON from form (exhaustive, gitleaks_enabled, rule_sets)."""
    if not scan_config_json or not scan_config_json.strip():
        return {}
    try:
        data = json.loads(scan_config_json)
        return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, TypeError):
        return {}


@router.post("/scan/upload")
async def upload_and_scan(
    background_tasks: BackgroundTasks,
    project_id: str = Form(...),
    ai_analysis: bool = Form(False),
    file: UploadFile = File(...),
    scan_config: str | None = Form(default=None),
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Upload a ZIP file and start SAST scan. Optional scan_config JSON: exhaustive, gitleaks_enabled, rule_sets."""
    project = (await db.execute(select(Project).where(Project.id == uuid.UUID(project_id)))).scalar_one_or_none()
    if not project:
        raise HTTPException(404, "Project not found")
    if not await user_can_write_project(db, current_user, project_id):
        raise HTTPException(403, "Access denied")
    await _check_sast_enabled(db, project.organization_id)

    # Validate file
    if not file.filename or not file.filename.lower().endswith(".zip"):
        raise HTTPException(400, "Only .zip files are accepted")

    # Save uploaded file
    upload_dir = tempfile.mkdtemp(prefix="sast_upload_")
    zip_path = os.path.join(upload_dir, file.filename)

    total_size = 0
    with open(zip_path, "wb") as f:
        while chunk := await file.read(8192):
            total_size += len(chunk)
            if total_size > MAX_UPLOAD_SIZE:
                os.remove(zip_path)
                shutil.rmtree(upload_dir, ignore_errors=True)
                raise HTTPException(400, f"File too large (max {MAX_UPLOAD_SIZE // 1024 // 1024}MB)")
            f.write(chunk)

    scan_cfg = _parse_scan_config_form(scan_config)

    # Create scan session
    scan_id = uuid.uuid4()
    session = SastScanSession(
        id=scan_id,
        project_id=uuid.UUID(project_id),
        organization_id=project.organization_id,
        scan_type="zip_upload",
        status="queued",
        source_info={"zip_filename": file.filename, "file_size_bytes": total_size},
        ai_analysis_enabled=ai_analysis,
        scan_config=scan_cfg or None,
        created_by=current_user.id,
    )
    db.add(session)
    await db.commit()

    # Start background scan
    api_key = await _resolve_api_key(db, project.organization_id) if ai_analysis else ""
    background_tasks.add_task(
        _run_zip_scan_background,
        scan_session_id=str(scan_id),
        project_id=project_id,
        organization_id=str(project.organization_id),
        zip_path=zip_path,
        upload_dir=upload_dir,
        ai_analysis_enabled=ai_analysis,
        api_key=api_key,
        user_id=str(current_user.id),
    )

    from app.services.audit_service import log_audit
    await log_audit(db, "sast_scan_upload", str(current_user.id), "sast_scan", str(scan_id),
                    {"filename": file.filename, "size": total_size})

    return {"scan_id": str(scan_id), "status": "queued", "message": "SAST scan started"}


async def _run_zip_scan_background(
    scan_session_id: str, project_id: str, organization_id: str,
    zip_path: str, upload_dir: str,
    ai_analysis_enabled: bool, api_key: str, user_id: str,
):
    """Background task: extract ZIP and run SAST scan."""
    from app.services.sast.code_extractor import extract_zip, cleanup_source
    from app.services.sast.scanner import run_sast_scan, _progress_set

    extract_dir = None
    try:
        # Update status
        async with AsyncSessionLocal() as db:
            session = (await db.execute(
                select(SastScanSession).where(SastScanSession.id == uuid.UUID(scan_session_id))
            )).scalar_one_or_none()
            if session:
                session.status = "extracting"
                await db.commit()

        # Extract
        extract_dir = extract_zip(zip_path)

        # Load scan_config from session
        async with AsyncSessionLocal() as db:
            session = (await db.execute(
                select(SastScanSession).where(SastScanSession.id == uuid.UUID(scan_session_id))
            )).scalar_one_or_none()
            scan_cfg = (session.scan_config or {}) if session else {}

        # Run scan
        await run_sast_scan(
            scan_session_id=scan_session_id,
            project_id=project_id,
            organization_id=organization_id,
            source_path=extract_dir,
            scan_config=scan_cfg,
            ai_analysis_enabled=ai_analysis_enabled,
            api_key=api_key,
            user_id=user_id,
        )

    except Exception as e:
        logger.exception("SAST ZIP scan failed: %s", e)
        _progress_set(scan_session_id, {"status": "failed", "error": str(e)[:500]})
        async with AsyncSessionLocal() as db:
            session = (await db.execute(
                select(SastScanSession).where(SastScanSession.id == uuid.UUID(scan_session_id))
            )).scalar_one_or_none()
            if session:
                session.status = "failed"
                session.error_message = str(e)[:500]
                await db.commit()
    finally:
        # Cleanup
        shutil.rmtree(upload_dir, ignore_errors=True)
        if extract_dir:
            cleanup_source(extract_dir)


class RepoScanRequest(BaseModel):
    project_id: str
    repository_id: str
    branch: str | None = None
    ai_analysis: bool = False
    scan_config: dict | None = None  # exhaustive, gitleaks_enabled, rule_sets


@router.post("/scan/repository")
async def scan_repository(
    req: RepoScanRequest,
    background_tasks: BackgroundTasks,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Start SAST scan on a connected repository."""
    project = (await db.execute(select(Project).where(Project.id == uuid.UUID(req.project_id)))).scalar_one_or_none()
    if not project:
        raise HTTPException(404, "Project not found")
    if not await user_can_write_project(db, current_user, req.project_id):
        raise HTTPException(403, "Access denied")
    await _check_sast_enabled(db, project.organization_id)

    # Get repository
    repo = (await db.execute(
        select(SastRepository).where(SastRepository.id == uuid.UUID(req.repository_id))
    )).scalar_one_or_none()
    if not repo:
        raise HTTPException(404, "Repository not found")

    branch = req.branch or repo.default_branch

    # Create scan session
    scan_id = uuid.uuid4()
    session = SastScanSession(
        id=scan_id,
        project_id=uuid.UUID(req.project_id),
        organization_id=project.organization_id,
        scan_type=repo.provider,
        status="queued",
        source_info={"repo_url": repo.repo_url, "branch": branch, "repo_name": repo.repo_name},
        ai_analysis_enabled=req.ai_analysis,
        created_by=current_user.id,
    )
    db.add(session)
    await db.commit()

    token, _ = await _resolve_repository_access_token(db, project.organization_id, repo)

    api_key = await _resolve_api_key(db, project.organization_id) if req.ai_analysis else ""
    background_tasks.add_task(
        _run_repo_scan_background,
        scan_session_id=str(scan_id),
        project_id=req.project_id,
        organization_id=str(project.organization_id),
        repo_url=repo.repo_url,
        branch=branch,
        token=token,
        ai_analysis_enabled=req.ai_analysis,
        api_key=api_key,
        user_id=str(current_user.id),
        scan_config=req.scan_config or {},
    )

    # Update last scan time
    repo.last_scan_at = datetime.utcnow()
    await db.commit()

    from app.services.audit_service import log_audit
    await log_audit(db, "sast_scan_repo", str(current_user.id), "sast_scan", str(scan_id),
                    {"repo": repo.repo_name, "branch": branch})

    return {"scan_id": str(scan_id), "status": "queued"}


class BulkRepoScanRequest(BaseModel):
    project_id: str
    repository_ids: list[str] | None = None
    ai_analysis: bool = False
    scan_config: dict | None = None


@router.post("/scan/repositories/bulk")
async def scan_repositories_bulk(
    req: BulkRepoScanRequest,
    background_tasks: BackgroundTasks,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Start SAST scans for all or selected connected repositories in a project."""
    project = (await db.execute(select(Project).where(Project.id == uuid.UUID(req.project_id)))).scalar_one_or_none()
    if not project:
        raise HTTPException(404, "Project not found")
    if not await user_can_write_project(db, current_user, req.project_id):
        raise HTTPException(403, "Access denied")
    await _check_sast_enabled(db, project.organization_id)

    query = select(SastRepository).where(SastRepository.project_id == uuid.UUID(req.project_id))
    if req.repository_ids:
        query = query.where(SastRepository.id.in_([uuid.UUID(rid) for rid in req.repository_ids]))
    repos = (await db.execute(query.order_by(desc(SastRepository.created_at)))).scalars().all()
    if not repos:
        raise HTTPException(404, "No repositories available for bulk scan")

    api_key = await _resolve_api_key(db, project.organization_id) if req.ai_analysis else ""
    launched: list[dict] = []
    scan_cfg = req.scan_config or {}
    for repo in repos:
        scan_id = uuid.uuid4()
        branch = repo.default_branch or "main"
        session = SastScanSession(
            id=scan_id,
            project_id=uuid.UUID(req.project_id),
            organization_id=project.organization_id,
            scan_type=repo.provider,
            status="queued",
            source_info={"repo_url": repo.repo_url, "branch": branch, "repo_name": repo.repo_name},
            ai_analysis_enabled=req.ai_analysis,
            scan_config=scan_cfg,
            created_by=current_user.id,
        )
        db.add(session)
        token, _ = await _resolve_repository_access_token(db, project.organization_id, repo)
        background_tasks.add_task(
            _run_repo_scan_background,
            scan_session_id=str(scan_id),
            project_id=req.project_id,
            organization_id=str(project.organization_id),
            repo_url=repo.repo_url,
            branch=branch,
            token=token,
            ai_analysis_enabled=req.ai_analysis,
            api_key=api_key,
            user_id=str(current_user.id),
            scan_config=scan_cfg,
        )
        repo.last_scan_at = datetime.utcnow()
        launched.append({"scan_id": str(scan_id), "repository_id": str(repo.id), "repo_name": repo.repo_name, "branch": branch})

    await db.commit()
    return {"status": "queued", "launched": launched, "count": len(launched)}


async def _run_repo_scan_background(
    scan_session_id: str, project_id: str, organization_id: str,
    repo_url: str, branch: str, token: str | None,
    ai_analysis_enabled: bool, api_key: str, user_id: str,
    scan_config: dict | None = None,
):
    """Background task: clone repo and run SAST scan."""
    from app.services.sast.code_extractor import clone_repo, cleanup_source
    from app.services.sast.scanner import run_sast_scan, _progress_set

    clone_dir = None
    try:
        async with AsyncSessionLocal() as db:
            session = (await db.execute(
                select(SastScanSession).where(SastScanSession.id == uuid.UUID(scan_session_id))
            )).scalar_one_or_none()
            if session:
                session.status = "extracting"
                await db.commit()
                # Use session.scan_config if not passed (e.g. bulk scan)
                if scan_config is None:
                    scan_config = session.scan_config or {}

        clone_dir = clone_repo(repo_url, branch=branch, token=token)

        await run_sast_scan(
            scan_session_id=scan_session_id,
            project_id=project_id,
            organization_id=organization_id,
            source_path=clone_dir,
            scan_config=scan_config,
            ai_analysis_enabled=ai_analysis_enabled,
            api_key=api_key,
            user_id=user_id,
        )
    except Exception as e:
        logger.exception("SAST repo scan failed: %s", e)
        _progress_set(scan_session_id, {"status": "failed", "error": str(e)[:500]})
        async with AsyncSessionLocal() as db:
            session = (await db.execute(
                select(SastScanSession).where(SastScanSession.id == uuid.UUID(scan_session_id))
            )).scalar_one_or_none()
            if session:
                session.status = "failed"
                session.error_message = str(e)[:500]
                await db.commit()
    finally:
        if clone_dir:
            cleanup_source(clone_dir)


@router.get("/scan/{scan_id}/progress")
async def get_scan_progress(
    scan_id: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get real-time scan progress."""
    session = (await db.execute(
        select(SastScanSession).where(SastScanSession.id == uuid.UUID(scan_id))
    )).scalar_one_or_none()
    if not session:
        raise HTTPException(404, "Scan not found")
    if not await user_can_read_project(db, current_user, str(session.project_id)):
        raise HTTPException(403, "Access denied")
    progress = _sast_progress_get(scan_id)
    if progress:
        return progress
    return {"status": "unknown", "message": "No progress data available"}


@router.get("/scan/{scan_id}/results")
async def get_scan_results(
    scan_id: str,
    severity: str | None = None,
    status: str | None = None,
    file_path: str | None = None,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get scan results with findings."""
    session = (await db.execute(
        select(SastScanSession).where(SastScanSession.id == uuid.UUID(scan_id))
    )).scalar_one_or_none()
    if not session:
        raise HTTPException(404, "Scan not found")
    if not await user_can_read_project(db, current_user, str(session.project_id)):
        raise HTTPException(403, "Access denied")

    # Build findings query
    q = select(SastFinding).where(SastFinding.scan_session_id == uuid.UUID(scan_id))
    if severity:
        q = q.where(SastFinding.severity == severity)
    if status:
        q = q.where(SastFinding.status == status)
    if file_path:
        q = q.where(SastFinding.file_path.ilike(f"%{file_path}%"))
    q = q.order_by(
        # Critical first
        case(
            (SastFinding.severity == "critical", 1),
            (SastFinding.severity == "high", 2),
            (SastFinding.severity == "medium", 3),
            (SastFinding.severity == "low", 4),
            (SastFinding.severity == "info", 5),
            else_=6,
        ),
        SastFinding.file_path,
        SastFinding.line_start,
    )

    findings_result = await db.execute(q)
    findings = [_finding_to_dict(f) for f in findings_result.scalars().all()]

    # Build file tree for sidebar
    file_tree = {}
    for f in findings:
        fp = f["file_path"]
        if fp not in file_tree:
            file_tree[fp] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0}
        file_tree[fp][f["severity"]] = file_tree[fp].get(f["severity"], 0) + 1
        file_tree[fp]["total"] += 1

    return {
        "scan": _session_to_dict(session),
        "findings": findings,
        "file_tree": file_tree,
        "total_findings": len(findings),
    }


@router.get("/scans/{project_id}")
async def list_scan_history(
    project_id: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List SAST scan history for a project."""
    if not await user_can_read_project(db, current_user, project_id):
        raise HTTPException(403, "Access denied")

    scans = (await db.execute(
        select(SastScanSession)
        .where(SastScanSession.project_id == uuid.UUID(project_id))
        .order_by(desc(SastScanSession.created_at))
        .limit(50)
    )).scalars().all()

    return {"scans": [_session_to_dict(s) for s in scans]}


@router.post("/scan/{scan_id}/stop")
async def stop_scan(
    scan_id: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Cancel a running scan."""
    session = (await db.execute(
        select(SastScanSession).where(SastScanSession.id == uuid.UUID(scan_id))
    )).scalar_one_or_none()
    if not session:
        raise HTTPException(404, "Scan not found")
    if not await user_can_write_project(db, current_user, str(session.project_id)):
        raise HTTPException(403, "Access denied")

    if session.status in ("queued", "extracting", "scanning", "ai_analyzing"):
        session.status = "stopped"
        session.completed_at = datetime.utcnow()
        await db.commit()
        try:
            from app.services.sast.scanner import _progress_set
            _progress_set(scan_id, {
                "status": "stopped",
                "phase": "done",
                "message": "Scan stopped by user",
                "last_updated": datetime.utcnow().isoformat(),
            })
        except Exception:
            logger.debug("Failed to update SAST progress on stop", exc_info=True)
        return {"status": "stopped"}

    return {"status": session.status, "message": "Scan already completed"}


@router.post("/scan/{scan_id}/ai-analyze")
async def trigger_ai_analysis(
    scan_id: str,
    background_tasks: BackgroundTasks,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Trigger AI analysis on existing scan findings."""
    session = (await db.execute(
        select(SastScanSession).where(SastScanSession.id == uuid.UUID(scan_id))
    )).scalar_one_or_none()
    if not session or session.status != "completed":
        raise HTTPException(400, "Scan must be completed first")
    if not await user_can_write_project(db, current_user, str(session.project_id)):
        raise HTTPException(403, "Access denied")

    api_key = await _resolve_api_key(db, session.organization_id)
    if not api_key:
        raise HTTPException(400, "No Anthropic API key configured")

    background_tasks.add_task(_run_ai_analysis_background, scan_id, api_key, str(session.organization_id))
    return {"status": "analyzing", "message": "AI analysis started"}


async def _run_ai_analysis_background(scan_id: str, api_key: str, org_id: str):
    """Background: run AI analysis on findings."""
    from app.services.sast.ai_analyzer import analyze_findings_with_ai

    async with AsyncSessionLocal() as db:
        findings = (await db.execute(
            select(SastFinding).where(SastFinding.scan_session_id == uuid.UUID(scan_id))
        )).scalars().all()

        if not findings:
            return

        finding_dicts = [_finding_to_dict(f) for f in findings]
        analyzed = await analyze_findings_with_ai(finding_dicts, api_key)

        # Update findings with AI analysis
        analysis_map = {a["id"]: a for a in analyzed}
        for f in findings:
            fid = str(f.id)
            if fid in analysis_map:
                ai = analysis_map[fid].get("ai_analysis")
                if ai:
                    f.ai_analysis = ai
                    f.fix_suggestion = analysis_map[fid].get("fix_suggestion") or f.fix_suggestion
                    f.fixed_code = analysis_map[fid].get("fixed_code") or f.fixed_code

        session = (await db.execute(
            select(SastScanSession).where(SastScanSession.id == uuid.UUID(scan_id))
        )).scalar_one_or_none()
        if session:
            session.ai_analysis_enabled = True

        await db.commit()


# ── Repository Management ──────────────────────────────────────────

class ConnectRepoRequest(BaseModel):
    project_id: str
    provider: str = "github"  # github, gitlab, bitbucket
    repo_url: str
    repo_name: str
    repo_owner: str | None = None
    default_branch: str = "main"
    auth_mode: str = "pat"  # pat, oauth, github_app
    access_token: str | None = None
    installation_id: int | None = None
    account_login: str | None = None


@router.post("/repositories")
async def connect_repository(
    req: ConnectRepoRequest,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Connect a source code repository for scanning."""
    project = (await db.execute(select(Project).where(Project.id == uuid.UUID(req.project_id)))).scalar_one_or_none()
    if not project:
        raise HTTPException(404, "Project not found")
    if not await user_can_write_project(db, current_user, req.project_id):
        raise HTTPException(403, "Access denied")
    await _check_sast_enabled(db, project.organization_id)

    from app.services.sast.github_client import (
        encrypt_token,
        verify_token,
        github_app_is_configured,
        list_installation_repos,
    )
    from app.services.admin_settings_service import get_github_platform_config
    from app.services.org_settings_service import get_github_config

    auth_mode = (req.auth_mode or "pat").lower()
    encrypted = None
    repo_scan_config = {"auth_mode": auth_mode}
    github_cfg = await get_github_config(db, project.organization_id)
    platform_github = await get_github_platform_config(db)

    if auth_mode == "pat":
        token = github_cfg.get("pat_token") or req.access_token
        if not token:
            raise HTTPException(400, "Organization GitHub PAT is not connected")
        try:
            await verify_token(token)
        except Exception as e:
            raise HTTPException(400, f"Invalid access token: {str(e)[:200]}")
        # Keep backward compatibility for older scans if token was provided inline.
        encrypted = encrypt_token(token) if req.access_token else None
    elif auth_mode == "oauth":
        token = github_cfg.get("oauth_token")
        if not token:
            raise HTTPException(400, "Organization GitHub OAuth is not connected")
    elif auth_mode == "github_app":
        if not req.installation_id:
            installation = github_cfg.get("app_installation") or {}
            req.installation_id = installation.get("installation_id")
        if not req.installation_id:
            raise HTTPException(400, "GitHub App installation_id is required")
        if not github_app_is_configured(platform_github):
            raise HTTPException(400, "GitHub App is not configured on this server")
        install_ctx = github_cfg.get("app_installation") or {}
        install_id = int(req.installation_id)
        if not install_ctx or int(install_ctx.get("installation_id", 0)) != install_id:
            raise HTTPException(400, "Organization GitHub App installation is missing or expired")
        try:
            repos = await list_installation_repos(install_id, config=platform_github)
        except Exception as e:
            raise HTTPException(400, f"Unable to verify GitHub App installation: {str(e)[:200]}")
        matched = next((r for r in repos if r.get("full_name") == f"{req.repo_owner}/{req.repo_name}" or r.get("name") == req.repo_name), None)
        if not matched:
            raise HTTPException(403, "Selected repository is not accessible through the GitHub App installation")
        repo_scan_config.update({
            "installation_id": install_id,
            "account_login": install_ctx.get("account_login") or req.account_login,
        })
    else:
        raise HTTPException(400, "Unsupported auth_mode")

    repo = SastRepository(
        organization_id=project.organization_id,
        project_id=uuid.UUID(req.project_id),
        provider=req.provider,
        repo_url=req.repo_url,
        repo_name=req.repo_name,
        repo_owner=req.repo_owner,
        default_branch=req.default_branch,
        access_token_encrypted=encrypted,
        scan_config=repo_scan_config,
        created_by=current_user.id,
    )
    db.add(repo)
    await db.commit()
    await db.refresh(repo)

    from app.services.audit_service import log_audit
    await log_audit(db, "sast_repo_connect", str(current_user.id), "sast_repository", str(repo.id),
                    {"repo": req.repo_name, "provider": req.provider})

    return {
        "id": str(repo.id),
        "repo_name": repo.repo_name,
        "provider": repo.provider,
        "auth_mode": auth_mode,
        "status": "connected",
    }


@router.get("/repositories/{project_id}")
async def list_repositories(
    project_id: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List connected repositories for a project."""
    if not await user_can_read_project(db, current_user, project_id):
        raise HTTPException(403, "Access denied")

    repos = (await db.execute(
        select(SastRepository)
        .where(SastRepository.project_id == uuid.UUID(project_id))
        .order_by(desc(SastRepository.created_at))
    )).scalars().all()

    return {"repositories": [{
        "id": str(r.id),
        "provider": r.provider,
        "repo_url": r.repo_url,
        "repo_name": r.repo_name,
        "repo_owner": r.repo_owner,
        "default_branch": r.default_branch,
        "auth_mode": (r.scan_config or {}).get("auth_mode", "pat"),
        "installation_id": (r.scan_config or {}).get("installation_id"),
        "account_login": (r.scan_config or {}).get("account_login"),
        "auto_scan_enabled": r.auto_scan_enabled,
        "last_scan_at": r.last_scan_at.isoformat() if r.last_scan_at else None,
        "created_at": r.created_at.isoformat() if r.created_at else None,
    } for r in repos]}


@router.delete("/repositories/{repo_id}")
async def disconnect_repository(
    repo_id: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Disconnect a repository."""
    repo = (await db.execute(
        select(SastRepository).where(SastRepository.id == uuid.UUID(repo_id))
    )).scalar_one_or_none()
    if not repo:
        raise HTTPException(404, "Repository not found")
    if repo.project_id and not await user_can_write_project(db, current_user, str(repo.project_id)):
        raise HTTPException(403, "Access denied")

    await db.delete(repo)
    await db.commit()

    from app.services.audit_service import log_audit
    await log_audit(db, "sast_repo_disconnect", str(current_user.id), "sast_repository", str(repo_id),
                    {"repo": repo.repo_name})

    return {"status": "disconnected"}


# ── GitHub Integration ─────────────────────────────────────────────

class GithubListReposRequest(BaseModel):
    project_id: str
    access_token: str
    page: int = 1


@router.post("/github/repos")
async def github_list_repos(
    req: GithubListReposRequest,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Validate and store an organization PAT, then list repos."""
    from app.services.sast.github_client import list_repos, verify_token
    from app.services.org_settings_service import update_github_pat_config

    project = (await db.execute(select(Project).where(Project.id == uuid.UUID(req.project_id)))).scalar_one_or_none()
    if not project:
        raise HTTPException(404, "Project not found")
    if not await user_can_write_project(db, current_user, req.project_id):
        raise HTTPException(403, "Access denied")

    try:
        account = await verify_token(req.access_token)
        repos = await list_repos(req.access_token, page=req.page)
        await update_github_pat_config(db, project.organization_id, req.access_token, account_login=account.get("login", ""))
        await db.commit()
        return {"repos": repos, "account": account, "auth_mode": "pat", "organization_connected": True}
    except Exception as e:
        raise HTTPException(400, f"GitHub API error: {str(e)[:200]}")


# ── GitHub Connection Status / App Integration ───────────────────

@router.get("/github/status")
async def github_status(
    project_id: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return available GitHub connection modes and cached session state."""
    from app.services.admin_settings_service import get_github_platform_config
    from app.services.sast.github_client import github_app_is_configured
    from app.services.org_settings_service import get_github_config

    if not await user_can_read_project(db, current_user, project_id):
        raise HTTPException(403, "Access denied")

    project = (await db.execute(select(Project).where(Project.id == uuid.UUID(project_id)))).scalar_one_or_none()
    if not project:
        raise HTTPException(404, "Project not found")

    platform_github = await get_github_platform_config(db)
    github_cfg = await get_github_config(db, project.organization_id)
    app_installation = github_cfg.get("app_installation")
    return {
        "oauth_configured": bool(platform_github.get("github_oauth_client_id") and platform_github.get("github_oauth_client_secret")),
        "oauth_connected": bool(github_cfg.get("oauth_token")),
        "oauth_account_login": github_cfg.get("oauth_account_login", ""),
        "pat_connected": bool(github_cfg.get("pat_token")),
        "pat_account_login": github_cfg.get("pat_account_login", ""),
        "github_app_configured": github_app_is_configured(platform_github),
        "github_app_connected": bool(app_installation),
        "github_app_installation": app_installation,
        "pat_supported": True,
    }


@router.get("/github/app/install")
async def github_app_install_start(
    project_id: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Start GitHub App installation flow for this user/project context."""
    import secrets as sec
    import redis.asyncio as aioredis
    from app.core.config import get_settings
    from app.services.admin_settings_service import get_github_platform_config
    from app.services.sast.github_client import github_app_is_configured, get_github_app_install_url

    if not await user_can_write_project(db, current_user, project_id):
        raise HTTPException(403, "Access denied")

    project = (await db.execute(select(Project).where(Project.id == uuid.UUID(project_id)))).scalar_one_or_none()
    if not project:
        raise HTTPException(404, "Project not found")

    platform_github = await get_github_platform_config(db)
    if not github_app_is_configured(platform_github):
        raise HTTPException(400, "GitHub App not configured. Use OAuth or PAT instead.")

    state = sec.token_urlsafe(32)
    r = aioredis.from_url(get_settings().redis_url, decode_responses=True)
    await r.setex(
        _github_app_state_key(state),
        600,
        json.dumps({
            "user_id": str(current_user.id),
            "project_id": project_id,
            "org_id": str(project.organization_id),
            "return_to": "project_sast",
        }),
    )
    await r.aclose()
    return {"install_url": get_github_app_install_url(state, platform_github), "state": state}


@router.get("/github/app/callback")
async def github_app_callback(
    installation_id: int,
    setup_action: str | None = None,
    state: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    """GitHub App callback after install/config update."""
    import redis.asyncio as aioredis
    from fastapi.responses import HTMLResponse
    from app.core.config import get_settings
    from app.services.admin_settings_service import get_github_platform_config
    from app.services.sast.github_client import get_installation_info
    from app.services.org_settings_service import update_github_app_installation

    if not state:
        raise HTTPException(400, "Missing state")

    r = aioredis.from_url(get_settings().redis_url, decode_responses=True)
    state_data = await r.get(_github_app_state_key(state))
    await r.delete(_github_app_state_key(state))
    if not state_data:
        await r.aclose()
        raise HTTPException(403, "Invalid or expired GitHub App state")

    state_info = json.loads(state_data)
    project_id = state_info.get("project_id")
    org_id = state_info.get("org_id")
    return_to = state_info.get("return_to", "project_sast")
    project = None
    organization_id = None
    if project_id:
        project = (await db.execute(select(Project).where(Project.id == uuid.UUID(project_id)))).scalar_one_or_none()
        if not project:
            await r.aclose()
            raise HTTPException(404, "Project not found")
        organization_id = project.organization_id
    elif org_id:
        org = (await db.execute(select(Organization).where(Organization.id == uuid.UUID(org_id)))).scalar_one_or_none()
        if not org:
            await r.aclose()
            raise HTTPException(404, "Organization not found")
        organization_id = org.id
    else:
        await r.aclose()
        raise HTTPException(400, "GitHub App state is missing project or organization context")
    platform_github = await get_github_platform_config(db)
    install_info = await get_installation_info(installation_id, platform_github)
    await update_github_app_installation(db, organization_id, {
        "installation_id": installation_id,
        "account_login": install_info.get("account_login"),
        "account_type": install_info.get("account_type"),
        "setup_action": setup_action or "install",
    })
    await db.commit()
    await r.aclose()

    frontend_origin = _public_frontend_origin()
    if return_to == "project_sast_import" and project_id:
        redirect_url = (
            f"{frontend_origin}/projects/{project_id}/sast"
            f"?github_app=success"
            f"&open_connect=1"
            f"&github_auth_mode=github_app"
        )
    elif return_to == "admin_settings":
        redirect_url = (
            f"{frontend_origin}/admin/settings"
            f"?tab=github"
            f"&github_app=success"
            f"&installation_id={installation_id}"
            f"&org_id={organization_id}"
        )
    else:
        redirect_url = (
            f"{frontend_origin}/projects/{project_id}/sast"
            f"?github_app=success"
            f"&installation_id={installation_id}"
        )
    html = f"""
    <html><body><script>
    if (window.opener) {{
        window.opener.postMessage({{
            type: "github_app_success",
            installation_id: "{installation_id}",
            project_id: "{project_id or ''}",
            account_login: "{install_info.get('account_login', '')}"
        }}, "*");
        window.close();
    }} else {{
        window.location.href = "{redirect_url}";
    }}
    </script><p>GitHub App connected. Redirecting...</p></body></html>
    """
    return HTMLResponse(html)


@router.get("/github/app/repos")
async def github_app_list_repos(
    project_id: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List repos available through the installed GitHub App context."""
    from app.services.admin_settings_service import get_github_platform_config
    from app.services.sast.github_client import list_installation_repos
    from app.services.org_settings_service import get_github_config

    if not await user_can_read_project(db, current_user, project_id):
        raise HTTPException(403, "Access denied")

    project = (await db.execute(select(Project).where(Project.id == uuid.UUID(project_id)))).scalar_one_or_none()
    if not project:
        raise HTTPException(404, "Project not found")
    github_cfg = await get_github_config(db, project.organization_id)
    install_ctx = github_cfg.get("app_installation")
    if not install_ctx:
        raise HTTPException(400, "No organization GitHub App installation found. Complete install flow first.")

    installation_id = int(install_ctx["installation_id"])
    platform_github = await get_github_platform_config(db)
    repos = await list_installation_repos(installation_id, config=platform_github)
    return {
        "repos": repos,
        "installation": install_ctx,
        "total": len(repos),
    }


@router.get("/github/pat/repos")
async def github_pat_list_repos(
    project_id: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List repos using the organization-scoped PAT connection."""
    from app.services.sast.github_client import list_repos
    from app.services.org_settings_service import get_github_config

    if not await user_can_read_project(db, current_user, project_id):
        raise HTTPException(403, "Access denied")
    project = (await db.execute(select(Project).where(Project.id == uuid.UUID(project_id)))).scalar_one_or_none()
    if not project:
        raise HTTPException(404, "Project not found")

    github_cfg = await get_github_config(db, project.organization_id)
    access_token = github_cfg.get("pat_token")
    if not access_token:
        raise HTTPException(400, "No organization GitHub PAT connection found.")

    repos = await list_repos(access_token, page=1, per_page=100)
    return {"repos": repos, "total": len(repos), "auth_mode": "pat"}


@router.get("/github/branches")
async def github_list_branches(
    project_id: str,
    repo_owner: str,
    repo_name: str,
    auth_mode: str = "github_app",
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List branches for a repository using the organization's GitHub connection."""
    from app.services.admin_settings_service import get_github_platform_config
    from app.services.org_settings_service import get_github_config
    from app.services.sast.github_client import get_branches, get_installation_access_token

    if not await user_can_read_project(db, current_user, project_id):
        raise HTTPException(403, "Access denied")
    project = (await db.execute(select(Project).where(Project.id == uuid.UUID(project_id)))).scalar_one_or_none()
    if not project:
        raise HTTPException(404, "Project not found")

    github_cfg = await get_github_config(db, project.organization_id)
    mode = (auth_mode or "github_app").lower()
    token = None
    if mode == "github_app":
        installation = github_cfg.get("app_installation") or {}
        installation_id = installation.get("installation_id")
        if not installation_id:
            raise HTTPException(400, "Organization GitHub App installation is missing")
        platform_github = await get_github_platform_config(db)
        token = await get_installation_access_token(int(installation_id), platform_github)
    elif mode == "oauth":
        token = github_cfg.get("oauth_token")
    elif mode == "pat":
        token = github_cfg.get("pat_token")
    if not token:
        raise HTTPException(400, f"No organization GitHub {mode} connection found")

    branches = await get_branches(token, repo_owner, repo_name)
    return {"branches": branches}


# ── GitHub OAuth Integration ──────────────────────────────────────

@router.get("/github/oauth/authorize")
async def github_oauth_start(
    project_id: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Start GitHub OAuth flow - returns URL to redirect user to."""
    from app.core.config import get_settings
    from app.services.admin_settings_service import get_github_platform_config
    import secrets as sec
    import redis.asyncio as aioredis

    settings = get_settings()
    platform_github = await get_github_platform_config(db)
    if not platform_github.get("github_oauth_client_id"):
        raise HTTPException(400, "GitHub OAuth not configured. Use PAT instead.")

    project = (await db.execute(select(Project).where(Project.id == uuid.UUID(project_id)))).scalar_one_or_none()
    if not project:
        raise HTTPException(404, "Project not found")
    if not await user_can_write_project(db, current_user, project_id):
        raise HTTPException(403, "Access denied")

    state = sec.token_urlsafe(32)

    # Store state in Redis for CSRF verification (5 min expiry)
    r = aioredis.from_url(settings.redis_url, decode_responses=True)
    await r.setex(
        _github_oauth_state_key(state),
        300,
        json.dumps({
            "user_id": str(current_user.id),
            "project_id": project_id,
            "org_id": str(project.organization_id),
            "return_to": "project_sast",
        }),
    )
    await r.aclose()

    redirect_uri = platform_github.get("github_oauth_redirect_uri") or settings.github_oauth_redirect_uri or (
        f"{_public_frontend_origin()}/api/sast/github/oauth/callback"
    )

    url = (
        f"https://github.com/login/oauth/authorize"
        f"?client_id={platform_github.get('github_oauth_client_id')}"
        f"&redirect_uri={redirect_uri}"
        f"&scope=repo read:org read:user user:email"
        f"&state={state}"
    )
    return {"authorize_url": url, "state": state}


@router.get("/github/oauth/callback")
async def github_oauth_callback(
    code: str,
    state: str,
    db: AsyncSession = Depends(get_db),
):
    """GitHub OAuth callback - exchange code for token, store it."""
    from app.core.config import get_settings
    from app.services.admin_settings_service import get_github_platform_config
    from fastapi.responses import HTMLResponse
    from app.services.org_settings_service import update_github_oauth_config
    import redis.asyncio as aioredis
    import httpx

    settings = get_settings()
    platform_github = await get_github_platform_config(db)

    # Verify CSRF state
    r = aioredis.from_url(settings.redis_url, decode_responses=True)
    state_data = await r.get(_github_oauth_state_key(state))
    await r.delete(_github_oauth_state_key(state))

    if not state_data:
        await r.aclose()
        raise HTTPException(403, "Invalid or expired OAuth state")

    state_info = json.loads(state_data)
    project_id = state_info.get("project_id")
    org_id = state_info.get("org_id")
    return_to = state_info.get("return_to", "project_sast")
    project = None
    organization_id = None
    if project_id:
        project = (await db.execute(select(Project).where(Project.id == uuid.UUID(project_id)))).scalar_one_or_none()
        if not project:
            await r.aclose()
            raise HTTPException(404, "Project not found")
        organization_id = project.organization_id
    elif org_id:
        org = (await db.execute(select(Organization).where(Organization.id == uuid.UUID(org_id)))).scalar_one_or_none()
        if not org:
            await r.aclose()
            raise HTTPException(404, "Organization not found")
        organization_id = org.id
    else:
        await r.aclose()
        raise HTTPException(400, "GitHub OAuth state is missing project or organization context")

    # Exchange code for access token
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            "https://github.com/login/oauth/access_token",
            json={
                "client_id": platform_github.get("github_oauth_client_id"),
                "client_secret": platform_github.get("github_oauth_client_secret"),
                "code": code,
            },
            headers={"Accept": "application/json"},
        )
        if resp.status_code != 200:
            await r.aclose()
            raise HTTPException(502, "Failed to exchange code with GitHub")
        token_data = resp.json()
        if "error" in token_data:
            await r.aclose()
            raise HTTPException(
                400,
                f"GitHub OAuth error: {token_data.get('error_description', token_data['error'])}",
            )
        access_token = token_data["access_token"]

    # Get user info from GitHub
    async with httpx.AsyncClient() as client:
        user_resp = await client.get(
            "https://api.github.com/user",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/vnd.github+json",
            },
        )
        github_user = user_resp.json()

    # Store token for the organization so other admins can reuse it.
    await update_github_oauth_config(
        db,
        organization_id,
        access_token,
        account_login=github_user.get("login", ""),
    )
    await db.commit()
    await r.aclose()

    frontend_origin = _public_frontend_origin()
    if return_to == "project_sast_import" and project_id:
        redirect_url = (
            f"{frontend_origin}/projects/{project_id}/sast"
            f"?github_oauth=success"
            f"&github_username={github_user.get('login', '')}"
            f"&open_connect=1"
            f"&github_auth_mode=oauth"
        )
    elif return_to == "admin_settings":
        redirect_url = (
            f"{frontend_origin}/admin/settings"
            f"?tab=github"
            f"&github_oauth=success"
            f"&github_username={github_user.get('login', '')}"
            f"&org_id={organization_id}"
        )
    else:
        redirect_url = (
            f"{frontend_origin}/projects/{project_id}/sast"
            f"?github_oauth=success"
            f"&github_username={github_user.get('login', '')}"
        )

    # Return HTML that posts message to parent window (if popup) or redirects
    html = f"""
    <html><body><script>
    if (window.opener) {{
        window.opener.postMessage({{
            type: "github_oauth_success",
            github_username: "{github_user.get('login', '')}",
            project_id: "{project_id or ''}"
        }}, "*");
        window.close();
    }} else {{
        window.location.href = "{redirect_url}";
    }}
    </script><p>Connected! Redirecting...</p></body></html>
    """
    return HTMLResponse(html)


@router.get("/github/oauth/repos")
async def github_oauth_list_repos(
    project_id: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List repos using the organization-scoped OAuth token."""
    from app.services.sast.github_client import list_repos
    from app.services.org_settings_service import get_github_config

    if not await user_can_read_project(db, current_user, project_id):
        raise HTTPException(403, "Access denied")
    project = (await db.execute(select(Project).where(Project.id == uuid.UUID(project_id)))).scalar_one_or_none()
    if not project:
        raise HTTPException(404, "Project not found")

    github_cfg = await get_github_config(db, project.organization_id)
    access_token = github_cfg.get("oauth_token")
    if not access_token:
        raise HTTPException(400, "No organization GitHub OAuth connection found. Complete OAuth flow first.")

    repos = await list_repos(access_token, page=1, per_page=100)
    return {"repos": repos, "total": len(repos), "auth_mode": "oauth"}


# ── Findings Management ───────────────────────────────────────────

@router.get("/findings/{scan_id}")
async def list_findings(
    scan_id: str,
    severity: str | None = None,
    status: str | None = None,
    confidence: str | None = None,
    rule_source: str | None = None,
    file_path: str | None = None,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List findings for a scan with filters."""
    session = (await db.execute(
        select(SastScanSession).where(SastScanSession.id == uuid.UUID(scan_id))
    )).scalar_one_or_none()
    if not session:
        raise HTTPException(404, "Scan not found")
    if not await user_can_read_project(db, current_user, str(session.project_id)):
        raise HTTPException(403, "Access denied")

    q = select(SastFinding).where(SastFinding.scan_session_id == uuid.UUID(scan_id))
    if severity:
        q = q.where(SastFinding.severity == severity)
    if status:
        q = q.where(SastFinding.status == status)
    if confidence:
        q = q.where(SastFinding.confidence == confidence)
    if rule_source:
        q = q.where(SastFinding.rule_source == rule_source)
    if file_path:
        q = q.where(SastFinding.file_path.ilike(f"%{file_path}%"))

    q = q.order_by(SastFinding.file_path, SastFinding.line_start)
    findings = (await db.execute(q)).scalars().all()

    return {"findings": [_finding_to_dict(f) for f in findings], "total": len(findings)}


class UpdateFindingStatusRequest(BaseModel):
    status: str  # open, confirmed, false_positive, fixed, ignored, wont_fix


@router.patch("/findings/{finding_id}/status")
async def update_finding_status(
    finding_id: str,
    req: UpdateFindingStatusRequest,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update a finding's status."""
    finding = (await db.execute(
        select(SastFinding).where(SastFinding.id == uuid.UUID(finding_id))
    )).scalar_one_or_none()
    if not finding:
        raise HTTPException(404, "Finding not found")
    if not await user_can_write_project(db, current_user, str(finding.project_id)):
        raise HTTPException(403, "Access denied")

    valid_statuses = {"open", "confirmed", "false_positive", "fixed", "ignored", "wont_fix"}
    if req.status not in valid_statuses:
        raise HTTPException(400, f"Invalid status. Must be one of: {valid_statuses}")

    finding.status = req.status
    await db.commit()

    return {"id": str(finding.id), "status": finding.status}


@router.get("/findings/{finding_id}/ai-explain")
async def ai_explain_finding(
    finding_id: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get detailed AI explanation for a finding."""
    finding = (await db.execute(
        select(SastFinding).where(SastFinding.id == uuid.UUID(finding_id))
    )).scalar_one_or_none()
    if not finding:
        raise HTTPException(404, "Finding not found")
    if not await user_can_read_project(db, current_user, str(finding.project_id)):
        raise HTTPException(403, "Access denied")

    # Get API key
    session = (await db.execute(
        select(SastScanSession).where(SastScanSession.id == finding.scan_session_id)
    )).scalar_one_or_none()
    if not session:
        raise HTTPException(404, "Scan session not found")

    api_key = await _resolve_api_key(db, session.organization_id)
    if not api_key:
        raise HTTPException(400, "No Anthropic API key configured")

    from app.services.sast.ai_analyzer import explain_finding
    result = await explain_finding(_finding_to_dict(finding), api_key)
    return result


class CreateFixPrRequest(BaseModel):
    repository_id: str | None = None
    base_branch: str | None = None
    branch_name: str | None = None
    title: str | None = None
    body: str | None = None


async def _resolve_repository_for_finding(
    db: AsyncSession,
    finding: SastFinding,
    session: SastScanSession,
    repository_id: str | None = None,
) -> SastRepository | None:
    repo = None
    if repository_id:
        repo = (await db.execute(
            select(SastRepository).where(SastRepository.id == uuid.UUID(repository_id))
        )).scalar_one_or_none()
    else:
        source_info = session.source_info or {}
        repo_name = source_info.get("repo_name")
        repo_url = source_info.get("repo_url")
        candidates = (await db.execute(
            select(SastRepository).where(SastRepository.project_id == finding.project_id)
        )).scalars().all()
        if repo_name:
            repo = next((r for r in candidates if r.repo_name == repo_name), None)
        if not repo and repo_url:
            repo = next((r for r in candidates if r.repo_url == repo_url), None)
        if not repo and len(candidates) == 1:
            repo = candidates[0]
    return repo


@router.get("/findings/{finding_id}/source")
async def get_finding_source(
    finding_id: str,
    repository_id: str | None = None,
    branch: str | None = None,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Fetch the exact repository file for a finding and return it for inline review."""
    from app.services.sast.github_client import get_file_content

    finding = (await db.execute(
        select(SastFinding).where(SastFinding.id == uuid.UUID(finding_id))
    )).scalar_one_or_none()
    if not finding:
        raise HTTPException(404, "Finding not found")
    if not await user_can_read_project(db, current_user, str(finding.project_id)):
        raise HTTPException(403, "Access denied")

    session = (await db.execute(
        select(SastScanSession).where(SastScanSession.id == finding.scan_session_id)
    )).scalar_one_or_none()
    if not session:
        raise HTTPException(404, "Scan session not found")

    repo = await _resolve_repository_for_finding(db, finding, session, repository_id)
    if not repo:
        raise HTTPException(400, "Unable to determine repository for this finding")

    access_token, auth_mode = await _resolve_repository_access_token(db, session.organization_id, repo)
    repo_owner = repo.repo_owner or ((repo.repo_url.rstrip("/").split("/")[-2]) if "/" in repo.repo_url.rstrip("/") else "")
    if not repo_owner:
        raise HTTPException(400, "Repository owner could not be determined")
    ref = branch or (session.source_info or {}).get("branch") or repo.default_branch or "main"

    try:
        source = await get_file_content(access_token, repo_owner, repo.repo_name, finding.file_path, ref=ref)
    except Exception as e:
        raise HTTPException(400, f"Unable to load source file: {str(e)[:200]}")

    html_url = source.get("html_url") or f"{repo.repo_url.rstrip('/')}/blob/{ref}/{finding.file_path.lstrip('/')}"
    if finding.line_start:
        html_url += f"#L{finding.line_start}"
        if finding.line_end and finding.line_end != finding.line_start:
            html_url += f"-L{finding.line_end}"

    return {
        "repository_id": str(repo.id),
        "repo_name": repo.repo_name,
        "repo_owner": repo_owner,
        "branch": ref,
        "auth_mode": auth_mode,
        "file_path": source.get("path") or finding.file_path,
        "content": source.get("content", ""),
        "html_url": html_url,
        "line_start": finding.line_start,
        "line_end": finding.line_end,
        "finding_id": str(finding.id),
    }


@router.post("/findings/{finding_id}/create-pr")
async def create_fix_pull_request(
    finding_id: str,
    req: CreateFixPrRequest,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Create a GitHub pull request containing an AI-generated fix for a SAST finding."""
    from app.services.sast.ai_analyzer import explain_finding
    from app.services.sast.github_client import create_pull_request
    from app.services.sast.remediation import apply_fix_and_push

    finding = (await db.execute(
        select(SastFinding).where(SastFinding.id == uuid.UUID(finding_id))
    )).scalar_one_or_none()
    if not finding:
        raise HTTPException(404, "Finding not found")
    if not await user_can_write_project(db, current_user, str(finding.project_id)):
        raise HTTPException(403, "Access denied")

    session = (await db.execute(
        select(SastScanSession).where(SastScanSession.id == finding.scan_session_id)
    )).scalar_one_or_none()
    if not session:
        raise HTTPException(404, "Scan session not found")

    # Ensure we have AI-generated fix content before trying to create a PR.
    if not finding.fixed_code:
        api_key = await _resolve_api_key(db, session.organization_id)
        if not api_key:
            raise HTTPException(400, "No AI-generated fix available and no Anthropic API key configured")
        ai_result = await explain_finding(_finding_to_dict(finding), api_key)
        fixed_code = ai_result.get("fixed_code")
        if not fixed_code:
            raise HTTPException(400, "AI could not produce a fixed code snippet for this finding")
        finding.fixed_code = fixed_code
        finding.fix_suggestion = ai_result.get("remediation") or finding.fix_suggestion
        await db.commit()

    repo = await _resolve_repository_for_finding(db, finding, session, req.repository_id)

    if not repo:
        raise HTTPException(400, "Unable to determine repository. Provide repository_id or run from a repository-backed scan.")

    access_token, auth_mode = await _resolve_repository_access_token(db, session.organization_id, repo)
    base_branch = req.base_branch or repo.default_branch or "main"
    branch_name = req.branch_name or f"navigator/ai-fix-{str(finding.id)[:8]}"
    commit_message = f"fix: remediate {finding.rule_id or 'security issue'}"
    repo_owner = repo.repo_owner or ((repo.repo_url.rstrip("/").split("/")[-2]) if "/" in repo.repo_url.rstrip("/") else "")
    if not repo_owner:
        raise HTTPException(400, "Repository owner could not be determined for PR creation")
    push_result = apply_fix_and_push(
        repo_url=repo.repo_url,
        access_token=access_token,
        base_branch=base_branch,
        target_file_path=finding.file_path,
        line_start=finding.line_start,
        line_end=finding.line_end,
        fixed_code=finding.fixed_code,
        branch_name=branch_name,
        commit_message=commit_message,
    )

    pr_title = req.title or f"Fix {finding.title}"
    pr_body = req.body or (
        f"Automated fix generated by Navigator for finding `{finding.rule_id}`.\n\n"
        f"- Severity: {finding.severity}\n"
        f"- File: `{finding.file_path}`\n"
        f"- Auth mode: `{auth_mode}`\n"
    )
    pr = await create_pull_request(
        access_token=access_token,
        owner=repo_owner,
        repo=repo.repo_name,
        title=pr_title,
        head=branch_name,
        base=base_branch,
        body=pr_body,
    )

    from app.services.audit_service import log_audit
    await log_audit(
        db,
        "sast_fix_pr_create",
        str(current_user.id),
        "sast_finding",
        str(finding.id),
        {
            "repository_id": str(repo.id),
            "branch_name": branch_name,
            "pr_url": pr.get("url"),
        },
    )
    return {
        "status": "created",
        "repository_id": str(repo.id),
        "branch_name": branch_name,
        "commit_sha": push_result.get("commit_sha"),
        "pr": pr,
    }


# ── Export ──────────────────────────────────────────────────────────

@router.get("/scan/{scan_id}/export/sarif")
async def export_sarif(
    scan_id: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Export scan findings as SARIF 2.1.0 JSON."""
    session = (await db.execute(
        select(SastScanSession).where(SastScanSession.id == uuid.UUID(scan_id))
    )).scalar_one_or_none()
    if not session:
        raise HTTPException(404, "Scan not found")
    if not await user_can_read_project(db, current_user, str(session.project_id)):
        raise HTTPException(403, "Access denied")

    findings = (await db.execute(
        select(SastFinding).where(SastFinding.scan_session_id == uuid.UUID(scan_id))
    )).scalars().all()

    from app.services.sast.sarif_export import export_sarif as _export
    sarif = _export(
        [_finding_to_dict(f) for f in findings],
        _session_to_dict(session),
    )

    from fastapi.responses import JSONResponse
    return JSONResponse(
        content=sarif,
        headers={"Content-Disposition": f'attachment; filename="sast-{scan_id[:8]}.sarif.json"'},
    )


@router.get("/scan/{scan_id}/export/json")
async def export_json(
    scan_id: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Export scan results as JSON."""
    session = (await db.execute(
        select(SastScanSession).where(SastScanSession.id == uuid.UUID(scan_id))
    )).scalar_one_or_none()
    if not session:
        raise HTTPException(404, "Scan not found")
    if not await user_can_read_project(db, current_user, str(session.project_id)):
        raise HTTPException(403, "Access denied")

    findings = (await db.execute(
        select(SastFinding).where(SastFinding.scan_session_id == uuid.UUID(scan_id))
    )).scalars().all()

    from fastapi.responses import JSONResponse
    return JSONResponse(
        content={
            "scan": _session_to_dict(session),
            "findings": [_finding_to_dict(f) for f in findings],
        },
        headers={"Content-Disposition": f'attachment; filename="sast-{scan_id[:8]}.json"'},
    )


@router.get("/scan/{scan_id}/export/csv")
async def export_csv(
    scan_id: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Export scan findings as CSV."""
    session = (await db.execute(
        select(SastScanSession).where(SastScanSession.id == uuid.UUID(scan_id))
    )).scalar_one_or_none()
    if not session:
        raise HTTPException(404, "Scan not found")
    if not await user_can_read_project(db, current_user, str(session.project_id)):
        raise HTTPException(403, "Access denied")

    findings = (await db.execute(
        select(SastFinding).where(SastFinding.scan_session_id == uuid.UUID(scan_id))
    )).scalars().all()

    import csv
    import io
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Severity", "Confidence", "Title", "File", "Line", "CWE", "OWASP", "Rule", "Status", "Description"])
    for f in findings:
        writer.writerow([
            f.severity, f.confidence, f.title, f.file_path, f.line_start,
            f.cwe_id or "", f.owasp_category or "", f.rule_id, f.status,
            (f.description or "")[:200],
        ])

    from fastapi.responses import Response
    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="sast-{scan_id[:8]}.csv"'},
    )


# ── SAST Report ───────────────────────────────────────────────────

@router.get("/scan/{scan_id}/report")
async def get_sast_report(
    scan_id: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Generate comprehensive SAST security report data."""
    session = (await db.execute(
        select(SastScanSession).where(SastScanSession.id == uuid.UUID(scan_id))
    )).scalar_one_or_none()
    if not session:
        raise HTTPException(404, "Scan not found")
    if not await user_can_read_project(db, current_user, str(session.project_id)):
        raise HTTPException(403, "Access denied")

    findings = (await db.execute(
        select(SastFinding)
        .where(SastFinding.scan_session_id == uuid.UUID(scan_id))
        .order_by(SastFinding.severity, SastFinding.created_at)
    )).scalars().all()

    from app.models.sast_scan import SastDependency
    deps = (await db.execute(
        select(SastDependency).where(SastDependency.scan_session_id == uuid.UUID(scan_id))
    )).scalars().all()

    from app.models.project import Project
    project = (await db.execute(
        select(Project).where(Project.id == session.project_id)
    )).scalar_one_or_none()

    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_findings = sorted(findings, key=lambda f: sev_order.get(f.severity, 5))

    # Build scanner breakdown
    scanner_counts: dict[str, int] = {}
    for f in findings:
        src = f.rule_source or "unknown"
        scanner_counts[src] = scanner_counts.get(src, 0) + 1

    # Build OWASP mapping
    owasp_counts: dict[str, int] = {}
    for f in findings:
        cat = f.owasp_category or "Unmapped"
        owasp_counts[cat] = owasp_counts.get(cat, 0) + 1

    # Risk score (0-100)
    sev_weights = {"critical": 25, "high": 15, "medium": 5, "low": 1, "info": 0}
    total_weight = sum(sev_weights.get(f.severity, 0) for f in findings)
    risk_score = min(100, total_weight)

    vulnerable_deps = [d for d in deps if d.vulnerabilities]

    return {
        "scan": _session_to_dict(session),
        "project": {
            "id": str(project.id) if project else None,
            "name": project.name if project else "Unknown",
        },
        "risk_score": risk_score,
        "severity_distribution": session.issues_by_severity or {},
        "owasp_mapping": owasp_counts,
        "scanner_breakdown": scanner_counts,
        "total_findings": len(findings),
        "total_dependencies": len(deps),
        "vulnerable_dependencies": len(vulnerable_deps),
        "findings": [_finding_to_dict(f) for f in sorted_findings],
        "executive_summary": {
            "scan_type": session.scan_type,
            "duration_seconds": session.scan_duration_seconds,
            "files_scanned": session.files_scanned or 0,
            "total_files": session.total_files or 0,
            "languages": list((session.language_stats or {}).keys()),
            "policy_passed": (session.policy_result or {}).get("passed"),
            "ai_enabled": session.ai_analysis_enabled,
            "claude_review": session.claude_review_enabled,
        },
    }


# ── Policies ───────────────────────────────────────────────────────

@router.get("/policies/{org_id}")
async def list_policies(
    org_id: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List SAST policies for an organization."""
    # Admin or super_admin only
    if current_user.role not in ("admin", "super_admin"):
        raise HTTPException(403, "Admin access required")
    if current_user.role == "admin" and str(current_user.organization_id) != org_id:
        raise HTTPException(403, "Access denied to this organization")

    policies = (await db.execute(
        select(SastPolicy)
        .where(SastPolicy.organization_id == uuid.UUID(org_id))
        .order_by(desc(SastPolicy.created_at))
    )).scalars().all()

    return {"policies": [{
        "id": str(p.id),
        "name": p.name,
        "description": p.description,
        "is_default": p.is_default,
        "severity_threshold": p.severity_threshold,
        "max_issues_allowed": p.max_issues_allowed,
        "fail_on_secrets": p.fail_on_secrets,
        "compliance_standards": p.compliance_standards,
        "is_active": p.is_active,
        "created_at": p.created_at.isoformat() if p.created_at else None,
    } for p in policies]}


class CreatePolicyRequest(BaseModel):
    organization_id: str
    name: str
    description: str | None = None
    severity_threshold: str = "critical"
    max_issues_allowed: int = -1
    fail_on_secrets: bool = True
    compliance_standards: list[str] | None = None
    is_default: bool = False


@router.post("/policies")
async def create_policy(
    req: CreatePolicyRequest,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Create a SAST policy."""
    if current_user.role not in ("admin", "super_admin"):
        raise HTTPException(403, "Admin access required")

    policy = SastPolicy(
        organization_id=uuid.UUID(req.organization_id),
        name=req.name,
        description=req.description,
        severity_threshold=req.severity_threshold,
        max_issues_allowed=req.max_issues_allowed,
        fail_on_secrets=req.fail_on_secrets,
        compliance_standards=req.compliance_standards,
        is_default=req.is_default,
    )
    db.add(policy)
    await db.commit()
    await db.refresh(policy)

    return {"id": str(policy.id), "name": policy.name, "status": "created"}


class UpdatePolicyRequest(BaseModel):
    name: str | None = None
    description: str | None = None
    severity_threshold: str | None = None
    max_issues_allowed: int | None = None
    fail_on_secrets: bool | None = None
    required_fix_categories: list | None = None
    compliance_standards: list | None = None
    exclude_rules: list | None = None
    is_active: bool | None = None


@router.patch("/policies/{policy_id}")
async def update_policy(
    policy_id: str,
    req: UpdatePolicyRequest,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update a SAST policy."""
    if current_user.role not in ("admin", "super_admin"):
        raise HTTPException(403, "Admin access required")

    policy = (await db.execute(
        select(SastPolicy).where(SastPolicy.id == uuid.UUID(policy_id))
    )).scalar_one_or_none()
    if not policy:
        raise HTTPException(404, "Policy not found")

    if req.name is not None:
        policy.name = req.name
    if req.description is not None:
        policy.description = req.description
    if req.severity_threshold is not None:
        policy.severity_threshold = req.severity_threshold
    if req.max_issues_allowed is not None:
        policy.max_issues_allowed = req.max_issues_allowed
    if req.fail_on_secrets is not None:
        policy.fail_on_secrets = req.fail_on_secrets
    if req.required_fix_categories is not None:
        policy.required_fix_categories = req.required_fix_categories
    if req.compliance_standards is not None:
        policy.compliance_standards = req.compliance_standards
    if req.exclude_rules is not None:
        policy.exclude_rules = req.exclude_rules
    if req.is_active is not None:
        policy.is_active = req.is_active
    policy.updated_at = datetime.utcnow()
    await db.commit()

    return {"id": str(policy.id), "status": "updated"}


@router.delete("/policies/{policy_id}")
async def delete_policy(
    policy_id: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Delete a SAST policy."""
    if current_user.role not in ("admin", "super_admin"):
        raise HTTPException(403, "Admin access required")

    policy = (await db.execute(
        select(SastPolicy).where(SastPolicy.id == uuid.UUID(policy_id))
    )).scalar_one_or_none()
    if not policy:
        raise HTTPException(404, "Policy not found")

    await db.delete(policy)
    await db.commit()
    return {"status": "deleted"}


# ── CI/CD Webhook ──────────────────────────────────────────────────

@router.get("/webhook/config/{project_id}")
async def get_webhook_config(
    project_id: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get webhook URL and CI/CD config snippets."""
    if not await user_can_read_project(db, current_user, project_id):
        raise HTTPException(403, "Access denied")

    from app.core.config import get_settings
    settings = get_settings()
    base_url = _public_frontend_origin()

    # Generate webhook token (deterministic per project for consistency)
    token = _build_webhook_token(project_id)
    webhook_url = f"{base_url}/api/sast/webhook/{token}"

    github_actions = f"""# .github/workflows/sast.yml
name: SAST Scan
on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  sast:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Trigger SAST Scan
        run: |
          zip -r source.zip . -x '.git/*' 'node_modules/*' 'vendor/*'
          curl -X POST {webhook_url} \\
            -F "file=@source.zip" \\
            -F "branch=${{{{ github.ref_name }}}}" \\
            -F "commit=${{{{ github.sha }}}}" \\
            -F "project_id={project_id}"
"""

    gitlab_ci = f"""# .gitlab-ci.yml
sast_scan:
  stage: test
  script:
    - apt-get update && apt-get install -y zip curl
    - zip -r source.zip . -x '.git/*' 'node_modules/*'
    - curl -X POST {webhook_url}
        -F "file=@source.zip"
        -F "branch=$CI_COMMIT_REF_NAME"
        -F "commit=$CI_COMMIT_SHA"
        -F "project_id={project_id}"
  only:
    - main
    - develop
"""

    jenkins = f"""// Jenkinsfile
stage('SAST Scan') {{
    steps {{
        sh '''
            zip -r source.zip . -x '.git/*' 'node_modules/*'
            curl -X POST {webhook_url} \\
                -F "file=@source.zip" \\
                -F "branch=$GIT_BRANCH" \\
                -F "commit=$GIT_COMMIT" \\
                -F "project_id={project_id}"
        '''
    }}
}}
"""

    return {
        "webhook_url": webhook_url,
        "token": token,
        "snippets": {
            "github_actions": github_actions,
            "gitlab_ci": gitlab_ci,
            "jenkins": jenkins,
        },
    }


@router.post("/webhook/{token}")
async def webhook_trigger(
    token: str,
    background_tasks: BackgroundTasks,
    project_id: str = Form(...),
    branch: str = Form("main"),
    commit: str = Form(""),
    file: UploadFile = File(None),
):
    """CI/CD webhook endpoint — trigger SAST scan."""
    from app.core.config import get_settings
    settings = get_settings()

    # Verify token
    expected = _build_webhook_token(project_id)
    if token != expected:
        raise HTTPException(403, "Invalid webhook token")

    if not file:
        raise HTTPException(400, "ZIP file is required")

    # Save uploaded file
    upload_dir = tempfile.mkdtemp(prefix="sast_webhook_")
    zip_path = os.path.join(upload_dir, "source.zip")

    total_size = 0
    with open(zip_path, "wb") as f:
        while chunk := await file.read(8192):
            total_size += len(chunk)
            if total_size > MAX_UPLOAD_SIZE:
                shutil.rmtree(upload_dir, ignore_errors=True)
                raise HTTPException(400, "File too large")
            f.write(chunk)

    # Look up project and org
    async with AsyncSessionLocal() as db:
        project = (await db.execute(select(Project).where(Project.id == uuid.UUID(project_id)))).scalar_one_or_none()
        if not project:
            shutil.rmtree(upload_dir, ignore_errors=True)
            raise HTTPException(404, "Project not found")

        org = (await db.execute(select(Organization).where(Organization.id == project.organization_id))).scalar_one_or_none()
        if not org or not getattr(org, "sast_enabled", False):
            shutil.rmtree(upload_dir, ignore_errors=True)
            raise HTTPException(403, "SAST not enabled")

        scan_id = uuid.uuid4()
        session = SastScanSession(
            id=scan_id,
            project_id=uuid.UUID(project_id),
            organization_id=project.organization_id,
            scan_type="cicd_webhook",
            status="queued",
            source_info={"branch": branch, "commit_sha": commit, "file_size_bytes": total_size},
            ai_analysis_enabled=getattr(org, "sast_ai_analysis_enabled", False),
        )
        db.add(session)
        await db.commit()

        api_key = ""
        if getattr(org, "sast_ai_analysis_enabled", False):
            from app.core.config import get_settings
            api_key = get_settings().anthropic_api_key or ""

    background_tasks.add_task(
        _run_zip_scan_background,
        scan_session_id=str(scan_id),
        project_id=project_id,
        organization_id=str(project.organization_id),
        zip_path=zip_path,
        upload_dir=upload_dir,
        ai_analysis_enabled=bool(api_key),
        api_key=api_key,
        user_id="",
    )

    return {"scan_id": str(scan_id), "status": "queued", "message": "CI/CD SAST scan triggered"}


# ── Admin SAST Settings ───────────────────────────────────────────

@router.get("/admin/usage")
async def admin_sast_usage(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get global SAST usage statistics (super_admin only)."""
    if current_user.role != "super_admin":
        raise HTTPException(403, "Super admin only")

    # Total scans
    total = (await db.execute(select(func.count(SastScanSession.id)))).scalar() or 0
    completed = (await db.execute(
        select(func.count(SastScanSession.id)).where(SastScanSession.status == "completed")
    )).scalar() or 0
    total_issues = (await db.execute(select(func.sum(SastScanSession.total_issues)))).scalar() or 0
    total_ai_cost = (await db.execute(select(func.sum(SastScanSession.ai_cost_usd)))).scalar() or 0

    # Per-org breakdown (include feature flags so super_admin can see/toggle full coverage)
    from sqlalchemy import text
    org_stats = (await db.execute(text("""
        SELECT o.id, o.name, o.sast_enabled,
               COALESCE(o.sast_sca_enabled, true), COALESCE(o.sast_iac_scanning_enabled, true),
               COALESCE(o.sast_claude_review_enabled, true), COALESCE(o.sast_pr_review_enabled, true),
               COUNT(s.id) as scans, COALESCE(SUM(s.total_issues), 0) as issues
        FROM organizations o
        LEFT JOIN sast_scan_sessions s ON s.organization_id = o.id
        GROUP BY o.id, o.name, o.sast_enabled, o.sast_sca_enabled, o.sast_iac_scanning_enabled,
                 o.sast_claude_review_enabled, o.sast_pr_review_enabled
        ORDER BY scans DESC
    """))).fetchall()

    return {
        "total_scans": total,
        "completed_scans": completed,
        "total_issues_found": int(total_issues),
        "total_ai_cost_usd": float(total_ai_cost),
        "organizations": [{
            "id": str(row[0]),
            "name": row[1],
            "sast_enabled": row[2],
            "sast_sca_enabled": row[3],
            "sast_iac_scanning_enabled": row[4],
            "sast_claude_review_enabled": row[5],
            "sast_pr_review_enabled": row[6],
            "total_scans": row[7],
            "total_issues": row[8],
        } for row in org_stats],
    }


class AdminSastSettingsUpdate(BaseModel):
    sast_enabled: bool | None = None
    sast_max_scans_per_day: int | None = None
    sast_ai_analysis_enabled: bool | None = None
    sast_monthly_budget_usd: float | None = None
    # Feature toggles: only super_admin can change; once enabled stay enabled (persisted)
    sast_sca_enabled: bool | None = None
    sast_iac_scanning_enabled: bool | None = None
    sast_claude_review_enabled: bool | None = None
    sast_pr_review_enabled: bool | None = None


@router.patch("/admin/settings/{org_id}")
async def admin_update_sast_settings(
    org_id: str,
    req: AdminSastSettingsUpdate,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update SAST settings for an organization (super_admin only)."""
    if current_user.role != "super_admin":
        raise HTTPException(403, "Super admin only")

    org = (await db.execute(select(Organization).where(Organization.id == uuid.UUID(org_id)))).scalar_one_or_none()
    if not org:
        raise HTTPException(404, "Organization not found")

    if req.sast_enabled is not None:
        org.sast_enabled = req.sast_enabled
    if req.sast_max_scans_per_day is not None:
        org.sast_max_scans_per_day = req.sast_max_scans_per_day
    if req.sast_ai_analysis_enabled is not None:
        org.sast_ai_analysis_enabled = req.sast_ai_analysis_enabled
    if req.sast_monthly_budget_usd is not None:
        org.sast_monthly_budget_usd = req.sast_monthly_budget_usd
    if req.sast_sca_enabled is not None:
        org.sast_sca_enabled = req.sast_sca_enabled
    if req.sast_iac_scanning_enabled is not None:
        org.sast_iac_scanning_enabled = req.sast_iac_scanning_enabled
    if req.sast_claude_review_enabled is not None:
        org.sast_claude_review_enabled = req.sast_claude_review_enabled
    if req.sast_pr_review_enabled is not None:
        org.sast_pr_review_enabled = req.sast_pr_review_enabled

    await db.commit()

    from app.services.audit_service import log_audit
    await log_audit(db, "sast_settings_update", str(current_user.id), "organization", str(org_id),
                    {"changes": req.model_dump(exclude_none=True)})

    return {"status": "updated", "org_id": org_id}


# ═══════════════════════════════════════════════════════════════════════
# Code Security Platform — New Endpoints (Phase 12)
# ═══════════════════════════════════════════════════════════════════════

# ── SCA / Dependencies ────────────────────────────────────────────────

@router.get("/scan/{scan_id}/dependencies")
async def get_scan_dependencies(
    scan_id: str,
    page: int = 1,
    per_page: int = 20,
    name: str | None = None,
    ecosystem: str | None = None,
    vulnerable: bool | None = None,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List dependencies with vulnerability status for a scan. Paginated and filterable."""
    from app.models.sast_scan import SastDependency

    session = (await db.execute(
        select(SastScanSession).where(SastScanSession.id == uuid.UUID(scan_id))
    )).scalar_one_or_none()
    if not session:
        raise HTTPException(404, "Scan not found")
    await _check_sast_enabled(db, session.organization_id)
    await _check_feature_flag(db, session.organization_id, "sast_sca_enabled", "SCA (Software Composition Analysis)")

    per_page = max(1, min(100, per_page))
    page = max(1, page)

    deps = (await db.execute(
        select(SastDependency)
        .where(SastDependency.scan_session_id == uuid.UUID(scan_id))
        .order_by(SastDependency.name)
    )).scalars().all()

    dep_list = []
    for d in deps:
        vulns = d.vulnerabilities or []
        cve_ids = []
        for v in (vulns if isinstance(vulns, list) else []):
            vid = v.get("id", "")
            for alias in v.get("aliases", []):
                if alias.startswith("CVE-"):
                    cve_ids.append(alias)
                    break
            else:
                if vid:
                    cve_ids.append(vid)
        latest_version = None
        for v in (vulns if isinstance(vulns, list) else []):
            for aff in v.get("affected", []):
                for rng in aff.get("ranges", []):
                    for evt in rng.get("events", []):
                        if "fixed" in evt:
                            latest_version = evt["fixed"]
                            break
        is_vuln = bool(vulns)
        dep_list.append({
            "id": str(d.id),
            "name": d.name,
            "version": d.version,
            "ecosystem": d.ecosystem,
            "manifest_file": d.manifest_file,
            "is_direct": d.is_direct,
            "license": d.license_id or None,
            "license_risk": d.license_risk,
            "is_vulnerable": is_vuln,
            "cve_ids": ", ".join(cve_ids[:5]) if cve_ids else None,
            "latest_version": latest_version,
            "epss_score": d.epss_score,
            "in_kev": d.in_kev,
            "cvss_score": d.cvss_score,
            "status": d.status,
        })

    # Filters
    if name and name.strip():
        q = name.strip().lower()
        dep_list = [x for x in dep_list if q in (x.get("name") or "").lower()]
    if ecosystem and ecosystem.strip():
        eco = ecosystem.strip().lower()
        dep_list = [x for x in dep_list if (x.get("ecosystem") or "").lower() == eco]
    if vulnerable is not None:
        dep_list = [x for x in dep_list if x.get("is_vulnerable") is vulnerable]

    total = len(dep_list)
    total_pages = (total + per_page - 1) // per_page if total else 1
    page = min(page, max(1, total_pages))
    start = (page - 1) * per_page
    end = start + per_page
    page_deps = dep_list[start:end]

    return {
        "scan_id": scan_id,
        "total": total,
        "page": page,
        "per_page": per_page,
        "total_pages": total_pages,
        "dependencies": page_deps,
    }


@router.get("/scan/{scan_id}/licenses")
async def get_scan_licenses(
    scan_id: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """License compliance report for a scan."""
    from app.models.sast_scan import SastDependency

    # Check feature flag
    scan_session = (await db.execute(
        select(SastScanSession).where(SastScanSession.id == uuid.UUID(scan_id))
    )).scalar_one_or_none()
    if scan_session and scan_session.organization_id:
        await _check_feature_flag(db, scan_session.organization_id, "sast_sca_enabled", "SCA (Software Composition Analysis)")

    deps = (await db.execute(
        select(SastDependency)
        .where(SastDependency.scan_session_id == uuid.UUID(scan_id))
    )).scalars().all()

    # Build license breakdown
    license_breakdown: dict[str, int] = {}
    blocked_count = 0
    compliant_count = 0
    unknown_count = 0
    blocked_list: list[str] = []

    # Load org blocked licenses
    try:
        scan_session = (await db.execute(
            select(SastScanSession).where(SastScanSession.id == uuid.UUID(scan_id))
        )).scalar_one_or_none()
        if scan_session and scan_session.organization_id:
            from app.models.organization import Organization
            org = (await db.execute(
                select(Organization).where(Organization.id == scan_session.organization_id)
            )).scalar_one_or_none()
            if org:
                blocked_list = getattr(org, "sast_blocked_licenses", None) or []
    except Exception:
        pass

    for d in deps:
        lid = d.license_id or "Unknown"
        license_breakdown[lid] = license_breakdown.get(lid, 0) + 1
        if lid == "Unknown" or not d.license_id:
            unknown_count += 1
        elif lid in blocked_list:
            blocked_count += 1
        else:
            compliant_count += 1

    return {
        "scan_id": scan_id,
        "total_packages": len(deps),
        "compliant": compliant_count,
        "blocked": blocked_count,
        "unknown": unknown_count,
        "blocked_list": blocked_list,
        "license_breakdown": license_breakdown,
    }


# ── SBOM ──────────────────────────────────────────────────────────────

@router.get("/scan/{scan_id}/sbom/cyclonedx")
async def get_sbom_cyclonedx(
    scan_id: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Export CycloneDX 1.5 SBOM for a scan."""
    from app.models.sast_scan import SastSBOM

    # Check SCA feature flag
    session = (await db.execute(
        select(SastScanSession).where(SastScanSession.id == uuid.UUID(scan_id))
    )).scalar_one_or_none()
    if session:
        await _check_feature_flag(db, session.organization_id, "sast_sca_enabled", "SCA (Software Composition Analysis)")

    sbom = (await db.execute(
        select(SastSBOM).where(
            SastSBOM.scan_session_id == uuid.UUID(scan_id),
            SastSBOM.format == "cyclonedx",
        )
    )).scalar_one_or_none()

    if not sbom:
        raise HTTPException(404, "SBOM not found. Run a scan with SCA enabled.")
    return sbom.sbom_data


@router.get("/scan/{scan_id}/sbom/spdx")
async def get_sbom_spdx(
    scan_id: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Export SPDX 2.3 SBOM for a scan."""
    from app.models.sast_scan import SastSBOM, SastDependency

    # Check SCA feature flag
    session = (await db.execute(
        select(SastScanSession).where(SastScanSession.id == uuid.UUID(scan_id))
    )).scalar_one_or_none()
    if session:
        await _check_feature_flag(db, session.organization_id, "sast_sca_enabled", "SCA (Software Composition Analysis)")

    sbom = (await db.execute(
        select(SastSBOM).where(
            SastSBOM.scan_session_id == uuid.UUID(scan_id),
            SastSBOM.format == "spdx",
        )
    )).scalar_one_or_none()

    if sbom:
        return sbom.sbom_data

    # Generate SPDX on-the-fly from CycloneDX data
    cdx = (await db.execute(
        select(SastSBOM).where(
            SastSBOM.scan_session_id == uuid.UUID(scan_id),
            SastSBOM.format == "cyclonedx",
        )
    )).scalar_one_or_none()

    if not cdx:
        raise HTTPException(404, "SBOM not found")

    deps = (await db.execute(
        select(SastDependency).where(SastDependency.scan_session_id == uuid.UUID(scan_id))
    )).scalars().all()

    from app.services.sast.sbom_generator import SBOMGenerator
    session = (await db.execute(
        select(SastScanSession).where(SastScanSession.id == uuid.UUID(scan_id))
    )).scalar_one_or_none()

    dep_dicts = [{
        "name": d.name, "version": d.version, "ecosystem": d.ecosystem,
        "license_id": d.license_id, "is_direct": d.is_direct,
        "vulnerabilities": d.vulnerabilities or [],
    } for d in deps]

    spdx = SBOMGenerator.generate_spdx(
        scan_session_id=scan_id,
        project_name="Project",
        dependencies=dep_dicts,
        language_stats=session.language_stats or {},
    )
    return spdx


@router.get("/project/{project_id}/sbom/diff")
async def compare_sboms(
    project_id: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Compare the latest two SBOMs for dependency drift detection."""
    from app.models.sast_scan import SastSBOM

    # Check SCA feature flag via project's org
    project = (await db.execute(
        select(Project).where(Project.id == uuid.UUID(project_id))
    )).scalar_one_or_none()
    if project:
        await _check_feature_flag(db, project.organization_id, "sast_sca_enabled", "SCA (Software Composition Analysis)")

    sboms = (await db.execute(
        select(SastSBOM)
        .where(SastSBOM.project_id == uuid.UUID(project_id), SastSBOM.format == "cyclonedx")
        .order_by(desc(SastSBOM.created_at))
        .limit(2)
    )).scalars().all()

    if len(sboms) < 2:
        raise HTTPException(400, "Need at least 2 SBOMs for comparison")

    from app.services.sast.sbom_generator import SBOMGenerator
    diff = SBOMGenerator.compare_sboms(sboms[1].sbom_data, sboms[0].sbom_data)
    return diff


# ── CVE Intelligence ──────────────────────────────────────────────────

@router.get("/scan/{scan_id}/cve-summary")
async def get_cve_summary(
    scan_id: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """CVE intelligence summary with exploitability scores."""
    from app.models.sast_scan import SastDependency

    deps = (await db.execute(
        select(SastDependency).where(SastDependency.scan_session_id == uuid.UUID(scan_id))
    )).scalars().all()

    # Flatten all CVEs from dependencies
    all_cves = []
    for d in deps:
        for v in (d.vulnerabilities or []):
            cve_id = None
            for alias in v.get("aliases", []):
                if alias.startswith("CVE-"):
                    cve_id = alias
                    break
            if not cve_id:
                cve_id = v.get("id", "UNKNOWN")
            all_cves.append({
                "cve_id": cve_id,
                "package": f"{d.name}@{d.version}",
                "cvss": d.cvss_score or 0,
                "epss": d.epss_score or 0,
                "in_kev": bool(d.in_kev),
                "priority": "critical" if d.in_kev else ("high" if (d.epss_score or 0) > 0.5 or (d.cvss_score or 0) >= 7 else "medium"),
            })

    kev_count = sum(1 for c in all_cves if c["in_kev"])
    high_epss_count = sum(1 for c in all_cves if c["epss"] > 0.5)
    cvss_scores = [c["cvss"] for c in all_cves if c["cvss"] > 0]
    avg_cvss = sum(cvss_scores) / len(cvss_scores) if cvss_scores else 0

    # Sort by priority: KEV first, then EPSS, then CVSS
    prioritized = sorted(all_cves, key=lambda x: (
        -int(x["in_kev"]),
        -x["epss"],
        -x["cvss"],
    ))[:30]

    return {
        "scan_id": scan_id,
        "total_cves": len(all_cves),
        "kev_count": kev_count,
        "high_epss_count": high_epss_count,
        "avg_cvss": avg_cvss,
        "prioritized": prioritized,
    }


# ── Claude Security Review ───────────────────────────────────────────

@router.post("/scan/{scan_id}/claude-review")
async def trigger_claude_review(
    scan_id: str,
    background_tasks: BackgroundTasks,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Trigger Claude security review on a completed scan."""
    session = (await db.execute(
        select(SastScanSession).where(SastScanSession.id == uuid.UUID(scan_id))
    )).scalar_one_or_none()
    if not session:
        raise HTTPException(404, "Scan not found")
    if session.status != "completed":
        raise HTTPException(400, "Scan must be completed before Claude review")
    if not await user_can_write_project(db, current_user, str(session.project_id)):
        raise HTTPException(403, "Access denied")

    await _check_feature_flag(
        db, session.organization_id,
        "sast_claude_review_enabled", "Claude security review",
    )

    api_key = await _resolve_api_key(db, session.organization_id)
    if not api_key:
        raise HTTPException(400, "No API key configured for AI analysis")

    background_tasks.add_task(
        _run_claude_review_background,
        scan_session_id=scan_id,
        organization_id=str(session.organization_id),
        project_id=str(session.project_id),
        api_key=api_key,
    )

    return {"status": "queued", "message": "Claude review triggered"}


async def _run_claude_review_background(
    scan_session_id: str,
    organization_id: str,
    project_id: str,
    api_key: str,
):
    """Background task: run Claude security review on completed scan findings."""
    from app.services.sast.claude_security_review import ClaudeSecurityReviewer
    from app.services.sast.scanner import _progress_set

    try:
        async with AsyncSessionLocal() as db:
            session = (await db.execute(
                select(SastScanSession).where(SastScanSession.id == uuid.UUID(scan_session_id))
            )).scalar_one_or_none()
            if not session:
                return

            session.claude_review_enabled = True
            await db.commit()

            # Determine source path from scan source_info
            source_info = session.source_info or {}
            source_path = source_info.get("source_path", "")
            languages = list((session.language_stats or {}).keys())

            reviewer = ClaudeSecurityReviewer(api_key=api_key)
            result = await reviewer.review_codebase(
                source_path=source_path,
                languages=languages,
                scan_config=session.scan_config,
            )

            # Store findings back in DB (sanitize to avoid varchar truncation)
            from app.services.sast.finding_sanitizer import sanitize_finding_for_db
            findings = result if isinstance(result, list) else []
            for finding_dict in findings:
                s = sanitize_finding_for_db({**finding_dict, "rule_source": "claude"})
                ai = s.get("ai_analysis")
                if ai is not None and not isinstance(ai, dict):
                    ai = None
                finding = SastFinding(
                    id=uuid.uuid4(),
                    scan_session_id=uuid.UUID(scan_session_id),
                    project_id=uuid.UUID(project_id),
                    rule_id=s.get("rule_id", "claude-review"),
                    rule_source="claude",
                    severity=s.get("severity", "medium"),
                    confidence=s.get("confidence", "medium"),
                    title=s.get("title", ""),
                    description=s.get("description") or "",
                    message=s.get("message") or "",
                    file_path=s.get("file_path", ""),
                    line_start=s.get("line_start", 0),
                    line_end=s.get("line_end", 0),
                    column_start=s.get("column_start"),
                    column_end=s.get("column_end"),
                    code_snippet=(s.get("code_snippet") or "")[:5000],
                    fix_suggestion=s.get("fix_suggestion"),
                    fixed_code=s.get("fixed_code"),
                    ai_analysis=ai,
                    cwe_id=s.get("cwe_id"),
                    owasp_category=s.get("owasp_category"),
                    references=s.get("references"),
                    fingerprint=s.get("fingerprint"),
                    status="open",
                )
                db.add(finding)

            # Update scan session with claude review stats
            session.claude_review_findings_count = len(findings)
            session.claude_review_cost_usd = sum(
                f.get("cost_usd", 0) for f in findings
            )
            session.total_issues = (session.total_issues or 0) + len(findings)
            await db.commit()

            _progress_set(scan_session_id, {
                "status": "completed",
                "phase": "claude_review_done",
                "message": f"Claude review complete — {len(findings)} finding(s)",
                "last_updated": datetime.utcnow().isoformat(),
            })

    except Exception as e:
        logger.exception("Claude security review failed: %s", e)
        async with AsyncSessionLocal() as db:
            session = (await db.execute(
                select(SastScanSession).where(SastScanSession.id == uuid.UUID(scan_session_id))
            )).scalar_one_or_none()
            if session:
                session.error_message = f"Claude review failed: {str(e)[:400]}"
                await db.commit()


# ── PR Review Webhook ─────────────────────────────────────────────────

@router.post("/webhook/pr/{token}")
async def pr_webhook(
    token: str,
    request: Request,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    """PR webhook endpoint for GitHub — triggers diff scan on PR events."""
    from app.models.sast_scan import SastRepository
    from app.services.sast.pr_reviewer import verify_github_webhook_signature, parse_pr_webhook_payload

    repo = (await db.execute(
        select(SastRepository).where(SastRepository.webhook_secret == token)
    )).scalar_one_or_none()

    if not repo:
        raise HTTPException(404, "Unknown webhook token")

    # Read raw body and verify HMAC-SHA256 signature
    body = await request.body()
    signature = request.headers.get("X-Hub-Signature-256", "")
    if not verify_github_webhook_signature(body, signature, repo.webhook_secret):
        raise HTTPException(403, "Invalid webhook signature")

    # Parse payload
    try:
        payload = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        raise HTTPException(400, "Invalid JSON payload")

    # Only process pull_request events
    event_type = request.headers.get("X-GitHub-Event", "")
    if event_type != "pull_request":
        return {"status": "ignored", "message": f"Event type '{event_type}' is not handled"}

    pr_info = parse_pr_webhook_payload(payload)
    if pr_info is None:
        action = payload.get("action", "unknown")
        return {"status": "ignored", "message": f"PR action '{action}' is not handled"}

    # Create scan session
    scan_id = uuid.uuid4()
    session = SastScanSession(
        id=scan_id,
        project_id=repo.project_id,
        organization_id=repo.organization_id,
        scan_type="pr_review",
        status="queued",
        source_info={
            "repo_url": repo.repo_url,
            "repo_name": pr_info["repo_full_name"],
            "pr_number": pr_info["pr_number"],
            "pr_title": pr_info["pr_title"],
            "head_branch": pr_info["head_branch"],
            "base_branch": pr_info["base_branch"],
            "head_sha": pr_info["head_sha"],
            "sender": pr_info["sender"],
            "action": pr_info["action"],
        },
    )
    db.add(session)
    await db.commit()

    # Resolve access token for cloning and posting reviews
    access_token, _ = await _resolve_repository_access_token(db, repo.organization_id, repo)

    background_tasks.add_task(
        _run_pr_review_background,
        scan_session_id=str(scan_id),
        project_id=str(repo.project_id),
        organization_id=str(repo.organization_id),
        repo_url=repo.repo_url,
        pr_info=pr_info,
        access_token=access_token,
    )

    return {"status": "received", "message": "PR webhook processed", "scan_id": str(scan_id)}


async def _run_pr_review_background(
    scan_session_id: str,
    project_id: str,
    organization_id: str,
    repo_url: str,
    pr_info: dict,
    access_token: str,
):
    """Background task: clone repo, run diff scan, and post PR review comments."""
    from app.services.sast.code_extractor import clone_repo, cleanup_source
    from app.services.sast.scanner import run_diff_scan, _progress_set
    from app.services.sast.pr_reviewer import PRReviewService

    clone_dir = None
    try:
        async with AsyncSessionLocal() as db:
            session = (await db.execute(
                select(SastScanSession).where(SastScanSession.id == uuid.UUID(scan_session_id))
            )).scalar_one_or_none()
            if session:
                session.status = "extracting"
                await db.commit()

        # Clone the repo at head branch
        clone_dir = clone_repo(
            repo_url,
            branch=pr_info["head_branch"],
            token=access_token,
        )

        # Run diff scan
        result = await run_diff_scan(
            scan_session_id=scan_session_id,
            project_id=project_id,
            organization_id=organization_id,
            source_path=clone_dir,
            base_branch=pr_info["base_branch"],
            head_branch=pr_info["head_branch"],
        )

        # Collect findings from DB
        async with AsyncSessionLocal() as db:
            findings = (await db.execute(
                select(SastFinding).where(
                    SastFinding.scan_session_id == uuid.UUID(scan_session_id)
                )
            )).scalars().all()
            finding_dicts = [_finding_to_dict(f) for f in findings]

        # Post PR review and commit status via GitHub API
        pr_service = PRReviewService(access_token=access_token)
        repo_owner = pr_info["repo_owner"]
        repo_name = pr_info["repo_name"]
        pr_number = pr_info["pr_number"]
        head_sha = pr_info["head_sha"]

        # Post commit status: pending -> success/failure
        if finding_dicts:
            action = PRReviewService.determine_review_action(finding_dicts)
            await pr_service.post_pr_review(
                owner=repo_owner,
                repo=repo_name,
                pr_number=pr_number,
                findings=finding_dicts,
                action=action,
            )
            state = "failure" if action == "REQUEST_CHANGES" else "success"
            desc = f"Found {len(finding_dicts)} security issue(s)"
        else:
            state = "success"
            desc = "No security issues found"

        await pr_service.post_commit_status(
            owner=repo_owner,
            repo=repo_name,
            sha=head_sha,
            state=state,
            description=desc,
        )

        _progress_set(scan_session_id, {
            "status": "completed",
            "phase": "pr_review_done",
            "message": f"PR review complete — {len(finding_dicts)} finding(s)",
            "last_updated": datetime.utcnow().isoformat(),
        })

    except Exception as e:
        logger.exception("PR review scan failed: %s", e)
        try:
            from app.services.sast.scanner import _progress_set as _ps
            _ps(scan_session_id, {"status": "failed", "error": str(e)[:500]})
        except Exception:
            pass
        async with AsyncSessionLocal() as db:
            session = (await db.execute(
                select(SastScanSession).where(SastScanSession.id == uuid.UUID(scan_session_id))
            )).scalar_one_or_none()
            if session:
                session.status = "failed"
                session.error_message = str(e)[:500]
                await db.commit()

        # Try to post failure status on the commit
        try:
            pr_service = PRReviewService(access_token=access_token)
            await pr_service.post_commit_status(
                owner=pr_info["repo_owner"],
                repo=pr_info["repo_name"],
                sha=pr_info["head_sha"],
                state="error",
                description=f"Security scan failed: {str(e)[:100]}",
            )
        except Exception:
            logger.debug("Failed to post error commit status", exc_info=True)
    finally:
        if clone_dir:
            cleanup_source(clone_dir)


# ── Diff Scan ─────────────────────────────────────────────────────────

class DiffScanRequest(BaseModel):
    project_id: str
    repo_url: str
    base_branch: str = "main"
    head_branch: str = "HEAD"
    ai_analysis: bool = False


@router.post("/scan/diff")
async def trigger_diff_scan(
    req: DiffScanRequest,
    background_tasks: BackgroundTasks,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Trigger a diff-aware SAST scan for changed files only."""
    project = (await db.execute(
        select(Project).where(Project.id == uuid.UUID(req.project_id))
    )).scalar_one_or_none()
    if not project:
        raise HTTPException(404, "Project not found")
    if not await user_can_write_project(db, current_user, req.project_id):
        raise HTTPException(403, "Access denied")
    await _check_sast_enabled(db, project.organization_id)

    # Look up existing repository or prepare to clone from repo_url
    repo = (await db.execute(
        select(SastRepository).where(
            SastRepository.project_id == uuid.UUID(req.project_id),
            SastRepository.repo_url == req.repo_url,
        )
    )).scalar_one_or_none()

    # Resolve access token if we have a linked repo
    access_token = None
    if repo:
        try:
            access_token, _ = await _resolve_repository_access_token(
                db, project.organization_id, repo,
            )
        except Exception:
            pass

    # Create scan session
    scan_id = uuid.uuid4()
    session = SastScanSession(
        id=scan_id,
        project_id=uuid.UUID(req.project_id),
        organization_id=project.organization_id,
        scan_type="diff",
        status="queued",
        source_info={
            "repo_url": req.repo_url,
            "base_branch": req.base_branch,
            "head_branch": req.head_branch,
        },
        ai_analysis_enabled=req.ai_analysis,
        created_by=current_user.id,
    )
    db.add(session)
    await db.commit()

    api_key = await _resolve_api_key(db, project.organization_id) if req.ai_analysis else ""

    background_tasks.add_task(
        _run_diff_scan_background,
        scan_session_id=str(scan_id),
        project_id=req.project_id,
        organization_id=str(project.organization_id),
        repo_url=req.repo_url,
        base_branch=req.base_branch,
        head_branch=req.head_branch,
        access_token=access_token,
        ai_analysis_enabled=req.ai_analysis,
        api_key=api_key,
    )

    from app.services.audit_service import log_audit
    await log_audit(
        db, "sast_diff_scan", str(current_user.id), "sast_scan", str(scan_id),
        {"repo_url": req.repo_url, "base": req.base_branch, "head": req.head_branch},
    )

    return {
        "scan_id": str(scan_id),
        "status": "queued",
        "message": f"Diff scan queued: {req.base_branch}..{req.head_branch}",
    }


async def _run_diff_scan_background(
    scan_session_id: str,
    project_id: str,
    organization_id: str,
    repo_url: str,
    base_branch: str,
    head_branch: str,
    access_token: str | None,
    ai_analysis_enabled: bool,
    api_key: str,
):
    """Background task: clone repo and run diff-aware SAST scan."""
    from app.services.sast.code_extractor import clone_repo, cleanup_source
    from app.services.sast.scanner import run_diff_scan, _progress_set

    clone_dir = None
    try:
        async with AsyncSessionLocal() as db:
            session = (await db.execute(
                select(SastScanSession).where(SastScanSession.id == uuid.UUID(scan_session_id))
            )).scalar_one_or_none()
            if session:
                session.status = "extracting"
                await db.commit()

        # Clone repository at head branch (full clone needed for diff)
        clone_dir = clone_repo(repo_url, branch=head_branch, token=access_token)

        # Run diff scan
        await run_diff_scan(
            scan_session_id=scan_session_id,
            project_id=project_id,
            organization_id=organization_id,
            source_path=clone_dir,
            base_branch=base_branch,
            head_branch=head_branch,
            api_key=api_key,
        )

    except Exception as e:
        logger.exception("SAST diff scan failed: %s", e)
        _progress_set(scan_session_id, {"status": "failed", "error": str(e)[:500]})
        async with AsyncSessionLocal() as db:
            session = (await db.execute(
                select(SastScanSession).where(SastScanSession.id == uuid.UUID(scan_session_id))
            )).scalar_one_or_none()
            if session:
                session.status = "failed"
                session.error_message = str(e)[:500]
                await db.commit()
    finally:
        if clone_dir:
            cleanup_source(clone_dir)


# ── DAST Schedule ─────────────────────────────────────────────────────

class DastScheduleRequest(BaseModel):
    project_id: str
    cron_expression: str = "@daily"
    scan_config: dict | None = None


@router.post("/dast/schedule")
async def create_dast_schedule(
    req: DastScheduleRequest,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Create or update a DAST scan schedule."""
    project = (await db.execute(
        select(Project).where(Project.id == uuid.UUID(req.project_id))
    )).scalar_one_or_none()
    if not project:
        raise HTTPException(404, "Project not found")

    from app.services.dast.scan_scheduler import ScanScheduler
    result = await ScanScheduler.create_schedule(
        db=db,
        project_id=req.project_id,
        organization_id=str(project.organization_id),
        cron_expression=req.cron_expression,
        scan_config=req.scan_config,
        created_by=str(current_user.id),
    )
    return result


@router.get("/dast/schedule/{project_id}")
async def get_dast_schedule(
    project_id: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get DAST scan schedule for a project."""
    from app.services.dast.scan_scheduler import ScanScheduler
    schedule = await ScanScheduler.get_schedule(db, project_id)
    if not schedule:
        raise HTTPException(404, "No schedule found")
    return schedule


@router.delete("/dast/schedule/{project_id}")
async def delete_dast_schedule(
    project_id: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Delete DAST scan schedule."""
    from app.services.dast.scan_scheduler import ScanScheduler
    deleted = await ScanScheduler.delete_schedule(db, project_id)
    if not deleted:
        raise HTTPException(404, "No schedule found")
    return {"status": "deleted"}


@router.get("/dast/baselines/{project_id}")
async def get_dast_baselines(
    project_id: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get DAST baseline comparison history."""
    from app.models.sast_scan import DastBaseline

    baselines = (await db.execute(
        select(DastBaseline)
        .where(DastBaseline.project_id == uuid.UUID(project_id))
        .order_by(desc(DastBaseline.created_at))
        .limit(20)
    )).scalars().all()

    return [{
        "id": str(b.id),
        "scan_session_id": b.scan_session_id,
        "total_findings": b.total_findings,
        "findings_by_severity": b.findings_by_severity,
        "new_findings": b.new_findings,
        "fixed_findings": b.fixed_findings,
        "unchanged_findings": b.unchanged_findings,
        "created_at": b.created_at.isoformat() if b.created_at else None,
    } for b in baselines]
