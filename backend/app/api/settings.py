"""Admin settings API — org-scoped JIRA, LLM. Enterprise multi-tenant."""
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.api.auth import require_admin, get_client_ip
from app.core.database import get_db
from app.core.config import get_settings
from app.models.user import User
from app.models.organization import Organization
from app.models.project import Project
from app.services.audit_service import log_audit
from app.services.org_settings_service import (
    get_llm_config,
    update_llm_config,
    get_jira_config,
    update_jira_config,
    get_custom_models,
    add_custom_model,
    remove_custom_model,
    get_github_config,
)
from app.services.admin_settings_service import (
    get_github_platform_config,
    update_github_platform_app_config,
    update_github_oauth_platform_config,
)
from app.services.llm_models_service import fetch_latest_models, is_valid_provider_model

router = APIRouter(prefix="/admin/settings", tags=["admin-settings"])


def _github_oauth_state_key(state: str) -> str:
    return f"github_oauth_state:{state}"


def _github_app_state_key(state: str) -> str:
    return f"github_app_state:{state}"


def _github_bootstrap_launch_key(token: str) -> str:
    return f"github_app_bootstrap_launch:{token}"


def _public_frontend_origin() -> str:
    settings = get_settings()
    origins = [origin.strip() for origin in settings.allowed_origins.split(",") if origin.strip()]
    for origin in origins:
        if "localhost" in origin or "127.0.0.1" in origin:
            continue
        return origin.rstrip("/")
    return (origins[0] if origins else "https://appsecd.com").rstrip("/")


async def _issue_github_app_bootstrap_launch(
    current_user: User,
    org_uuid: UUID | None,
    project_id: str | None,
    auto_install: bool,
) -> str:
    import json as _json
    import secrets as sec
    import redis.asyncio as aioredis

    settings = get_settings()
    launch_token = sec.token_urlsafe(32)
    r = aioredis.from_url(settings.redis_url, decode_responses=True)
    await r.setex(
        _github_bootstrap_launch_key(launch_token),
        600,
        _json.dumps({
            "user_id": str(current_user.id),
            "org_id": str(org_uuid) if org_uuid else "",
            "project_id": project_id or "",
            "auto_install": bool(auto_install),
        }),
    )
    await r.aclose()
    return f"/api/admin/settings/github/bootstrap/app/launch?token={launch_token}"


async def _resolve_org_id(current_user: User, org_id: str | None, db: AsyncSession) -> tuple[UUID | None, Organization | None]:
    """Resolve organization for settings. Super_admin can pick any org; admin auto-scoped to their org."""
    if current_user.role == "admin":
        # Admin is always scoped to their own org
        if not current_user.organization_id:
            raise HTTPException(400, "Admin must belong to an organization")
        org_result = await db.execute(select(Organization).where(Organization.id == current_user.organization_id))
        org = org_result.scalar_one_or_none()
        return current_user.organization_id, org

    # Super admin — use provided org_id or None
    if org_id:
        try:
            oid = UUID(org_id)
        except ValueError:
            raise HTTPException(400, "Invalid org_id")
        org_result = await db.execute(select(Organization).where(Organization.id == oid))
        org = org_result.scalar_one_or_none()
        if not org:
            raise HTTPException(404, "Organization not found")
        return oid, org
    return None, None


@router.get("")
async def get_settings_status(
    org_id: str | None = Query(None, description="Organization ID (super_admin only)"),
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """
    Return integration status. Admin: auto-scoped to their org. Super_admin: can pass org_id.
    """
    org_uuid, org = await _resolve_org_id(current_user, org_id, db)
    s = get_settings()
    provider, model, api_key = await get_llm_config(db, org_uuid)
    custom = await get_custom_models(db, org_uuid)
    jira_base, jira_email, jira_token, jira_key = await get_jira_config(db, org_uuid)
    github_cfg = await get_github_config(db, org_uuid)
    platform_github = await get_github_platform_config(db)
    github_app_missing = [
        name for name, value in {
            "GITHUB_APP_ID": platform_github.get("github_app_id"),
            "GITHUB_APP_SLUG": platform_github.get("github_app_slug"),
            "GITHUB_APP_PRIVATE_KEY": platform_github.get("github_app_private_key"),
        }.items() if not value
    ]
    github_oauth_missing = [
        name for name, value in {
            "GITHUB_OAUTH_CLIENT_ID": platform_github.get("github_oauth_client_id"),
            "GITHUB_OAUTH_CLIENT_SECRET": platform_github.get("github_oauth_client_secret"),
        }.items() if not value
    ]

    openai_k = s.openai_api_key or (api_key if provider == "openai" else None)
    google_k = s.google_api_key or (api_key if provider == "google" else None)
    models = fetch_latest_models(
        openai_key=openai_k,
        google_key=google_k,
        custom_models=custom,
    )
    return {
        "organization_id": str(org_uuid) if org_uuid else None,
        "organization_name": org.name if org else None,
        "github": {
            "oauth_configured": not github_oauth_missing,
            "oauth_connected": bool(github_cfg.get("oauth_token")),
            "oauth_account_login": github_cfg.get("oauth_account_login", ""),
            "pat_connected": bool(github_cfg.get("pat_token")),
            "pat_account_login": github_cfg.get("pat_account_login", ""),
            "github_app_configured": not github_app_missing,
            "github_app_connected": bool(github_cfg.get("app_installation")),
            "github_app_installation": github_cfg.get("app_installation"),
            "github_app_name": platform_github.get("github_app_name", "") or s.github_app_name or "",
            "github_app_slug": platform_github.get("github_app_slug", ""),
            "github_oauth_redirect_uri": platform_github.get("github_oauth_redirect_uri", ""),
            "github_oauth_client_id": platform_github.get("github_oauth_client_id", ""),
            "github_app_missing_env": github_app_missing,
            "oauth_missing_env": github_oauth_missing,
            "hint": "GitHub App is the recommended enterprise path. OAuth and PAT remain available as fallback options.",
        },
        "jira": {
            "configured": bool(jira_base and jira_email and jira_token and jira_key),
            "base_url": jira_base or "",
            "email": jira_email or "",
            "project_key": jira_key or "",
            "hint": "Configure JIRA below for this organization, or set in backend/.env as fallback.",
        },
        "ai": {
            "mode": "llm" if api_key else "rule_based",
            "provider": provider,
            "model": model,
            "hint": "Configure provider, model and API key below. Env fallback when not set.",
        },
        "llm_models": [{"provider": p, "value": m, "label": l} for p, m, l in models],
    }


@router.get("/github/connect/app")
async def start_github_app_connect(
    org_id: str | None = Query(None),
    project_id: str | None = Query(None),
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Start org-scoped GitHub App installation from admin settings."""
    import json as _json
    import secrets as sec
    import redis.asyncio as aioredis
    from app.services.sast.github_client import github_app_is_configured, get_github_app_install_url

    org_uuid, _ = await _resolve_org_id(current_user, org_id, db)
    if not org_uuid:
        raise HTTPException(400, "Organization required for GitHub connection.")
    project = None
    if project_id:
        project = (await db.execute(select(Project).where(Project.id == UUID(project_id)))).scalar_one_or_none()
        if not project:
            raise HTTPException(404, "Project not found")
        if project.organization_id != org_uuid:
            raise HTTPException(400, "Project does not belong to the selected organization.")
    platform_github = await get_github_platform_config(db)
    if not github_app_is_configured(platform_github):
        launch_url = await _issue_github_app_bootstrap_launch(current_user, org_uuid, project_id, auto_install=True)
        return {"install_url": launch_url, "state": None, "mode": "bootstrap_then_install"}

    state = sec.token_urlsafe(32)
    r = aioredis.from_url(get_settings().redis_url, decode_responses=True)
    await r.setex(
        _github_app_state_key(state),
        600,
        _json.dumps({
            "user_id": str(current_user.id),
            "org_id": str(org_uuid),
            "project_id": project_id or "",
            "return_to": "project_sast_import" if project_id else "admin_settings",
        }),
    )
    await r.aclose()
    return {"install_url": get_github_app_install_url(state, platform_github), "state": state, "mode": "install"}


@router.get("/github/connect/oauth")
async def start_github_oauth_connect(
    org_id: str | None = Query(None),
    project_id: str | None = Query(None),
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Start org-scoped GitHub OAuth flow from admin settings."""
    import json as _json
    import secrets as sec
    import redis.asyncio as aioredis

    org_uuid, _ = await _resolve_org_id(current_user, org_id, db)
    if not org_uuid:
        raise HTTPException(400, "Organization required for GitHub connection.")
    if project_id:
        project = (await db.execute(select(Project).where(Project.id == UUID(project_id)))).scalar_one_or_none()
        if not project:
            raise HTTPException(404, "Project not found")
        if project.organization_id != org_uuid:
            raise HTTPException(400, "Project does not belong to the selected organization.")

    settings = get_settings()
    platform_github = await get_github_platform_config(db)
    if not (platform_github.get("github_oauth_client_id") and platform_github.get("github_oauth_client_secret")):
        raise HTTPException(400, "GitHub OAuth is not configured on the platform yet.")

    state = sec.token_urlsafe(32)
    r = aioredis.from_url(settings.redis_url, decode_responses=True)
    await r.setex(
        _github_oauth_state_key(state),
        300,
        _json.dumps({
            "user_id": str(current_user.id),
            "org_id": str(org_uuid),
            "project_id": project_id or "",
            "return_to": "project_sast_import" if project_id else "admin_settings",
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


class GithubPlatformConfigUpdate(BaseModel):
    github_app_name: str | None = None
    github_app_slug: str | None = None
    github_oauth_client_id: str | None = None
    github_oauth_client_secret: str | None = None
    github_oauth_redirect_uri: str | None = None


@router.put("/github/platform")
async def update_github_platform_settings(
    request: Request,
    payload: GithubPlatformConfigUpdate,
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Store platform-wide GitHub settings in admin settings so env vars are optional."""
    await update_github_platform_app_config(
        db,
        app_name=payload.github_app_name,
        app_slug=payload.github_app_slug,
    )
    await update_github_oauth_platform_config(
        db,
        client_id=payload.github_oauth_client_id,
        client_secret=payload.github_oauth_client_secret,
        redirect_uri=payload.github_oauth_redirect_uri,
    )
    await db.commit()
    await log_audit(
        db,
        "update_github_platform_settings",
        user_id=str(current_user.id),
        resource_type="settings",
        details={"github_app_slug": payload.github_app_slug or "", "oauth_redirect_configured": bool(payload.github_oauth_redirect_uri)},
        ip_address=get_client_ip(request),
    )
    return {"ok": True}


@router.get("/github/bootstrap/app")
async def start_github_app_bootstrap(
    org_id: str | None = Query(None),
    project_id: str | None = Query(None),
    auto_install: bool = Query(False),
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Create a one-time public bootstrap launch URL for a popup."""

    org_uuid, _ = await _resolve_org_id(current_user, org_id, db)
    if project_id:
        project = (await db.execute(select(Project).where(Project.id == UUID(project_id)))).scalar_one_or_none()
        if not project:
            raise HTTPException(404, "Project not found")
        if org_uuid and project.organization_id != org_uuid:
            raise HTTPException(400, "Project does not belong to the selected organization.")
    launch_url = await _issue_github_app_bootstrap_launch(current_user, org_uuid, project_id, auto_install)
    return {"launch_url": launch_url}


@router.get("/github/bootstrap/app/launch")
async def launch_github_app_bootstrap(
    token: str,
    db: AsyncSession = Depends(get_db),
):
    """Public one-time launch page for GitHub App bootstrap popups."""
    import json as _json
    import secrets as sec
    import redis.asyncio as aioredis
    from fastapi.responses import HTMLResponse

    settings = get_settings()
    r = aioredis.from_url(settings.redis_url, decode_responses=True)
    launch_data = await r.get(_github_bootstrap_launch_key(token))
    await r.delete(_github_bootstrap_launch_key(token))
    if not launch_data:
        await r.aclose()
        raise HTTPException(403, "Invalid or expired GitHub App bootstrap launch token")

    launch_info = _json.loads(launch_data)
    frontend_origin = _public_frontend_origin()
    platform_github = await get_github_platform_config(db)
    redirect_url = f"{frontend_origin}/api/admin/settings/github/bootstrap/app/callback"
    setup_url = f"{frontend_origin}/api/sast/github/app/callback"
    webhook_url = f"{frontend_origin}/api/admin/settings/github/bootstrap/app/webhook"
    state = sec.token_urlsafe(32)
    await r.setex(
        _github_app_state_key(state),
        3600,
        _json.dumps({
            "user_id": launch_info.get("user_id", ""),
            "org_id": launch_info.get("org_id", ""),
            "project_id": launch_info.get("project_id", ""),
            "return_to": "admin_settings",
            "auto_install": bool(launch_info.get("auto_install")),
        }),
    )
    await r.aclose()

    manifest = {
        "name": platform_github.get("github_app_name") or settings.github_app_name or "Navigator AppSec",
        "url": frontend_origin,
        "hook_attributes": {"url": webhook_url, "active": True},
        "redirect_url": redirect_url,
        "setup_url": setup_url,
        "public": True,
        "setup_on_update": True,
        "default_permissions": {
            "contents": "write",
            "pull_requests": "write",
        },
        "default_events": [],
        "description": "Navigator AppSec GitHub integration for repository SAST scans and AI-assisted fix pull requests.",
    }
    action = "https://github.com/settings/apps/new"
    html = f"""
    <html><body style="font-family:sans-serif;background:#0f172a;color:#e2e8f0;display:flex;align-items:center;justify-content:center;min-height:100vh;">
      <form id="manifestForm" action="{action}?state={state}" method="post">
        <input type="hidden" name="manifest" value='{_json.dumps(manifest)}' />
      </form>
      <script>document.getElementById('manifestForm').submit();</script>
      <p>Redirecting to GitHub App creation...</p>
    </body></html>
    """
    return HTMLResponse(html)


@router.get("/github/bootstrap/app/callback")
async def github_app_bootstrap_callback(
    code: str,
    state: str,
    db: AsyncSession = Depends(get_db),
):
    """Exchange the GitHub App manifest code and store platform app credentials."""
    import json as _json
    import secrets as sec
    import redis.asyncio as aioredis
    import httpx
    from fastapi.responses import HTMLResponse
    from app.services.sast.github_client import get_github_app_install_url

    settings = get_settings()
    r = aioredis.from_url(settings.redis_url, decode_responses=True)
    state_data = await r.get(_github_app_state_key(state))
    await r.delete(_github_app_state_key(state))
    if not state_data:
        await r.aclose()
        raise HTTPException(403, "Invalid or expired GitHub App bootstrap state")

    async with httpx.AsyncClient(timeout=30) as client:
        response = await client.post(
            f"https://api.github.com/app-manifests/{code}/conversions",
            headers={"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"},
        )
        if response.status_code >= 400:
            await r.aclose()
            raise HTTPException(502, f"GitHub App bootstrap failed: {response.text[:200]}")
        data = response.json()

    await update_github_platform_app_config(
        db,
        app_id=str(data.get("id") or ""),
        app_slug=data.get("slug") or "",
        app_name=data.get("name") or "",
        client_id=data.get("client_id") or "",
        client_secret=data.get("client_secret") or "",
        private_key=data.get("pem") or "",
        webhook_secret=data.get("webhook_secret") or "",
    )
    await db.commit()

    state_info = _json.loads(state_data)
    org_id_value = state_info.get("org_id") or ""
    project_id_value = state_info.get("project_id") or ""
    auto_install = bool(state_info.get("auto_install"))
    platform_github = await get_github_platform_config(db)
    if auto_install and org_id_value:
        install_state = sec.token_urlsafe(32)
        await r.setex(
            _github_app_state_key(install_state),
            600,
            _json.dumps({
                "user_id": state_info.get("user_id", ""),
                "org_id": org_id_value,
                "project_id": project_id_value,
                "return_to": "project_sast_import" if project_id_value else "admin_settings",
            }),
        )
        await r.aclose()
        install_url = get_github_app_install_url(install_state, platform_github)
        html = f"""
        <html><body><script>
        window.location.href = "{install_url}";
        </script><p>GitHub App created. Redirecting to installation...</p></body></html>
        """
        return HTMLResponse(html)

    await r.aclose()
    frontend_origin = _public_frontend_origin()
    redirect_url = f"{frontend_origin}/admin/settings?tab=github"
    if org_id_value:
        redirect_url += f"&org_id={org_id_value}"
    redirect_url += "&github_app_bootstrap=success"
    html = f"""
    <html><body><script>
    if (window.opener) {{
        window.opener.postMessage({{
            type: "github_app_bootstrap_success",
            app_slug: "{data.get('slug', '')}",
            app_name: "{data.get('name', '')}"
        }}, "*");
        window.close();
    }} else {{
        window.location.href = "{redirect_url}";
    }}
    </script><p>GitHub App created. Redirecting...</p></body></html>
    """
    return HTMLResponse(html)


@router.post("/github/bootstrap/app/webhook")
async def github_app_bootstrap_webhook():
    """Minimal webhook receiver so the bootstrap-created app has a valid webhook URL."""
    return {"ok": True}


@router.delete("/github/connection")
async def disconnect_github_connection(
    mode: str = Query(..., description="github_app, oauth, pat, or all"),
    org_id: str | None = Query(None),
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Disconnect org-scoped GitHub credentials from admin settings."""
    from app.services.org_settings_service import (
        update_github_app_installation,
        update_github_oauth_config,
        update_github_pat_config,
    )

    org_uuid, _ = await _resolve_org_id(current_user, org_id, db)
    if not org_uuid:
        raise HTTPException(400, "Organization required for GitHub connection.")

    normalized = (mode or "").lower()
    if normalized not in {"github_app", "oauth", "pat", "all"}:
        raise HTTPException(400, "Unsupported disconnect mode")

    if normalized in {"github_app", "all"}:
        await update_github_app_installation(db, org_uuid, None)
    if normalized in {"oauth", "all"}:
        await update_github_oauth_config(db, org_uuid, "", account_login="")
    if normalized in {"pat", "all"}:
        await update_github_pat_config(db, org_uuid, "", account_login="")
    await db.commit()
    return {"ok": True}


@router.get("/llm/models")
async def refresh_llm_models(
    org_id: str | None = Query(None),
    refresh: bool = False,
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Refresh and return latest models from provider APIs."""
    org_uuid, _ = await _resolve_org_id(current_user, org_id, db)
    s = get_settings()
    provider, _, api_key = await get_llm_config(db, org_uuid)
    custom = await get_custom_models(db, org_uuid)
    openai_k = s.openai_api_key or (api_key if provider == "openai" else None)
    google_k = s.google_api_key or (api_key if provider == "google" else None)
    models = fetch_latest_models(
        openai_key=openai_k,
        google_key=google_k,
        custom_models=custom,
        force_refresh=refresh,
    )
    return {"llm_models": [{"provider": p, "value": m, "label": l} for p, m, l in models]}


class LlmSettingsUpdate(BaseModel):
    provider: str = "openai"
    model: str = "gpt-4o-mini"
    api_key: str | None = None


@router.put("/llm")
async def update_llm_settings(
    request: Request,
    payload: LlmSettingsUpdate,
    org_id: str | None = Query(None),
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Update LLM config. Admin: auto-scoped to org. Super_admin: must select org."""
    org_uuid, _ = await _resolve_org_id(current_user, org_id, db)
    if not org_uuid:
        raise HTTPException(400, "Select an organization to configure.")
    if not is_valid_provider_model(payload.provider, payload.model):
        raise HTTPException(400, "Invalid provider or model.")
    await update_llm_config(db, payload.provider, payload.model, payload.api_key, org_uuid)
    await log_audit(db, "update_llm_settings", user_id=str(current_user.id), resource_type="settings", details={"provider": payload.provider, "model": payload.model, "org_id": str(org_uuid) if org_uuid else None}, ip_address=get_client_ip(request))
    return {"ok": True}


class JiraSettingsUpdate(BaseModel):
    base_url: str = ""
    email: str = ""
    api_token: str = ""
    project_key: str = ""


@router.put("/jira")
async def update_jira_settings(
    request: Request,
    payload: JiraSettingsUpdate,
    org_id: str | None = Query(None),
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Update JIRA config for organization. Admin: auto-scoped. Super_admin: per-org."""
    org_uuid, _ = await _resolve_org_id(current_user, org_id, db)
    if not org_uuid:
        raise HTTPException(400, "Organization required for JIRA config. Select an organization.")
    await update_jira_config(
        db,
        payload.base_url,
        payload.email,
        payload.api_token,
        payload.project_key,
        org_uuid,
    )
    await log_audit(db, "update_jira_settings", user_id=str(current_user.id), resource_type="settings", details={"org_id": str(org_uuid) if org_uuid else None}, ip_address=get_client_ip(request))
    return {"ok": True}


class CustomModelAdd(BaseModel):
    provider: str
    model: str
    label: str = ""


@router.post("/llm/custom-model")
async def add_llm_custom_model(
    payload: CustomModelAdd,
    org_id: str | None = Query(None),
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Add a custom/future model. Org-scoped."""
    org_uuid, _ = await _resolve_org_id(current_user, org_id, db)
    if not is_valid_provider_model(payload.provider, payload.model):
        raise HTTPException(400, "Invalid provider or model.")
    await add_custom_model(db, payload.provider, payload.model, payload.label or payload.model, org_uuid)
    return {"ok": True}


@router.delete("/llm/custom-model")
async def delete_llm_custom_model(
    provider: str,
    model: str,
    org_id: str | None = Query(None),
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Remove a custom model."""
    org_uuid, _ = await _resolve_org_id(current_user, org_id, db)
    await remove_custom_model(db, provider, model, org_uuid)
    return {"ok": True}


# ═══════════════════════════════════════════════════════════
# Notification Settings (SMTP, Slack, Webhook)
# ═══════════════════════════════════════════════════════════

class NotificationSettingsUpdate(BaseModel):
    slack_webhook_url: str = ""
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = ""
    smtp_tls: bool = True
    notification_emails: str = ""
    webhook_url: str = ""


@router.get("/notifications")
async def get_notification_settings(
    org_id: str | None = Query(None),
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Get notification settings. Returns current config (passwords masked)."""
    import json as _json
    from app.models.org_setting import OrgSetting
    org_uuid, org = await _resolve_org_id(current_user, org_id, db)

    # Try org-scoped settings first
    config = {}
    if org_uuid:
        result = await db.execute(
            select(OrgSetting).where(
                OrgSetting.organization_id == org_uuid,
                OrgSetting.key == "notification_settings",
            )
        )
        setting = result.scalar_one_or_none()
        if setting and setting.value:
            try:
                config = _json.loads(setting.value) if isinstance(setting.value, str) else setting.value
            except (ValueError, TypeError):
                config = {}

    # Fall back to env
    s = get_settings()
    return {
        "organization_id": str(org_uuid) if org_uuid else None,
        "slack_webhook_url": config.get("slack_webhook_url", s.slack_webhook_url or ""),
        "smtp_host": config.get("smtp_host", s.smtp_host or ""),
        "smtp_port": config.get("smtp_port", s.smtp_port),
        "smtp_user": config.get("smtp_user", s.smtp_user or ""),
        "smtp_password_set": bool(config.get("smtp_password") or s.smtp_password),
        "smtp_from": config.get("smtp_from", s.smtp_from or ""),
        "smtp_tls": config.get("smtp_tls", s.smtp_tls),
        "notification_emails": config.get("notification_emails", s.notification_emails or ""),
        "webhook_url": config.get("webhook_url", s.webhook_url or ""),
    }


@router.put("/notifications")
async def update_notification_settings(
    request: Request,
    payload: NotificationSettingsUpdate,
    org_id: str | None = Query(None),
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Update notification settings per organization."""
    import json as _json
    from app.models.org_setting import OrgSetting
    org_uuid, _ = await _resolve_org_id(current_user, org_id, db)
    if not org_uuid:
        raise HTTPException(400, "Organization required for notification settings.")

    result = await db.execute(
        select(OrgSetting).where(
            OrgSetting.organization_id == org_uuid,
            OrgSetting.key == "notification_settings",
        )
    )
    setting = result.scalar_one_or_none()

    config = {
        "slack_webhook_url": payload.slack_webhook_url,
        "smtp_host": payload.smtp_host,
        "smtp_port": payload.smtp_port,
        "smtp_user": payload.smtp_user,
        "smtp_from": payload.smtp_from,
        "smtp_tls": payload.smtp_tls,
        "notification_emails": payload.notification_emails,
        "webhook_url": payload.webhook_url,
    }
    # Only update password if provided (non-empty)
    if payload.smtp_password:
        config["smtp_password"] = payload.smtp_password
    elif setting and setting.value:
        try:
            old = _json.loads(setting.value) if isinstance(setting.value, str) else setting.value
            config["smtp_password"] = old.get("smtp_password", "")
        except (ValueError, TypeError):
            pass

    config_str = _json.dumps(config)
    if setting:
        setting.value = config_str
    else:
        setting = OrgSetting(
            organization_id=org_uuid,
            key="notification_settings",
            value=config_str,
        )
        db.add(setting)

    await db.commit()
    await log_audit(db, "update_notification_settings", user_id=str(current_user.id), resource_type="settings", details={"org_id": str(org_uuid)}, ip_address=get_client_ip(request))
    return {"ok": True, "message": "Notification settings saved"}


@router.post("/notifications/test-slack")
async def test_slack_notification(
    org_id: str | None = Query(None),
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Send a test Slack notification."""
    import json as _json
    from app.services.notification_service import notify_slack
    from app.models.org_setting import OrgSetting

    org_uuid, _ = await _resolve_org_id(current_user, org_id, db)
    webhook_url = ""
    if org_uuid:
        result = await db.execute(
            select(OrgSetting).where(
                OrgSetting.organization_id == org_uuid,
                OrgSetting.key == "notification_settings",
            )
        )
        setting = result.scalar_one_or_none()
        if setting and setting.value:
            try:
                cfg = _json.loads(setting.value) if isinstance(setting.value, str) else setting.value
                webhook_url = cfg.get("slack_webhook_url", "")
            except (ValueError, TypeError):
                pass

    if not webhook_url:
        webhook_url = get_settings().slack_webhook_url

    if not webhook_url:
        raise HTTPException(400, "No Slack webhook URL configured")

    ok = await notify_slack(":white_check_mark: AppSecD test notification — Slack integration is working!", webhook_url)
    if not ok:
        raise HTTPException(500, "Failed to send Slack notification. Check webhook URL.")
    return {"ok": True, "message": "Test notification sent to Slack"}


@router.post("/notifications/test-smtp")
async def test_smtp_notification(
    org_id: str | None = Query(None),
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Send a test SMTP email."""
    import json as _json
    from app.models.org_setting import OrgSetting
    import smtplib
    from email.mime.text import MIMEText

    org_uuid, _ = await _resolve_org_id(current_user, org_id, db)
    config = {}
    if org_uuid:
        result = await db.execute(
            select(OrgSetting).where(
                OrgSetting.organization_id == org_uuid,
                OrgSetting.key == "notification_settings",
            )
        )
        setting = result.scalar_one_or_none()
        if setting and setting.value:
            try:
                config = _json.loads(setting.value) if isinstance(setting.value, str) else setting.value
            except (ValueError, TypeError):
                config = {}

    s = get_settings()
    host = config.get("smtp_host") or s.smtp_host
    port = config.get("smtp_port") or s.smtp_port
    user = config.get("smtp_user") or s.smtp_user
    password = config.get("smtp_password") or s.smtp_password
    from_email = config.get("smtp_from") or s.smtp_from
    tls = config.get("smtp_tls", s.smtp_tls)
    emails = config.get("notification_emails") or s.notification_emails

    if not host:
        raise HTTPException(400, "SMTP host not configured")
    if not emails:
        raise HTTPException(400, "No notification emails configured")

    to_list = [e.strip() for e in emails.split(",") if e.strip()]
    try:
        msg = MIMEText("This is a test notification from AppSecD. SMTP integration is working!")
        msg["Subject"] = "[AppSecD] Test Email Notification"
        msg["From"] = from_email
        msg["To"] = ", ".join(to_list)
        with smtplib.SMTP(host, port) as server:
            if tls:
                server.starttls()
            if user and password:
                server.login(user, password)
            server.sendmail(from_email, to_list, msg.as_string())
        return {"ok": True, "message": f"Test email sent to {', '.join(to_list)}"}
    except Exception as e:
        raise HTTPException(500, f"SMTP test failed: {str(e)}")


@router.post("/llm/test")
async def test_llm_connection(
    org_id: str | None = Query(None),
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Test the configured LLM API key by making a small API call. Uses org-scoped config."""
    org_uuid, _ = await _resolve_org_id(current_user, org_id, db)
    provider, model, api_key = await get_llm_config(db, org_uuid)
    if not api_key:
        return {"ok": False, "error": "No API key configured. Save your API key first, then test.", "mode": "rule_based"}
    try:
        if provider == "anthropic":
            from anthropic import Anthropic
            client = Anthropic(api_key=api_key)
            r = client.messages.create(
                model=model or "claude-sonnet-4-20250514",
                max_tokens=10,
                messages=[{"role": "user", "content": "Say 'ok' in one word."}],
            )
            text = (r.content[0].text if r.content else "").strip()
            return {"ok": True, "model": model, "response": text, "mode": "llm", "provider": provider}
        elif provider == "google":
            import google.generativeai as genai
            genai.configure(api_key=api_key)
            m = genai.GenerativeModel(model or "gemini-1.5-flash")
            r = m.generate_content("Say 'ok' in one word.")
            text = (r.text or "").strip()
            return {"ok": True, "model": model, "response": text, "mode": "llm", "provider": provider}
        else:
            from openai import OpenAI
            client = OpenAI(api_key=api_key)
            response = client.chat.completions.create(
                model=model or "gpt-4o-mini",
                messages=[{"role": "user", "content": "Say 'ok' in one word."}],
                max_tokens=5,
                temperature=0,
            )
            text = (response.choices[0].message.content or "").strip()
            return {"ok": True, "model": model, "response": text, "mode": "llm", "provider": provider}
    except Exception as e:
        return {"ok": False, "error": str(e), "model": model, "mode": "llm", "provider": provider}


@router.post("/jira/test")
async def test_jira_connection(
    org_id: str | None = Query(None),
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Test the configured JIRA connection. Uses org-scoped config first, then env fallback."""
    org_uuid, _ = await _resolve_org_id(current_user, org_id, db)
    jira_base, jira_email, jira_token, jira_key = await get_jira_config(db, org_uuid)

    # Fallback to env vars if org config not set
    if not (jira_base and jira_email and jira_token):
        s = get_settings()
        jira_base = jira_base or s.jira_base_url
        jira_email = jira_email or s.jira_email
        jira_token = jira_token or s.jira_api_token
        jira_key = jira_key or s.jira_project_key

    if not (jira_base and jira_email and jira_token):
        return {"ok": False, "error": "JIRA not configured. Save JIRA URL, email, and API token first."}
    try:
        import httpx
        base = jira_base.rstrip("/")
        with httpx.Client(timeout=10) as client:
            r = client.get(
                f"{base}/rest/api/3/myself",
                auth=(jira_email, jira_token),
            )
            if r.status_code == 200:
                data = r.json()
                return {"ok": True, "user": data.get("displayName", "Unknown"), "email": data.get("emailAddress", ""), "project_key": jira_key}
            else:
                return {"ok": False, "error": f"JIRA returned {r.status_code}: {r.text[:200]}"}
    except Exception as e:
        return {"ok": False, "error": str(e)}
