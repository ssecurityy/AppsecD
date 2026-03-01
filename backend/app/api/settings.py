"""Admin settings API — org-scoped JIRA, LLM. Enterprise multi-tenant."""
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.api.auth import require_admin
from app.core.database import get_db
from app.core.config import get_settings
from app.models.user import User
from app.models.organization import Organization
from app.services.audit_service import log_audit
from app.services.org_settings_service import (
    get_llm_config,
    update_llm_config,
    get_jira_config,
    update_jira_config,
    get_custom_models,
    add_custom_model,
    remove_custom_model,
)
from app.services.llm_models_service import fetch_latest_models, is_valid_provider_model

router = APIRouter(prefix="/admin/settings", tags=["admin-settings"])


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
    await log_audit(db, "update_llm_settings", user_id=str(current_user.id), resource_type="settings", details={"provider": payload.provider, "model": payload.model, "org_id": str(org_uuid) if org_uuid else None})
    return {"ok": True}


class JiraSettingsUpdate(BaseModel):
    base_url: str = ""
    email: str = ""
    api_token: str = ""
    project_key: str = ""


@router.put("/jira")
async def update_jira_settings(
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
    await log_audit(db, "update_jira_settings", user_id=str(current_user.id), resource_type="settings", details={"org_id": str(org_uuid) if org_uuid else None})
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
    await log_audit(db, "update_notification_settings", user_id=str(current_user.id), resource_type="settings", details={"org_id": str(org_uuid)})
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
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Test the configured LLM API key by making a small API call."""
    _provider, model, api_key = await get_llm_config(db)
    if not api_key:
        return {"ok": False, "error": "No API key configured", "mode": "rule_based"}
    try:
        from openai import OpenAI
        client = OpenAI(api_key=api_key)
        response = client.chat.completions.create(
            model=model or "gpt-4o-mini",
            messages=[{"role": "user", "content": "Say 'ok' in one word."}],
            max_tokens=5,
            temperature=0,
        )
        text = (response.choices[0].message.content or "").strip()
        return {"ok": True, "model": model, "response": text, "mode": "llm"}
    except Exception as e:
        return {"ok": False, "error": str(e), "model": model, "mode": "llm"}


@router.post("/jira/test")
async def test_jira_connection(
    current_user: User = Depends(require_admin),
):
    """Test the configured JIRA connection."""
    s = get_settings()
    if not (s.jira_base_url and s.jira_email and s.jira_api_token):
        return {"ok": False, "error": "JIRA not configured. Set env variables."}
    try:
        import httpx
        base = s.jira_base_url.rstrip("/")
        with httpx.Client(timeout=10) as client:
            r = client.get(
                f"{base}/rest/api/3/myself",
                auth=(s.jira_email, s.jira_api_token),
            )
            if r.status_code == 200:
                data = r.json()
                return {"ok": True, "user": data.get("displayName", "Unknown"), "email": data.get("emailAddress", "")}
            else:
                return {"ok": False, "error": f"JIRA returned {r.status_code}: {r.text[:200]}"}
    except Exception as e:
        return {"ok": False, "error": str(e)}
