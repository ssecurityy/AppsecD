"""Notification service — Slack, SMTP, generic webhook.

Enterprise: fire-and-forget, non-blocking. Failures logged but don't block API.
"""
import asyncio
import logging
from typing import Any, Optional
import httpx

from app.core.config import get_settings

logger = logging.getLogger(__name__)


async def _post_json(url: str, payload: dict, timeout: float = 10.0) -> bool:
    """POST JSON to URL. Returns True on success."""
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            r = await client.post(url, json=payload)
            if r.status_code >= 400:
                logger.warning("Notification POST failed: %s %s", url, r.status_code)
                return False
            return True
    except Exception as e:
        logger.warning("Notification POST error: %s", e)
        return False


async def notify_slack(message: str, webhook_url: Optional[str] = None) -> bool:
    """Send message to Slack via webhook."""
    s = get_settings()
    url = webhook_url or s.slack_webhook_url
    if not url:
        return False
    payload = {"text": message}
    return await _post_json(url, payload)


async def notify_webhook(event: str, data: dict, webhook_url: Optional[str] = None) -> bool:
    """Send event to generic webhook."""
    s = get_settings()
    url = webhook_url or s.webhook_url
    if not url:
        return False
    payload = {"event": event, "data": data}
    return await _post_json(url, payload)


async def notify_critical_finding(
    project_name: str,
    finding_title: str,
    severity: str,
    finding_id: str,
    project_id: str,
    *,
    slack_url: Optional[str] = None,
    webhook_url: Optional[str] = None,
    send_email: bool = True,
) -> None:
    """Fire notifications for critical finding. Non-blocking."""
    s = get_settings()
    msg = f":rotating_light: *Critical Finding*\n• Project: {project_name}\n• Finding: {finding_title}\n• Severity: {severity}"
    tasks = []
    if s.slack_webhook_url or slack_url:
        tasks.append(notify_slack(msg, slack_url))
    if s.webhook_url or webhook_url:
        tasks.append(notify_webhook(
            "finding.created",
            {
                "project_id": project_id,
                "project_name": project_name,
                "finding_id": finding_id,
                "title": finding_title,
                "severity": severity,
            },
            webhook_url,
        ))
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)
    if send_email and s.smtp_host and s.notification_emails:
        to_list = [e.strip() for e in s.notification_emails.split(",") if e.strip()]
        if to_list:
            try:
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(
                    None,
                    _send_smtp_critical_finding,
                    project_name,
                    finding_title,
                    severity,
                    to_list,
                )
            except Exception as e:
                logger.warning("SMTP notification error: %s", e)


def _send_smtp_critical_finding(
    project_name: str, finding_title: str, severity: str, to_emails: list[str]
) -> None:
    """Sync SMTP send. Called from executor."""
    import smtplib
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart

    s = get_settings()
    if not s.smtp_host or not to_emails:
        return
    try:
        msg = MIMEMultipart()
        msg["Subject"] = f"[AppSecD] Critical Finding: {finding_title[:50]}"
        msg["From"] = s.smtp_from
        msg["To"] = ", ".join(to_emails)
        body = f"Project: {project_name}\nFinding: {finding_title}\nSeverity: {severity}"
        msg.attach(MIMEText(body, "plain"))
        with smtplib.SMTP(s.smtp_host, s.smtp_port) as server:
            if s.smtp_tls:
                server.starttls()
            if s.smtp_user and s.smtp_password:
                server.login(s.smtp_user, s.smtp_password)
            server.sendmail(s.smtp_from, to_emails, msg.as_string())
    except Exception as e:
        logger.warning("SMTP send failed: %s", e)
