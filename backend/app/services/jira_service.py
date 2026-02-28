"""JIRA integration — create issues from findings. Supports per-org config."""
import httpx


def create_jira_issue_from_finding(
    finding: dict,
    project_key: str | None = None,
    *,
    base_url: str | None = None,
    email: str | None = None,
    api_token: str | None = None,
    default_project_key: str | None = None,
) -> dict | None:
    """
    Create a JIRA issue from a finding.
    When base_url, email, api_token are provided, use them (org-scoped).
    Otherwise fall back to env (legacy).
    """
    if base_url and email and api_token:
        base = base_url.rstrip("/")
        pk = project_key or default_project_key or ""
    else:
        from app.core.config import get_settings
        s = get_settings()
        if not (s.jira_base_url and s.jira_email and s.jira_api_token):
            return None
        base = s.jira_base_url.rstrip("/")
        pk = project_key or s.jira_project_key
        email = s.jira_email
        api_token = s.jira_api_token

    if not pk:
        return None

    url = f"{base}/rest/api/3/issue"
    severity_map = {"critical": "Highest", "high": "High", "medium": "Medium", "low": "Low", "info": "Lowest"}
    severity = severity_map.get((finding.get("severity") or "medium").lower(), "Medium")
    summary = (finding.get("title") or "Security Finding")[:255]
    body_parts = [
        f"*Description:*\n{finding.get('description') or 'N/A'}",
        f"\n*Severity:* {severity}",
        f"\n*Affected URL:* {finding.get('affected_url') or 'N/A'}",
        f"\n*OWASP:* {finding.get('owasp_category') or 'N/A'}",
        f"\n*CWE:* {finding.get('cwe_id') or 'N/A'}",
        f"\n*Reproduction Steps:*\n{finding.get('reproduction_steps') or 'N/A'}",
        f"\n*Recommendation:*\n{finding.get('recommendation') or 'N/A'}",
    ]
    body = "\n".join(body_parts)
    payload = {
        "fields": {
            "project": {"key": pk},
            "summary": summary,
            "description": {
                "type": "doc",
                "version": 1,
                "content": [
                    {"type": "paragraph", "content": [{"type": "text", "text": body}]},
                ],
            },
            "issuetype": {"name": "Bug"},
            "priority": {"name": severity},
        }
    }
    auth = (email, api_token)
    try:
        with httpx.Client(timeout=30) as client:
            r = client.post(url, json=payload, auth=auth)
            r.raise_for_status()
            data = r.json()
            return {"key": data.get("key"), "url": f"{base}/browse/{data.get('key')}"}
    except Exception:
        return None


def _jira_configured(base_url: str = "", email: str = "", token: str = "", project_key: str = "") -> bool:
    """Check if JIRA is configured. Pass org config or empty for env check."""
    if base_url and email and token and project_key:
        return True
    from app.core.config import get_settings
    s = get_settings()
    return bool(s.jira_base_url and s.jira_email and s.jira_api_token and s.jira_project_key)
