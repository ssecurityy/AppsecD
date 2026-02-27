"""JIRA integration — create issues from findings."""
import httpx
from app.core.config import get_settings


def _jira_configured() -> bool:
    s = get_settings()
    return bool(s.jira_base_url and s.jira_email and s.jira_api_token and s.jira_project_key)


def create_jira_issue_from_finding(
    finding: dict,
    project_key: str | None = None,
) -> dict | None:
    """
    Create a JIRA issue from a finding. Returns issue key (e.g. PROJ-123) or None on failure.
    """
    if not _jira_configured():
        return None
    s = get_settings()
    pk = project_key or s.jira_project_key
    base = s.jira_base_url.rstrip("/")
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
                    {
                        "type": "paragraph",
                        "content": [{"type": "text", "text": body}],
                    }
                ],
            },
            "issuetype": {"name": "Bug"},
            "priority": {"name": severity},
        }
    }

    auth = (s.jira_email, s.jira_api_token)
    try:
        with httpx.Client(timeout=30) as client:
            r = client.post(url, json=payload, auth=auth)
            r.raise_for_status()
            data = r.json()
            return {"key": data.get("key"), "url": f"{base}/browse/{data.get('key')}"}
    except Exception:
        return None
