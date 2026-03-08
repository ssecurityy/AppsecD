"""Pull Request review service — webhook handling and inline PR comments."""
import hashlib
import hmac
import json
import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)

GITHUB_API = "https://api.github.com"
REQUEST_TIMEOUT = 30


class PRReviewService:
    """Handles PR webhook events, triggers diff scans, and posts inline comments."""

    def __init__(self, access_token: str):
        self.access_token = access_token
        self._headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    async def get_pr_diff(self, owner: str, repo: str, pr_number: int) -> str:
        """Fetch unified diff for a pull request."""
        headers = {**self._headers, "Accept": "application/vnd.github.v3.diff"}
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
            resp = await client.get(
                f"{GITHUB_API}/repos/{owner}/{repo}/pulls/{pr_number}",
                headers=headers,
            )
            resp.raise_for_status()
            return resp.text

    async def get_pr_info(self, owner: str, repo: str, pr_number: int) -> dict:
        """Get PR metadata (head/base branches, title, etc.)."""
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
            resp = await client.get(
                f"{GITHUB_API}/repos/{owner}/{repo}/pulls/{pr_number}",
                headers=self._headers,
            )
            resp.raise_for_status()
            data = resp.json()
            return {
                "title": data.get("title", ""),
                "head_branch": data.get("head", {}).get("ref", ""),
                "base_branch": data.get("base", {}).get("ref", ""),
                "head_sha": data.get("head", {}).get("sha", ""),
                "base_sha": data.get("base", {}).get("sha", ""),
                "changed_files": data.get("changed_files", 0),
                "additions": data.get("additions", 0),
                "deletions": data.get("deletions", 0),
                "state": data.get("state", ""),
                "user": data.get("user", {}).get("login", ""),
            }

    async def get_pr_files(self, owner: str, repo: str, pr_number: int) -> list[dict]:
        """Get list of changed files in a PR."""
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
            resp = await client.get(
                f"{GITHUB_API}/repos/{owner}/{repo}/pulls/{pr_number}/files",
                headers=self._headers,
                params={"per_page": 100},
            )
            resp.raise_for_status()
            return [
                {
                    "filename": f.get("filename", ""),
                    "status": f.get("status", ""),
                    "additions": f.get("additions", 0),
                    "deletions": f.get("deletions", 0),
                    "patch": f.get("patch", ""),
                }
                for f in resp.json()
            ]

    async def post_pr_review(
        self,
        owner: str,
        repo: str,
        pr_number: int,
        findings: list[dict],
        action: str = "COMMENT",
    ) -> dict:
        """Create a GitHub PR review with inline comments on findings.

        Args:
            action: APPROVE, REQUEST_CHANGES, or COMMENT
        """
        comments = []
        for f in findings:
            file_path = f.get("file_path", "")
            line = f.get("line_start", 1)
            severity = f.get("severity", "medium").upper()
            title = f.get("title", "Security Issue")
            desc = f.get("description", "")
            cwe = f.get("cwe_id", "")
            remediation = f.get("fix_suggestion", "")

            body_parts = [
                f"**{severity}**: {title}",
                f"CWE: {cwe}" if cwe else "",
                "",
                desc[:500] if desc else "",
            ]
            if remediation:
                body_parts.extend(["", f"**Remediation:** {remediation[:300]}"])

            body = "\n".join(p for p in body_parts if p is not None)

            comments.append({
                "path": file_path,
                "line": max(1, line),
                "body": body,
            })

        if not comments:
            body_text = "Navigator Security Review: No security issues found in this PR."
        else:
            severity_counts = {}
            for f in findings:
                s = f.get("severity", "medium")
                severity_counts[s] = severity_counts.get(s, 0) + 1
            summary_parts = [f"{v} {k}" for k, v in sorted(severity_counts.items())]
            body_text = (
                f"Navigator Security Review found **{len(findings)}** issue(s): "
                + ", ".join(summary_parts)
            )

        payload: dict[str, Any] = {
            "body": body_text,
            "event": action,
        }
        if comments:
            payload["comments"] = comments[:50]

        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
            resp = await client.post(
                f"{GITHUB_API}/repos/{owner}/{repo}/pulls/{pr_number}/reviews",
                headers=self._headers,
                json=payload,
            )
            resp.raise_for_status()
            return resp.json()

    async def post_commit_status(
        self,
        owner: str,
        repo: str,
        sha: str,
        state: str,
        description: str,
        context: str = "navigator/security-review",
        target_url: str | None = None,
    ) -> None:
        """Post a commit status check."""
        payload: dict[str, Any] = {
            "state": state,
            "description": description[:140],
            "context": context,
        }
        if target_url:
            payload["target_url"] = target_url

        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
            resp = await client.post(
                f"{GITHUB_API}/repos/{owner}/{repo}/statuses/{sha}",
                headers=self._headers,
                json=payload,
            )
            resp.raise_for_status()

    @staticmethod
    def determine_review_action(findings: list[dict], block_on_high: bool = True) -> str:
        """Determine review action based on findings and policy.

        Returns: APPROVE, REQUEST_CHANGES, or COMMENT
        """
        if not findings:
            return "APPROVE"

        severities = {f.get("severity", "medium") for f in findings}
        if block_on_high and severities & {"critical", "high"}:
            return "REQUEST_CHANGES"
        return "COMMENT"


def verify_github_webhook_signature(payload_body: bytes, signature: str, secret: str) -> bool:
    """Verify GitHub webhook HMAC-SHA256 signature."""
    if not signature or not signature.startswith("sha256="):
        return False
    expected = "sha256=" + hmac.new(
        secret.encode(), payload_body, hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(expected, signature)


def parse_pr_webhook_payload(payload: dict) -> dict | None:
    """Extract relevant info from a GitHub PR webhook payload.

    Returns None if this event should be ignored.
    """
    action = payload.get("action", "")
    if action not in ("opened", "synchronize", "reopened"):
        return None

    pr = payload.get("pull_request", {})
    repo = payload.get("repository", {})

    return {
        "action": action,
        "pr_number": pr.get("number"),
        "pr_title": pr.get("title", ""),
        "head_branch": pr.get("head", {}).get("ref", ""),
        "base_branch": pr.get("base", {}).get("ref", ""),
        "head_sha": pr.get("head", {}).get("sha", ""),
        "repo_full_name": repo.get("full_name", ""),
        "repo_owner": repo.get("owner", {}).get("login", ""),
        "repo_name": repo.get("name", ""),
        "clone_url": repo.get("clone_url", ""),
        "sender": payload.get("sender", {}).get("login", ""),
    }
