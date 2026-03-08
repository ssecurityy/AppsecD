"""Multi-SCM provider abstraction — GitHub, GitLab, Bitbucket support.

Provides a unified interface for SCM operations:
- PR/MR diff retrieval
- Inline review comments
- Commit status reporting
- Webhook signature verification

Routes to the correct provider based on SastRepository.provider field.
"""
import hashlib
import hmac
import json
import logging
from abc import ABC, abstractmethod
from typing import Any, Optional

import httpx

logger = logging.getLogger(__name__)

REQUEST_TIMEOUT = 30


class SCMProvider(ABC):
    """Abstract base class for source code management providers."""

    @abstractmethod
    async def get_pr_diff(self, owner: str, repo: str, pr_number: int) -> str:
        """Fetch unified diff for a pull request / merge request."""
        ...

    @abstractmethod
    async def get_pr_info(self, owner: str, repo: str, pr_number: int) -> dict:
        """Get PR/MR metadata."""
        ...

    @abstractmethod
    async def get_pr_files(self, owner: str, repo: str, pr_number: int) -> list[dict]:
        """Get list of changed files."""
        ...

    @abstractmethod
    async def post_pr_review(
        self, owner: str, repo: str, pr_number: int,
        findings: list[dict], action: str = "COMMENT",
    ) -> dict:
        """Post review with inline comments."""
        ...

    @abstractmethod
    async def post_commit_status(
        self, owner: str, repo: str, sha: str,
        state: str, description: str, context: str = "navigator/security-review",
        target_url: str | None = None,
    ) -> None:
        """Post commit/pipeline status."""
        ...

    @staticmethod
    @abstractmethod
    def verify_webhook_signature(payload_body: bytes, signature: str, secret: str) -> bool:
        """Verify webhook signature."""
        ...

    @staticmethod
    @abstractmethod
    def parse_webhook_payload(payload: dict, event_type: str) -> dict | None:
        """Parse webhook payload and extract PR info."""
        ...


class GitHubProvider(SCMProvider):
    """GitHub SCM provider."""

    API_BASE = "https://api.github.com"

    def __init__(self, access_token: str):
        self.access_token = access_token
        self._headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    async def get_pr_diff(self, owner: str, repo: str, pr_number: int) -> str:
        headers = {**self._headers, "Accept": "application/vnd.github.v3.diff"}
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
            resp = await client.get(
                f"{self.API_BASE}/repos/{owner}/{repo}/pulls/{pr_number}",
                headers=headers,
            )
            resp.raise_for_status()
            return resp.text

    async def get_pr_info(self, owner: str, repo: str, pr_number: int) -> dict:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
            resp = await client.get(
                f"{self.API_BASE}/repos/{owner}/{repo}/pulls/{pr_number}",
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
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
            resp = await client.get(
                f"{self.API_BASE}/repos/{owner}/{repo}/pulls/{pr_number}/files",
                headers=self._headers, params={"per_page": 100},
            )
            resp.raise_for_status()
            return [
                {"filename": f.get("filename", ""), "status": f.get("status", ""),
                 "additions": f.get("additions", 0), "deletions": f.get("deletions", 0),
                 "patch": f.get("patch", "")}
                for f in resp.json()
            ]

    async def post_pr_review(
        self, owner: str, repo: str, pr_number: int,
        findings: list[dict], action: str = "COMMENT",
    ) -> dict:
        comments = []
        for f in findings:
            severity = f.get("severity", "medium").upper()
            title = f.get("title", "Security Issue")
            desc = f.get("description", "")[:500]
            cwe = f.get("cwe_id", "")
            remediation = f.get("fix_suggestion", "")

            body_parts = [f"**{severity}**: {title}"]
            if cwe:
                body_parts.append(f"CWE: {cwe}")
            if desc:
                body_parts.extend(["", desc])
            if remediation:
                body_parts.extend(["", f"**Remediation:** {remediation[:300]}"])

            comments.append({
                "path": f.get("file_path", ""),
                "line": max(1, f.get("line_start", 1)),
                "body": "\n".join(body_parts),
            })

        severity_counts = {}
        for f in findings:
            s = f.get("severity", "medium")
            severity_counts[s] = severity_counts.get(s, 0) + 1
        summary = ", ".join(f"{v} {k}" for k, v in sorted(severity_counts.items()))
        body_text = (
            f"Navigator Security Review found **{len(findings)}** issue(s): {summary}"
            if findings else "Navigator Security Review: No security issues found."
        )

        payload: dict[str, Any] = {"body": body_text, "event": action}
        if comments:
            payload["comments"] = comments[:50]

        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
            resp = await client.post(
                f"{self.API_BASE}/repos/{owner}/{repo}/pulls/{pr_number}/reviews",
                headers=self._headers, json=payload,
            )
            resp.raise_for_status()
            return resp.json()

    async def post_commit_status(
        self, owner: str, repo: str, sha: str,
        state: str, description: str, context: str = "navigator/security-review",
        target_url: str | None = None,
    ) -> None:
        payload: dict[str, Any] = {
            "state": state, "description": description[:140], "context": context,
        }
        if target_url:
            payload["target_url"] = target_url
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
            resp = await client.post(
                f"{self.API_BASE}/repos/{owner}/{repo}/statuses/{sha}",
                headers=self._headers, json=payload,
            )
            resp.raise_for_status()

    @staticmethod
    def verify_webhook_signature(payload_body: bytes, signature: str, secret: str) -> bool:
        if not signature or not signature.startswith("sha256="):
            return False
        expected = "sha256=" + hmac.new(secret.encode(), payload_body, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, signature)

    @staticmethod
    def parse_webhook_payload(payload: dict, event_type: str) -> dict | None:
        if event_type != "pull_request":
            return None
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


class GitLabProvider(SCMProvider):
    """GitLab SCM provider — supports Merge Requests, notes, and pipeline status."""

    API_BASE = "https://gitlab.com/api/v4"

    def __init__(self, access_token: str, base_url: str | None = None):
        self.access_token = access_token
        if base_url:
            self.API_BASE = base_url.rstrip("/") + "/api/v4"
        self._headers = {
            "PRIVATE-TOKEN": access_token,
            "Content-Type": "application/json",
        }

    def _project_path(self, owner: str, repo: str) -> str:
        """URL-encode project path for GitLab API."""
        import urllib.parse
        return urllib.parse.quote(f"{owner}/{repo}", safe="")

    async def get_pr_diff(self, owner: str, repo: str, pr_number: int) -> str:
        project = self._project_path(owner, repo)
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
            resp = await client.get(
                f"{self.API_BASE}/projects/{project}/merge_requests/{pr_number}/changes",
                headers=self._headers,
            )
            resp.raise_for_status()
            data = resp.json()
            diffs = []
            for change in data.get("changes", []):
                diffs.append(change.get("diff", ""))
            return "\n".join(diffs)

    async def get_pr_info(self, owner: str, repo: str, pr_number: int) -> dict:
        project = self._project_path(owner, repo)
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
            resp = await client.get(
                f"{self.API_BASE}/projects/{project}/merge_requests/{pr_number}",
                headers=self._headers,
            )
            resp.raise_for_status()
            data = resp.json()
            return {
                "title": data.get("title", ""),
                "head_branch": data.get("source_branch", ""),
                "base_branch": data.get("target_branch", ""),
                "head_sha": data.get("sha", ""),
                "base_sha": data.get("diff_refs", {}).get("base_sha", ""),
                "changed_files": data.get("changes_count", 0),
                "additions": 0,
                "deletions": 0,
                "state": data.get("state", ""),
                "user": data.get("author", {}).get("username", ""),
            }

    async def get_pr_files(self, owner: str, repo: str, pr_number: int) -> list[dict]:
        project = self._project_path(owner, repo)
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
            resp = await client.get(
                f"{self.API_BASE}/projects/{project}/merge_requests/{pr_number}/changes",
                headers=self._headers,
            )
            resp.raise_for_status()
            return [
                {
                    "filename": c.get("new_path", ""),
                    "status": "renamed" if c.get("renamed_file") else ("added" if c.get("new_file") else "modified"),
                    "additions": 0, "deletions": 0,
                    "patch": c.get("diff", ""),
                }
                for c in resp.json().get("changes", [])
            ]

    async def post_pr_review(
        self, owner: str, repo: str, pr_number: int,
        findings: list[dict], action: str = "COMMENT",
    ) -> dict:
        project = self._project_path(owner, repo)

        # Post individual notes for each finding (GitLab uses discussions)
        results = []
        for f in findings[:50]:
            severity = f.get("severity", "medium").upper()
            title = f.get("title", "Security Issue")
            body = f"**{severity}**: {title}\n\n{f.get('description', '')[:500]}"
            if f.get("fix_suggestion"):
                body += f"\n\n**Remediation:** {f['fix_suggestion'][:300]}"

            payload = {
                "body": body,
                "position": {
                    "position_type": "text",
                    "new_path": f.get("file_path", ""),
                    "new_line": max(1, f.get("line_start", 1)),
                },
            }

            try:
                async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
                    resp = await client.post(
                        f"{self.API_BASE}/projects/{project}/merge_requests/{pr_number}/discussions",
                        headers=self._headers, json=payload,
                    )
                    if resp.status_code < 300:
                        results.append(resp.json())
            except Exception as e:
                logger.warning("GitLab inline comment failed: %s", e)

        # Post summary note
        severity_counts = {}
        for f in findings:
            s = f.get("severity", "medium")
            severity_counts[s] = severity_counts.get(s, 0) + 1
        summary = ", ".join(f"{v} {k}" for k, v in sorted(severity_counts.items()))
        summary_body = (
            f"**Navigator Security Review** found **{len(findings)}** issue(s): {summary}"
            if findings else "**Navigator Security Review**: No security issues found."
        )

        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
            resp = await client.post(
                f"{self.API_BASE}/projects/{project}/merge_requests/{pr_number}/notes",
                headers=self._headers, json={"body": summary_body},
            )

        return {"posted_comments": len(results), "summary": summary_body}

    async def post_commit_status(
        self, owner: str, repo: str, sha: str,
        state: str, description: str, context: str = "navigator/security-review",
        target_url: str | None = None,
    ) -> None:
        # GitLab uses different state names
        gitlab_state = {
            "success": "success", "failure": "failed",
            "error": "failed", "pending": "pending",
        }.get(state, "failed")

        project = self._project_path(owner, repo)
        payload: dict[str, Any] = {
            "state": gitlab_state,
            "description": description[:140],
            "name": context,
        }
        if target_url:
            payload["target_url"] = target_url

        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
            resp = await client.post(
                f"{self.API_BASE}/projects/{project}/statuses/{sha}",
                headers=self._headers, json=payload,
            )
            resp.raise_for_status()

    @staticmethod
    def verify_webhook_signature(payload_body: bytes, signature: str, secret: str) -> bool:
        """GitLab uses X-Gitlab-Token header (plain text secret comparison)."""
        if not signature:
            return False
        return hmac.compare_digest(signature, secret)

    @staticmethod
    def parse_webhook_payload(payload: dict, event_type: str) -> dict | None:
        if event_type != "merge_request":
            return None
        attrs = payload.get("object_attributes", {})
        action = attrs.get("action", "")
        if action not in ("open", "update", "reopen"):
            return None
        project = payload.get("project", {})
        path_parts = project.get("path_with_namespace", "").split("/", 1)
        return {
            "action": action,
            "pr_number": attrs.get("iid"),
            "pr_title": attrs.get("title", ""),
            "head_branch": attrs.get("source_branch", ""),
            "base_branch": attrs.get("target_branch", ""),
            "head_sha": attrs.get("last_commit", {}).get("id", ""),
            "repo_full_name": project.get("path_with_namespace", ""),
            "repo_owner": path_parts[0] if path_parts else "",
            "repo_name": path_parts[1] if len(path_parts) > 1 else "",
            "clone_url": project.get("git_http_url", ""),
            "sender": payload.get("user", {}).get("username", ""),
        }


class BitbucketProvider(SCMProvider):
    """Bitbucket Cloud SCM provider — supports PRs, inline comments, build status."""

    API_BASE = "https://api.bitbucket.org/2.0"

    def __init__(self, access_token: str):
        self.access_token = access_token
        self._headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        }

    async def get_pr_diff(self, owner: str, repo: str, pr_number: int) -> str:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
            resp = await client.get(
                f"{self.API_BASE}/repositories/{owner}/{repo}/pullrequests/{pr_number}/diff",
                headers=self._headers,
            )
            resp.raise_for_status()
            return resp.text

    async def get_pr_info(self, owner: str, repo: str, pr_number: int) -> dict:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
            resp = await client.get(
                f"{self.API_BASE}/repositories/{owner}/{repo}/pullrequests/{pr_number}",
                headers=self._headers,
            )
            resp.raise_for_status()
            data = resp.json()
            source = data.get("source", {})
            dest = data.get("destination", {})
            return {
                "title": data.get("title", ""),
                "head_branch": source.get("branch", {}).get("name", ""),
                "base_branch": dest.get("branch", {}).get("name", ""),
                "head_sha": source.get("commit", {}).get("hash", ""),
                "base_sha": dest.get("commit", {}).get("hash", ""),
                "changed_files": 0,
                "additions": 0, "deletions": 0,
                "state": data.get("state", ""),
                "user": data.get("author", {}).get("display_name", ""),
            }

    async def get_pr_files(self, owner: str, repo: str, pr_number: int) -> list[dict]:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
            resp = await client.get(
                f"{self.API_BASE}/repositories/{owner}/{repo}/pullrequests/{pr_number}/diffstat",
                headers=self._headers,
            )
            resp.raise_for_status()
            return [
                {
                    "filename": v.get("new", {}).get("path", "") or v.get("old", {}).get("path", ""),
                    "status": v.get("status", "modified"),
                    "additions": v.get("lines_added", 0),
                    "deletions": v.get("lines_removed", 0),
                    "patch": "",
                }
                for v in resp.json().get("values", [])
            ]

    async def post_pr_review(
        self, owner: str, repo: str, pr_number: int,
        findings: list[dict], action: str = "COMMENT",
    ) -> dict:
        results = []
        for f in findings[:50]:
            severity = f.get("severity", "medium").upper()
            title = f.get("title", "Security Issue")
            body = f"**{severity}**: {title}\n\n{f.get('description', '')[:500]}"

            payload = {
                "content": {"raw": body},
                "inline": {
                    "path": f.get("file_path", ""),
                    "to": max(1, f.get("line_start", 1)),
                },
            }

            try:
                async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
                    resp = await client.post(
                        f"{self.API_BASE}/repositories/{owner}/{repo}/pullrequests/{pr_number}/comments",
                        headers=self._headers, json=payload,
                    )
                    if resp.status_code < 300:
                        results.append(resp.json())
            except Exception as e:
                logger.warning("Bitbucket inline comment failed: %s", e)

        return {"posted_comments": len(results)}

    async def post_commit_status(
        self, owner: str, repo: str, sha: str,
        state: str, description: str, context: str = "navigator/security-review",
        target_url: str | None = None,
    ) -> None:
        bb_state = {
            "success": "SUCCESSFUL", "failure": "FAILED",
            "error": "FAILED", "pending": "INPROGRESS",
        }.get(state, "FAILED")

        payload: dict[str, Any] = {
            "state": bb_state,
            "key": context,
            "description": description[:140],
        }
        if target_url:
            payload["url"] = target_url

        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
            resp = await client.post(
                f"{self.API_BASE}/repositories/{owner}/{repo}/commit/{sha}/statuses/build",
                headers=self._headers, json=payload,
            )
            resp.raise_for_status()

    @staticmethod
    def verify_webhook_signature(payload_body: bytes, signature: str, secret: str) -> bool:
        """Bitbucket Cloud doesn't use signatures — it uses IP whitelisting + UUID."""
        # For Bitbucket Server, HMAC-SHA256 is used
        if not signature:
            return True  # Bitbucket Cloud doesn't sign webhooks
        expected = "sha256=" + hmac.new(secret.encode(), payload_body, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, signature)

    @staticmethod
    def parse_webhook_payload(payload: dict, event_type: str) -> dict | None:
        if event_type not in ("pullrequest:created", "pullrequest:updated"):
            return None
        pr = payload.get("pullrequest", {})
        repo = payload.get("repository", {})
        source = pr.get("source", {})
        dest = pr.get("destination", {})
        full_name = repo.get("full_name", "")
        parts = full_name.split("/", 1)
        return {
            "action": "opened" if "created" in event_type else "synchronize",
            "pr_number": pr.get("id"),
            "pr_title": pr.get("title", ""),
            "head_branch": source.get("branch", {}).get("name", ""),
            "base_branch": dest.get("branch", {}).get("name", ""),
            "head_sha": source.get("commit", {}).get("hash", ""),
            "repo_full_name": full_name,
            "repo_owner": parts[0] if parts else "",
            "repo_name": parts[1] if len(parts) > 1 else "",
            "clone_url": repo.get("links", {}).get("html", {}).get("href", ""),
            "sender": payload.get("actor", {}).get("display_name", ""),
        }


def get_scm_provider(provider_type: str, access_token: str, base_url: str | None = None) -> SCMProvider:
    """Factory function to create the appropriate SCM provider.

    Args:
        provider_type: One of 'github', 'gitlab', 'bitbucket'
        access_token: Authentication token
        base_url: Custom API base URL (for self-hosted instances)
    """
    providers = {
        "github": GitHubProvider,
        "gitlab": lambda token: GitLabProvider(token, base_url),
        "bitbucket": BitbucketProvider,
    }

    factory = providers.get(provider_type.lower())
    if not factory:
        raise ValueError(f"Unsupported SCM provider: {provider_type}. Supported: {list(providers.keys())}")

    if provider_type.lower() == "gitlab":
        return factory(access_token)
    return factory(access_token)
