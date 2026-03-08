"""GitHub API integration for SAST repository management."""
import base64
import logging
import time
from cryptography.fernet import Fernet

import httpx
from jose import jwt

from app.core.config import get_settings
from app.core.security import get_fernet_key

logger = logging.getLogger(__name__)

GITHUB_API = "https://api.github.com"
REQUEST_TIMEOUT = 30

# Derive encryption key from environment or app secret
_ENCRYPTION_KEY = None


def _cfg(config: dict | None = None) -> dict:
    return config or get_settings().model_dump()


def _get_fernet() -> Fernet:
    """Get Fernet encryption instance for token storage."""
    global _ENCRYPTION_KEY
    if _ENCRYPTION_KEY is None:
        _ENCRYPTION_KEY = get_fernet_key()
    return Fernet(_ENCRYPTION_KEY)


def encrypt_token(token: str) -> str:
    """Encrypt an access token for database storage."""
    return _get_fernet().encrypt(token.encode()).decode()


def decrypt_token(encrypted: str) -> str:
    """Decrypt an access token from database storage."""
    return _get_fernet().decrypt(encrypted.encode()).decode()


async def list_repos(access_token: str, page: int = 1, per_page: int = 30) -> list[dict]:
    """List user's GitHub repositories.

    Returns list of: {name, full_name, url, default_branch, private, language, updated_at}
    """
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
        response = await client.get(
            f"{GITHUB_API}/user/repos",
            headers=headers,
            params={
                "sort": "updated",
                "direction": "desc",
                "per_page": per_page,
                "page": page,
                "type": "all",
            },
        )
        response.raise_for_status()

    repos = []
    for r in response.json():
        repos.append({
            "name": r["name"],
            "full_name": r["full_name"],
            "url": r["html_url"],
            "clone_url": r["clone_url"],
            "default_branch": r.get("default_branch", "main"),
            "private": r.get("private", False),
            "language": r.get("language"),
            "updated_at": r.get("updated_at"),
            "description": r.get("description", ""),
            "size_kb": r.get("size", 0),
        })
    return repos


async def get_branches(access_token: str, owner: str, repo: str) -> list[str]:
    """Get branches for a repository."""
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/vnd.github+json",
    }

    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
        response = await client.get(
            f"{GITHUB_API}/repos/{owner}/{repo}/branches",
            headers=headers,
            params={"per_page": 50},
        )
        response.raise_for_status()

    return [b["name"] for b in response.json()]


async def verify_token(access_token: str) -> dict:
    """Verify a GitHub access token and return user info.

    Returns: {login, name, email, avatar_url} or raises on invalid token.
    """
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/vnd.github+json",
    }

    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
        response = await client.get(f"{GITHUB_API}/user", headers=headers)
        response.raise_for_status()

    user = response.json()
    return {
        "login": user["login"],
        "name": user.get("name", ""),
        "email": user.get("email", ""),
        "avatar_url": user.get("avatar_url", ""),
    }


async def get_repo_info(access_token: str, owner: str, repo: str) -> dict:
    """Get detailed repository information."""
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/vnd.github+json",
    }

    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
        response = await client.get(
            f"{GITHUB_API}/repos/{owner}/{repo}",
            headers=headers,
        )
        response.raise_for_status()

    r = response.json()
    return {
        "name": r["name"],
        "full_name": r["full_name"],
        "url": r["html_url"],
        "clone_url": r["clone_url"],
        "default_branch": r.get("default_branch", "main"),
        "private": r.get("private", False),
        "language": r.get("language"),
        "size_kb": r.get("size", 0),
        "description": r.get("description", ""),
    }


async def get_file_content(access_token: str, owner: str, repo: str, path: str, ref: str | None = None) -> dict:
    """Fetch repository file content from GitHub contents API."""
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    params = {"ref": ref} if ref else None
    normalized_path = path.lstrip("/")

    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
        response = await client.get(
            f"{GITHUB_API}/repos/{owner}/{repo}/contents/{normalized_path}",
            headers=headers,
            params=params,
        )
        response.raise_for_status()

    payload = response.json()
    if isinstance(payload, list):
        raise ValueError("Requested path is a directory, not a file")

    encoded = payload.get("content", "")
    encoding = payload.get("encoding", "base64")
    content = encoded
    if encoding == "base64":
        content = base64.b64decode(encoded.encode()).decode("utf-8", errors="replace")
    return {
        "path": payload.get("path", normalized_path),
        "sha": payload.get("sha"),
        "size": payload.get("size", 0),
        "content": content,
        "html_url": payload.get("html_url"),
        "download_url": payload.get("download_url"),
        "encoding": encoding,
    }


def github_app_is_configured(config: dict | None = None) -> bool:
    """Return True when enough GitHub App settings exist for server-side repo access."""
    s = _cfg(config)
    return bool(s.get("github_app_id") and s.get("github_app_private_key") and s.get("github_app_slug"))


def get_github_app_install_url(state: str, config: dict | None = None) -> str:
    """Build the GitHub App installation URL."""
    s = _cfg(config)
    return f"https://github.com/apps/{s.get('github_app_slug')}/installations/new?state={state}"


def _normalize_private_key(raw_key: str) -> str:
    return raw_key.replace("\\n", "\n").strip()


def build_github_app_jwt(config: dict | None = None) -> str:
    """Create a short-lived JWT for GitHub App authentication."""
    s = _cfg(config)
    if not github_app_is_configured(s):
        raise RuntimeError("GitHub App is not configured")

    now = int(time.time())
    payload = {
        "iat": now - 60,
        "exp": now + 540,
        "iss": s.get("github_app_id"),
    }
    return jwt.encode(payload, _normalize_private_key(s.get("github_app_private_key", "")), algorithm="RS256")


async def get_installation_access_token(installation_id: int, config: dict | None = None) -> str:
    """Exchange a GitHub App installation for a short-lived installation token."""
    app_jwt = build_github_app_jwt(config)
    headers = {
        "Authorization": f"Bearer {app_jwt}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
        response = await client.post(
            f"{GITHUB_API}/app/installations/{installation_id}/access_tokens",
            headers=headers,
        )
        response.raise_for_status()
    data = response.json()
    return data["token"]


async def get_installation_info(installation_id: int, config: dict | None = None) -> dict:
    """Fetch installation metadata for UI and repo connection flows."""
    app_jwt = build_github_app_jwt(config)
    headers = {
        "Authorization": f"Bearer {app_jwt}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
        response = await client.get(
            f"{GITHUB_API}/app/installations/{installation_id}",
            headers=headers,
        )
        response.raise_for_status()
    data = response.json()
    account = data.get("account") or {}
    return {
        "installation_id": data["id"],
        "account_login": account.get("login"),
        "account_type": account.get("type"),
        "target_type": data.get("target_type"),
    }


async def list_installation_repos(installation_id: int, page: int = 1, per_page: int = 100, config: dict | None = None) -> list[dict]:
    """List repos visible to a GitHub App installation."""
    token = await get_installation_access_token(installation_id, config)
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
        response = await client.get(
            f"{GITHUB_API}/installation/repositories",
            headers=headers,
            params={"per_page": per_page, "page": page},
        )
        response.raise_for_status()
    payload = response.json()
    repos = []
    for r in payload.get("repositories", []):
        repos.append({
            "id": r["id"],
            "name": r["name"],
            "full_name": r["full_name"],
            "url": r["html_url"],
            "html_url": r["html_url"],
            "clone_url": r["clone_url"],
            "default_branch": r.get("default_branch", "main"),
            "private": r.get("private", False),
            "language": r.get("language"),
            "updated_at": r.get("updated_at"),
            "description": r.get("description", ""),
            "size_kb": r.get("size", 0),
            "owner": r.get("owner", {}).get("login"),
        })
    return repos


async def create_pull_request(
    access_token: str,
    owner: str,
    repo: str,
    title: str,
    head: str,
    base: str,
    body: str,
) -> dict:
    """Create a GitHub pull request."""
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    payload = {
        "title": title,
        "head": head,
        "base": base,
        "body": body,
    }
    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
        response = await client.post(
            f"{GITHUB_API}/repos/{owner}/{repo}/pulls",
            headers=headers,
            json=payload,
        )
        response.raise_for_status()
    pr = response.json()
    return {
        "number": pr["number"],
        "url": pr["html_url"],
        "state": pr["state"],
    }
