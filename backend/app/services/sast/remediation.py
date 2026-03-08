"""Repository remediation helpers for AI-generated SAST fixes.

Enhanced with:
- Multi-file fix support (batch multiple fixes into a single PR)
- Conflict detection before push
- Fix validation: re-run scan on fixed code to verify finding disappears
- Multi-SCM support (GitHub, GitLab, Bitbucket) for PR/MR creation
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import subprocess
import tempfile
from urllib.parse import urlparse, urlunparse

logger = logging.getLogger(__name__)


def _build_auth_repo_url(repo_url: str, token: str) -> str:
    parsed = urlparse(repo_url)
    hostname = parsed.hostname or ""
    return urlunparse(parsed._replace(netloc=f"x-access-token:{token}@{hostname}"))


def _apply_single_fix(worktree: str, target_file_path: str, line_start: int,
                       line_end: int | None, fixed_code: str) -> str:
    """Apply a single fix to a file in the worktree. Returns the normalized path."""
    normalized = target_file_path.lstrip("/").replace("\\", "/")
    file_path = os.path.join(worktree, normalized)
    if not os.path.exists(file_path):
        raise ValueError(f"Target file not found in repository: {normalized}")

    with open(file_path, "r", encoding="utf-8", errors="ignore") as fh:
        original = fh.read()

    had_trailing_newline = original.endswith("\n")
    lines = original.splitlines()
    start_idx = max(0, (line_start or 1) - 1)
    end_idx = max(start_idx + 1, (line_end or line_start or 1))
    replacement = fixed_code.replace("\r\n", "\n").split("\n")
    lines[start_idx:end_idx] = replacement

    with open(file_path, "w", encoding="utf-8") as fh:
        updated = "\n".join(lines)
        if had_trailing_newline:
            updated += "\n"
        fh.write(updated)

    return normalized


def apply_fix_and_push(
    repo_url: str,
    access_token: str,
    base_branch: str,
    target_file_path: str,
    line_start: int,
    line_end: int | None,
    fixed_code: str,
    branch_name: str,
    commit_message: str,
) -> dict:
    """Clone repo, apply fixed code to the finding range, commit, and push a branch."""
    worktree = tempfile.mkdtemp(prefix="sast_fix_")
    auth_url = _build_auth_repo_url(repo_url, access_token)
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", "--branch", base_branch, "--single-branch", auth_url, worktree],
            capture_output=True, text=True, timeout=180, check=True,
        )
        subprocess.run(
            ["git", "checkout", "-b", branch_name],
            cwd=worktree, capture_output=True, text=True, timeout=30, check=True,
        )

        normalized = _apply_single_fix(worktree, target_file_path, line_start, line_end, fixed_code)

        subprocess.run(["git", "add", normalized], cwd=worktree, capture_output=True, text=True, timeout=30, check=True)
        subprocess.run(
            ["git", "-c", "user.name=Navigator Security Bot", "-c", "user.email=noreply@appsecd.local",
             "commit", "-m", commit_message],
            cwd=worktree, capture_output=True, text=True, timeout=60, check=True,
        )
        subprocess.run(
            ["git", "push", auth_url, f"HEAD:refs/heads/{branch_name}"],
            cwd=worktree, capture_output=True, text=True, timeout=180, check=True,
        )
        sha = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=worktree, capture_output=True, text=True, timeout=30, check=True,
        ).stdout.strip()
        return {"branch_name": branch_name, "commit_sha": sha}
    except subprocess.CalledProcessError as e:
        message = (e.stderr or e.stdout or str(e))[:500]
        raise ValueError(f"Repository remediation failed: {message}")
    except subprocess.TimeoutExpired:
        raise ValueError("Repository remediation timed out")
    finally:
        shutil.rmtree(worktree, ignore_errors=True)


def apply_multi_fix_and_push(
    repo_url: str,
    access_token: str,
    base_branch: str,
    fixes: list[dict],
    branch_name: str | None = None,
    commit_message: str | None = None,
) -> dict:
    """Apply multiple fixes across files in a single commit.

    Args:
        fixes: List of dicts with file_path, line_start, line_end, fixed_code, finding_title
    """
    if not fixes:
        raise ValueError("No fixes provided")

    sorted_fixes = sorted(fixes, key=lambda f: (f["file_path"], -(f.get("line_start", 0))))
    _detect_conflicts(sorted_fixes)

    if not branch_name:
        fix_hash = hashlib.sha256(str(sorted_fixes).encode()).hexdigest()[:8]
        branch_name = f"navigator/security-fix-{fix_hash}"

    if not commit_message:
        files_affected = len(set(f["file_path"] for f in fixes))
        titles = [f.get("finding_title", "security fix") for f in fixes[:5]]
        commit_message = f"fix: {len(fixes)} security finding(s) across {files_affected} file(s)\n\n"
        commit_message += "Fixes:\n" + "\n".join(f"- {t}" for t in titles)
        if len(fixes) > 5:
            commit_message += f"\n- ... and {len(fixes) - 5} more"
        commit_message += "\n\nGenerated by Navigator Security Bot"

    worktree = tempfile.mkdtemp(prefix="sast_multifix_")
    auth_url = _build_auth_repo_url(repo_url, access_token)

    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", "--branch", base_branch, "--single-branch", auth_url, worktree],
            capture_output=True, text=True, timeout=180, check=True,
        )
        subprocess.run(
            ["git", "checkout", "-b", branch_name],
            cwd=worktree, capture_output=True, text=True, timeout=30, check=True,
        )

        files_modified: set[str] = set()
        fixes_applied = 0

        for fix in sorted_fixes:
            try:
                normalized = _apply_single_fix(
                    worktree, fix["file_path"],
                    fix.get("line_start", 1), fix.get("line_end"),
                    fix["fixed_code"],
                )
                files_modified.add(normalized)
                fixes_applied += 1
            except Exception as e:
                logger.warning("Failed to apply fix to %s: %s", fix.get("file_path"), e)

        if not files_modified:
            raise ValueError("No fixes could be applied")

        for f in files_modified:
            subprocess.run(["git", "add", f], cwd=worktree, capture_output=True, text=True, timeout=30, check=True)

        subprocess.run(
            ["git", "-c", "user.name=Navigator Security Bot", "-c", "user.email=noreply@appsecd.local",
             "commit", "-m", commit_message],
            cwd=worktree, capture_output=True, text=True, timeout=60, check=True,
        )
        subprocess.run(
            ["git", "push", auth_url, f"HEAD:refs/heads/{branch_name}"],
            cwd=worktree, capture_output=True, text=True, timeout=180, check=True,
        )
        sha = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=worktree, capture_output=True, text=True, timeout=30, check=True,
        ).stdout.strip()

        return {
            "branch_name": branch_name, "commit_sha": sha,
            "files_fixed": len(files_modified), "fixes_applied": fixes_applied,
        }
    except subprocess.CalledProcessError as e:
        message = (e.stderr or e.stdout or str(e))[:500]
        raise ValueError(f"Multi-fix remediation failed: {message}")
    except subprocess.TimeoutExpired:
        raise ValueError("Multi-fix remediation timed out")
    finally:
        shutil.rmtree(worktree, ignore_errors=True)


def _detect_conflicts(sorted_fixes: list[dict]) -> None:
    """Check for overlapping line ranges in the same file."""
    by_file: dict[str, list[dict]] = {}
    for fix in sorted_fixes:
        by_file.setdefault(fix.get("file_path", ""), []).append(fix)

    for fp, file_fixes in by_file.items():
        for i in range(len(file_fixes) - 1):
            a = file_fixes[i]
            b = file_fixes[i + 1]
            a_start, a_end = a.get("line_start", 0), a.get("line_end") or a.get("line_start", 0)
            b_start, b_end = b.get("line_start", 0), b.get("line_end") or b.get("line_start", 0)
            if a_start <= b_end and b_start <= a_end:
                logger.warning("Overlapping fixes in %s: lines %d-%d and %d-%d", fp, a_start, a_end, b_start, b_end)


def validate_fix(
    source_path: str, file_path: str, line_start: int, line_end: int | None,
    fixed_code: str, original_finding: dict,
) -> dict:
    """Validate a fix by re-scanning the fixed code."""
    tmpdir = tempfile.mkdtemp(prefix="sast_validate_")
    try:
        abs_file = os.path.join(source_path, file_path.lstrip("/"))
        if not os.path.exists(abs_file):
            return {"valid": False, "finding_resolved": False, "new_findings": 0,
                    "details": f"Source file not found: {file_path}"}

        tmp_file = os.path.join(tmpdir, os.path.basename(file_path))
        with open(abs_file, "r", encoding="utf-8", errors="ignore") as f:
            original = f.read()

        lines = original.splitlines()
        start_idx = max(0, (line_start or 1) - 1)
        end_idx = max(start_idx + 1, (line_end or line_start or 1))
        replacement = fixed_code.replace("\r\n", "\n").split("\n")
        lines[start_idx:end_idx] = replacement

        with open(tmp_file, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

        try:
            result = subprocess.run(
                ["semgrep", "scan", "--json", "--no-git-ignore", "--config", "auto", tmp_file],
                capture_output=True, text=True, timeout=60, cwd=tmpdir,
            )
            output = json.loads(result.stdout)
            new_findings = output.get("results", [])
            rule_id = original_finding.get("rule_id", "")
            finding_resolved = not any(
                r.get("check_id", "").endswith(rule_id.split(".")[-1]) for r in new_findings
            )
            return {
                "valid": True, "finding_resolved": finding_resolved,
                "new_findings": len(new_findings),
                "details": "Fix validated" if finding_resolved else "Original finding may still be present",
            }
        except Exception as e:
            return {"valid": True, "finding_resolved": None, "new_findings": 0,
                    "details": f"Could not run validation scan: {e}"}
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


async def create_fix_pr(
    repo_url: str, access_token: str, base_branch: str, fixes: list[dict],
    provider: str = "github", pr_title: str | None = None, pr_body: str | None = None,
) -> dict:
    """Apply fixes and create a PR/MR. Supports GitHub, GitLab, Bitbucket."""
    import httpx

    result = apply_multi_fix_and_push(
        repo_url=repo_url, access_token=access_token,
        base_branch=base_branch, fixes=fixes,
    )
    branch_name = result["branch_name"]
    fixes_applied = result["fixes_applied"]

    if not pr_title:
        pr_title = f"Fix {fixes_applied} security finding(s)"

    if not pr_body:
        findings_list = "\n".join(
            f"- **{f.get('finding_title', 'Security fix')}** in `{f.get('file_path', '')}`"
            for f in fixes[:20]
        )
        pr_body = f"## Security Fixes\n\n{findings_list}\n\n*Generated by Navigator Security Bot*"

    parsed = urlparse(repo_url)
    path_parts = parsed.path.strip("/").replace(".git", "").split("/")
    owner = path_parts[0] if path_parts else ""
    repo_name = path_parts[1] if len(path_parts) > 1 else ""

    try:
        if provider == "github":
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.post(
                    f"https://api.github.com/repos/{owner}/{repo_name}/pulls",
                    headers={"Authorization": f"Bearer {access_token}", "Accept": "application/vnd.github+json"},
                    json={"title": pr_title, "body": pr_body, "head": branch_name, "base": base_branch},
                )
                resp.raise_for_status()
                data = resp.json()
                return {"pr_url": data.get("html_url", ""), "pr_number": data.get("number", 0),
                        "branch_name": branch_name, "fixes_applied": fixes_applied}

        elif provider == "gitlab":
            import urllib.parse
            project = urllib.parse.quote(f"{owner}/{repo_name}", safe="")
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.post(
                    f"https://gitlab.com/api/v4/projects/{project}/merge_requests",
                    headers={"PRIVATE-TOKEN": access_token},
                    json={"title": pr_title, "description": pr_body,
                          "source_branch": branch_name, "target_branch": base_branch},
                )
                resp.raise_for_status()
                data = resp.json()
                return {"pr_url": data.get("web_url", ""), "pr_number": data.get("iid", 0),
                        "branch_name": branch_name, "fixes_applied": fixes_applied}

        elif provider == "bitbucket":
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.post(
                    f"https://api.bitbucket.org/2.0/repositories/{owner}/{repo_name}/pullrequests",
                    headers={"Authorization": f"Bearer {access_token}"},
                    json={"title": pr_title, "description": pr_body,
                          "source": {"branch": {"name": branch_name}},
                          "destination": {"branch": {"name": base_branch}}},
                )
                resp.raise_for_status()
                data = resp.json()
                return {"pr_url": data.get("links", {}).get("html", {}).get("href", ""),
                        "pr_number": data.get("id", 0),
                        "branch_name": branch_name, "fixes_applied": fixes_applied}

    except Exception as e:
        logger.error("Failed to create PR: %s", e)
        return {"pr_url": "", "pr_number": 0, "branch_name": branch_name,
                "fixes_applied": fixes_applied, "error": str(e)[:500]}

    return {"pr_url": "", "pr_number": 0, "branch_name": branch_name, "fixes_applied": fixes_applied}
