"""DAST discovery: directory/path discovery, ffuf, httpx fallback."""
import json
import logging
import os
import random
import subprocess
import tempfile
import time
from urllib.parse import urlparse, urljoin

import httpx

from .base import DastResult, HEADERS, USER_AGENTS, TIMEOUT, get_scan_ctx, safe_get
from .wordlists import (
    WORDLIST_PATHS,
    load_discovery_wordlist,
    get_available_full_wordlists,
    get_wordlist_path,
)

logger = logging.getLogger(__name__)


def _run_ffuf_discovery(target_url: str, wordlist_path: str, max_paths: int) -> list[dict]:
    """Run ffuf for directory discovery. Returns list of {path, status}."""
    try:
        parsed = urlparse(target_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        u = f"{base.rstrip('/')}/FUZZ"
        fd, outpath = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        try:
            proc = subprocess.run(
                [
                    "ffuf", "-u", u, "-w", wordlist_path,
                    "-mc", "200,201,301,302,401,403", "-fc", "404",
                    "-t", "20", "-o", outpath, "-of", "json",
                ],
                capture_output=True, timeout=90, env={**os.environ},
            )
            if proc.returncode != 0:
                return []
            with open(outpath, "rb") as f:
                data = json.loads(f.read().decode("utf-8", errors="ignore"))
        finally:
            try:
                os.unlink(outpath)
            except OSError:
                pass
        results = data.get("results", [])[:max_paths]
        return [
            {"path": "/" + str(r.get("input", {}).get("FUZZ", "")), "status": r.get("status", 0)}
            for r in results
        ]
    except (FileNotFoundError, subprocess.TimeoutExpired, json.JSONDecodeError, KeyError, OSError) as e:
        logger.debug("ffuf discovery skipped: %s", e)
        return []


def run_ffuf_full_scan(
    target_url: str, base_path: str = "/", wordlist_key: str = "small", max_results: int = 200
) -> dict:
    """Run ffuf wordlist scan on base path. Returns {success, discovered, wordlist_used, error}."""
    parsed = urlparse(target_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    path = (base_path or "/").rstrip("/")
    base_url = f"{base}{path}/"
    fuzz_url = f"{base_url.rstrip('/')}/FUZZ"

    resolved = get_wordlist_path(wordlist_key)
    if not resolved:
        return {"success": False, "discovered": [], "wordlist_used": "", "error": "No wordlist available"}
    wordlist_key, wordlist_path = resolved
    wordlist_path = str(wordlist_path)

    outpath = None
    try:
        fd, outpath = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        proc = subprocess.run(
            [
                "ffuf", "-u", fuzz_url, "-w", wordlist_path,
                "-mc", "200,201,204,301,302,307,401,403,405", "-fc", "404",
                "-t", "25", "-o", outpath, "-of", "json",
            ],
            capture_output=True, timeout=180, env={**os.environ},
        )
        if proc.returncode != 0:
            stderr = (proc.stderr or b"").decode("utf-8", errors="ignore")[:500]
            return {"success": False, "discovered": [], "wordlist_used": wordlist_key, "error": f"ffuf exit {proc.returncode}: {stderr}"}
        with open(outpath, "rb") as f:
            data = json.loads(f.read().decode("utf-8", errors="ignore"))
        results = data.get("results", [])[:max_results]
        discovered = [
            {"path": f"{path}/{r.get('input', {}).get('FUZZ', '')}".replace("//", "/"), "status": r.get("status", 0)}
            for r in results
        ]
        return {"success": True, "discovered": discovered, "wordlist_used": wordlist_key, "error": ""}
    except subprocess.TimeoutExpired:
        return {"success": False, "discovered": [], "wordlist_used": wordlist_key, "error": "ffuf timeout (180s)"}
    except FileNotFoundError:
        return {"success": False, "discovered": [], "wordlist_used": "", "error": "ffuf not installed"}
    except Exception as e:
        return {"success": False, "discovered": [], "wordlist_used": "", "error": str(e)}
    finally:
        if outpath and os.path.exists(outpath):
            try:
                os.unlink(outpath)
            except OSError:
                pass


def run_ffuf_exhaustive_scan(
    target_url: str, base_path: str = "/", max_per_wordlist: int = 300
) -> dict:
    """Run all available wordlists and merge. Uses IntruderPayloads + SecLists."""
    by_path: dict[str, int] = {}
    wordlists_used: list[str] = []
    errors: list[str] = []
    available = get_available_full_wordlists()
    if not available:
        return {
            "success": True,
            "discovered": [],
            "wordlists_used": [],
            "total_wordlists": 0,
            "errors": ["No wordlist files found. Add IntruderPayloads or SecLists under data/"],
        }
    for key, wp in available:
        r = run_ffuf_full_scan(target_url, base_path, key, max_per_wordlist)
        if r.get("success"):
            wordlists_used.append(r.get("wordlist_used", key))
            for d in r.get("discovered", []):
                p = (d.get("path") or "").replace("//", "/")
                if p and p not in by_path:
                    by_path[p] = d.get("status", 0)
        else:
            err = r.get("error", "")
            if err:
                errors.append(f"{key}: {err[:80]}")
    discovered = [{"path": k, "status": v} for k, v in sorted(by_path.items())]
    return {
        "success": True,
        "discovered": discovered,
        "wordlists_used": wordlists_used,
        "total_wordlists": len(wordlists_used),
        "errors": errors[:5],
    }


def check_directory_discovery(target_url: str) -> DastResult:
    """Discover hidden paths via ffuf or httpx fallback."""
    result = DastResult(
        check_id="DAST-DIR-02",
        title="Directory & Path Discovery",
        owasp_ref="A05:2021",
        cwe_id="CWE-548",
    )
    base_resp = safe_get(target_url)
    if not base_resp:
        result.status = "error"
        result.description = "Could not reach target"
        return result

    base = urlparse(target_url)
    root = f"{base.scheme}://{base.netloc}"
    discovered = []
    wordlist = load_discovery_wordlist(400)
    wordlist_source = "IntruderPayloads/SecLists (merged)"

    for wp in WORDLIST_PATHS:
        if wp.exists():
            ffuf_results = _run_ffuf_discovery(target_url, str(wp), 80)
            if ffuf_results:
                discovered.extend(ffuf_results)
                wordlist_source = f"ffuf+{wp.name}"
                break

    if discovered:
        by_path: dict[str, dict] = {}
        for d in discovered:
            p = d.get("path", "")
            if p and p not in by_path:
                by_path[p] = d
        discovered = list(by_path.values())

    if not discovered:
        discard_codes = {404, 410}
        for i, path in enumerate(wordlist):
            path = path.strip().lstrip("/")
            if not path:
                continue
            if i > 0:
                time.sleep(random.uniform(0.15, 0.4))
            test_url = urljoin(root + "/", path)
            try:
                with httpx.Client(
                    timeout=httpx.Timeout(5.0, connect=3.0),
                    headers={**HEADERS, "User-Agent": USER_AGENTS[i % len(USER_AGENTS)]},
                    verify=False,
                    follow_redirects=True,
                ) as client:
                    r = client.get(test_url)
            except Exception:
                continue
            if r.status_code not in discard_codes:
                discovered.append({"path": f"/{path}", "status": r.status_code})
            if len(discovered) >= 50:
                break

    result.details = {"paths_checked": len(wordlist), "discovered": discovered, "wordlist_source": wordlist_source, "payload_tested": f"ffuf/httpx dir fuzz with {len(wordlist)} paths from {wordlist_source}"}
    if base_resp:
        result.request_raw = f"GET {target_url} HTTP/1.1\nHost: {base.netloc}"
        result.response_raw = f"HTTP/1.1 {base_resp.status_code}\n" + "\n".join(f"{k}: {v}" for k, v in base_resp.headers.items()) + "\n\n" + (base_resp.text[:1500] if base_resp.text else "")
    if discovered:
        result.status = "failed"
        result.severity = "low"
        result.description = f"Discovered {len(discovered)} path(s) on target"
        result.evidence = ", ".join(f"{d['path']} ({d['status']})" for d in discovered[:10])
        result.remediation = "Restrict access to sensitive paths. Disable directory listing."
        result.reproduction_steps = f"1. Fuzz base URL with wordlist\n2. Paths found: {', '.join(d['path'] for d in discovered[:8])}"
    else:
        result.status = "passed"
        result.description = f"No additional paths discovered ({len(wordlist)} paths checked)"
    return result
