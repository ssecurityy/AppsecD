"""Lightweight SCA: package.json, JS library version detection, npm audit, Retire.js."""
import json
import logging
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Callable

logger = logging.getLogger(__name__)


def _find_retire() -> list[str] | None:
    """Find retire CLI: PATH or npx. Returns [cmd, ...] for subprocess."""
    found = shutil.which("retire")
    if found:
        return [found]
    if shutil.which("npx"):
        return ["npx", "retire"]
    return None

def _version_in_range(ver: str, base: str) -> bool:
    """Check if ver is in same major.minor as base (simplified semver)."""
    try:
        va = [int(x) for x in ver.split(".")[:3]]
        vb = [int(x) for x in base.split(".")[:3]]
        return va[0] == vb[0] and (len(va) < 2 or va[1] == vb[1])
    except (ValueError, IndexError):
        return False


# Known vulnerable lib versions (common CVEs) - extend via OSS Index / Snyk in future
_KNOWN_VULNS: dict[tuple[str, str], list[str]] = {
    ("jquery", "3.4.1"): ["CVE-2019-11358", "CVE-2020-11022", "CVE-2020-11023"],
    ("jquery", "3.5.0"): ["CVE-2020-11022", "CVE-2020-11023"],
    ("lodash", "4.17.20"): ["CVE-2020-8203"],
    ("lodash", "4.17.21"): [],  # patched
}


def _run_npm_audit(project_dir: str) -> dict[str, Any]:
    """Run npm audit in project_dir. Returns {vulnerabilities: [...], summary: {...}}."""
    try:
        proc = subprocess.run(
            ["npm", "audit", "--json"],
            cwd=project_dir,
            capture_output=True,
            timeout=60,
            env={**__import__("os").environ},
        )
        if proc.returncode != 0 and proc.stdout:
            data = json.loads(proc.stdout.decode("utf-8", errors="ignore"))
            return {
                "vulnerabilities": list(data.get("vulnerabilities", {}).values()),
                "metadata": data.get("metadata", {}),
                "summary": data.get("metadata", {}).get("vulnerabilities", {}),
            }
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError) as e:
        logger.debug("npm audit failed: %s", e)
    return {"vulnerabilities": [], "summary": {}}


def scan_package_json_content(content: str) -> dict[str, Any]:
    """
    Parse package.json content and optionally run npm audit.
    Used when we fetch package.json from a crawled URL.

    Returns {dependencies: {...}, has_lockfile: bool, audit: {...} or None}.
    """
    try:
        pkg = json.loads(content)
        deps = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}
        if not deps:
            return {"dependencies": {}, "count": 0}

        # Write temp package.json and run npm audit
        with tempfile.TemporaryDirectory() as tmp:
            pkg_path = Path(tmp) / "package.json"
            pkg_path.write_text(content, encoding="utf-8")
            audit_result = _run_npm_audit(tmp)
            return {
                "dependencies": deps,
                "count": len(deps),
                "audit": audit_result if audit_result.get("vulnerabilities") else None,
            }
    except json.JSONDecodeError:
        return {"dependencies": {}, "count": 0}
    except Exception as e:
        logger.debug("package.json scan error: %s", e)
        return {"dependencies": {}, "count": 0}


def scan_js_libraries(libraries: list[dict]) -> dict[str, Any]:
    """
    Check JS libraries (from js_analysis) for known vulnerabilities.
    libraries: [{name, version}, ...]

    Returns {libraries: [...], vulnerabilities: [...], summary: {...}}
    """
    vulns: list[dict] = []
    checked: list[dict] = []

    for lib in libraries:
        name = (lib.get("name") or "").strip().lower()
        version = (lib.get("version") or "").strip()
        if not name or not version:
            continue

        cves = _KNOWN_VULNS.get((name, version), [])
        if not cves and name in ("lodash", "jquery"):
            # Fallback: check if version is in known vulnerable range
            for (k, v), cve_list in _KNOWN_VULNS.items():
                if k == name and cve_list and _version_in_range(version, v):
                    cves = cve_list
                    break

        checked.append({"name": name, "version": version})
        if cves:
            vulns.append({"name": name, "version": version, "cves": cves})

    return {
        "libraries": checked,
        "vulnerabilities": vulns,
        "summary": {"total": len(checked), "vulnerable": len(vulns)},
    }


def scan_js_with_retire(
    js_entries: list[dict], fetch_fn: Callable[[str], str]
) -> dict[str, Any]:
    """
    Run Retire.js on crawled JS files. Writes content to temp dir, runs retire --path.

    js_entries: [{url, ...}]  (url is required)
    fetch_fn: callable(url) -> content

    Returns {by_url: {url: [vulns]}, data: [...], total_vulns: int}
    """
    result: dict[str, Any] = {"by_url": {}, "data": [], "total_vulns": 0}
    cmd_base = _find_retire()
    if not cmd_base:
        logger.debug("Retire.js not found (npm install -g retire)")
        return result

    to_scan: list[tuple[str, str]] = []  # (url, content)
    for entry in js_entries:
        url = entry.get("url", "")
        if not url:
            continue
        content = fetch_fn(url) if fetch_fn else ""
        if not content or len(content) > 2 * 1024 * 1024:  # skip > 2MB
            continue
        to_scan.append((url, content))

    if not to_scan:
        return result

    try:
        with tempfile.TemporaryDirectory(prefix="retire_") as tmp:
            url_to_path: dict[str, str] = {}
            for i, (url, content) in enumerate(to_scan):
                ext = ".js"
                if ".min.js" in url:
                    ext = ".min.js"
                elif ".mjs" in url:
                    ext = ".mjs"
                fname = f"f{i}{ext}"
                path = os.path.join(tmp, fname)
                Path(path).write_text(content, encoding="utf-8", errors="replace")
                url_to_path[url] = path

            cmd = cmd_base + ["--path", tmp, "--outputformat", "json"]
            proc = subprocess.run(cmd, capture_output=True, timeout=120)
            out = proc.stdout.decode("utf-8", errors="ignore")
            err = proc.stderr.decode("utf-8", errors="ignore")

            if proc.returncode not in (0, 13) and not out.strip():
                logger.debug("Retire.js failed: %s", err[:500])
                return result

            try:
                data = json.loads(out)
            except json.JSONDecodeError:
                return result

            items = data.get("data", data) if isinstance(data, dict) else data
            if not isinstance(items, list):
                items = []

            all_vulns: list[dict] = []
            path_to_url = {os.path.basename(p): u for u, p in url_to_path.items()}
            for item in items:
                fpath = item.get("file", "")
                vulns_list = item.get("vulnerabilities", [])
                if not vulns_list:
                    continue
                fbase = os.path.basename(fpath)
                url_str = path_to_url.get(fbase)
                if url_str:
                    result["by_url"][url_str] = vulns_list
                all_vulns.extend(vulns_list)

            result["data"] = items
            result["total_vulns"] = len(all_vulns)
    except subprocess.TimeoutExpired:
        logger.debug("Retire.js timed out")
    except Exception as e:
        logger.debug("Retire.js scan failed: %s", e)

    return result
