"""JS/secret detection in crawled content - API keys, tokens, passwords, etc."""
import json
import re
import logging
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def _find_trufflehog() -> str | None:
    """Find trufflehog binary (Go or Python CLI)."""
    for p in ("/usr/local/bin/trufflehog", "/usr/bin/trufflehog"):
        if Path(p).is_file():
            return p
    return shutil.which("trufflehog")

SECRET_RULES = [
    {"id": "apikey_generic", "name": "Generic API Key", "pattern": r"(?i)(?:api[_-]?key|apikey|api_key)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{20,})['\"]?"},
    {"id": "aws_access", "name": "AWS Access Key", "pattern": r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"},
    {"id": "aws_secret", "name": "AWS Secret Key", "pattern": r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"},
    {"id": "github_token", "name": "GitHub Token", "pattern": r"gh[pousr]_[A-Za-z0-9_]{36,}"},
    {"id": "slack_token", "name": "Slack Token", "pattern": r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*"},
    {"id": "stripe_key", "name": "Stripe Key", "pattern": r"(?:sk|pk)_live_[0-9a-zA-Z]{24,}"},
    {"id": "google_oauth", "name": "Google OAuth/API", "pattern": r"(?i)(?:AIza|ya29)[0-9a-zA-Z\-_]{35}"},
    {"id": "firebase", "name": "Firebase URL/Key", "pattern": r"(?i)firebase.*(?:apiKey|authDomain)[\"']?\s*:\s*['\"]([^'\"]+)['\"]"},
    {"id": "jwt", "name": "JWT Token", "pattern": r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"},
    {"id": "private_key", "name": "Private Key (PEM)", "pattern": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"},
    {"id": "password_in_code", "name": "Hardcoded Password", "pattern": r"(?i)(?:password|passwd|pwd)\s*[:=]\s*['\"]([^'\"]{8,})['\"]"},
    {"id": "connection_string", "name": "DB Connection String", "pattern": r"(?i)(?:mongodb|mysql|postgres|redis):\/\/[^\s'\"]+"},
    {"id": "bearer_token", "name": "Bearer Token", "pattern": r"(?i)bearer\s+[a-zA-Z0-9_\-\.]{20,}"},
    {"id": "base64_secret", "name": "Base64 Secret-like", "pattern": r"(?i)(?:secret|token|key)\s*[:=]\s*['\"]?([A-Za-z0-9+/]{40,}={0,2})['\"]?"},
]


def _mask_secret(s: str, max_visible: int = 4) -> str:
    """Mask secret for safe logging/display."""
    if len(s) <= max_visible * 2:
        return "*" * len(s)
    return s[:max_visible] + "*" * (len(s) - max_visible * 2) + s[-max_visible:]


def _scan_with_trufflehog(content: str, source_url: str = "") -> list[dict[str, Any]]:
    """Run trufflehog CLI on temp file for broader secret coverage. Returns findings list."""
    findings: list[dict[str, Any]] = []
    bin_path = _find_trufflehog()
    if not bin_path or not content:
        return findings

    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".js", delete=False, encoding="utf-8"
        ) as f:
            f.write(content)
            tmp_path = f.name
        try:
            proc = subprocess.run(
                [bin_path, "filesystem", tmp_path, "--json"],
                capture_output=True,
                timeout=15,
            )
            out = proc.stdout.decode("utf-8", errors="ignore")
            for line in out.strip().splitlines():
                if not line.strip():
                    continue
                try:
                    r = json.loads(line)
                    reason = r.get("DetectorName", r.get("DetectorType", "trufflehog"))
                    raw = r.get("Raw", r.get("RawV2", ""))[:80]
                    findings.append({
                        "rule_id": reason,
                        "rule_name": reason,
                        "match_preview": _mask_secret(raw),
                        "line_no": 0,
                        "severity": "medium",
                        "source_url": source_url,
                        "source": "trufflehog",
                    })
                except json.JSONDecodeError:
                    pass
        finally:
            Path(tmp_path).unlink(missing_ok=True)
    except subprocess.TimeoutExpired:
        logger.debug("TruffleHog scan timed out")
    except Exception as e:
        logger.debug("TruffleHog scan failed: %s", e)
    return findings


def scan_content(content: str, source_url: str = "", use_trufflehog: bool = True) -> list[dict[str, Any]]:
    """
    Scan text content for potential secrets.
    Uses regex rules plus trufflehog3 when installed for better coverage.

    Args:
        content: Raw text (JS, HTML, config, etc.)
        source_url: Optional URL where content was fetched from.
        use_trufflehog: If True and trufflehog3 available, run trufflehog scan.

    Returns:
        List of findings: [{rule_id, rule_name, match_preview, line_no, severity}]
    """
    findings: list[dict[str, Any]] = []
    if not content or not isinstance(content, str):
        return findings

    # Regex-based scan
    lines = content.split("\n")
    seen_hashes: set[str] = set()
    for i, line in enumerate(lines, 1):
        for rule in SECRET_RULES:
            try:
                m = re.search(rule["pattern"], line)
                if m:
                    match_full = m.group(0)
                    h = hash(match_full[:50])
                    if h in seen_hashes:
                        continue
                    seen_hashes.add(h)
                    if len(match_full) > 120:
                        preview = match_full[:60] + "..." + match_full[-20:]
                    else:
                        preview = match_full
                    findings.append({
                        "rule_id": rule["id"],
                        "rule_name": rule["name"],
                        "match_preview": _mask_secret(preview),
                        "line_no": i,
                        "severity": "high" if rule["id"] in ("aws_secret", "private_key", "github_token") else "medium",
                        "source_url": source_url,
                        "source": "regex",
                    })
            except re.error:
                continue
            except Exception as e:
                logger.debug("Secret rule %s error: %s", rule["id"], e)

    # TruffleHog CLI when available (merges, dedupes by preview)
    if use_trufflehog and _find_trufflehog():
        th_findings = _scan_with_trufflehog(content, source_url)
        existing_previews = {f.get("match_preview", "") for f in findings}
        for f in th_findings:
            if f.get("match_preview") and f["match_preview"] not in existing_previews:
                findings.append(f)
                existing_previews.add(f["match_preview"])

    return findings


def scan_js_files(js_entries: list[dict], fetch_fn) -> list[dict]:
    """
    Fetch JS file content and scan for secrets.

    Args:
        js_entries: List of {url, status_code, source}.
        fetch_fn: Callable(url) -> str (content) or None.

    Returns:
        js_entries with added "secrets" key per entry.
    """
    result = []
    for entry in js_entries:
        url = entry.get("url", "")
        if not url:
            result.append(entry)
            continue
        try:
            content = fetch_fn(url) if fetch_fn else ""
            secrets = scan_content(content, url) if content else []
            result.append({**entry, "secrets": secrets, "secrets_count": len(secrets)})
        except Exception as e:
            logger.debug("JS fetch/scan error for %s: %s", url, e)
            result.append({**entry, "secrets": [], "secrets_count": 0})
    return result
