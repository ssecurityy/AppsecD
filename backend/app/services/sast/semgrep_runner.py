"""Semgrep execution wrapper — runs semgrep scans and parses results."""
import json
import logging
import subprocess
import hashlib
from pathlib import Path

logger = logging.getLogger(__name__)

# Full path to semgrep binary (virtualenv)
SEMGREP_BIN = "/opt/navigator/backend/venv/bin/semgrep"

# Default rule packs by scan scope
RULE_PACKS = {
    "security": "p/security-audit",
    "owasp": "p/owasp-top-ten",
    "cwe": "p/cwe-top-25",
    "secrets": "p/secrets",
    "default": "p/default",
    # Language-specific
    "python": "p/python",
    "javascript": "p/javascript",
    "typescript": "p/typescript",
    "java": "p/java",
    "go": "p/go",
    "ruby": "p/ruby",
    "php": "p/php",
    "c": "p/c",
    "csharp": "p/csharp",
    "rust": "p/rust",
    "kotlin": "p/kotlin",
    "swift": "p/swift",
    # Framework-specific
    "react": "p/react",
    "nextjs": "p/nextjs",
    "django": "p/django",
    "flask": "p/flask",
    "docker": "p/docker",
    "terraform": "p/terraform",
    "kubernetes": "p/kubernetes",
    "dockerfile": "p/dockerfile",
    # Ported tools
    "bandit": "p/bandit",
    "eslint": "p/eslint",
    "gosec": "p/gosec",
    "findsecbugs": "p/findsecbugs",
    "nodejsscan": "p/nodejsscan",
    # Category-specific
    "xss": "p/xss",
    "sql-injection": "p/sql-injection",
    "command-injection": "p/command-injection",
    "insecure-transport": "p/insecure-transport",
    "jwt": "p/jwt",
}

UNSUPPORTED_RULE_PACKS = {
    "p/express",
    "p/spring",
}

# Comprehensive language-to-ruleset mapping
LANGUAGE_RULE_MAP = {
    "python": ["p/python", "p/bandit", "p/django", "p/flask"],
    "javascript": ["p/javascript", "p/eslint", "p/react", "p/nextjs", "p/nodejsscan"],
    "typescript": ["p/typescript", "p/eslint", "p/react", "p/nextjs", "p/nodejsscan"],
    "java": ["p/java", "p/findsecbugs"],
    "go": ["p/go", "p/gosec"],
    "ruby": ["p/ruby"],
    "php": ["p/php"],
    "c": ["p/c"],
    "cpp": ["p/c"],
    "csharp": ["p/csharp"],
    "rust": ["p/rust"],
    "kotlin": ["p/kotlin"],
    "swift": ["p/swift"],
    "terraform": ["p/terraform"],
    "dockerfile": ["p/dockerfile", "p/docker"],
    "yaml": ["p/kubernetes"],
}

# Semgrep severity mapping
SEVERITY_MAP = {
    "ERROR": "high",
    "WARNING": "medium",
    "INFO": "low",
    "INVENTORY": "info",
}

# Scan timeout: 5 minutes
SCAN_TIMEOUT = 300


def check_semgrep_installed() -> bool:
    """Check if semgrep is available."""
    try:
        result = subprocess.run(
            [SEMGREP_BIN, "--version"],
            capture_output=True, text=True, timeout=10,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def get_semgrep_version() -> str:
    """Get semgrep version string."""
    try:
        result = subprocess.run(
            [SEMGREP_BIN, "--version"],
            capture_output=True, text=True, timeout=10,
        )
        return result.stdout.strip()
    except Exception:
        return "unknown"


def build_rule_config(languages: list[str] | None = None,
                      rule_sets: list[str] | None = None,
                      custom_rules_path: str | None = None) -> list[str]:
    """Build semgrep --config arguments based on scan configuration.

    Returns list of config args: ["--config", "p/security-audit", "--config", "p/python", ...]
    """
    configs = []
    added = set()

    def _add_config(pack: str) -> None:
        if pack in UNSUPPORTED_RULE_PACKS:
            logger.warning("Skipping unsupported Semgrep pack: %s", pack)
            return
        if pack not in added:
            added.add(pack)
            configs.extend(["--config", pack])

    # Always include security baseline packs
    _add_config(RULE_PACKS["default"])
    _add_config(RULE_PACKS["security"])
    _add_config(RULE_PACKS["owasp"])
    _add_config(RULE_PACKS["cwe"])
    _add_config(RULE_PACKS["secrets"])

    # Add language-specific rules using comprehensive mapping
    if languages:
        for lang in languages:
            # Check comprehensive mapping first
            lang_packs = LANGUAGE_RULE_MAP.get(lang, [])
            for pack in lang_packs:
                _add_config(pack)
            # Fallback: check direct RULE_PACKS mapping
            if not lang_packs:
                pack = RULE_PACKS.get(lang)
                if pack:
                    _add_config(pack)

    # Add custom rule sets
    if rule_sets:
        for rs in rule_sets:
            if rs in RULE_PACKS:
                configs.extend(["--config", RULE_PACKS[rs]])
            elif rs.startswith("p/") or rs.startswith("r/"):
                configs.extend(["--config", rs])

    # Add custom rules file/dir
    if custom_rules_path and Path(custom_rules_path).exists():
        _add_config(custom_rules_path)

    # Fallback: if no configs were added beyond the baseline, use --config auto
    if not configs:
        configs.extend(["--config", "auto"])

    return configs


def _contains_invalid_config_error(errors: list[str]) -> bool:
    joined = " ".join(errors).lower()
    return (
        "invalid configuration file" in joined
        or "failed to download configuration" in joined
        or "http 404" in joined
    )


def run_semgrep(source_dir: str,
                languages: list[str] | None = None,
                rule_sets: list[str] | None = None,
                custom_rules_path: str | None = None,
                exclude_patterns: list[str] | None = None,
                timeout: int = SCAN_TIMEOUT,
                max_memory: int = 4096) -> dict:
    """Run semgrep scan on source directory.

    Returns dict with: {findings: [...], stats: {...}, rules_used: int, errors: [...]}
    """
    if not check_semgrep_installed():
        raise RuntimeError("semgrep is not installed. Run: pip install semgrep")

    default_excludes = [
        "node_modules", "vendor", ".git", "__pycache__", "dist", "build",
        "*.min.js", "*.min.css", "*.map", "*.lock",
    ]
    all_excludes = default_excludes + (exclude_patterns or [])
    def _run_with_configs(config_args: list[str]) -> dict:
        cmd = [
            SEMGREP_BIN, "scan",
            *config_args,
            "--json",
            "--no-git-ignore",
            f"--timeout={timeout}",
            f"--max-memory={max_memory}",
            "--metrics=off",
        ]
        for pattern in all_excludes:
            cmd.extend(["--exclude", pattern])
        cmd.append(source_dir)

        logger.info("Running semgrep: %s", " ".join(cmd[:12]) + "...")
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout + 30,
                cwd=source_dir,
            )
        except subprocess.TimeoutExpired:
            logger.error("Semgrep scan timed out after %ds", timeout + 30)
            return {"findings": [], "stats": {}, "rules_used": 0, "errors": ["Scan timed out"]}

        try:
            output = json.loads(result.stdout) if result.stdout else {}
        except json.JSONDecodeError:
            logger.error("Failed to parse semgrep output: %s", result.stdout[:500])
            return {
                "findings": [],
                "stats": {},
                "rules_used": 0,
                "errors": [f"Parse error: {result.stderr[:500]}"],
            }

        findings = []
        for r in output.get("results", []):
            finding = _parse_semgrep_result(r, source_dir)
            if finding:
                findings.append(finding)

        errors = [str(err.get("message", err))[:500] for err in output.get("errors", [])]
        stats = {
            "total_results": len(output.get("results", [])),
            "total_errors": len(output.get("errors", [])),
            "paths_scanned": output.get("paths", {}).get("scanned", []),
            "num_files_scanned": len(output.get("paths", {}).get("scanned", [])),
        }
        rules_used = len(set(r.get("check_id", "") for r in output.get("results", [])))
        return {
            "findings": findings,
            "stats": stats,
            "rules_used": rules_used,
            "errors": errors[:20],
        }

    result = _run_with_configs(build_rule_config(languages, rule_sets, custom_rules_path))
    if _contains_invalid_config_error(result.get("errors", [])):
        logger.warning("Retrying Semgrep with safe fallback rules after invalid config error")
        fallback = _run_with_configs(build_rule_config(languages, None, custom_rules_path))
        if fallback.get("rules_used", 0) or fallback.get("findings"):
            fallback["errors"] = [
                "Recovered from invalid Semgrep registry config by retrying a safe ruleset.",
                *fallback.get("errors", []),
            ][:20]
            return fallback
        result["errors"] = [
            "Semgrep registry config was invalid for this stack; scan may be incomplete.",
            *result.get("errors", []),
        ][:20]

    return {
        "findings": result.get("findings", []),
        "stats": result.get("stats", {}),
        "rules_used": result.get("rules_used", 0),
        "errors": result.get("errors", [])[:20],
    }


def _parse_semgrep_result(result: dict, source_dir: str) -> dict | None:
    """Parse a single semgrep result into our finding format."""
    try:
        check_id = result.get("check_id", "unknown")
        extra = result.get("extra", {})

        # Get file path relative to source dir
        abs_path = result.get("path", "")
        try:
            file_path = str(Path(abs_path).relative_to(source_dir))
        except ValueError:
            file_path = abs_path

        # Map severity
        semgrep_severity = extra.get("severity", "WARNING")
        severity = SEVERITY_MAP.get(semgrep_severity, "medium")

        # Get code snippet
        lines = extra.get("lines", "")

        # Build fingerprint for dedup
        fp_raw = f"{check_id}|{file_path}|{result.get('start', {}).get('line', 0)}"
        fingerprint = hashlib.sha256(fp_raw.encode()).hexdigest()[:32]

        # Extract metadata
        metadata = extra.get("metadata", {})
        cwe_list = metadata.get("cwe", [])
        cwe_id = cwe_list[0] if cwe_list else None
        if isinstance(cwe_id, str) and ":" in cwe_id:
            cwe_id = cwe_id.split(":")[0].strip()

        owasp_list = metadata.get("owasp", [])
        owasp_category = owasp_list[0] if owasp_list else None

        references = metadata.get("references", [])
        if isinstance(references, str):
            references = [references]

        return {
            "rule_id": check_id,
            "rule_source": "semgrep",
            "severity": severity,
            "confidence": metadata.get("confidence", "MEDIUM").lower(),
            "title": _rule_id_to_title(check_id),
            "description": metadata.get("description", ""),
            "message": extra.get("message", ""),
            "file_path": file_path,
            "line_start": result.get("start", {}).get("line", 0),
            "line_end": result.get("end", {}).get("line", 0),
            "column_start": result.get("start", {}).get("col", None),
            "column_end": result.get("end", {}).get("col", None),
            "code_snippet": lines,
            "fix_suggestion": extra.get("fix", None),
            "cwe_id": cwe_id,
            "owasp_category": owasp_category,
            "references": references,
            "fingerprint": fingerprint,
        }
    except Exception as e:
        logger.warning("Failed to parse semgrep result: %s", e)
        return None


def _rule_id_to_title(rule_id: str) -> str:
    """Convert a semgrep rule ID to a human-readable title.

    e.g. 'python.lang.security.audit.dangerous-system-call' → 'Dangerous System Call'
    """
    # Take last part, replace hyphens/underscores with spaces, title-case
    parts = rule_id.split(".")
    name = parts[-1] if parts else rule_id
    return name.replace("-", " ").replace("_", " ").title()
