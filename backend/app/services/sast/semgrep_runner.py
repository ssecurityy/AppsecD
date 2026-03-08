"""Semgrep execution wrapper — runs semgrep scans and parses results.

Rule sources (Semgrep Registry — https://semgrep.dev/explore):
- OWASP: p/owasp-top-ten (OWASP Top 10); OWASP ASVS: see docs/sast-semgrep-rules.md
- SANS / MITRE CWE: p/cwe-top-25 (CWE Top 25 = SANS Top 25 style); MITRE CWE coverage in rule metadata
- Ported tools: Bandit, ESLint, FindSecBugs, Gosec, Brakeman, Flawfinder, Gitleaks, etc.
- Pro rules (paid): Semgrep AppSec Platform; use --config=auto with Semgrep Cloud for Pro rules
"""
import json
import logging
import subprocess
import hashlib
from pathlib import Path

logger = logging.getLogger(__name__)

# Full path to semgrep binary (virtualenv)
SEMGREP_BIN = "/opt/navigator/backend/venv/bin/semgrep"

# -----------------------------------------------------------------------------
# Rule packs: OWASP, SANS/MITRE CWE, ported tools, languages, frameworks
# Registry: https://semgrep.dev/explore | Repo: https://github.com/semgrep/semgrep-rules
# -----------------------------------------------------------------------------
RULE_PACKS = {
    # --- Standards (always included in baseline) ---
    "default": "p/default",
    "security": "p/security-audit",
    "owasp": "p/owasp-top-ten",
    "cwe": "p/cwe-top-25",  # CWE Top 25 (MITRE); aligns with SANS Top 25 focus
    "secrets": "p/secrets",
    "secure-defaults": "p/secure-defaults",
    "r2c-security-audit": "p/r2c-security-audit",  # Optional: add via rule_sets for extra coverage
    # --- Languages ---
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
    "scala": "p/scala",
    "bash": "p/bash",   # in UNSUPPORTED — do not use
    "solidity": "p/solidity",
    "apex": "p/apex",
    "elixir": "p/elixir",
    "clojure": "p/clojure",
    "ocaml": "p/ocaml",
    "html": "p/html",   # in UNSUPPORTED — do not use
    "json": "p/json",   # in UNSUPPORTED — do not use
    # --- Frameworks ---
    "react": "p/react",
    "nextjs": "p/nextjs",
    "django": "p/django",
    "flask": "p/flask",
    "fastapi": "p/fastapi",
    "docker": "p/docker",
    "terraform": "p/terraform",
    "kubernetes": "p/kubernetes",
    "dockerfile": "p/dockerfile",
    "docker-compose": "p/docker-compose",
    "nginx": "p/nginx",
    # --- Ported security tools (Bandit, ESLint, FindSecBugs, Gosec, etc.) ---
    "bandit": "p/bandit",
    "eslint": "p/eslint",
    "gosec": "p/gosec",
    "findsecbugs": "p/findsecbugs",
    "nodejsscan": "p/nodejsscan",
    "brakeman": "p/brakeman",
    "flawfinder": "p/flawfinder",
    "gitleaks": "p/gitleaks",
    "phpcs-security-audit": "p/phpcs-security-audit",
    "security-code-scan": "p/security-code-scan",
    # --- Vulnerability categories ---
    "xss": "p/xss",
    "sql-injection": "p/sql-injection",
    "command-injection": "p/command-injection",
    "insecure-transport": "p/insecure-transport",
    "jwt": "p/jwt",
}

# Packs that return HTTP 404 or invalid config from semgrep.dev registry — do not request these.
UNSUPPORTED_RULE_PACKS = {
    "p/express",   # Often 404 or deprecated in registry
    "p/spring",    # Often 404 or deprecated in registry
    "p/json",     # Registry returns 404 — no such ruleset
    "p/bash",     # Registry returns 404 — no such ruleset
    "p/html",     # Registry returns 404 — no such ruleset
}

# Language → list of registry rulesets (language + ported tools + frameworks)
LANGUAGE_RULE_MAP = {
    "python": ["p/python", "p/bandit", "p/django", "p/flask", "p/fastapi", "p/jwt"],
    "javascript": ["p/javascript", "p/eslint", "p/react", "p/nextjs", "p/nodejsscan", "p/xss"],
    "typescript": ["p/typescript", "p/eslint", "p/react", "p/nextjs", "p/nodejsscan", "p/xss"],
    "java": ["p/java", "p/findsecbugs"],
    "go": ["p/go", "p/gosec"],
    "ruby": ["p/ruby", "p/brakeman"],
    "php": ["p/php", "p/phpcs-security-audit"],
    "c": ["p/c", "p/flawfinder"],
    "cpp": ["p/c", "p/flawfinder"],
    "csharp": ["p/csharp", "p/security-code-scan"],
    "rust": ["p/rust"],
    "kotlin": ["p/kotlin"],
    "swift": ["p/swift"],
    "scala": ["p/scala"],
    "terraform": ["p/terraform"],
    "dockerfile": ["p/dockerfile", "p/docker"],
    "yaml": ["p/kubernetes", "p/docker-compose"],
    "bash": [],   # p/bash 404 — use baseline only
    "solidity": ["p/solidity"],
    "apex": ["p/apex"],
    "elixir": ["p/elixir"],
    "clojure": ["p/clojure"],
    "html": [],   # p/html 404 — use baseline only
    "json": [],   # p/json 404 — use baseline only
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

    # Add custom rule sets (skip unsupported/404 packs)
    if rule_sets:
        for rs in rule_sets:
            pack = RULE_PACKS.get(rs) if rs in RULE_PACKS else (rs if (rs.startswith("p/") or rs.startswith("r/")) else None)
            if pack and pack not in UNSUPPORTED_RULE_PACKS and pack not in added:
                added.add(pack)
                configs.extend(["--config", pack])

    # Add custom rules file/dir
    if custom_rules_path and Path(custom_rules_path).exists():
        _add_config(custom_rules_path)

    # Fallback: if no configs were added beyond the baseline, use --config auto
    if not configs:
        configs.extend(["--config", "auto"])

    return configs


def build_rule_config_safe(custom_rules_path: str | None = None) -> list[str]:
    """Build semgrep config with only registry packs that exist on semgrep.dev/explore (minimal 404 risk)."""
    configs = []
    # Minimal baseline: default, owasp, cwe (all listed on Explore); skip security-audit/secrets in case of 404
    for key in ("default", "owasp", "cwe", "secure-defaults"):
        pack = RULE_PACKS.get(key)
        if pack and pack not in UNSUPPORTED_RULE_PACKS:
            configs.extend(["--config", pack])
    if custom_rules_path and Path(custom_rules_path).exists():
        configs.extend(["--config", custom_rules_path])
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

        raw_errors = [str(err.get("message", err))[:500] for err in output.get("errors", [])]

        def _is_semgrep_parser_noise(e: str) -> bool:
            if not e:
                return True
            low = e.lower()
            if "syntax error" in low and "metavariable-pattern" in low:
                return True
            if "when parsing a snippet as bash" in low and "${{" in e:
                return True
            return False

        errors = [e for e in raw_errors if not _is_semgrep_parser_noise(e)]
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

    config_args = build_rule_config(languages, rule_sets, custom_rules_path)
    result = _run_with_configs(config_args)
    errors = result.get("errors", [])

    if _contains_invalid_config_error(errors):
        logger.warning(
            "Semgrep reported invalid/404 configs (e.g. p/json, p/bash, p/html); retrying with safe baseline only."
        )
        safe_config_args = build_rule_config_safe(custom_rules_path)
        fallback = _run_with_configs(safe_config_args)
        fallback_errors = fallback.get("errors", [])
        if _contains_invalid_config_error(fallback_errors):
            logger.warning("Safe fallback also had config errors; returning first run and filtering error message.")
            result["errors"] = [
                "Some Semgrep registry configs were unavailable (e.g. json/bash/html); scan used available rules.",
                *[e for e in errors if "404" not in e and "invalid configuration" not in e.lower()],
            ][:20]
        elif fallback.get("rules_used", 0) or fallback.get("findings"):
            fallback["errors"] = [
                e for e in fallback_errors if "404" not in e and "invalid configuration" not in e.lower()
            ][:20]
            return fallback
        else:
            result["errors"] = [
                "Some Semgrep registry configs were unavailable; scan may be incomplete.",
                *[e for e in errors if "404" not in e and "invalid configuration" not in e.lower()],
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
