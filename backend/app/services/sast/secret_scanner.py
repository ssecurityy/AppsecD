"""Secret detection in source code — regex + entropy analysis."""
import hashlib
import json
import logging
import math
import os
import re
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Binary file extensions to skip during git diff scanning
# ---------------------------------------------------------------------------
BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".bmp", ".tiff", ".webp",
    ".svg", ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar",
    ".exe", ".dll", ".so", ".dylib", ".bin", ".o", ".a", ".class",
    ".pyc", ".pyo", ".wasm", ".map", ".min.js", ".min.css",
    ".mp3", ".mp4", ".avi", ".mov", ".wav", ".flac",
    ".lock", ".sum",
}

# ---------------------------------------------------------------------------
# Secret patterns — list of dicts
#
# Each dict has:
#   name             — human label
#   pattern          — regex string
#   severity         — critical | high | medium | low
#   type             — api_key | private_key | certificate | connection_string | generic
#   context_required — (optional) if present, the line must also match this
#                      substring (case-insensitive) for the pattern to fire.
#                      Use | for OR logic (e.g. ".p12|.pfx|pkcs12").
# ---------------------------------------------------------------------------
SECRET_PATTERNS = [
    # ── AWS ──────────────────────────────────────────────────────────
    {"name": "AWS Access Key", "pattern": r"(?:AKIA|ASIA)[A-Z0-9]{16}", "severity": "critical", "type": "api_key"},
    {"name": "AWS Secret Key", "pattern": r"(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})", "severity": "critical", "type": "api_key"},
    {"name": "AWS MWS Key", "pattern": r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "severity": "critical", "type": "api_key"},
    # ── GCP ──────────────────────────────────────────────────────────
    {"name": "GCP API Key", "pattern": r"AIza[0-9A-Za-z\-_]{35}", "severity": "high", "type": "api_key"},
    {"name": "GCP Service Account", "pattern": r'"type"\s*:\s*"service_account"', "severity": "critical", "type": "api_key"},
    {"name": "GCP OAuth Secret", "pattern": r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com", "severity": "high", "type": "api_key"},
    # ── Azure ────────────────────────────────────────────────────────
    {"name": "Azure Storage Key", "pattern": r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}", "severity": "critical", "type": "api_key"},
    {"name": "Azure SAS Token", "pattern": r"(?:sv|sig|se|sp|spr)=[^&\s]{10,}", "severity": "medium", "type": "api_key"},
    {"name": "Azure AD Client Secret", "pattern": r"(?:client.secret|AZURE_CLIENT_SECRET)\s*[=:]\s*['\"]?([A-Za-z0-9~._-]{34,})['\"]?", "severity": "critical", "type": "api_key"},
    # ── GitHub ───────────────────────────────────────────────────────
    {"name": "GitHub Token", "pattern": r"gh[pousr]_[A-Za-z0-9_]{36,255}", "severity": "critical", "type": "api_key"},
    {"name": "GitHub OAuth", "pattern": r"gho_[A-Za-z0-9]{36}", "severity": "critical", "type": "api_key"},
    {"name": "GitHub App Key", "pattern": r"(?:github|gh).*private[_-]?key.*-----BEGIN", "severity": "critical", "type": "private_key"},
    # ── GitLab ───────────────────────────────────────────────────────
    {"name": "GitLab Token", "pattern": r"glpat-[A-Za-z0-9\-_]{20,}", "severity": "critical", "type": "api_key"},
    {"name": "GitLab Pipeline Token", "pattern": r"glptt-[A-Za-z0-9]{20,}", "severity": "high", "type": "api_key"},
    # ── Generic Keys & Tokens ────────────────────────────────────────
    {"name": "Private Key", "pattern": r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----", "severity": "critical", "type": "private_key"},
    {"name": "JWT Token", "pattern": r"eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+", "severity": "high", "type": "api_key"},
    {"name": "Generic API Key", "pattern": r"(?:api[_-]?key|apikey)\s*[=:]\s*['\"]?([A-Za-z0-9\-_]{20,60})['\"]?", "severity": "medium", "type": "generic"},
    {"name": "Generic Secret", "pattern": r"(?:secret|password|passwd|pwd)\s*[=:]\s*['\"]([^'\"]{8,60})['\"]", "severity": "medium", "type": "generic"},
    # ── Slack ────────────────────────────────────────────────────────
    {"name": "Slack Token", "pattern": r"xox[bpors]-[A-Za-z0-9\-]{10,250}", "severity": "high", "type": "api_key"},
    {"name": "Slack Webhook", "pattern": r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+", "severity": "high", "type": "api_key"},
    # ── Stripe ───────────────────────────────────────────────────────
    {"name": "Stripe Secret Key", "pattern": r"sk_(?:test|live)_[A-Za-z0-9]{20,100}", "severity": "critical", "type": "api_key"},
    {"name": "Stripe Publishable Key", "pattern": r"pk_(?:test|live)_[A-Za-z0-9]{20,100}", "severity": "low", "type": "api_key"},
    {"name": "Stripe Webhook Secret", "pattern": r"whsec_[A-Za-z0-9]{20,100}", "severity": "high", "type": "api_key"},
    # ── Other Payment ────────────────────────────────────────────────
    {"name": "Square Access Token", "pattern": r"sq0atp-[A-Za-z0-9\-_]{22}", "severity": "critical", "type": "api_key"},
    {"name": "Square OAuth Secret", "pattern": r"sq0csp-[A-Za-z0-9\-_]{43}", "severity": "critical", "type": "api_key"},
    {"name": "PayPal Bearer Token", "pattern": r"access_token\$production\$[a-z0-9]{16}\$[a-f0-9]{32}", "severity": "critical", "type": "api_key"},
    # ── Communication ────────────────────────────────────────────────
    {"name": "SendGrid Key", "pattern": r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}", "severity": "high", "type": "api_key"},
    {"name": "Twilio Key", "pattern": r"SK[0-9a-fA-F]{32}", "severity": "high", "type": "api_key"},
    {"name": "Twilio Auth Token", "pattern": r"(?:twilio|TWILIO).*[0-9a-fA-F]{32}", "severity": "high", "type": "api_key"},
    {"name": "Mailgun Key", "pattern": r"key-[0-9a-zA-Z]{32}", "severity": "high", "type": "api_key"},
    {"name": "Mailchimp API Key", "pattern": r"[0-9a-f]{32}-us[0-9]{1,2}", "severity": "high", "type": "api_key"},
    # ── Cloud Providers ──────────────────────────────────────────────
    {"name": "DigitalOcean Token", "pattern": r"dop_v1_[a-f0-9]{64}", "severity": "critical", "type": "api_key"},
    {"name": "DigitalOcean OAuth", "pattern": r"doo_v1_[a-f0-9]{64}", "severity": "critical", "type": "api_key"},
    {"name": "Heroku API Key", "pattern": r"[hH]eroku.*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}", "severity": "high", "type": "api_key"},
    {"name": "Cloudflare API Key", "pattern": r"(?:cloudflare|CF).*[0-9a-f]{37}", "severity": "high", "type": "api_key"},
    # ── Monitoring & Analytics ───────────────────────────────────────
    {"name": "Datadog API Key", "pattern": r"(?:datadog|DD_API_KEY)\s*[=:]\s*['\"]?([a-f0-9]{32})['\"]?", "severity": "high", "type": "api_key"},
    {"name": "Datadog App Key", "pattern": r"(?:DD_APP_KEY)\s*[=:]\s*['\"]?([a-f0-9]{40})['\"]?", "severity": "high", "type": "api_key"},
    {"name": "New Relic Key", "pattern": r"(?:NRAK|NR-)[A-Za-z0-9]{27,}", "severity": "high", "type": "api_key"},
    {"name": "Sentry DSN", "pattern": r"https://[a-f0-9]{32}@[a-z0-9]+\.ingest\.sentry\.io/[0-9]+", "severity": "medium", "type": "api_key"},
    {"name": "Algolia API Key", "pattern": r"(?:algolia|ALGOLIA).*[a-f0-9]{32}", "severity": "medium", "type": "api_key"},
    # ── Firebase ─────────────────────────────────────────────────────
    {"name": "Firebase Secret", "pattern": r"(?:firebase|FIREBASE).*[A-Za-z0-9]{39}", "severity": "high", "type": "api_key"},
    # ── Shopify ──────────────────────────────────────────────────────
    {"name": "Shopify Access Token", "pattern": r"shpat_[a-fA-F0-9]{32}", "severity": "critical", "type": "api_key"},
    {"name": "Shopify Shared Secret", "pattern": r"shpss_[a-fA-F0-9]{32}", "severity": "critical", "type": "api_key"},
    {"name": "Shopify Custom Token", "pattern": r"shpca_[a-fA-F0-9]{32}", "severity": "high", "type": "api_key"},
    # ── NPM ──────────────────────────────────────────────────────────
    {"name": "NPM Token", "pattern": r"npm_[A-Za-z0-9]{36}", "severity": "critical", "type": "api_key"},
    # ── PyPI ─────────────────────────────────────────────────────────
    {"name": "PyPI Token", "pattern": r"pypi-[A-Za-z0-9\-_]{100,}", "severity": "critical", "type": "api_key"},
    # ── OAuth Client Secrets ─────────────────────────────────────────
    {"name": "OAuth Client Secret", "pattern": r"(?:client.secret|CLIENT_SECRET)\s*[=:]\s*['\"]?([A-Za-z0-9\-_]{20,})['\"]?", "severity": "high", "type": "api_key"},
    # ── Connection Strings ───────────────────────────────────────────
    {"name": "Database URL", "pattern": r"(?:postgres|mysql|mongodb|redis|amqp|mssql)://[^\s'\"]+:[^\s'\"]+@[^\s'\"]+", "severity": "critical", "type": "connection_string"},
    {"name": "JDBC Connection", "pattern": r"jdbc:[a-z]+://[^\s'\"]+(?:password|passwd|pwd)=[^\s&'\"]+", "severity": "critical", "type": "connection_string"},
    {"name": "ODBC Connection", "pattern": r"(?:Pwd|Password)\s*=\s*[^;'\"\s]{4,}", "severity": "high", "type": "connection_string"},
    # ── SSH Keys in non-standard formats ─────────────────────────────
    {"name": "SSH Key Base64", "pattern": r"AAAA[A-Za-z0-9+/]{50,}={0,3}\s+\S+@\S+", "severity": "high", "type": "private_key"},
    # ── Encoded Secrets ──────────────────────────────────────────────
    {"name": "Base64 Encoded Secret", "pattern": r"(?:secret|password|key|token).*base64[_-]?(?:encode|decode)?\s*[=:(\s]+['\"]?([A-Za-z0-9+/=]{40,})['\"]?", "severity": "medium", "type": "generic"},
    # ── Misc ─────────────────────────────────────────────────────────
    {"name": "Bearer Token", "pattern": r"[Bb]earer\s+[A-Za-z0-9\-_\.]{20,500}", "severity": "medium", "type": "generic"},
    {"name": "Hardcoded Password", "pattern": r"(?:password|passwd|pwd)\s*=\s*['\"](?!(?:\{|\$|%|<|none|null|empty|changeme|password|test))[^'\"]{4,60}['\"]", "severity": "high", "type": "generic"},

    # ══════════════════════════════════════════════════════════════════
    # NEW PATTERNS (30+)
    # ══════════════════════════════════════════════════════════════════

    # ── AI/ML Platform Keys ──────────────────────────────────────────
    {"name": "Anthropic API Key", "pattern": r"sk-ant-[a-zA-Z0-9_-]{20,}", "severity": "critical", "type": "api_key"},
    {"name": "OpenAI API Key (Project)", "pattern": r"sk-proj-[a-zA-Z0-9_-]{20,}", "severity": "critical", "type": "api_key"},
    {"name": "OpenAI API Key (Service)", "pattern": r"sk-svcacct-[a-zA-Z0-9_-]{20,}", "severity": "critical", "type": "api_key"},
    {"name": "OpenAI API Key (Legacy)", "pattern": r"sk-[a-zA-Z0-9]{20,}T3BlbkFJ[a-zA-Z0-9]{20,}", "severity": "critical", "type": "api_key"},
    {"name": "HuggingFace Token", "pattern": r"hf_[a-zA-Z0-9]{34,}", "severity": "high", "type": "api_key"},
    {"name": "Cohere API Key", "pattern": r"[a-zA-Z0-9]{40}", "severity": "high", "type": "api_key", "context_required": "cohere"},
    {"name": "Replicate API Token", "pattern": r"r8_[a-zA-Z0-9]{37}", "severity": "high", "type": "api_key"},

    # ── Cloud & Infrastructure ───────────────────────────────────────
    {"name": "Supabase API Key", "pattern": r"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+", "severity": "high", "type": "api_key", "context_required": "supabase"},
    {"name": "Vercel Token", "pattern": r"vercel_[a-zA-Z0-9]{24,}", "severity": "high", "type": "api_key"},
    {"name": "Netlify Token", "pattern": r"nfp_[a-zA-Z0-9]{40,}", "severity": "high", "type": "api_key"},
    {"name": "Terraform Cloud Token", "pattern": r"[a-zA-Z0-9]{14}\.atlasv1\.[a-zA-Z0-9_-]{60,}", "severity": "critical", "type": "api_key"},
    {"name": "PlanetScale Token", "pattern": r"pscale_tkn_[a-zA-Z0-9_-]{40,}", "severity": "high", "type": "api_key"},
    {"name": "PlanetScale OAuth Token", "pattern": r"pscale_oauth_[a-zA-Z0-9_-]{40,}", "severity": "high", "type": "api_key"},
    {"name": "Neon Database Token", "pattern": r"neon_[a-zA-Z0-9]{32,}", "severity": "high", "type": "api_key"},
    {"name": "Cloudflare API Token", "pattern": r"[a-zA-Z0-9_-]{40}", "severity": "high", "type": "api_key", "context_required": "cloudflare"},
    {"name": "Cloudflare Global API Key", "pattern": r"[a-f0-9]{37}", "severity": "critical", "type": "api_key", "context_required": "cloudflare"},
    {"name": "DigitalOcean Token (v1)", "pattern": r"dop_v1_[a-f0-9]{64}", "severity": "critical", "type": "api_key"},
    {"name": "DigitalOcean OAuth (v1)", "pattern": r"doo_v1_[a-f0-9]{64}", "severity": "critical", "type": "api_key"},

    # ── Developer Tools ──────────────────────────────────────────────
    {"name": "Docker Hub Token", "pattern": r"dckr_pat_[a-zA-Z0-9_-]{27,}", "severity": "high", "type": "api_key"},
    {"name": "CircleCI Token", "pattern": r"circle-token-[a-f0-9]{40}", "severity": "high", "type": "api_key"},
    {"name": "Travis CI Token", "pattern": r"travis-[a-zA-Z0-9]{22}", "severity": "high", "type": "api_key"},
    {"name": "NuGet API Key", "pattern": r"oy2[a-z0-9]{43}", "severity": "high", "type": "api_key"},
    {"name": "RubyGems API Key", "pattern": r"rubygems_[a-f0-9]{48}", "severity": "high", "type": "api_key"},
    {"name": "Postman API Key", "pattern": r"PMAK-[a-f0-9]{24}-[a-f0-9]{34}", "severity": "medium", "type": "api_key"},

    # ── SaaS / Productivity ──────────────────────────────────────────
    {"name": "Linear API Key", "pattern": r"lin_api_[a-zA-Z0-9]{40}", "severity": "medium", "type": "api_key"},
    {"name": "Notion Integration Token", "pattern": r"(secret|ntn)_[a-zA-Z0-9]{43}", "severity": "medium", "type": "api_key"},
    {"name": "Airtable API Key", "pattern": r"pat[a-zA-Z0-9]{14}\.[a-f0-9]{64}", "severity": "medium", "type": "api_key"},
    {"name": "Figma Token", "pattern": r"figd_[a-zA-Z0-9_-]{40,}", "severity": "medium", "type": "api_key"},
    {"name": "Asana Token", "pattern": r"[0-9]+/[0-9]{16}:[a-f0-9]{32}", "severity": "medium", "type": "api_key"},
    {"name": "Atlassian API Token", "pattern": r"ATATT3xFfGF0[a-zA-Z0-9_-]{50,}", "severity": "high", "type": "api_key"},
    {"name": "Jira Token", "pattern": r"[a-zA-Z0-9]{24}", "severity": "medium", "type": "api_key", "context_required": "jira"},

    # ── Certificates & Keys ──────────────────────────────────────────
    {"name": "PKCS12 Certificate", "pattern": r"MII[A-Za-z0-9+/]{60,}", "severity": "critical", "type": "certificate", "context_required": ".p12|.pfx|pkcs12"},
    {"name": "PEM Private Key", "pattern": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "severity": "critical", "type": "private_key"},
    {"name": "PEM Certificate", "pattern": r"-----BEGIN CERTIFICATE-----", "severity": "medium", "type": "certificate"},

    # ── Database Connection Strings ──────────────────────────────────
    {"name": "MongoDB Connection String", "pattern": r"mongodb(\+srv)?://[a-zA-Z0-9_:%-]+@[a-zA-Z0-9._%-]+", "severity": "critical", "type": "connection_string"},
    {"name": "PostgreSQL Connection String", "pattern": r"postgres(ql)?://[a-zA-Z0-9_:%-]+@[a-zA-Z0-9._%-]+", "severity": "critical", "type": "connection_string"},
    {"name": "MySQL Connection String", "pattern": r"mysql://[a-zA-Z0-9_:%-]+@[a-zA-Z0-9._%-]+", "severity": "critical", "type": "connection_string"},
    {"name": "Redis Connection String", "pattern": r"redis(s)?://[a-zA-Z0-9_:%-]*@?[a-zA-Z0-9._%-]+:[0-9]+", "severity": "high", "type": "connection_string"},
]

# Files to always check
PRIORITY_FILES = {".env", ".env.local", ".env.production", ".env.staging",
                  "config.py", "settings.py", "secrets.yaml", "credentials.json",
                  "application.properties", "application.yml", "wp-config.php"}

# Files to skip
SKIP_EXTENSIONS = {".min.js", ".map", ".lock", ".sum", ".svg", ".png", ".jpg",
                   ".gif", ".ico", ".woff", ".woff2", ".ttf", ".eot", ".pdf",
                   ".zip", ".tar", ".gz", ".bz2"}

MAX_FILE_SIZE = 1 * 1024 * 1024  # 1MB per file

# Early-exit threshold for git history scanning
_GIT_HISTORY_MAX_FINDINGS = 100


def _context_matches(line: str, context_required: str) -> bool:
    """Check whether *line* satisfies the context_required constraint.

    ``context_required`` is a ``|``-delimited set of substrings.  The check
    is case-insensitive.  If *any* of the substrings appears in *line*,
    the context matches.
    """
    line_lower = line.lower()
    for token in context_required.split("|"):
        if token.strip().lower() in line_lower:
            return True
    return False


def scan_secrets(source_dir: str) -> list[dict]:
    """Scan source directory for secrets.

    Returns list of secret findings.
    """
    findings = []
    files_scanned = 0
    limit_reached = False

    for root, dirs, filenames in os.walk(source_dir):
        if limit_reached:
            break

        # Skip common non-code directories
        dirs[:] = [d for d in dirs if d not in {"node_modules", ".git", "vendor", "__pycache__", "dist", "build", ".next"}]

        for fname in filenames:
            if files_scanned >= 50000:
                limit_reached = True
                break

            ext = os.path.splitext(fname)[1].lower()
            if ext in SKIP_EXTENSIONS:
                continue

            fpath = os.path.join(root, fname)

            # Size check
            try:
                if os.path.getsize(fpath) > MAX_FILE_SIZE:
                    continue
            except OSError:
                continue

            try:
                rel_path = os.path.relpath(fpath, source_dir)
                file_findings = _scan_file(fpath, rel_path)
                findings.extend(file_findings)
                files_scanned += 1
            except Exception as e:
                logger.debug("Secret scan skipped %s: %s", fname, e)

    # Deduplicate by fingerprint
    seen = set()
    deduped = []
    for f in findings:
        if f["fingerprint"] not in seen:
            seen.add(f["fingerprint"])
            deduped.append(f)

    return deduped


def scan_secrets_trufflehog(source_path: str) -> list[dict]:
    """Run TruffleHog v3 on a filesystem path and return SastFinding-compatible dicts."""
    TRUFFLEHOG_BIN = "/usr/local/bin/trufflehog"
    TIMEOUT_SECONDS = 120

    if not os.path.isfile(TRUFFLEHOG_BIN):
        logger.warning("TruffleHog binary not found at %s — skipping", TRUFFLEHOG_BIN)
        return []

    try:
        result = subprocess.run(
            [TRUFFLEHOG_BIN, "filesystem", "--json", "--no-update", source_path],
            capture_output=True,
            text=True,
            timeout=TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        logger.error("TruffleHog scan timed out after %ds for %s", TIMEOUT_SECONDS, source_path)
        return []
    except (OSError, subprocess.SubprocessError) as exc:
        logger.error("TruffleHog subprocess error: %s", exc)
        return []

    findings: list[dict] = []
    seen_fingerprints: set[str] = set()

    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue

        detector_name = obj.get("DetectorName", obj.get("DetectorType", "Unknown"))
        verified = bool(obj.get("Verified", False))
        raw_secret = obj.get("Raw", "")

        source_meta = (
            obj.get("SourceMetadata", {})
            .get("Data", {})
            .get("Filesystem", {})
        )
        abs_file = source_meta.get("file", "")
        line_number = source_meta.get("line", 0)

        if abs_file:
            try:
                file_path = os.path.relpath(abs_file, source_path)
            except ValueError:
                file_path = abs_file
        else:
            file_path = ""

        if len(raw_secret) > 8:
            masked = raw_secret[:4] + "****" + raw_secret[-4:]
        else:
            masked = "****"

        fp_raw = f"{detector_name}|{file_path}|{raw_secret}"
        fingerprint = hashlib.sha256(fp_raw.encode()).hexdigest()[:32]

        if fingerprint in seen_fingerprints:
            continue
        seen_fingerprints.add(fingerprint)

        verified_label = " (verified)" if verified else ""
        severity = "critical" if verified else "high"
        confidence = "high" if verified else "medium"

        findings.append({
            "rule_id": f"trufflehog.{detector_name}",
            "rule_source": "trufflehog",
            "severity": severity,
            "confidence": confidence,
            "title": f"Leaked {detector_name} secret detected{verified_label}",
            "description": (
                f"TruffleHog detected a {detector_name} secret in {file_path or 'unknown file'}. "
                f"Verified: {'yes' if verified else 'no'}. "
                f"Hard-coded secrets in source code can be extracted by anyone with "
                f"repository access, leading to unauthorized access to the associated "
                f"service or infrastructure."
            ),
            "message": f"{detector_name} secret found{verified_label} in {file_path}",
            "file_path": file_path,
            "line_start": line_number if line_number else 0,
            "line_end": line_number if line_number else 0,
            "code_snippet": masked,
            "fix_suggestion": (
                f"Rotate this {detector_name} secret immediately. Remove it from "
                f"source code and use environment variables or a secrets manager "
                f"(e.g., HashiCorp Vault, AWS Secrets Manager)."
            ),
            "cwe_id": "CWE-798",
            "owasp_category": "A07:2021",
            "fingerprint": fingerprint,
            "references": [
                "https://cwe.mitre.org/data/definitions/798.html",
                "https://github.com/trufflesecurity/trufflehog",
            ],
        })

    logger.info(
        "TruffleHog scan: %d secrets found (%d verified) in %s",
        len(findings),
        sum(1 for f in findings if f["severity"] == "critical"),
        source_path,
    )
    return findings


def _scan_file(file_path: str, rel_path: str) -> list[dict]:
    """Scan a single file for secrets."""
    findings = []

    try:
        with open(file_path, "r", errors="ignore") as f:
            lines = f.readlines()
    except (OSError, UnicodeDecodeError):
        return []

    for line_num, line in enumerate(lines, 1):
        # Skip comment-only lines (reduce false positives)
        stripped = line.strip()
        if stripped.startswith("#") or stripped.startswith("//") or stripped.startswith("/*") or (stripped.startswith("*") and not stripped.startswith("*/")):
            # But still check .env files (comments in .env start with #)
            if not rel_path.startswith(".env"):
                continue

        for pat in SECRET_PATTERNS:
            pattern_name = pat["name"]
            pattern = pat["pattern"]
            severity = pat["severity"]
            context_required = pat.get("context_required")

            # If this pattern requires context, check that the line contains it
            if context_required and not _context_matches(line, context_required):
                continue

            match = re.search(pattern, line)
            if match:
                # Get matched value (group 1 if capture group, else full match)
                value = match.group(1) if match.lastindex else match.group(0)
                # Mask the value
                masked = value[:4] + "****" + value[-4:] if len(value) > 8 else "****"

                # Context: 2 lines before and after
                start = max(0, line_num - 3)
                end = min(len(lines), line_num + 2)
                snippet = "".join(lines[start:end])

                fp_raw = f"{pattern_name}|{rel_path}|{line_num}"
                fingerprint = hashlib.sha256(fp_raw.encode()).hexdigest()[:32]

                findings.append({
                    "rule_id": f"secret.{pattern_name.lower().replace(' ', '-')}",
                    "rule_source": "secret_scan",
                    "severity": severity,
                    "confidence": "high",
                    "title": f"Exposed {pattern_name}",
                    "description": f"Potential {pattern_name} found in source code. Value preview: {masked}",
                    "message": f"{pattern_name} detected at line {line_num}",
                    "file_path": rel_path,
                    "line_start": line_num,
                    "line_end": line_num,
                    "code_snippet": snippet[:2000],
                    "cwe_id": "CWE-798",
                    "owasp_category": "A07:2021",
                    "fingerprint": fingerprint,
                    "references": ["https://cwe.mitre.org/data/definitions/798.html"],
                })

    # Entropy check for .env files and config files
    basename = os.path.basename(file_path)
    if basename in PRIORITY_FILES or basename.endswith(".env"):
        for line_num, line in enumerate(lines, 1):
            entropy_findings = _check_entropy(line, line_num, rel_path)
            findings.extend(entropy_findings)

    return findings


def _check_entropy(line: str, line_num: int, rel_path: str) -> list[dict]:
    """Check for high-entropy strings that might be secrets."""
    findings = []
    # Look for KEY=VALUE patterns
    match = re.match(r'^([A-Z_]+)\s*=\s*["\']?(.+?)["\']?\s*$', line.strip())
    if not match:
        return []

    key, value = match.groups()
    # Skip non-secret keys
    skip_keys = {"PATH", "HOME", "USER", "SHELL", "LANG", "TERM", "NODE_ENV",
                 "DEBUG", "PORT", "HOST", "APP_NAME", "LOG_LEVEL"}
    if key in skip_keys or len(value) < 16:
        return []

    entropy = _shannon_entropy(value)
    if entropy > 4.5:  # High entropy threshold
        fp_raw = f"entropy|{rel_path}|{line_num}"
        fingerprint = hashlib.sha256(fp_raw.encode()).hexdigest()[:32]
        masked = value[:4] + "****" + value[-4:] if len(value) > 8 else "****"
        findings.append({
            "rule_id": "secret.high-entropy-string",
            "rule_source": "secret_scan",
            "severity": "medium",
            "confidence": "low",
            "title": f"High-Entropy String in {key}",
            "description": f"Variable {key} contains a high-entropy value ({entropy:.1f} bits). Preview: {masked}",
            "message": f"Possible secret in environment variable {key}",
            "file_path": rel_path,
            "line_start": line_num,
            "line_end": line_num,
            "code_snippet": line.strip()[:200],
            "cwe_id": "CWE-798",
            "owasp_category": "A07:2021",
            "fingerprint": fingerprint,
            "references": [],
        })
    return findings


def _shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not data:
        return 0.0
    counts = {}
    for c in data:
        counts[c] = counts.get(c, 0) + 1
    length = len(data)
    entropy = 0.0
    for count in counts.values():
        prob = count / length
        if prob > 0:
            entropy -= prob * math.log2(prob)
    return entropy


def _is_binary_file(file_path: str) -> bool:
    """Return True if *file_path* looks like a binary file (by extension)."""
    ext = os.path.splitext(file_path)[1].lower()
    return ext in BINARY_EXTENSIONS


# ── Git History Scanning ──────────────────────────────────────────────

def _get_local_branches(repo_path: str) -> list[str]:
    """Return a list of local branch names in the repo."""
    try:
        result = subprocess.run(
            ["git", "branch", "--format=%(refname:short)"],
            capture_output=True, text=True, timeout=30, cwd=repo_path,
        )
        if result.returncode != 0:
            return []
        return [b.strip() for b in result.stdout.strip().split("\n") if b.strip()]
    except (subprocess.TimeoutExpired, Exception):
        return []


def scan_git_history(repo_path: str, max_commits: int = 500) -> list[dict]:
    """Scan recent git commits for leaked secrets.

    Checks the diff of each recent commit for secret patterns.

    Enhancements over the original implementation:
      - Configurable depth (default 500, capped at 5000).
      - Scans all local branches, not just HEAD.
      - Skips binary files in diffs.
      - Early exit when >100 unique secrets are found.
    """

    # Clamp depth
    max_commits = max(1, min(max_commits, 5000))

    findings: list[dict] = []
    seen: set[str] = set()

    if not os.path.isdir(os.path.join(repo_path, ".git")):
        return findings

    # Collect commit SHAs across all local branches (deduplicated, order preserved)
    branches = _get_local_branches(repo_path)
    if not branches:
        branches = ["HEAD"]

    all_shas: list[str] = []
    seen_shas: set[str] = set()

    for branch in branches:
        try:
            result = subprocess.run(
                ["git", "log", branch, f"--max-count={max_commits}",
                 "--pretty=format:%H", "--diff-filter=AMCR"],
                capture_output=True, text=True, timeout=60, cwd=repo_path,
            )
            if result.returncode != 0:
                continue
            for sha in result.stdout.strip().split("\n"):
                sha = sha.strip()
                if sha and sha not in seen_shas:
                    seen_shas.add(sha)
                    all_shas.append(sha)
        except (subprocess.TimeoutExpired, Exception):
            continue

    # Cap the total number of commits we inspect
    all_shas = all_shas[:max_commits]

    for sha in all_shas:
        # Early exit when we have accumulated too many findings
        if len(findings) >= _GIT_HISTORY_MAX_FINDINGS:
            logger.warning(
                "Git history scan: early exit — %d secrets found, threshold reached",
                len(findings),
            )
            break

        try:
            diff_result = subprocess.run(
                ["git", "diff", f"{sha}~1..{sha}", "--no-color", "-U0"],
                capture_output=True, text=True, timeout=30, cwd=repo_path,
            )
            if diff_result.returncode != 0:
                continue

            diff_text = diff_result.stdout
            current_file = ""
            for line in diff_text.split("\n"):
                if line.startswith("diff --git"):
                    parts = line.split(" b/")
                    current_file = parts[-1] if len(parts) > 1 else ""
                    continue

                # Skip binary files
                if current_file and _is_binary_file(current_file):
                    continue

                if line.startswith("+") and not line.startswith("+++"):
                    added_line = line[1:]
                    for pat in SECRET_PATTERNS:
                        pattern_name = pat["name"]
                        pattern = pat["pattern"]
                        severity = pat["severity"]
                        context_required = pat.get("context_required")

                        # Context check for patterns that require it
                        if context_required and not _context_matches(added_line, context_required):
                            continue

                        match = re.search(pattern, added_line)
                        if match:
                            value = match.group(1) if match.lastindex else match.group(0)
                            masked = value[:4] + "****" + value[-4:] if len(value) > 8 else "****"
                            fp_raw = f"git_history|{pattern_name}|{sha[:8]}|{current_file}"
                            fingerprint = hashlib.sha256(fp_raw.encode()).hexdigest()[:32]

                            if fingerprint in seen:
                                break  # already recorded for this commit+file+pattern

                            seen.add(fingerprint)
                            findings.append({
                                "rule_id": f"secret.git_history.{pattern_name.lower().replace(' ', '-')}",
                                "rule_source": "secret_scan",
                                "severity": severity,
                                "confidence": "medium",
                                "title": f"Secret Leaked in Git History: {pattern_name}",
                                "description": (
                                    f"{pattern_name} found in commit {sha[:8]} in file {current_file}. "
                                    f"Value preview: {masked}. Even if removed in later commits, "
                                    f"secrets in git history can be extracted."
                                ),
                                "message": f"Secret in git history: {sha[:8]}",
                                "file_path": current_file,
                                "line_start": 0,
                                "line_end": 0,
                                "code_snippet": added_line[:200],
                                "cwe_id": "CWE-798",
                                "owasp_category": "A07:2021",
                                "fingerprint": fingerprint,
                                "references": [
                                    {"url": "https://cwe.mitre.org/data/definitions/798.html"},
                                ],
                            })
                            break
        except (subprocess.TimeoutExpired, Exception):
            continue

    logger.info("Git history scan: %d secrets found in %d commits across %d branches",
                len(findings), len(all_shas), len(branches))
    return findings


# ── Secret Verification (with Redis-backed rate limiting) ─────────────

async def _is_verification_rate_limited(secret_hash: str) -> bool:
    """Check if we have already verified this secret in the last 24 h.

    Uses Redis key ``secret_verify:<hash>`` with a 24-hour TTL.
    Returns True (rate-limited / skip) or False (proceed with verification).
    Falls back to "not limited" when Redis is unavailable.
    """
    try:
        from app.core.redis_client import get_redis
        r = await get_redis()
        cache_key = f"secret_verify:{secret_hash}"
        cached = await r.get(cache_key)
        if cached is not None:
            return True
        # Mark as verified for the next 24 h
        await r.set(cache_key, "1", ex=86400)
        return False
    except Exception:
        # Redis unavailable — proceed without rate limiting
        return False


async def _verify_openai_key(key: str) -> dict:
    """Verify an OpenAI API key by calling the models endpoint."""
    import httpx

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                "https://api.openai.com/v1/models",
                headers={"Authorization": f"Bearer {key}"},
            )
            if resp.status_code == 200:
                return {"active": True, "verified": True,
                        "detail": "Active OpenAI API key"}
            return {"active": False, "verified": True,
                    "detail": f"OpenAI key returned {resp.status_code}"}
    except Exception as e:
        return {"active": False, "verified": False,
                "detail": f"OpenAI verification failed: {str(e)[:100]}"}


async def _verify_anthropic_key(key: str) -> dict:
    """Verify an Anthropic API key using a minimal request."""
    import httpx

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            # A minimal messages request with an intentionally tiny max_tokens
            # will authenticate without consuming meaningful usage.
            resp = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": "claude-3-haiku-20240307",
                    "max_tokens": 1,
                    "messages": [{"role": "user", "content": "hi"}],
                },
            )
            if resp.status_code == 200:
                return {"active": True, "verified": True,
                        "detail": "Active Anthropic API key"}
            if resp.status_code == 401:
                return {"active": False, "verified": True,
                        "detail": "Anthropic key is invalid (401)"}
            return {"active": False, "verified": True,
                    "detail": f"Anthropic key returned {resp.status_code}"}
    except Exception as e:
        return {"active": False, "verified": False,
                "detail": f"Anthropic verification failed: {str(e)[:100]}"}


async def _verify_aws_key(access_key: str, secret_key: str) -> dict:
    """Verify AWS credentials via STS GetCallerIdentity.

    Uses raw HTTP with AWS Signature Version 4 (no boto3 dependency required)
    via the ``httpx`` client.  Falls back gracefully on any error.
    """
    import datetime
    import hmac
    import httpx

    try:
        service = "sts"
        host = "sts.amazonaws.com"
        region = "us-east-1"
        endpoint = f"https://{host}"
        request_body = "Action=GetCallerIdentity&Version=2011-06-15"

        now = datetime.datetime.utcnow()
        amz_date = now.strftime("%Y%m%dT%H%M%SZ")
        date_stamp = now.strftime("%Y%m%d")

        # --- AWS Sig V4 helpers ---
        def _sign(key: bytes, msg: str) -> bytes:
            return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

        def _get_signature_key(k: str, ds: str, r: str, s: str) -> bytes:
            k_date = _sign(("AWS4" + k).encode("utf-8"), ds)
            k_region = _sign(k_date, r)
            k_service = _sign(k_region, s)
            return _sign(k_service, "aws4_request")

        content_type = "application/x-www-form-urlencoded; charset=utf-8"
        payload_hash = hashlib.sha256(request_body.encode("utf-8")).hexdigest()

        canonical_headers = (
            f"content-type:{content_type}\n"
            f"host:{host}\n"
            f"x-amz-date:{amz_date}\n"
        )
        signed_headers = "content-type;host;x-amz-date"

        canonical_request = "\n".join([
            "POST", "/", "",
            canonical_headers, signed_headers, payload_hash,
        ])

        credential_scope = f"{date_stamp}/{region}/{service}/aws4_request"
        string_to_sign = "\n".join([
            "AWS4-HMAC-SHA256", amz_date, credential_scope,
            hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
        ])

        signing_key = _get_signature_key(secret_key, date_stamp, region, service)
        signature = hmac.new(signing_key, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()

        auth_header = (
            f"AWS4-HMAC-SHA256 Credential={access_key}/{credential_scope}, "
            f"SignedHeaders={signed_headers}, Signature={signature}"
        )

        headers = {
            "Content-Type": content_type,
            "Host": host,
            "X-Amz-Date": amz_date,
            "Authorization": auth_header,
        }

        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(endpoint, content=request_body, headers=headers)
            if resp.status_code == 200:
                return {"active": True, "verified": True,
                        "detail": "Active AWS credentials (STS GetCallerIdentity succeeded)"}
            if resp.status_code in (403, 401):
                return {"active": False, "verified": True,
                        "detail": f"AWS credentials invalid ({resp.status_code})"}
            return {"active": False, "verified": True,
                    "detail": f"AWS STS returned {resp.status_code}"}
    except Exception as e:
        return {"active": False, "verified": False,
                "detail": f"AWS verification failed: {str(e)[:100]}"}


async def verify_secret(pattern_name: str, secret_value: str) -> dict:
    """Test if a detected secret is currently active/valid.

    Returns: {active: bool, verified: bool, detail: str}

    Includes Redis-backed rate limiting: each unique secret is only verified
    once per 24-hour window to avoid hammering third-party APIs.
    """
    import httpx

    # Rate-limit check (keyed on SHA-256 of the secret value)
    secret_hash = hashlib.sha256(secret_value.encode()).hexdigest()[:32]
    if await _is_verification_rate_limited(secret_hash):
        return {"active": False, "verified": False,
                "detail": "Verification skipped — already checked in the last 24 h"}

    name_lower = pattern_name.lower()

    try:
        # ── OpenAI ───────────────────────────────────────────────────
        if "openai" in name_lower and secret_value.startswith("sk-"):
            return await _verify_openai_key(secret_value)

        # ── Anthropic ────────────────────────────────────────────────
        if "anthropic" in name_lower and secret_value.startswith("sk-ant-"):
            return await _verify_anthropic_key(secret_value)

        # ── AWS ──────────────────────────────────────────────────────
        if "aws" in name_lower:
            # For AWS we need both access key and secret key.  The secret_value
            # for AWS Access Key findings is just the AKIA… portion; the caller
            # can optionally pass a colon-separated pair "AKIA…:secret".
            if ":" in secret_value:
                access_key, aws_secret = secret_value.split(":", 1)
                return await _verify_aws_key(access_key, aws_secret)
            # Cannot verify with only the access key ID
            return {"active": False, "verified": False,
                    "detail": "AWS verification requires both access key and secret key (pass as AKIA…:secret)"}

        # ── GitHub ───────────────────────────────────────────────────
        if "github" in name_lower and secret_value.startswith("gh"):
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(
                    "https://api.github.com/user",
                    headers={"Authorization": f"Bearer {secret_value}"},
                )
                if resp.status_code == 200:
                    user = resp.json().get("login", "unknown")
                    return {"active": True, "verified": True,
                            "detail": f"Active GitHub token for user: {user}"}
                return {"active": False, "verified": True,
                        "detail": f"GitHub token returned {resp.status_code}"}

        # ── Slack ────────────────────────────────────────────────────
        if "slack" in name_lower and secret_value.startswith("xox"):
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(
                    "https://slack.com/api/auth.test",
                    headers={"Authorization": f"Bearer {secret_value}"},
                )
                data = resp.json()
                if data.get("ok"):
                    return {"active": True, "verified": True,
                            "detail": f"Active Slack token for team: {data.get('team', 'unknown')}"}
                return {"active": False, "verified": True,
                        "detail": "Slack token invalid"}

        # ── SendGrid ─────────────────────────────────────────────────
        if "sendgrid" in name_lower and secret_value.startswith("SG."):
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(
                    "https://api.sendgrid.com/v3/user/profile",
                    headers={"Authorization": f"Bearer {secret_value}"},
                )
                if resp.status_code == 200:
                    return {"active": True, "verified": True,
                            "detail": "Active SendGrid API key"}
                return {"active": False, "verified": True,
                        "detail": f"SendGrid key returned {resp.status_code}"}

        return {"active": False, "verified": False,
                "detail": "Verification not available for this secret type"}

    except Exception as e:
        return {"active": False, "verified": False,
                "detail": f"Verification failed: {str(e)[:100]}"}


def get_rotation_recommendation(pattern_name: str) -> str:
    """Return rotation steps per secret type."""
    recommendations = {
        "aws": "1. Go to IAM Console -> Users -> Security credentials\n"
               "2. Create new access key\n3. Update all services using old key\n"
               "4. Deactivate, then delete old key",
        "github": "1. Go to Settings -> Developer settings -> Tokens\n"
                  "2. Revoke the exposed token\n3. Generate a new token\n"
                  "4. Update all services using the token",
        "slack": "1. Go to api.slack.com -> Your Apps -> OAuth & Permissions\n"
                 "2. Rotate the token\n3. Update all integrations",
        "stripe": "1. Go to Stripe Dashboard -> Developers -> API Keys\n"
                  "2. Roll the secret key\n3. Update all integrations",
        "database": "1. Change the database password immediately\n"
                    "2. Update connection strings in all services\n"
                    "3. Review access logs for unauthorized access",
        "private key": "1. Generate a new key pair\n"
                       "2. Replace the public key in all authorized_keys\n"
                       "3. Revoke any certificates signed with the old key",
        "openai": "1. Go to platform.openai.com -> API Keys\n"
                  "2. Revoke the exposed key\n3. Create a new API key\n"
                  "4. Update all services using the key",
        "anthropic": "1. Go to console.anthropic.com -> API Keys\n"
                     "2. Delete the exposed key\n3. Create a new API key\n"
                     "4. Update all services using the key",
        "huggingface": "1. Go to huggingface.co -> Settings -> Access Tokens\n"
                       "2. Revoke the exposed token\n3. Create a new token\n"
                       "4. Update all services using the token",
        "vercel": "1. Go to Vercel Dashboard -> Settings -> Tokens\n"
                  "2. Delete the exposed token\n3. Create a new token\n"
                  "4. Update all deployments using the token",
        "netlify": "1. Go to Netlify Dashboard -> User settings -> Applications\n"
                   "2. Delete the exposed token\n3. Create a new personal access token\n"
                   "4. Update all integrations",
        "docker": "1. Go to Docker Hub -> Account Settings -> Security\n"
                  "2. Delete the exposed access token\n3. Create a new token\n"
                  "4. Run docker login with the new token",
        "supabase": "1. Go to Supabase Dashboard -> Settings -> API\n"
                    "2. Regenerate the API keys\n3. Update all services\n"
                    "4. Review Row Level Security policies",
        "terraform": "1. Go to app.terraform.io -> User Settings -> Tokens\n"
                     "2. Delete the exposed token\n3. Create a new API token\n"
                     "4. Update all CI/CD pipelines",
        "planetscale": "1. Go to PlanetScale Dashboard -> Organization settings\n"
                       "2. Delete the exposed token\n3. Create a new service token\n"
                       "4. Update all connection configurations",
    }
    name_lower = pattern_name.lower()
    for key, recommendation in recommendations.items():
        if key in name_lower:
            return recommendation
    return ("1. Revoke/rotate the exposed secret immediately\n"
            "2. Update all services using the secret\n"
            "3. Review access logs for unauthorized usage")
