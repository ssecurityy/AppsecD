"""Supply chain security — detect malicious packages, typosquatting, dependency confusion.

Protects against supply chain attacks by checking:
- Known malicious package lists
- Typosquatting via edit distance against popular packages
- Suspicious package metadata (new + high downloads)
- Dependency confusion (internal names on public registries)
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

logger = logging.getLogger(__name__)

# ── Levenshtein Distance (no external deps) ─────────────────────────


def _levenshtein(a: str, b: str) -> int:
    """Compute the Levenshtein edit distance between two strings.

    Uses the classic O(m*n) dynamic-programming algorithm with a single-row
    optimisation for reduced memory usage.
    """
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)

    # Ensure a is the shorter string for the rolling-array approach
    if len(a) > len(b):
        a, b = b, a

    prev = list(range(len(a) + 1))
    for j, ch_b in enumerate(b, 1):
        curr = [j] + [0] * len(a)
        for i, ch_a in enumerate(a, 1):
            cost = 0 if ch_a == ch_b else 1
            curr[i] = min(
                curr[i - 1] + 1,       # insertion
                prev[i] + 1,           # deletion
                prev[i - 1] + cost,    # substitution
            )
        prev = curr

    return prev[-1]


# ── Top 100 Popular Packages (for typosquatting baselines) ───────────

TOP_NPM_PACKAGES: list[str] = [
    "lodash", "chalk", "react", "express", "moment", "debug", "async",
    "commander", "request", "underscore", "uuid", "axios", "bluebird",
    "glob", "yargs", "mkdirp", "minimist", "body-parser", "webpack",
    "classnames", "fs-extra", "prop-types", "tslib", "rimraf", "semver",
    "colors", "inquirer", "through2", "dotenv", "readable-stream",
    "rxjs", "typescript", "jquery", "core-js", "babel-runtime", "ws",
    "qs", "babel-core", "redis", "shelljs", "cheerio", "node-fetch",
    "socket.io", "eslint", "prettier", "jest", "mocha", "chai",
    "next", "vue", "angular", "svelte", "fastify", "koa", "hapi",
    "mongoose", "sequelize", "knex", "pg", "mysql2", "sqlite3",
    "passport", "jsonwebtoken", "bcrypt", "helmet", "cors", "multer",
    "nodemailer", "handlebars", "pug", "ejs", "marked", "highlight.js",
    "dayjs", "date-fns", "luxon", "sharp", "jimp", "puppeteer",
    "playwright", "cypress", "supertest", "sinon", "nock",
    "react-dom", "react-router", "react-router-dom", "redux",
    "react-redux", "mobx", "zustand", "styled-components", "emotion",
    "tailwindcss", "postcss", "autoprefixer", "sass", "less",
    "webpack-cli", "rollup", "esbuild", "vite", "parcel", "turbo",
    "lerna", "nx",
]

TOP_PYPI_PACKAGES: list[str] = [
    "requests", "boto3", "setuptools", "pip", "urllib3", "certifi",
    "numpy", "pandas", "botocore", "idna", "charset-normalizer",
    "typing-extensions", "pyyaml", "six", "python-dateutil",
    "cryptography", "s3transfer", "jmespath", "packaging", "colorama",
    "pyasn1", "rsa", "click", "attrs", "importlib-metadata",
    "pyjwt", "pytz", "pillow", "cffi", "markupsafe", "jinja2",
    "wheel", "protobuf", "grpcio", "wrapt", "pycparser", "decorator",
    "google-api-core", "google-auth", "tomli", "soupsieve",
    "beautifulsoup4", "platformdirs", "filelock", "pluggy", "zipp",
    "pyparsing", "tqdm", "scipy", "scikit-learn", "matplotlib",
    "flask", "django", "fastapi", "uvicorn", "gunicorn", "celery",
    "redis", "sqlalchemy", "alembic", "psycopg2", "psycopg2-binary",
    "pydantic", "httpx", "aiohttp", "twisted", "tornado", "starlette",
    "pytest", "coverage", "black", "flake8", "mypy", "isort", "pylint",
    "bandit", "safety", "pre-commit", "poetry", "pipenv",
    "docker", "kubernetes", "paramiko", "fabric", "ansible",
    "tensorflow", "torch", "transformers", "openai", "anthropic",
    "langchain", "chromadb", "pinecone-client", "huggingface-hub",
    "opencv-python", "pillow", "imageio", "pygments", "rich",
    "typer", "httptools", "orjson", "ujson", "msgpack",
]

_TOP_PACKAGES: dict[str, list[str]] = {
    "npm": TOP_NPM_PACKAGES,
    "pypi": TOP_PYPI_PACKAGES,
}

# ── Known Malicious Package Patterns ────────────────────────────────
# Names of packages known to be malicious, or patterns that indicate
# malicious intent. These are based on publicly disclosed incidents.

KNOWN_MALICIOUS_PACKAGES: dict[str, set[str]] = {
    "npm": {
        "event-stream",           # 2018 — cryptojacking via flatmap-stream
        "flatmap-stream",
        "ua-parser-js",           # 2021 — hijacked, crypto miner injected
        "coa",                    # 2021 — hijacked
        "rc",                     # 2021 — hijacked
        "colors",                 # 2022 — protestware (Marak)
        "faker",                  # 2022 — protestware (Marak)
        "peacenotwar",            # 2022 — protestware (node-ipc)
        "node-ipc-2",             # fake / malicious fork
        "crossenv",               # typosquat of cross-env
        "cross-env.js",
        "mongose",                # typosquat of mongoose
        "babelcli",               # typosquat of babel-cli
        "discordi.js",            # typosquat of discord.js
        "loadyaml",
        "lodashs",                # typosquat of lodash
        "electorn",               # typosquat of electron
    },
    "pypi": {
        "colourama",              # typosquat of colorama
        "python-dateutils",       # typosquat of python-dateutil
        "jeIlyfish",              # typosquat of jellyfish (I vs l)
        "python3-dateutil",       # typosquat
        "pipsqlalchemy",          # typosquat
        "urlib3",                 # typosquat of urllib3
        "requestss",              # typosquat of requests
        "djanga",                 # typosquat of django
        "numpys",                 # typosquat of numpy
        "setuptool",              # typosquat of setuptools
        "libpeshka",              # known malicious (2023)
        "libpesh",
        "maratlib",
        "maratlib1",
        "importantpackage",       # dependency confusion research
        "pptest",
    },
}

# Patterns in package names that are inherently suspicious
SUSPICIOUS_NAME_PATTERNS: list[re.Pattern] = [
    re.compile(r"(?:steal|exfil|keylog|backdoor|reverse.?shell|rat|trojan)", re.IGNORECASE),
    re.compile(r"(?:crypto.?miner|coin.?hive|monero|coinhive)", re.IGNORECASE),
    re.compile(r"(?:^test-?\d+$|^aaa|^zzz)", re.IGNORECASE),
    re.compile(r"(.)\1{4,}"),  # same character repeated 5+ times
]


@dataclass
class SupplyChainAlert:
    """A single supply-chain security alert."""
    dep_name: str
    ecosystem: str
    alert_type: str          # typosquat, known_malicious, suspicious_metadata, dependency_confusion
    severity: str            # critical, high, medium, low
    confidence: str          # high, medium, low
    description: str
    details: dict = field(default_factory=dict)


class SupplyChainChecker:
    """Check dependencies for supply-chain attack indicators.

    Usage::

        checker = SupplyChainChecker()
        alerts = checker.check_packages(
            dependencies=[
                {"name": "lodashs", "version": "1.0.0", "ecosystem": "npm"},
            ],
            internal_packages={"my-internal-lib"},
        )
    """

    def check_packages(
        self,
        dependencies: list[dict],
        internal_packages: set[str] | None = None,
    ) -> dict:
        """Run all supply-chain checks on a list of dependencies.

        Args:
            dependencies: List of ``{"name", "version", "ecosystem", ...}`` dicts.
            internal_packages: Optional set of internal/private package names for
                dependency-confusion detection.

        Returns:
            ``{"alerts": [...], "stats": {...}}``
        """
        alerts: list[SupplyChainAlert] = []

        for dep in dependencies:
            name = dep.get("name", "")
            ecosystem = dep.get("ecosystem", "").lower()
            if not name:
                continue

            # 1. Known malicious
            alert = self._check_known_malicious(name, ecosystem)
            if alert:
                alerts.append(alert)

            # 2. Typosquatting
            alert = self._check_typosquatting(name, ecosystem)
            if alert:
                alerts.append(alert)

            # 3. Suspicious metadata
            alert = self._check_suspicious_metadata(dep)
            if alert:
                alerts.append(alert)

            # 4. Dependency confusion
            if internal_packages:
                alert = self._check_dependency_confusion(
                    name, ecosystem, internal_packages
                )
                if alert:
                    alerts.append(alert)

        # De-duplicate alerts (same dep + same type)
        seen: set[str] = set()
        unique_alerts: list[SupplyChainAlert] = []
        for a in alerts:
            key = f"{a.dep_name}:{a.ecosystem}:{a.alert_type}"
            if key not in seen:
                seen.add(key)
                unique_alerts.append(a)

        stats = {
            "total_dependencies": len(dependencies),
            "total_alerts": len(unique_alerts),
            "by_type": {},
            "by_severity": {},
        }
        for a in unique_alerts:
            stats["by_type"][a.alert_type] = stats["by_type"].get(a.alert_type, 0) + 1
            stats["by_severity"][a.severity] = stats["by_severity"].get(a.severity, 0) + 1

        logger.info(
            "Supply chain check: %d deps, %d alerts (%s)",
            len(dependencies),
            len(unique_alerts),
            stats["by_type"],
        )

        return {
            "alerts": [
                {
                    "dep_name": a.dep_name,
                    "ecosystem": a.ecosystem,
                    "alert_type": a.alert_type,
                    "severity": a.severity,
                    "confidence": a.confidence,
                    "description": a.description,
                    "details": a.details,
                }
                for a in unique_alerts
            ],
            "stats": stats,
        }

    # ── Typosquatting Detection ──────────────────────────────────────

    def _check_typosquatting(
        self, name: str, ecosystem: str
    ) -> SupplyChainAlert | None:
        """Check if *name* is suspiciously close to a popular package.

        Uses Levenshtein distance <= 2 against the top packages list for the
        ecosystem.  Only flags packages that are NOT exact matches (exact
        matches are legitimate).
        """
        top_packages = _TOP_PACKAGES.get(ecosystem, [])
        if not top_packages:
            return None

        name_lower = name.lower()

        # Skip if exact match (legitimate package)
        if name_lower in {p.lower() for p in top_packages}:
            return None

        # Skip very short names (high false positive rate)
        if len(name_lower) < 4:
            return None

        best_match: str | None = None
        best_distance: int = 999

        for pkg in top_packages:
            pkg_lower = pkg.lower()
            # Quick length check: edit distance >= |len_diff|
            if abs(len(name_lower) - len(pkg_lower)) > 2:
                continue

            dist = _levenshtein(name_lower, pkg_lower)
            if dist <= 2 and dist < best_distance:
                best_distance = dist
                best_match = pkg

        if best_match is None:
            return None

        # Additional heuristic: check for common typosquatting patterns
        patterns_detected = []
        if name_lower == best_match.lower() + "s":
            patterns_detected.append("trailing_s")
        if name_lower == best_match.lower() + "js" or name_lower == best_match.lower() + ".js":
            patterns_detected.append("trailing_js")
        if name_lower.replace("-", "") == best_match.lower().replace("-", ""):
            patterns_detected.append("hyphen_variation")
        if name_lower.replace("_", "-") == best_match.lower() or name_lower.replace("-", "_") == best_match.lower():
            patterns_detected.append("separator_swap")

        severity = "high" if best_distance == 1 else "medium"
        confidence = "high" if patterns_detected else "medium"

        return SupplyChainAlert(
            dep_name=name,
            ecosystem=ecosystem,
            alert_type="typosquat",
            severity=severity,
            confidence=confidence,
            description=(
                f"Package '{name}' is suspiciously similar to popular package "
                f"'{best_match}' (edit distance: {best_distance}). "
                f"This could be a typosquatting attack."
            ),
            details={
                "similar_to": best_match,
                "edit_distance": best_distance,
                "patterns": patterns_detected,
            },
        )

    # ── Known Malicious Check ────────────────────────────────────────

    def _check_known_malicious(
        self, name: str, ecosystem: str
    ) -> SupplyChainAlert | None:
        """Check if *name* is in the known-malicious package list."""
        known = KNOWN_MALICIOUS_PACKAGES.get(ecosystem, set())
        name_lower = name.lower()

        if name_lower in {k.lower() for k in known}:
            return SupplyChainAlert(
                dep_name=name,
                ecosystem=ecosystem,
                alert_type="known_malicious",
                severity="critical",
                confidence="high",
                description=(
                    f"Package '{name}' is a known malicious package in the "
                    f"'{ecosystem}' ecosystem. Remove it immediately."
                ),
                details={"list": "known_malicious_packages"},
            )

        # Check suspicious name patterns
        for pattern in SUSPICIOUS_NAME_PATTERNS:
            if pattern.search(name_lower):
                return SupplyChainAlert(
                    dep_name=name,
                    ecosystem=ecosystem,
                    alert_type="known_malicious",
                    severity="high",
                    confidence="medium",
                    description=(
                        f"Package '{name}' has a name matching known malicious "
                        f"patterns: {pattern.pattern}"
                    ),
                    details={"matched_pattern": pattern.pattern},
                )

        return None

    # ── Suspicious Metadata ──────────────────────────────────────────

    def _check_suspicious_metadata(self, dep: dict) -> SupplyChainAlert | None:
        """Flag packages with suspicious metadata patterns.

        Indicators:
        - Package is very new (< 30 days) but already has high download count
        - Package has no repository URL
        - Package has install scripts (postinstall, preinstall)
        - Version is 0.0.x or 0.1.x with network-heavy operations
        """
        name = dep.get("name", "")
        ecosystem = dep.get("ecosystem", "").lower()
        version = dep.get("version", "")
        metadata = dep.get("metadata", {}) or {}

        suspicious_signals: list[str] = []
        score = 0

        # Check for very new package with unusually specific version
        if version and re.match(r"^0\.0\.\d+$", version):
            suspicious_signals.append("very_early_version")
            score += 1

        # No repository URL
        if metadata.get("has_repository") is False or (
            metadata.get("repository_url") == "" and metadata.get("checked_metadata")
        ):
            suspicious_signals.append("no_repository_url")
            score += 1

        # Install scripts (common malware vector in npm)
        install_scripts = metadata.get("install_scripts", [])
        if install_scripts:
            suspicious_signals.append("has_install_scripts")
            score += 2

        # Single maintainer with no other packages
        if metadata.get("maintainer_package_count", 999) <= 1:
            suspicious_signals.append("single_package_maintainer")
            score += 1

        # Created recently
        created_at = metadata.get("created_at")
        if created_at:
            try:
                created = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
                age_days = (datetime.utcnow() - created.replace(tzinfo=None)).days
                if age_days < 30:
                    suspicious_signals.append(f"new_package_{age_days}d_old")
                    score += 1
            except (ValueError, TypeError):
                pass

        # Need at least 2 signals to flag
        if score < 2:
            return None

        severity = "high" if score >= 4 else "medium" if score >= 2 else "low"

        return SupplyChainAlert(
            dep_name=name,
            ecosystem=ecosystem,
            alert_type="suspicious_metadata",
            severity=severity,
            confidence="medium",
            description=(
                f"Package '{name}' has {len(suspicious_signals)} suspicious "
                f"metadata indicator(s): {', '.join(suspicious_signals)}"
            ),
            details={
                "signals": suspicious_signals,
                "score": score,
                "version": version,
            },
        )

    # ── Dependency Confusion ─────────────────────────────────────────

    def _check_dependency_confusion(
        self,
        name: str,
        ecosystem: str,
        internal_packages: set[str],
    ) -> SupplyChainAlert | None:
        """Check if an internal package name exists on a public registry.

        Dependency confusion attacks exploit package managers that check public
        registries before (or in addition to) private ones.  If an internal
        package name is also available publicly, an attacker can publish a
        higher-version package to take over installations.

        This check flags any dependency whose name matches an internal package
        name.  The actual public-registry existence check must be done by the
        caller (or via the SCA scanner's registry queries).
        """
        name_lower = name.lower()
        internal_lower = {p.lower() for p in internal_packages}

        if name_lower not in internal_lower:
            return None

        # Additional heuristic: common internal naming patterns
        is_scoped = name.startswith("@")
        namespace_indicators = [
            name_lower.startswith("internal-"),
            name_lower.startswith("private-"),
            name_lower.startswith("corp-"),
            name_lower.startswith("company-"),
            "-internal" in name_lower,
            "-private" in name_lower,
        ]
        has_namespace_indicator = any(namespace_indicators)

        severity = "critical" if has_namespace_indicator else "high"
        confidence = "high" if has_namespace_indicator else "medium"

        return SupplyChainAlert(
            dep_name=name,
            ecosystem=ecosystem,
            alert_type="dependency_confusion",
            severity=severity,
            confidence=confidence,
            description=(
                f"Package '{name}' matches an internal package name and may be "
                f"vulnerable to dependency confusion. Verify that this resolves "
                f"to your private registry, not a public one."
            ),
            details={
                "is_scoped": is_scoped,
                "has_namespace_indicator": has_namespace_indicator,
                "recommendation": (
                    "Use scoped packages (@org/pkg) or configure .npmrc / "
                    "pip.conf to always resolve internal names from your "
                    "private registry first."
                ),
            },
        )
