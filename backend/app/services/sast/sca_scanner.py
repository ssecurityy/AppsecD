"""Software Composition Analysis (SCA) scanner.

Parses dependency manifest files from a source directory, queries the OSV
vulnerability database (https://osv.dev) for known CVEs, and returns
findings compatible with the SastFinding / SastDependency schemas used by
the rest of the SAST pipeline.

Supported ecosystems:
    - npm  (package.json, package-lock.json, yarn.lock, pnpm-lock.yaml)
    - PyPI (requirements.txt, Pipfile.lock, poetry.lock)
    - Go   (go.mod, go.sum)
    - Maven (pom.xml, build.gradle)
    - RubyGems (Gemfile.lock)
    - crates.io (Cargo.lock)
    - Packagist (composer.lock)
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
from pathlib import Path
from typing import Any

import httpx

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_BATCH_SIZE = 100
OSV_TIMEOUT_SECONDS = 30

# Manifest filenames we look for, mapped to their parse function name.
# The actual functions are defined later in the module.
_MANIFEST_PARSERS: dict[str, str] = {
    "package.json": "_parse_package_json",
    "package-lock.json": "_parse_package_lock_json",
    "yarn.lock": "_parse_yarn_lock",
    "pnpm-lock.yaml": "_parse_pnpm_lock_yaml",
    "requirements.txt": "_parse_requirements_txt",
    "Pipfile.lock": "_parse_pipfile_lock",
    "poetry.lock": "_parse_poetry_lock",
    "go.mod": "_parse_go_mod",
    "go.sum": "_parse_go_sum",
    "pom.xml": "_parse_pom_xml",
    "build.gradle": "_parse_build_gradle",
    "Gemfile.lock": "_parse_gemfile_lock",
    "Cargo.lock": "_parse_cargo_lock",
    "composer.lock": "_parse_composer_lock",
}

# Ecosystem names for OSV queries
_ECOSYSTEM_MAP: dict[str, str] = {
    "package.json": "npm",
    "package-lock.json": "npm",
    "yarn.lock": "npm",
    "pnpm-lock.yaml": "npm",
    "requirements.txt": "PyPI",
    "Pipfile.lock": "PyPI",
    "poetry.lock": "PyPI",
    "go.mod": "Go",
    "go.sum": "Go",
    "pom.xml": "Maven",
    "build.gradle": "Maven",
    "Gemfile.lock": "RubyGems",
    "Cargo.lock": "crates.io",
    "composer.lock": "Packagist",
}

# OSV / CVSS severity normalisation
_SEVERITY_MAP: dict[str, str] = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MODERATE": "medium",
    "MEDIUM": "medium",
    "LOW": "low",
    "NONE": "low",
}

# OWASP A06:2021 — Vulnerable and Outdated Components
_OWASP_CATEGORY = "A06:2021"

# Directories that should be skipped when walking for manifests
_SKIP_DIRS = {
    "node_modules", ".git", "vendor", "__pycache__", "dist", "build",
    ".next", ".tox", ".venv", "venv", "env", ".mypy_cache",
}


# ---------------------------------------------------------------------------
# Data class for an individual dependency
# ---------------------------------------------------------------------------

class _Dep:
    """Lightweight container for a parsed dependency."""

    __slots__ = ("name", "version", "ecosystem", "manifest_file", "is_direct", "code_snippet", "license_id")

    def __init__(
        self,
        name: str,
        version: str,
        ecosystem: str,
        manifest_file: str,
        is_direct: bool = True,
        code_snippet: str = "",
        license_id: str | None = None,
    ) -> None:
        self.name = name
        self.version = version
        self.ecosystem = ecosystem
        self.manifest_file = manifest_file
        self.is_direct = is_direct
        self.code_snippet = code_snippet
        self.license_id = license_id

    def osv_query(self) -> dict:
        """Return an OSV query payload for this dependency."""
        return {
            "version": self.version,
            "package": {
                "name": self.name,
                "ecosystem": self.ecosystem,
            },
        }


# ===================================================================
# Main entry point
# ===================================================================

async def scan_dependencies(source_path: str) -> dict:
    """Scan all dependency manifests and check for known vulnerabilities.

    Returns:
        {
            "findings": [...],         # SastFinding-compatible dicts
            "dependencies": [...],     # SastDependency-compatible dicts
            "manifests_found": [...],  # list of manifest files found
            "total_packages": int,
            "vulnerable_packages": int,
        }
    """
    logger.info("SCA scan starting for %s", source_path)

    # 1. Discover manifest files
    manifests = _discover_manifests(source_path)
    logger.info("SCA: found %d manifest file(s): %s", len(manifests), [m[1] for m in manifests])

    if not manifests:
        logger.info("SCA: no manifest files found — nothing to scan")
        return {
            "findings": [],
            "dependencies": [],
            "manifests_found": [],
            "total_packages": 0,
            "vulnerable_packages": 0,
        }

    # 2. Parse all manifests into a flat list of _Dep objects
    all_deps: list[_Dep] = []
    manifest_rel_paths: list[str] = []
    for abs_path, rel_path in manifests:
        manifest_rel_paths.append(rel_path)
        try:
            deps = _parse_manifest(abs_path, rel_path)
            all_deps.extend(deps)
            logger.info("SCA: parsed %d dependencies from %s", len(deps), rel_path)
        except Exception:
            logger.exception("SCA: failed to parse %s", rel_path)

    # Deduplicate deps (same ecosystem+name+version keeps the first manifest)
    all_deps = _deduplicate_deps(all_deps)
    logger.info("SCA: %d unique packages after dedup", len(all_deps))

    # 3. Query OSV for vulnerabilities
    vuln_map = await _query_osv(all_deps)

    # 4. Build output structures
    findings: list[dict] = []
    dependencies: list[dict] = []
    vulnerable_names: set[str] = set()

    for dep in all_deps:
        dep_key = f"{dep.ecosystem}:{dep.name}:{dep.version}"
        dep_vulns = vuln_map.get(dep_key, [])

        # Build dependency record
        dep_dict: dict[str, Any] = {
            "name": dep.name,
            "version": dep.version,
            "ecosystem": dep.ecosystem.lower() if dep.ecosystem != "PyPI" else "pypi",
            "manifest_file": dep.manifest_file,
            "is_direct": dep.is_direct,
            "license_id": dep.license_id,
            "vulnerabilities": dep_vulns,
            "is_outdated": False,
        }
        dependencies.append(dep_dict)

        # Build a finding for each vulnerability
        for vuln in dep_vulns:
            vuln_id = vuln.get("id", "UNKNOWN")
            severity = _extract_severity(vuln)
            cwe_id = _extract_cwe(vuln)
            aliases = vuln.get("aliases", [])
            summary = vuln.get("summary", "")
            details = vuln.get("details", "")
            refs = [{"url": r.get("url", "")} for r in vuln.get("references", []) if r.get("url")]

            # Prefer a CVE alias for the rule_id when available
            cve_alias = next((a for a in aliases if a.startswith("CVE-")), vuln_id)

            ecosystem_label = dep.ecosystem.lower().replace(".", "")
            rule_id = f"sca.{ecosystem_label}.{dep.name}.{cve_alias}"

            title = f"{dep.name} {dep.version} has known vulnerability {cve_alias}"

            # Extract fixed version from OSV data
            fixed_versions: list[str] = []
            for affected in vuln.get("affected", []):
                for r in affected.get("ranges", []):
                    for event in r.get("events", []):
                        if "fixed" in event:
                            fixed_versions.append(event["fixed"])
            fix_version = fixed_versions[0] if fixed_versions else None

            # Build rich description
            desc_parts: list[str] = []
            if summary:
                desc_parts.append(summary)
            if details and details != summary:
                desc_parts.append(details[:500])
            desc_parts.append(f"Affected package: {dep.name} {dep.version} ({dep.ecosystem})")
            if fix_version:
                desc_parts.append(f"Fixed in version: {fix_version}")
            if aliases:
                desc_parts.append(f"Aliases: {', '.join(aliases[:5])}")
            description = "\n\n".join(desc_parts)

            message = description[:500]

            # Build upgrade suggestion
            if fix_version:
                if dep.ecosystem == "npm":
                    upgrade_cmd = f"npm update {dep.name}"
                elif dep.ecosystem == "PyPI":
                    upgrade_cmd = f"pip install --upgrade {dep.name}"
                else:
                    upgrade_cmd = f"{dep.name}@{fix_version}"
                fix_suggestion = (
                    f"Upgrade {dep.name} from {dep.version} to {fix_version}. "
                    f"Run: {upgrade_cmd}."
                )
            else:
                fix_suggestion = (
                    f"Check for a patched version of {dep.name} or consider an alternative package."
                )

            fixed_code = f'"{dep.name}": "{fix_version}"' if fix_version else None

            fingerprint_raw = f"{dep.ecosystem}:{dep.name}:{dep.version}:{vuln_id}"
            fingerprint = hashlib.sha256(fingerprint_raw.encode()).hexdigest()

            findings.append({
                "rule_id": rule_id,
                "rule_source": "sca",
                "severity": severity,
                "confidence": "high",
                "title": title,
                "description": description,
                "message": message,
                "file_path": dep.manifest_file,
                "line_start": 0,
                "line_end": 0,
                "code_snippet": dep.code_snippet or f'"{dep.name}": "{dep.version}"',
                "fix_suggestion": fix_suggestion,
                "fixed_code": fixed_code,
                "cwe_id": cwe_id,
                "owasp_category": _OWASP_CATEGORY,
                "references": refs,
                "fingerprint": fingerprint,
            })
            vulnerable_names.add(dep_key)

    logger.info(
        "SCA scan complete: %d packages, %d vulnerable, %d findings",
        len(dependencies),
        len(vulnerable_names),
        len(findings),
    )

    return {
        "findings": findings,
        "dependencies": dependencies,
        "manifests_found": manifest_rel_paths,
        "total_packages": len(dependencies),
        "vulnerable_packages": len(vulnerable_names),
    }


# ===================================================================
# Manifest discovery
# ===================================================================

def _discover_manifests(source_path: str) -> list[tuple[str, str]]:
    """Walk *source_path* and return (abs_path, rel_path) for each manifest."""
    results: list[tuple[str, str]] = []
    target_names = set(_MANIFEST_PARSERS.keys())

    for root, dirs, files in os.walk(source_path):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for fname in files:
            if fname in target_names:
                abs_path = os.path.join(root, fname)
                rel_path = os.path.relpath(abs_path, source_path)
                results.append((abs_path, rel_path))

    return results


# ===================================================================
# Generic parse dispatch
# ===================================================================

def _parse_manifest(abs_path: str, rel_path: str) -> list[_Dep]:
    """Dispatch to the correct parser based on the filename."""
    fname = os.path.basename(abs_path)
    parser_name = _MANIFEST_PARSERS.get(fname)
    if not parser_name:
        return []
    parser_fn = globals().get(parser_name)
    if not parser_fn:
        logger.warning("SCA: parser function %s not found", parser_name)
        return []
    return parser_fn(abs_path, rel_path)


# ===================================================================
# npm ecosystem parsers
# ===================================================================

def _parse_package_json(abs_path: str, rel_path: str) -> list[_Dep]:
    """Parse package.json — direct dependencies and devDependencies."""
    try:
        with open(abs_path, "r", encoding="utf-8", errors="replace") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("SCA: cannot parse %s: %s", rel_path, exc)
        return []

    deps: list[_Dep] = []
    ecosystem = _ECOSYSTEM_MAP["package.json"]
    pkg_license = data.get("license", None)
    if isinstance(pkg_license, dict):
        pkg_license = pkg_license.get("type", None)

    for section in ("dependencies", "devDependencies"):
        for name, version_spec in (data.get(section) or {}).items():
            version = _clean_npm_version(version_spec)
            if not version:
                continue
            snippet = f'"{name}": "{version_spec}"'
            deps.append(_Dep(
                name=name,
                version=version,
                ecosystem=ecosystem,
                manifest_file=rel_path,
                is_direct=True,
                code_snippet=snippet,
                license_id=pkg_license,
            ))

    return deps


def _parse_package_lock_json(abs_path: str, rel_path: str) -> list[_Dep]:
    """Parse package-lock.json for all resolved packages (including transitive)."""
    try:
        with open(abs_path, "r", encoding="utf-8", errors="replace") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("SCA: cannot parse %s: %s", rel_path, exc)
        return []

    deps: list[_Dep] = []
    ecosystem = _ECOSYSTEM_MAP["package-lock.json"]

    # lockfile v2/v3 uses "packages" key
    packages = data.get("packages") or {}
    # lockfile v1 uses "dependencies" key
    if not packages:
        packages_v1 = data.get("dependencies") or {}
        for name, info in packages_v1.items():
            version = info.get("version", "")
            if not version:
                continue
            snippet = f'"{name}": "{version}"'
            deps.append(_Dep(
                name=name,
                version=version,
                ecosystem=ecosystem,
                manifest_file=rel_path,
                is_direct=False,
                code_snippet=snippet,
            ))
            # Recurse into nested dependencies
            deps.extend(_parse_lockv1_nested(info.get("dependencies", {}), ecosystem, rel_path))
        return deps

    # v2/v3 path: key is "node_modules/<name>" or "" (root)
    root_deps_names: set[str] = set()
    root_pkg = packages.get("", {})
    for section in ("dependencies", "devDependencies"):
        root_deps_names.update((root_pkg.get(section) or {}).keys())

    for pkg_path, info in packages.items():
        if pkg_path == "":
            continue  # skip root
        version = info.get("version", "")
        if not version:
            continue
        # Extract name from path: "node_modules/@scope/foo" -> "@scope/foo"
        name = pkg_path.split("node_modules/")[-1] if "node_modules/" in pkg_path else pkg_path
        is_direct = name in root_deps_names
        snippet = f'"{name}": "{version}"'
        pkg_license = info.get("license", None)
        deps.append(_Dep(
            name=name,
            version=version,
            ecosystem=ecosystem,
            manifest_file=rel_path,
            is_direct=is_direct,
            code_snippet=snippet,
            license_id=pkg_license,
        ))

    return deps


def _parse_lockv1_nested(
    deps_dict: dict, ecosystem: str, rel_path: str
) -> list[_Dep]:
    """Recurse into nested dependencies in package-lock v1 format."""
    results: list[_Dep] = []
    for name, info in deps_dict.items():
        version = info.get("version", "")
        if version:
            results.append(_Dep(
                name=name,
                version=version,
                ecosystem=ecosystem,
                manifest_file=rel_path,
                is_direct=False,
                code_snippet=f'"{name}": "{version}"',
            ))
        results.extend(
            _parse_lockv1_nested(info.get("dependencies", {}), ecosystem, rel_path)
        )
    return results


def _parse_yarn_lock(abs_path: str, rel_path: str) -> list[_Dep]:
    """Parse yarn.lock — simplified line-by-line parser."""
    try:
        with open(abs_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except OSError as exc:
        logger.warning("SCA: cannot read %s: %s", rel_path, exc)
        return []

    deps: list[_Dep] = []
    ecosystem = _ECOSYSTEM_MAP["yarn.lock"]

    # Yarn v1 lock format:
    #   "name@^1.0.0", "name@~1.2.0":
    #     version "1.2.3"
    current_names: list[str] = []
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        # Header line — package specifier
        if not line.startswith(" ") and not line.startswith("\t"):
            current_names = _extract_yarn_names(stripped)
            continue

        # Version line
        version_match = re.match(r'^\s+version\s+"?([^"]+)"?', line)
        if version_match and current_names:
            version = version_match.group(1).strip()
            for name in current_names:
                snippet = f"{name}@{version}"
                deps.append(_Dep(
                    name=name,
                    version=version,
                    ecosystem=ecosystem,
                    manifest_file=rel_path,
                    is_direct=False,
                    code_snippet=snippet,
                ))
            current_names = []

    return deps


def _extract_yarn_names(header: str) -> list[str]:
    """Extract package names from a yarn.lock header line."""
    names: list[str] = []
    # Remove trailing colon
    header = header.rstrip(":")
    # Split on ", " for multiple specifiers
    for spec in header.split(","):
        spec = spec.strip().strip('"')
        # "@scope/name@^1.0.0" -> "@scope/name"
        # "name@^1.0.0" -> "name"
        if spec.startswith("@"):
            at_idx = spec.index("@", 1)
            name = spec[:at_idx]
        else:
            at_idx = spec.find("@")
            name = spec[:at_idx] if at_idx > 0 else spec
        if name:
            names.append(name)
    # Deduplicate while preserving order
    seen: set[str] = set()
    unique: list[str] = []
    for n in names:
        if n not in seen:
            seen.add(n)
            unique.append(n)
    return unique


def _parse_pnpm_lock_yaml(abs_path: str, rel_path: str) -> list[_Dep]:
    """Parse pnpm-lock.yaml with a basic regex approach (no YAML dependency)."""
    try:
        with open(abs_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except OSError as exc:
        logger.warning("SCA: cannot read %s: %s", rel_path, exc)
        return []

    deps: list[_Dep] = []
    ecosystem = _ECOSYSTEM_MAP["pnpm-lock.yaml"]

    # pnpm-lock v6+: packages section with keys like "/@scope/name@1.2.3:" or "/name@1.2.3:"
    # pnpm-lock v9+: packages section with keys like "@scope/name@1.2.3:" or "name@1.2.3:"
    pattern = re.compile(
        r"^\s{2,4}'?/?(@?[a-zA-Z0-9._-]+(?:/[a-zA-Z0-9._-]+)?)@(\d+\.\d+[^':\s]*)'?\s*:",
        re.MULTILINE,
    )
    for match in pattern.finditer(content):
        name = match.group(1)
        version = match.group(2)
        snippet = f"{name}@{version}"
        deps.append(_Dep(
            name=name,
            version=version,
            ecosystem=ecosystem,
            manifest_file=rel_path,
            is_direct=False,
            code_snippet=snippet,
        ))

    return deps


# ===================================================================
# PyPI ecosystem parsers
# ===================================================================

def _parse_requirements_txt(abs_path: str, rel_path: str) -> list[_Dep]:
    """Parse requirements.txt line by line.

    Handles:  name==1.0, name>=1.0, name~=1.0, name<=1.0, name!=1.0
    Also handles extras: name[extra]==1.0
    """
    try:
        with open(abs_path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except OSError as exc:
        logger.warning("SCA: cannot read %s: %s", rel_path, exc)
        return []

    deps: list[_Dep] = []
    ecosystem = _ECOSYSTEM_MAP["requirements.txt"]

    # Pattern: package_name[extras] operator version
    spec_re = re.compile(
        r"^([A-Za-z0-9_][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*"
        r"(?:==|~=|>=|<=|!=|>|<)\s*"
        r"([A-Za-z0-9._*-]+)"
    )

    for raw_line in lines:
        line = raw_line.strip()
        # Skip blanks, comments, options, constraints
        if not line or line.startswith("#") or line.startswith("-") or line.startswith("--"):
            continue
        match = spec_re.match(line)
        if match:
            name = match.group(1)
            version = match.group(2)
            snippet = line
            deps.append(_Dep(
                name=name,
                version=version,
                ecosystem=ecosystem,
                manifest_file=rel_path,
                is_direct=True,
                code_snippet=snippet,
            ))

    return deps


def _parse_pipfile_lock(abs_path: str, rel_path: str) -> list[_Dep]:
    """Parse Pipfile.lock (JSON format)."""
    try:
        with open(abs_path, "r", encoding="utf-8", errors="replace") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("SCA: cannot parse %s: %s", rel_path, exc)
        return []

    deps: list[_Dep] = []
    ecosystem = _ECOSYSTEM_MAP["Pipfile.lock"]

    for section in ("default", "develop"):
        for name, info in (data.get(section) or {}).items():
            version = (info.get("version") or "").lstrip("=")
            if not version:
                continue
            snippet = f'"{name}": {{"version": "=={version}"}}'
            deps.append(_Dep(
                name=name,
                version=version,
                ecosystem=ecosystem,
                manifest_file=rel_path,
                is_direct=(section == "default"),
                code_snippet=snippet,
                license_id=None,
            ))

    return deps


def _parse_poetry_lock(abs_path: str, rel_path: str) -> list[_Dep]:
    """Parse poetry.lock — TOML-ish line-by-line (no TOML dependency)."""
    try:
        with open(abs_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except OSError as exc:
        logger.warning("SCA: cannot read %s: %s", rel_path, exc)
        return []

    deps: list[_Dep] = []
    ecosystem = _ECOSYSTEM_MAP["poetry.lock"]

    # Each package block starts with [[package]] and has name = "..." and version = "..."
    blocks = content.split("[[package]]")
    for block in blocks[1:]:  # skip preamble
        name_m = re.search(r'^name\s*=\s*"([^"]+)"', block, re.MULTILINE)
        ver_m = re.search(r'^version\s*=\s*"([^"]+)"', block, re.MULTILINE)
        if name_m and ver_m:
            name = name_m.group(1)
            version = ver_m.group(1)
            snippet = f'{name} = "{version}"'
            deps.append(_Dep(
                name=name,
                version=version,
                ecosystem=ecosystem,
                manifest_file=rel_path,
                is_direct=False,
                code_snippet=snippet,
            ))

    return deps


# ===================================================================
# Go ecosystem parsers
# ===================================================================

def _parse_go_mod(abs_path: str, rel_path: str) -> list[_Dep]:
    """Parse go.mod require blocks."""
    try:
        with open(abs_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except OSError as exc:
        logger.warning("SCA: cannot read %s: %s", rel_path, exc)
        return []

    deps: list[_Dep] = []
    ecosystem = _ECOSYSTEM_MAP["go.mod"]

    # Single-line requires: require module/path v1.2.3
    single_re = re.compile(r"^require\s+(\S+)\s+(v\S+)", re.MULTILINE)
    for m in single_re.finditer(content):
        name, version = m.group(1), m.group(2)
        snippet = f"require {name} {version}"
        deps.append(_Dep(name=name, version=version, ecosystem=ecosystem,
                         manifest_file=rel_path, is_direct=True, code_snippet=snippet))

    # Block requires:
    #   require (
    #       module/path v1.2.3
    #   )
    block_re = re.compile(r"require\s*\((.*?)\)", re.DOTALL)
    for block in block_re.finditer(content):
        for line in block.group(1).splitlines():
            line = line.strip()
            if not line or line.startswith("//"):
                continue
            parts = line.split()
            if len(parts) >= 2:
                name, version = parts[0], parts[1]
                # Skip indirect markers
                is_direct = "// indirect" not in line
                snippet = f"{name} {version}"
                deps.append(_Dep(name=name, version=version, ecosystem=ecosystem,
                                 manifest_file=rel_path, is_direct=is_direct,
                                 code_snippet=snippet))

    return deps


def _parse_go_sum(abs_path: str, rel_path: str) -> list[_Dep]:
    """Parse go.sum — each line is module version hash."""
    try:
        with open(abs_path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except OSError as exc:
        logger.warning("SCA: cannot read %s: %s", rel_path, exc)
        return []

    deps: list[_Dep] = []
    ecosystem = _ECOSYSTEM_MAP["go.sum"]
    seen: set[str] = set()

    for raw_line in lines:
        parts = raw_line.strip().split()
        if len(parts) < 3:
            continue
        name = parts[0]
        version = parts[1].split("/")[0]  # strip /go.mod suffix
        key = f"{name}@{version}"
        if key in seen:
            continue
        seen.add(key)
        snippet = f"{name} {version}"
        deps.append(_Dep(name=name, version=version, ecosystem=ecosystem,
                         manifest_file=rel_path, is_direct=False, code_snippet=snippet))

    return deps


# ===================================================================
# Maven ecosystem parsers
# ===================================================================

def _parse_pom_xml(abs_path: str, rel_path: str) -> list[_Dep]:
    """Parse pom.xml using simple regex to avoid XML parser dependency."""
    try:
        with open(abs_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except OSError as exc:
        logger.warning("SCA: cannot read %s: %s", rel_path, exc)
        return []

    deps: list[_Dep] = []
    ecosystem = _ECOSYSTEM_MAP["pom.xml"]

    # Match <dependency> blocks
    dep_re = re.compile(
        r"<dependency>\s*"
        r"<groupId>\s*([^<]+?)\s*</groupId>\s*"
        r"<artifactId>\s*([^<]+?)\s*</artifactId>\s*"
        r"(?:<version>\s*([^<$]+?)\s*</version>)?",
        re.DOTALL,
    )
    for m in dep_re.finditer(content):
        group_id = m.group(1).strip()
        artifact_id = m.group(2).strip()
        version = (m.group(3) or "").strip()
        if not version or version.startswith("$"):
            # Property-referenced versions cannot be resolved without full Maven context
            continue
        name = f"{group_id}:{artifact_id}"
        snippet = f"<groupId>{group_id}</groupId><artifactId>{artifact_id}</artifactId><version>{version}</version>"
        deps.append(_Dep(name=name, version=version, ecosystem=ecosystem,
                         manifest_file=rel_path, is_direct=True, code_snippet=snippet))

    return deps


def _parse_build_gradle(abs_path: str, rel_path: str) -> list[_Dep]:
    """Parse build.gradle dependency declarations."""
    try:
        with open(abs_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except OSError as exc:
        logger.warning("SCA: cannot read %s: %s", rel_path, exc)
        return []

    deps: list[_Dep] = []
    ecosystem = _ECOSYSTEM_MAP["build.gradle"]

    # Match patterns like:
    #   implementation 'group:artifact:version'
    #   implementation "group:artifact:version"
    #   compile group: 'g', name: 'a', version: 'v'
    string_re = re.compile(
        r"(?:implementation|compile|api|runtimeOnly|testImplementation|testCompile|compileOnly)"
        r"\s+['\"]([^'\"]+):([^'\"]+):([^'\"]+)['\"]"
    )
    for m in string_re.finditer(content):
        group_id = m.group(1).strip()
        artifact_id = m.group(2).strip()
        version = m.group(3).strip()
        if not version or version.startswith("$"):
            continue
        name = f"{group_id}:{artifact_id}"
        snippet = f"{group_id}:{artifact_id}:{version}"
        deps.append(_Dep(name=name, version=version, ecosystem=ecosystem,
                         manifest_file=rel_path, is_direct=True, code_snippet=snippet))

    # Map-style: compile group: 'g', name: 'a', version: 'v'
    map_re = re.compile(
        r"(?:implementation|compile|api|runtimeOnly|testImplementation|testCompile|compileOnly)"
        r"\s+group:\s*['\"]([^'\"]+)['\"],\s*name:\s*['\"]([^'\"]+)['\"],\s*version:\s*['\"]([^'\"]+)['\"]"
    )
    for m in map_re.finditer(content):
        group_id = m.group(1).strip()
        artifact_id = m.group(2).strip()
        version = m.group(3).strip()
        if not version or version.startswith("$"):
            continue
        name = f"{group_id}:{artifact_id}"
        snippet = f"group: '{group_id}', name: '{artifact_id}', version: '{version}'"
        deps.append(_Dep(name=name, version=version, ecosystem=ecosystem,
                         manifest_file=rel_path, is_direct=True, code_snippet=snippet))

    return deps


# ===================================================================
# RubyGems ecosystem parser
# ===================================================================

def _parse_gemfile_lock(abs_path: str, rel_path: str) -> list[_Dep]:
    """Parse Gemfile.lock for resolved gem versions."""
    try:
        with open(abs_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except OSError as exc:
        logger.warning("SCA: cannot read %s: %s", rel_path, exc)
        return []

    deps: list[_Dep] = []
    ecosystem = _ECOSYSTEM_MAP["Gemfile.lock"]

    # In the "specs:" section, gems are listed as:
    #     name (version)
    in_specs = False
    for line in content.splitlines():
        stripped = line.strip()
        if stripped == "specs:":
            in_specs = True
            continue
        if in_specs:
            if not line.startswith(" ") and not line.startswith("\t"):
                in_specs = False
                continue
            # Match "    name (version)"
            m = re.match(r"^\s{4}(\S+)\s+\(([^)]+)\)", line)
            if m:
                name = m.group(1)
                version = m.group(2)
                snippet = f"{name} ({version})"
                deps.append(_Dep(name=name, version=version, ecosystem=ecosystem,
                                 manifest_file=rel_path, is_direct=False,
                                 code_snippet=snippet))

    return deps


# ===================================================================
# crates.io ecosystem parser
# ===================================================================

def _parse_cargo_lock(abs_path: str, rel_path: str) -> list[_Dep]:
    """Parse Cargo.lock (TOML-ish format)."""
    try:
        with open(abs_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except OSError as exc:
        logger.warning("SCA: cannot read %s: %s", rel_path, exc)
        return []

    deps: list[_Dep] = []
    ecosystem = _ECOSYSTEM_MAP["Cargo.lock"]

    # Each package block starts with [[package]] and has name = "..." and version = "..."
    blocks = content.split("[[package]]")
    for block in blocks[1:]:
        name_m = re.search(r'^name\s*=\s*"([^"]+)"', block, re.MULTILINE)
        ver_m = re.search(r'^version\s*=\s*"([^"]+)"', block, re.MULTILINE)
        if name_m and ver_m:
            name = name_m.group(1)
            version = ver_m.group(1)
            snippet = f'{name} = "{version}"'
            deps.append(_Dep(name=name, version=version, ecosystem=ecosystem,
                             manifest_file=rel_path, is_direct=False,
                             code_snippet=snippet))

    return deps


# ===================================================================
# Packagist (PHP) ecosystem parser
# ===================================================================

def _parse_composer_lock(abs_path: str, rel_path: str) -> list[_Dep]:
    """Parse composer.lock (JSON format)."""
    try:
        with open(abs_path, "r", encoding="utf-8", errors="replace") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("SCA: cannot parse %s: %s", rel_path, exc)
        return []

    deps: list[_Dep] = []
    ecosystem = _ECOSYSTEM_MAP["composer.lock"]

    for section in ("packages", "packages-dev"):
        for pkg in (data.get(section) or []):
            name = pkg.get("name", "")
            version = (pkg.get("version") or "").lstrip("v")
            if not name or not version:
                continue
            snippet = f'"{name}": "{version}"'
            pkg_licenses = pkg.get("license", [])
            pkg_license = pkg_licenses[0] if pkg_licenses else None
            deps.append(_Dep(
                name=name,
                version=version,
                ecosystem=ecosystem,
                manifest_file=rel_path,
                is_direct=(section == "packages"),
                code_snippet=snippet,
                license_id=pkg_license,
            ))

    return deps


# ===================================================================
# Version helpers
# ===================================================================

def _clean_npm_version(raw: str) -> str:
    """Strip semver range operators to get a concrete version for OSV queries.

    e.g. "^4.17.20" -> "4.17.20", "~1.2.3" -> "1.2.3", ">=2.0.0" -> "2.0.0"
    If the specifier is a URL, tag, or wildcard, return empty string.
    """
    if not raw:
        return ""
    stripped = raw.strip()
    # Skip non-version specifiers
    if stripped.startswith(("git+", "http:", "https:", "file:", "link:")) or stripped in ("*", "latest"):
        return ""
    # Remove leading range chars
    cleaned = re.sub(r"^[\^~>=<|! ]+", "", stripped)
    # Take the first version if there are multiple separated by space or ||
    cleaned = re.split(r"[\s|]+", cleaned)[0]
    # Validate it looks like a version
    if re.match(r"^\d+", cleaned):
        return cleaned
    return ""


# ===================================================================
# Deduplication
# ===================================================================

def _deduplicate_deps(deps: list[_Dep]) -> list[_Dep]:
    """Remove duplicates by ecosystem+name+version, keeping first occurrence."""
    seen: set[str] = set()
    result: list[_Dep] = []
    for dep in deps:
        key = f"{dep.ecosystem}:{dep.name}:{dep.version}"
        if key not in seen:
            seen.add(key)
            result.append(dep)
    return result


# ===================================================================
# OSV vulnerability querying
# ===================================================================

async def _query_osv(deps: list[_Dep]) -> dict[str, list[dict]]:
    """Query OSV in batches and return a mapping of dep_key -> list of vulns.

    Network errors are handled gracefully: the function returns whatever
    results have been gathered so far rather than raising.
    """
    vuln_map: dict[str, list[dict]] = {}

    if not deps:
        return vuln_map

    # Build batches of up to OSV_BATCH_SIZE queries
    batches: list[list[_Dep]] = []
    for i in range(0, len(deps), OSV_BATCH_SIZE):
        batches.append(deps[i : i + OSV_BATCH_SIZE])

    logger.info("SCA: querying OSV for %d packages in %d batch(es)", len(deps), len(batches))

    async with httpx.AsyncClient(timeout=httpx.Timeout(OSV_TIMEOUT_SECONDS)) as client:
        for batch_idx, batch in enumerate(batches):
            queries = [dep.osv_query() for dep in batch]
            payload = {"queries": queries}

            try:
                resp = await client.post(OSV_BATCH_URL, json=payload)
                resp.raise_for_status()
                data = resp.json()
            except httpx.TimeoutException:
                logger.warning("SCA: OSV batch %d/%d timed out — returning partial results",
                               batch_idx + 1, len(batches))
                break
            except httpx.HTTPStatusError as exc:
                logger.warning("SCA: OSV batch %d/%d HTTP error %s — returning partial results",
                               batch_idx + 1, len(batches), exc.response.status_code)
                break
            except httpx.HTTPError as exc:
                logger.warning("SCA: OSV batch %d/%d network error: %s — returning partial results",
                               batch_idx + 1, len(batches), exc)
                break
            except Exception as exc:
                logger.warning("SCA: OSV batch %d/%d unexpected error: %s — returning partial results",
                               batch_idx + 1, len(batches), exc)
                break

            results = data.get("results", [])
            for dep, result in zip(batch, results):
                vulns = result.get("vulns", [])
                if vulns:
                    dep_key = f"{dep.ecosystem}:{dep.name}:{dep.version}"
                    vuln_map[dep_key] = vulns

            logger.info("SCA: OSV batch %d/%d returned %d vulnerable packages",
                        batch_idx + 1, len(batches),
                        sum(1 for r in results if r.get("vulns")))

    return vuln_map


# ===================================================================
# Severity & CWE extraction helpers
# ===================================================================

def _extract_severity(vuln: dict) -> str:
    """Extract a normalized severity string from an OSV vulnerability entry.

    OSV provides severity via several paths:
      1. severity[].type == "CVSS_V3" -> score string -> parse base score
      2. database_specific.severity
      3. ecosystem_specific.severity
    Falls back to "medium" if nothing can be determined.
    """
    # 1. Try CVSS vector in severity array
    for sev in vuln.get("severity", []):
        if sev.get("type") in ("CVSS_V3", "CVSS_V4"):
            score = _cvss_score_from_vector(sev.get("score", ""))
            if score is not None:
                return _score_to_severity(score)

    # 2. Try database_specific.severity (often a textual label)
    db_specific = vuln.get("database_specific", {})
    if isinstance(db_specific, dict):
        raw = db_specific.get("severity", "")
        if isinstance(raw, str):
            mapped = _SEVERITY_MAP.get(raw.upper())
            if mapped:
                return mapped
        # GitHub Advisory uses cvss.score
        cvss_obj = db_specific.get("cvss", {})
        if isinstance(cvss_obj, dict):
            score = cvss_obj.get("score")
            if isinstance(score, (int, float)):
                return _score_to_severity(float(score))

    # 3. Try ecosystem_specific.severity
    eco_specific = vuln.get("ecosystem_specific", {})
    if isinstance(eco_specific, dict):
        raw = eco_specific.get("severity", "")
        if isinstance(raw, str):
            mapped = _SEVERITY_MAP.get(raw.upper())
            if mapped:
                return mapped

    return "medium"


def _cvss_score_from_vector(vector: str) -> float | None:
    """Attempt to extract a numeric base score from a CVSS vector string.

    Some OSV entries put the score directly (e.g. "7.5"), others provide
    the full vector.  We look for a number first.
    """
    if not vector:
        return None
    # If the string is just a number, use it
    try:
        return float(vector)
    except ValueError:
        pass
    # Try to find a "baseScore:X.X" style in the vector
    m = re.search(r"(\d+\.?\d*)", vector)
    if m:
        try:
            return float(m.group(1))
        except ValueError:
            pass
    return None


def _score_to_severity(score: float) -> str:
    """Map a numeric CVSS score to a severity label."""
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def _extract_cwe(vuln: dict) -> str:
    """Extract the first CWE identifier from an OSV vulnerability.

    Returns "CWE-1035" (vulnerable components) as fallback.
    """
    # database_specific may contain cwes or cwe_ids
    db = vuln.get("database_specific", {})
    if isinstance(db, dict):
        for key in ("cwe_ids", "cwes", "cwe"):
            val = db.get(key)
            if isinstance(val, list) and val:
                first = val[0]
                if isinstance(first, str) and first.startswith("CWE-"):
                    return first
                if isinstance(first, dict):
                    cid = first.get("id", "")
                    if cid.startswith("CWE-"):
                        return cid

    # Scan aliases for a CWE reference
    for alias in vuln.get("aliases", []):
        if isinstance(alias, str) and alias.startswith("CWE-"):
            return alias

    # Default: CWE-1035 — Using Components with Known Vulnerabilities
    return "CWE-1035"
