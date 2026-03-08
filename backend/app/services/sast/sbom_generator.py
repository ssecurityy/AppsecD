"""Software Bill of Materials (SBOM) generator — CycloneDX 1.5 and SPDX 2.3 JSON."""
import logging
import re
import uuid
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# Mapping from common ecosystem names to PURL type qualifiers.
# https://github.com/package-url/purl-spec/blob/master/PURL-TYPES.rst
ECOSYSTEM_PURL_MAP: dict[str, str] = {
    "npm": "npm",
    "pypi": "pypi",
    "go": "golang",
    "maven": "maven",
    "rubygems": "gem",
    "cargo": "cargo",
    "nuget": "nuget",
    "packagist": "composer",
}

# Characters that must be percent-encoded in PURL name/version segments.
_PURL_UNSAFE = re.compile(r"[^A-Za-z0-9._~-]")


def _purl_encode(segment: str) -> str:
    """Percent-encode a PURL segment (name or version)."""
    return _PURL_UNSAFE.sub(lambda m: f"%{ord(m.group()):02X}", segment)


class SBOMGenerator:
    """Generate SBOM from scan dependencies in CycloneDX and SPDX formats."""

    # ------------------------------------------------------------------
    # Package URL
    # ------------------------------------------------------------------

    @staticmethod
    def _make_purl(name: str, version: str, ecosystem: str) -> str:
        """Generate a Package URL (purl) string.

        Examples:
            pkg:npm/lodash@4.17.21
            pkg:pypi/requests@2.28.0
            pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1

        See https://github.com/package-url/purl-spec
        """
        purl_type = ECOSYSTEM_PURL_MAP.get(ecosystem.lower(), ecosystem.lower())
        encoded_name = _purl_encode(name)
        encoded_version = _purl_encode(version)
        return f"pkg:{purl_type}/{encoded_name}@{encoded_version}"

    # ------------------------------------------------------------------
    # CycloneDX 1.5
    # ------------------------------------------------------------------

    @classmethod
    def generate_cyclonedx(
        cls,
        scan_session_id: str,
        project_name: str,
        dependencies: list[dict],
        language_stats: dict,
        organization_name: str = "",
    ) -> dict:
        """Generate a CycloneDX 1.5 SBOM.

        Args:
            scan_session_id: UUID of the SAST scan session that produced the dep list.
            project_name: Human-readable project name used as the root component.
            dependencies: List of dependency dicts.  Each must contain at least
                ``name``, ``version``, and ``ecosystem``.  Optional keys:
                ``license_id``, ``is_direct``, ``vulnerabilities``.
            language_stats: Language breakdown dict (e.g. ``{"Python": 65, "JS": 35}``).
            organization_name: Org name shown in ``metadata.manufacture``.

        Returns:
            A dict conforming to the CycloneDX 1.5 JSON schema.
        """
        serial = f"urn:uuid:{uuid.uuid4()}"
        timestamp = datetime.now(timezone.utc).isoformat()

        components: list[dict] = []
        vulnerabilities: list[dict] = []

        for dep in dependencies:
            dep_name: str = dep.get("name", "unknown")
            dep_version: str = dep.get("version", "0.0.0")
            dep_ecosystem: str = dep.get("ecosystem", "unknown")
            purl = cls._make_purl(dep_name, dep_version, dep_ecosystem)

            license_id = dep.get("license_id", "NOASSERTION")
            licenses_list: list[dict] = []
            if license_id and license_id != "NOASSERTION":
                licenses_list.append({"license": {"id": license_id}})
            else:
                licenses_list.append({"license": {"id": "NOASSERTION"}})

            component: dict = {
                "type": "library",
                "name": dep_name,
                "version": dep_version,
                "purl": purl,
                "bom-ref": purl,
                "licenses": licenses_list,
                "properties": [
                    {"name": "navigator:ecosystem", "value": dep_ecosystem},
                    {"name": "navigator:is_direct", "value": str(dep.get("is_direct", True))},
                ],
            }
            components.append(component)

            # Collect vulnerabilities attached to this dependency.
            for vuln in dep.get("vulnerabilities", []):
                ratings: list[dict] = []
                severity = vuln.get("severity", "UNKNOWN")
                rating_entry: dict = {"severity": severity}
                cvss_score = vuln.get("cvss")
                if cvss_score is not None:
                    rating_entry["score"] = cvss_score
                ratings.append(rating_entry)

                vuln_entry: dict = {
                    "id": vuln.get("osv_id", vuln.get("id", f"VULN-{uuid.uuid4().hex[:8]}")),
                    "source": {"name": "OSV", "url": "https://osv.dev"},
                    "ratings": ratings,
                    "affects": [{"ref": purl}],
                    "description": vuln.get("summary", ""),
                }
                vulnerabilities.append(vuln_entry)

        # Language properties on the root component
        root_properties: list[dict] = [
            {"name": "navigator:scan_session_id", "value": scan_session_id},
        ]
        for lang, pct in language_stats.items():
            root_properties.append({"name": f"navigator:language:{lang}", "value": str(pct)})

        metadata: dict = {
            "timestamp": timestamp,
            "tools": [
                {
                    "vendor": "Navigator",
                    "name": "SAST Scanner",
                    "version": "1.0",
                },
            ],
            "component": {
                "type": "application",
                "name": project_name,
                "bom-ref": "project-root",
                "properties": root_properties,
            },
        }
        if organization_name:
            metadata["manufacture"] = {"name": organization_name}

        bom: dict = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": serial,
            "version": 1,
            "metadata": metadata,
            "components": components,
        }

        if vulnerabilities:
            bom["vulnerabilities"] = vulnerabilities

        logger.info(
            "CycloneDX SBOM generated: %d components, %d vulnerabilities (scan %s)",
            len(components),
            len(vulnerabilities),
            scan_session_id,
        )
        return bom

    # ------------------------------------------------------------------
    # SPDX 2.3
    # ------------------------------------------------------------------

    @classmethod
    def generate_spdx(
        cls,
        scan_session_id: str,
        project_name: str,
        dependencies: list[dict],
        language_stats: dict,
        organization_name: str = "",
    ) -> dict:
        """Generate an SPDX 2.3 SBOM.

        Args:
            scan_session_id: UUID of the SAST scan session.
            project_name: Human-readable project name.
            dependencies: List of dependency dicts (same schema as CycloneDX).
            language_stats: Language breakdown dict.
            organization_name: Org name for creator field.

        Returns:
            A dict conforming to the SPDX 2.3 JSON schema.
        """
        doc_namespace = f"https://navigator.app/spdx/{scan_session_id}/{uuid.uuid4()}"
        timestamp = datetime.now(timezone.utc).isoformat()

        creators: list[str] = ["Tool: Navigator-SAST-1.0"]
        if organization_name:
            creators.append(f"Organization: {organization_name}")

        packages: list[dict] = []
        relationships: list[dict] = []

        for dep in dependencies:
            dep_name: str = dep.get("name", "unknown")
            dep_version: str = dep.get("version", "0.0.0")
            dep_ecosystem: str = dep.get("ecosystem", "unknown")
            purl = cls._make_purl(dep_name, dep_version, dep_ecosystem)

            # SPDX IDs must match [A-Za-z0-9.-]+ after the prefix.
            safe_name = re.sub(r"[^A-Za-z0-9._-]", "-", dep_name)
            safe_version = re.sub(r"[^A-Za-z0-9._-]", "-", dep_version)
            spdx_id = f"SPDXRef-Package-{dep_ecosystem}-{safe_name}-{safe_version}"

            license_id = dep.get("license_id", "NOASSERTION")

            package: dict = {
                "SPDXID": spdx_id,
                "name": dep_name,
                "versionInfo": dep_version,
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "supplier": "NOASSERTION",
                "licenseConcluded": license_id,
                "licenseDeclared": license_id,
                "copyrightText": "NOASSERTION",
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": purl,
                    },
                ],
            }

            # Attach vulnerability annotations as SPDX annotations if present.
            if dep.get("vulnerabilities"):
                vuln_ids = [v.get("osv_id", v.get("id", "unknown")) for v in dep["vulnerabilities"]]
                package["comment"] = f"Known vulnerabilities: {', '.join(vuln_ids)}"

            packages.append(package)

            # DESCRIBES relationship from document to each package
            relationships.append({
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": spdx_id,
            })

            # Dependency relationships — direct vs transitive
            is_direct = dep.get("is_direct", True)
            if is_direct:
                relationships.append({
                    "spdxElementId": "SPDXRef-DOCUMENT",
                    "relationshipType": "DEPENDS_ON",
                    "relatedSpdxElement": spdx_id,
                })

        spdx_doc: dict = {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": project_name,
            "documentNamespace": doc_namespace,
            "creationInfo": {
                "created": timestamp,
                "creators": creators,
                "licenseListVersion": "3.19",
            },
            "packages": packages,
            "relationships": relationships,
        }

        logger.info(
            "SPDX SBOM generated: %d packages, %d relationships (scan %s)",
            len(packages),
            len(relationships),
            scan_session_id,
        )
        return spdx_doc

    # ------------------------------------------------------------------
    # SBOM Comparison / Drift Detection
    # ------------------------------------------------------------------

    @classmethod
    def compare_sboms(cls, sbom_a: dict, sbom_b: dict) -> dict:
        """Compare two SBOMs for dependency drift detection.

        Accepts either CycloneDX or SPDX format for both inputs.  The two SBOMs
        do *not* need to be in the same format — components are normalised to
        ``(name, version)`` tuples internally.

        Returns:
            {
                "added_components": [...],
                "removed_components": [...],
                "version_changes": [{"name": ..., "old": ..., "new": ...}],
                "new_vulnerabilities": [...],
                "fixed_vulnerabilities": [...],
            }
        """
        comps_a = cls._extract_components(sbom_a)
        comps_b = cls._extract_components(sbom_b)

        vulns_a = cls._extract_vulnerabilities(sbom_a)
        vulns_b = cls._extract_vulnerabilities(sbom_b)

        # Build lookup maps keyed by component name.
        map_a: dict[str, dict] = {c["name"]: c for c in comps_a}
        map_b: dict[str, dict] = {c["name"]: c for c in comps_b}

        names_a = set(map_a.keys())
        names_b = set(map_b.keys())

        added = [map_b[n] for n in sorted(names_b - names_a)]
        removed = [map_a[n] for n in sorted(names_a - names_b)]

        version_changes: list[dict] = []
        for name in sorted(names_a & names_b):
            old_ver = map_a[name].get("version", "")
            new_ver = map_b[name].get("version", "")
            if old_ver != new_ver:
                version_changes.append({
                    "name": name,
                    "old": old_ver,
                    "new": new_ver,
                })

        # Vulnerability diff
        vuln_ids_a = {v.get("id", "") for v in vulns_a}
        vuln_ids_b = {v.get("id", "") for v in vulns_b}

        vuln_map_a = {v.get("id", ""): v for v in vulns_a}
        vuln_map_b = {v.get("id", ""): v for v in vulns_b}

        new_vulnerabilities = [vuln_map_b[vid] for vid in sorted(vuln_ids_b - vuln_ids_a)]
        fixed_vulnerabilities = [vuln_map_a[vid] for vid in sorted(vuln_ids_a - vuln_ids_b)]

        result = {
            "added_components": added,
            "removed_components": removed,
            "version_changes": version_changes,
            "new_vulnerabilities": new_vulnerabilities,
            "fixed_vulnerabilities": fixed_vulnerabilities,
        }

        logger.info(
            "SBOM comparison: +%d -%d components, %d version changes, +%d -%d vulnerabilities",
            len(added),
            len(removed),
            len(version_changes),
            len(new_vulnerabilities),
            len(fixed_vulnerabilities),
        )
        return result

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_components(sbom: dict) -> list[dict]:
        """Extract a normalised component list from either format.

        Returns list of ``{"name": ..., "version": ..., "purl": ...}``.
        """
        components: list[dict] = []

        # CycloneDX path
        if sbom.get("bomFormat") == "CycloneDX":
            for comp in sbom.get("components", []):
                components.append({
                    "name": comp.get("name", ""),
                    "version": comp.get("version", ""),
                    "purl": comp.get("purl", ""),
                })
            return components

        # SPDX path
        if sbom.get("spdxVersion", "").startswith("SPDX"):
            for pkg in sbom.get("packages", []):
                purl = ""
                for ref in pkg.get("externalRefs", []):
                    if ref.get("referenceType") == "purl":
                        purl = ref.get("referenceLocator", "")
                        break
                components.append({
                    "name": pkg.get("name", ""),
                    "version": pkg.get("versionInfo", ""),
                    "purl": purl,
                })
            return components

        logger.warning("Unknown SBOM format — returning empty component list")
        return components

    @staticmethod
    def _extract_vulnerabilities(sbom: dict) -> list[dict]:
        """Extract a normalised vulnerability list from either format.

        Returns list of ``{"id": ..., "severity": ..., "affects": ..., "description": ...}``.
        """
        vulns: list[dict] = []

        # CycloneDX stores vulnerabilities at the top level.
        if sbom.get("bomFormat") == "CycloneDX":
            for v in sbom.get("vulnerabilities", []):
                severity = "UNKNOWN"
                if v.get("ratings"):
                    severity = v["ratings"][0].get("severity", "UNKNOWN")
                affects = [a.get("ref", "") for a in v.get("affects", [])]
                vulns.append({
                    "id": v.get("id", ""),
                    "severity": severity,
                    "affects": affects,
                    "description": v.get("description", ""),
                })
            return vulns

        # SPDX does not have a first-class vulnerability section in 2.3.
        # We extract from package comments if we previously embedded them.
        if sbom.get("spdxVersion", "").startswith("SPDX"):
            for pkg in sbom.get("packages", []):
                comment = pkg.get("comment", "")
                if comment.startswith("Known vulnerabilities:"):
                    ids_str = comment.replace("Known vulnerabilities:", "").strip()
                    for vid in ids_str.split(","):
                        vid = vid.strip()
                        if vid:
                            vulns.append({
                                "id": vid,
                                "severity": "UNKNOWN",
                                "affects": [pkg.get("name", "")],
                                "description": "",
                            })
            return vulns

        return vulns

    # ------------------------------------------------------------------
    # VEX (Vulnerability Exploitability Exchange) Generation
    # ------------------------------------------------------------------

    @staticmethod
    def generate_vex_cyclonedx(
        scan_session_id: str,
        project_name: str,
        dependencies: list[dict],
        reachability_results: dict | None = None,
    ) -> dict:
        """Generate a CycloneDX VEX document.

        VEX classifies each vulnerability as:
        - affected: Vulnerability is exploitable
        - not_affected: Vulnerability exists but is not exploitable
        - fixed: Vulnerability has been fixed
        - under_investigation: Assessment in progress

        Required for EU Cyber Resilience Act (CRA) compliance (Sept 2026 deadline).

        Args:
            scan_session_id: UUID of the scan session
            project_name: Project name for metadata
            dependencies: List of dependency dicts from SCA scan
            reachability_results: Optional reachability analysis results
                {dep_name: {"reachable": bool, "imports": [...], "reason": str}}

        Returns:
            CycloneDX VEX JSON dict
        """
        reachability = reachability_results or {}
        now = datetime.now(timezone.utc).isoformat()

        vulnerabilities = []
        for dep in dependencies:
            dep_vulns = dep.get("vulnerabilities") or []
            if not dep_vulns:
                continue

            dep_name = dep.get("name", "unknown")
            dep_version = dep.get("version", "")
            ecosystem = dep.get("ecosystem", "unknown")
            bom_ref = f"{ecosystem}:{dep_name}@{dep_version}"

            reach_info = reachability.get(dep_name, {})
            is_reachable = reach_info.get("reachable", True)

            for vuln in dep_vulns:
                vuln_id = vuln if isinstance(vuln, str) else vuln.get("id", "")
                if not vuln_id:
                    continue

                if not is_reachable:
                    status = "not_affected"
                    justification = "code_not_reachable"
                    detail = f"Vulnerable code path in {dep_name} is not imported or called."
                    if reach_info.get("reason"):
                        detail += f" Reason: {reach_info['reason']}"
                else:
                    status = "affected"
                    justification = None
                    detail = f"Dependency {dep_name}@{dep_version} is imported and potentially reachable."

                vuln_entry = {
                    "id": vuln_id,
                    "source": {"name": "OSV", "url": f"https://osv.dev/vulnerability/{vuln_id}"},
                    "analysis": {"state": status, "detail": detail},
                    "affects": [{"ref": bom_ref}],
                    "properties": [
                        {"name": "navigator:reachable", "value": str(is_reachable).lower()},
                    ],
                }
                if justification:
                    vuln_entry["analysis"]["justification"] = justification
                if isinstance(vuln, dict) and vuln.get("severity"):
                    vuln_entry["ratings"] = [{"severity": vuln["severity"].upper()}]
                if status == "affected":
                    vuln_entry["analysis"]["response"] = ["update"]
                elif status == "not_affected":
                    vuln_entry["analysis"]["response"] = ["will_not_fix"]

                vulnerabilities.append(vuln_entry)

        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "metadata": {
                "timestamp": now,
                "component": {
                    "type": "application",
                    "name": project_name,
                    "bom-ref": f"project:{project_name}",
                },
                "tools": [{"vendor": "Navigator", "name": "Navigator SAST VEX Generator", "version": "2.0.0"}],
            },
            "vulnerabilities": vulnerabilities,
        }

    @staticmethod
    def generate_vex_csaf(
        scan_session_id: str,
        project_name: str,
        dependencies: list[dict],
        reachability_results: dict | None = None,
    ) -> dict:
        """Generate a CSAF VEX document (Common Security Advisory Framework).

        CSAF VEX is the OASIS standard, required for EU CRA compliance.

        Returns:
            CSAF VEX JSON dict
        """
        reachability = reachability_results or {}
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        product_tree_branches = []
        vulnerabilities_csaf = []
        seen_products: set[str] = set()

        for dep in dependencies:
            dep_vulns = dep.get("vulnerabilities") or []
            if not dep_vulns:
                continue
            dep_name = dep.get("name", "unknown")
            dep_version = dep.get("version", "")
            ecosystem = dep.get("ecosystem", "unknown")
            product_id = f"{ecosystem}:{dep_name}:{dep_version}"
            if product_id not in seen_products:
                seen_products.add(product_id)
                product_tree_branches.append({
                    "category": "product_version",
                    "name": f"{dep_name}@{dep_version}",
                    "product": {"product_id": product_id, "name": f"{dep_name} {dep_version}"},
                })
            reach_info = reachability.get(dep_name, {})
            is_reachable = reach_info.get("reachable", True)
            for vuln in dep_vulns:
                vuln_id = vuln if isinstance(vuln, str) else vuln.get("id", "")
                if not vuln_id:
                    continue
                status = "known_affected" if is_reachable else "known_not_affected"
                csaf_vuln: dict = {
                    "ids": [{"system_name": "OSV", "text": vuln_id}],
                    "title": f"Vulnerability in {dep_name}",
                    "product_status": {status: [product_id]},
                    "threats": [{
                        "category": "impact",
                        "details": f"{'Reachable' if is_reachable else 'Not reachable'} in project {project_name}",
                        "product_ids": [product_id],
                    }],
                }
                if vuln_id.startswith("CVE-"):
                    csaf_vuln["cve"] = vuln_id
                if not is_reachable:
                    csaf_vuln["flags"] = [{
                        "label": "vulnerable_code_not_in_execute_path",
                        "product_ids": [product_id],
                    }]
                vulnerabilities_csaf.append(csaf_vuln)

        return {
            "document": {
                "category": "csaf_vex",
                "csaf_version": "2.0",
                "title": f"VEX for {project_name}",
                "publisher": {"category": "tool", "name": "Navigator SAST", "namespace": "https://appsecd.com"},
                "tracking": {
                    "current_release_date": now,
                    "id": f"navigator-vex-{scan_session_id}",
                    "initial_release_date": now,
                    "revision_history": [{"date": now, "number": "1", "summary": "Initial VEX document"}],
                    "status": "final",
                    "version": "1",
                },
            },
            "product_tree": {"branches": product_tree_branches},
            "vulnerabilities": vulnerabilities_csaf,
        }
