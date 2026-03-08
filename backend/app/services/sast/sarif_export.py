"""SARIF 2.1.0 export for SAST findings.

Enhanced with:
- Suppression tracking for false_positive/ignored/wont_fix findings
- Full invocation metadata (command line, timing, exit code)
- Scanner source tags per finding
- Configurable tool name/version
- Related locations for multi-file findings
- Baseline GUID support for trend comparison
- GitHub Code Scanning, Azure DevOps, VS Code SARIF Viewer compatible
"""
import json
import uuid
from datetime import datetime
from typing import Optional


# Scanner source to SARIF tag mapping
SCANNER_TAGS = {
    "semgrep": ["security", "sast", "semgrep"],
    "sca": ["security", "sca", "dependency"],
    "iac": ["security", "iac", "infrastructure"],
    "secret_scan": ["security", "secrets", "credentials"],
    "claude_review": ["security", "ai-review", "claude"],
    "js_deep": ["security", "javascript", "deep-analysis"],
    "container": ["security", "container", "docker"],
    "license": ["compliance", "license"],
    "custom": ["security", "custom-rule"],
}


def export_sarif(
    findings: list[dict],
    scan_info: dict,
    tool_name: str = "Navigator SAST",
    tool_version: str = "2.0.0",
    tool_uri: str = "https://appsecd.com",
    baseline_guid: str | None = None,
    include_suppressed: bool = True,
) -> dict:
    """Export findings as SARIF 2.1.0 JSON.

    Compatible with GitHub Code Scanning, Azure DevOps, VS Code SARIF Viewer.

    Args:
        findings: List of finding dicts from scan pipeline
        scan_info: Scan session metadata (id, created_at, completed_at, status, etc.)
        tool_name: Configurable tool display name
        tool_version: Tool version string
        tool_uri: Tool information URI
        baseline_guid: Optional GUID of baseline scan for comparison
        include_suppressed: Whether to include suppressed findings (with suppressions array)
    """
    run_guid = str(uuid.uuid4())

    # Collect unique rules with enhanced metadata
    rules_map = {}
    for f in findings:
        rid = f.get("rule_id", "unknown")
        if rid not in rules_map:
            source = f.get("rule_source", "semgrep")
            tags = SCANNER_TAGS.get(source, ["security"])
            if f.get("cwe_id"):
                tags.append(f"external/cwe/{f['cwe_id']}")
            if f.get("owasp_category"):
                tags.append(f"external/owasp/{f['owasp_category']}")

            rule = {
                "id": rid,
                "shortDescription": {"text": f.get("title", rid)[:256]},
                "fullDescription": {"text": (f.get("description", "") or "")[:2000]},
                "defaultConfiguration": {
                    "level": _severity_to_sarif_level(f.get("severity", "medium")),
                },
                "properties": {
                    "tags": tags,
                    "security-severity": _severity_to_score(f.get("severity", "medium")),
                    "source": source,
                },
                "helpUri": _get_help_uri(f),
            }

            # Add CWE reference if available
            if f.get("cwe_id"):
                rule["relationships"] = [{
                    "target": {
                        "id": f["cwe_id"],
                        "guid": str(uuid.uuid5(uuid.NAMESPACE_URL, f"https://cwe.mitre.org/data/definitions/{f['cwe_id'].replace('CWE-', '')}.html")),
                        "toolComponent": {"name": "CWE", "index": 0},
                    },
                    "kinds": ["superset"],
                }]

            rules_map[rid] = rule

    # Build results with full SARIF features
    results = []
    rule_index = {rid: idx for idx, rid in enumerate(rules_map)}

    for f in findings:
        status = f.get("status", "open")
        is_suppressed = status in ("false_positive", "ignored", "wont_fix")

        # Skip suppressed if not requested
        if is_suppressed and not include_suppressed:
            continue

        result = {
            "ruleId": f.get("rule_id", "unknown"),
            "ruleIndex": rule_index.get(f.get("rule_id", "unknown"), 0),
            "level": _severity_to_sarif_level(f.get("severity", "medium")),
            "message": {
                "text": f.get("message") or f.get("title", ""),
                "markdown": _build_markdown_message(f),
            },
            "locations": [_build_location(f)],
            "fingerprints": {
                "primaryLocationHash": f.get("fingerprint", ""),
            },
            "partialFingerprints": {
                "primaryLocationLineHash": f.get("fingerprint", "")[:16] if f.get("fingerprint") else "",
            },
            "properties": {
                "security-severity": _severity_to_score(f.get("severity", "medium")),
                "source": f.get("rule_source", "semgrep"),
                "confidence": str(f.get("confidence", "medium")),
            },
        }

        # Add suppressions for false_positive/ignored/wont_fix findings
        if is_suppressed:
            suppression = {
                "kind": "inSource" if status == "false_positive" else "external",
                "status": _status_to_suppression_status(status),
            }
            ai_analysis = f.get("ai_analysis", {})
            if isinstance(ai_analysis, dict):
                justification = ai_analysis.get("suppression_reason") or ai_analysis.get("reason", "")
                if justification:
                    suppression["justification"] = {"text": justification[:500]}
            result["suppressions"] = [suppression]

        # Add fix suggestions
        if f.get("fix_suggestion"):
            fix = {
                "description": {"text": f["fix_suggestion"][:1000]},
            }
            if f.get("fixed_code"):
                fix["artifactChanges"] = [{
                    "artifactLocation": {
                        "uri": f.get("file_path", ""),
                        "uriBaseId": "%SRCROOT%",
                    },
                    "replacements": [{
                        "deletedRegion": {
                            "startLine": f.get("line_start") or 1,
                            "endLine": f.get("line_end") or f.get("line_start") or 1,
                        },
                        "insertedContent": {"text": f["fixed_code"][:5000]},
                    }],
                }]
            result["fixes"] = [fix]

        # Add related locations for multi-file findings
        related = f.get("related_locations", [])
        if related:
            result["relatedLocations"] = [
                {
                    "id": idx,
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": rl.get("file_path", ""),
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine": rl.get("line_start", 1),
                        },
                    },
                    "message": {"text": rl.get("message", "Related location")},
                }
                for idx, rl in enumerate(related)
            ]

        # Add code flow for data flow findings (injection, SSRF, etc.)
        if f.get("data_flow"):
            result["codeFlows"] = [_build_code_flow(f["data_flow"])]

        results.append(result)

    # Build invocation with full metadata
    invocation = _build_invocation(scan_info)

    # Build the run object
    run = {
        "tool": {
            "driver": {
                "name": tool_name,
                "version": tool_version,
                "semanticVersion": tool_version,
                "informationUri": tool_uri,
                "rules": list(rules_map.values()),
                "properties": {
                    "scanners": list(set(f.get("rule_source", "semgrep") for f in findings)),
                },
            },
            "extensions": _build_extensions(findings),
        },
        "invocations": [invocation],
        "results": results,
        "automationDetails": {
            "id": f"{scan_info.get('id', 'unknown')}/",
            "guid": run_guid,
        },
    }

    # Add baseline GUID for comparison
    if baseline_guid:
        run["baselineGuid"] = baseline_guid

    # Add artifacts (files scanned)
    if scan_info.get("files_scanned"):
        unique_files = set(f.get("file_path", "") for f in findings if f.get("file_path"))
        run["artifacts"] = [
            {
                "location": {"uri": fp, "uriBaseId": "%SRCROOT%"},
                "roles": ["analysisTarget"],
            }
            for fp in sorted(unique_files)
        ]

    # Add taxonomies for CWE references
    cwe_ids = set(f.get("cwe_id", "") for f in findings if f.get("cwe_id"))
    if cwe_ids:
        run["taxonomies"] = [{
            "name": "CWE",
            "version": "4.13",
            "informationUri": "https://cwe.mitre.org/data/published/cwe_v4.13.pdf",
            "organization": "MITRE",
            "shortDescription": {"text": "Common Weakness Enumeration"},
            "taxa": [
                {
                    "id": cwe_id,
                    "guid": str(uuid.uuid5(uuid.NAMESPACE_URL, f"https://cwe.mitre.org/{cwe_id}")),
                    "helpUri": f"https://cwe.mitre.org/data/definitions/{cwe_id.replace('CWE-', '')}.html",
                }
                for cwe_id in sorted(cwe_ids)
            ],
        }]

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [run],
    }

    return sarif


def export_sarif_json(
    findings: list[dict],
    scan_info: dict,
    **kwargs,
) -> str:
    """Export findings as SARIF 2.1.0 JSON string."""
    sarif = export_sarif(findings, scan_info, **kwargs)
    return json.dumps(sarif, indent=2, default=str)


# ── Helper Functions ──────────────────────────────────────────────────


def _severity_to_sarif_level(severity: str) -> str:
    """Map our severity to SARIF level."""
    return {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "none",
    }.get(severity, "warning")


def _severity_to_score(severity: str) -> str:
    """Map severity to CVSS-like score string for GitHub Code Scanning."""
    return {
        "critical": "9.5",
        "high": "8.0",
        "medium": "5.5",
        "low": "3.0",
        "info": "1.0",
    }.get(severity, "5.0")


def _status_to_suppression_status(status: str) -> str:
    """Map finding status to SARIF suppression status."""
    return {
        "false_positive": "acceptedRiskAccepted",
        "wont_fix": "acceptedRiskAccepted",
        "ignored": "underReview",
    }.get(status, "underReview")


def _get_help_uri(finding: dict) -> str:
    """Generate help URI for a finding."""
    cwe_id = finding.get("cwe_id", "")
    if cwe_id:
        num = cwe_id.replace("CWE-", "")
        return f"https://cwe.mitre.org/data/definitions/{num}.html"
    refs = finding.get("references", [])
    if refs and isinstance(refs, list) and refs[0]:
        return refs[0]
    return "https://appsecd.com/docs/findings"


def _build_location(finding: dict) -> dict:
    """Build a SARIF physical location from a finding."""
    location = {
        "physicalLocation": {
            "artifactLocation": {
                "uri": finding.get("file_path", ""),
                "uriBaseId": "%SRCROOT%",
            },
            "region": {
                "startLine": finding.get("line_start") or 1,
                "endLine": finding.get("line_end") or finding.get("line_start") or 1,
            },
        },
    }

    if finding.get("column_start"):
        location["physicalLocation"]["region"]["startColumn"] = finding["column_start"]
    if finding.get("column_end"):
        location["physicalLocation"]["region"]["endColumn"] = finding["column_end"]
    if finding.get("code_snippet"):
        location["physicalLocation"]["region"]["snippet"] = {
            "text": finding["code_snippet"][:1000],
        }

    return location


def _build_markdown_message(finding: dict) -> str:
    """Build a rich markdown message for the finding."""
    parts = []

    title = finding.get("title", "Security Issue")
    parts.append(f"**{title}**")

    if finding.get("description"):
        parts.append(finding["description"][:500])

    if finding.get("message") and finding["message"] != title:
        parts.append(f"\n**Exploit Scenario:** {finding['message'][:300]}")

    if finding.get("cwe_id"):
        cwe_num = finding["cwe_id"].replace("CWE-", "")
        parts.append(f"\n[{finding['cwe_id']}](https://cwe.mitre.org/data/definitions/{cwe_num}.html)")

    if finding.get("fix_suggestion"):
        parts.append(f"\n**Remediation:** {finding['fix_suggestion'][:300]}")

    return "\n".join(parts)


def _build_invocation(scan_info: dict) -> dict:
    """Build a full SARIF invocation object."""
    status = scan_info.get("status", "completed")
    invocation = {
        "executionSuccessful": status in ("completed", "done"),
        "startTimeUtc": scan_info.get("created_at", datetime.utcnow().isoformat()),
        "endTimeUtc": scan_info.get("completed_at", datetime.utcnow().isoformat()),
        "properties": {
            "scanType": scan_info.get("scan_type", "full"),
            "totalFiles": scan_info.get("total_files", 0),
            "filesScanned": scan_info.get("files_scanned", 0),
            "totalIssues": scan_info.get("total_issues", 0),
            "scanDurationSeconds": scan_info.get("scan_duration_seconds", 0),
        },
    }

    if scan_info.get("error_message"):
        invocation["toolExecutionNotifications"] = [{
            "level": "error",
            "message": {"text": scan_info["error_message"][:500]},
        }]

    if scan_info.get("language_stats"):
        invocation["properties"]["languageStats"] = scan_info["language_stats"]

    if scan_info.get("scan_config"):
        invocation["properties"]["scanConfig"] = scan_info["scan_config"]

    # Scanner breakdown
    scanner_counts = scan_info.get("scanner_counts", {})
    if scanner_counts:
        invocation["properties"]["scannerBreakdown"] = scanner_counts

    return invocation


def _build_extensions(findings: list[dict]) -> list[dict]:
    """Build tool extensions for each scanner type used."""
    sources = set(f.get("rule_source", "semgrep") for f in findings)
    extensions = []

    extension_info = {
        "semgrep": ("Semgrep", "https://semgrep.dev"),
        "sca": ("SCA Scanner", "https://osv.dev"),
        "iac": ("IaC Scanner", "https://appsecd.com/docs/iac"),
        "secret_scan": ("Secret Scanner", "https://appsecd.com/docs/secrets"),
        "claude_review": ("Claude AI Review", "https://anthropic.com"),
        "js_deep": ("JS/TS Analyzer", "https://appsecd.com/docs/js"),
        "container": ("Container Scanner", "https://appsecd.com/docs/container"),
        "license": ("License Checker", "https://appsecd.com/docs/license"),
        "custom": ("Custom Rules", "https://appsecd.com/docs/custom"),
    }

    for source in sorted(sources):
        name, uri = extension_info.get(source, (source.title(), "https://appsecd.com"))
        extensions.append({
            "name": name,
            "version": "1.0.0",
            "informationUri": uri,
        })

    return extensions


def _build_code_flow(data_flow: list[dict]) -> dict:
    """Build a SARIF codeFlow from data flow trace."""
    thread_flow_locations = []
    for step in data_flow:
        tfl = {
            "location": {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": step.get("file_path", ""),
                        "uriBaseId": "%SRCROOT%",
                    },
                    "region": {
                        "startLine": step.get("line", 1),
                    },
                },
                "message": {"text": step.get("message", "")},
            },
        }
        if step.get("kind"):
            tfl["kinds"] = [step["kind"]]
        thread_flow_locations.append(tfl)

    return {
        "threadFlows": [{
            "locations": thread_flow_locations,
        }],
    }
