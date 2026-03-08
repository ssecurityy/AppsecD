"""Policy evaluation engine — evaluates SAST scan results against org policies."""
import logging

logger = logging.getLogger(__name__)

# Severity ordering
SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def evaluate_policy(policy: dict, findings: list[dict], secrets_count: int = 0) -> dict:
    """Evaluate scan results against a policy.

    Args:
        policy: Policy dict with threshold, max_issues, fail_on_secrets, etc.
        findings: List of finding dicts
        secrets_count: Number of secrets found

    Returns: {passed: bool, violations: [...], summary: str}
    """
    violations = []

    # 1. Severity threshold check
    threshold = policy.get("severity_threshold", "critical")
    threshold_level = SEVERITY_ORDER.get(threshold, 4)

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.get("severity", "info")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    for sev, count in severity_counts.items():
        if count > 0 and SEVERITY_ORDER.get(sev, 0) >= threshold_level:
            violations.append({
                "type": "severity_threshold",
                "message": f"Found {count} {sev} issue(s) — threshold is {threshold}",
                "severity": sev,
                "count": count,
            })

    # 2. Max issues check
    max_issues = policy.get("max_issues_allowed", -1)
    if max_issues >= 0 and len(findings) > max_issues:
        violations.append({
            "type": "max_issues",
            "message": f"Total issues ({len(findings)}) exceeds maximum ({max_issues})",
            "count": len(findings),
            "max": max_issues,
        })

    # 3. Secrets check
    if policy.get("fail_on_secrets", True) and secrets_count > 0:
        violations.append({
            "type": "secrets_detected",
            "message": f"Found {secrets_count} secret(s) in code",
            "count": secrets_count,
        })

    # 4. Required fix categories
    required_cats = policy.get("required_fix_categories", [])
    if required_cats:
        finding_cats = set()
        for f in findings:
            rule_id = f.get("rule_id", "")
            # Extract category from rule_id (e.g., "python.security.injection.sql" → "injection")
            parts = rule_id.split(".")
            for part in parts:
                if part in (
                    "injection", "auth", "xss", "crypto", "ssrf", "deserialization",
                    "sqli", "sql-injection", "rce", "command-injection",
                    "path-traversal", "traversal", "secrets", "secret",
                    "xxe", "idor", "csrf", "cors", "open-redirect",
                    "insecure-transport", "hardcoded", "misconfiguration",
                    "buffer-overflow", "race-condition", "jwt",
                    "ldap-injection", "xpath-injection", "ssti",
                    "unsafe-deserialization", "prototype-pollution",
                ):
                    finding_cats.add(part)

        for cat in required_cats:
            if cat in finding_cats:
                cat_findings = [f for f in findings if cat in f.get("rule_id", "")]
                violations.append({
                    "type": "required_fix_category",
                    "message": f"Found {len(cat_findings)} issue(s) in required-fix category: {cat}",
                    "category": cat,
                    "count": len(cat_findings),
                })

    # 5. SCA critical vulnerability check
    if policy.get("fail_on_sca_critical", True):
        sca_criticals = [
            f for f in findings
            if f.get("rule_source") == "sca" and f.get("severity") == "critical"
        ]
        if sca_criticals:
            violations.append({
                "type": "sca_critical",
                "message": f"Found {len(sca_criticals)} critical dependency vulnerability(ies)",
                "count": len(sca_criticals),
            })

    # 6. KEV (Known Exploited Vulnerabilities) check
    if policy.get("fail_on_kev", True):
        kev_findings = [
            f for f in findings
            if any(
                isinstance(ref, dict) and ref.get("in_kev")
                for ref in (f.get("references") or [])
            )
        ]
        if kev_findings:
            violations.append({
                "type": "kev_detected",
                "message": f"Found {len(kev_findings)} finding(s) with known exploited vulnerabilities (CISA KEV)",
                "count": len(kev_findings),
            })

    # 7. Max dependency issues check
    max_dep = policy.get("max_dependency_issues", -1)
    if max_dep >= 0:
        sca_count = len([f for f in findings if f.get("rule_source") == "sca"])
        if sca_count > max_dep:
            violations.append({
                "type": "max_dependency_issues",
                "message": f"Dependency issues ({sca_count}) exceeds maximum ({max_dep})",
                "count": sca_count,
                "max": max_dep,
            })

    # 8. Blocked licenses check
    blocked_licenses = policy.get("blocked_licenses") or []
    if blocked_licenses:
        license_findings = [
            f for f in findings
            if f.get("rule_source") == "license" and "blocked" in f.get("rule_id", "")
        ]
        if license_findings:
            violations.append({
                "type": "blocked_licenses",
                "message": f"Found {len(license_findings)} dependency(ies) with blocked licenses",
                "count": len(license_findings),
            })

    # 9. IaC critical check
    if policy.get("fail_on_iac_critical", True):
        iac_criticals = [
            f for f in findings
            if f.get("rule_source") == "iac" and f.get("severity") == "critical"
        ]
        if iac_criticals:
            violations.append({
                "type": "iac_critical",
                "message": f"Found {len(iac_criticals)} critical IaC misconfiguration(s)",
                "count": len(iac_criticals),
            })

    # 10. Container critical check
    if policy.get("fail_on_container_critical", True):
        container_criticals = [
            f for f in findings
            if f.get("rule_source") == "container" and f.get("severity") == "critical"
        ]
        if container_criticals:
            violations.append({
                "type": "container_critical",
                "message": f"Found {len(container_criticals)} critical container issue(s)",
                "count": len(container_criticals),
            })

    passed = len(violations) == 0

    # Per-scanner breakdown
    scanner_breakdown = {}
    for f in findings:
        source = f.get("rule_source", "unknown")
        if source not in scanner_breakdown:
            scanner_breakdown[source] = {"total": 0, "by_severity": {}}
        scanner_breakdown[source]["total"] += 1
        sev = f.get("severity", "info")
        scanner_breakdown[source]["by_severity"][sev] = scanner_breakdown[source]["by_severity"].get(sev, 0) + 1

    # Summary
    if passed:
        summary = f"Policy '{policy.get('name', 'Default')}' PASSED — {len(findings)} issues found, all within thresholds"
    else:
        summary = f"Policy '{policy.get('name', 'Default')}' FAILED — {len(violations)} violation(s)"

    return {
        "passed": passed,
        "policy_name": policy.get("name", "Default"),
        "violations": violations,
        "summary": summary,
        "severity_counts": severity_counts,
        "total_issues": len(findings),
        "secrets_count": secrets_count,
        "scanner_breakdown": scanner_breakdown,
    }
