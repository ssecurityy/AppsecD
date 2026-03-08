"""Compliance reporting — generate reports mapping findings to compliance frameworks.

Supports:
- OWASP Top 10 2021
- CWE Top 25 2023
- PCI DSS v4.0 Requirement 6
- SOC 2 CC4.1 / CC7.1
- NIST 800-53 SA-11
- EU Cyber Resilience Act (CRA)
"""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime
from typing import Any

logger = logging.getLogger(__name__)

# ── OWASP Top 10 2021 ───────────────────────────────────────────────
# CWE -> OWASP Top 10 category mapping.  Based on the official OWASP
# CWE-to-Top-10 mapping at https://owasp.org/Top10/

OWASP_TOP10_2021: dict[str, dict[str, str]] = {
    "A01": {"id": "A01:2021", "name": "Broken Access Control"},
    "A02": {"id": "A02:2021", "name": "Cryptographic Failures"},
    "A03": {"id": "A03:2021", "name": "Injection"},
    "A04": {"id": "A04:2021", "name": "Insecure Design"},
    "A05": {"id": "A05:2021", "name": "Security Misconfiguration"},
    "A06": {"id": "A06:2021", "name": "Vulnerable and Outdated Components"},
    "A07": {"id": "A07:2021", "name": "Identification and Authentication Failures"},
    "A08": {"id": "A08:2021", "name": "Software and Data Integrity Failures"},
    "A09": {"id": "A09:2021", "name": "Security Logging and Monitoring Failures"},
    "A10": {"id": "A10:2021", "name": "Server-Side Request Forgery (SSRF)"},
}

# CWE -> OWASP Top 10 category.  50+ CWEs covered.
CWE_TO_OWASP: dict[str, str] = {
    # A01: Broken Access Control
    "CWE-22": "A01",    # Path Traversal
    "CWE-23": "A01",    # Relative Path Traversal
    "CWE-35": "A01",    # Path Traversal
    "CWE-59": "A01",    # Symlink Following
    "CWE-200": "A01",   # Information Exposure
    "CWE-219": "A01",   # Storage of File with Sensitive Data Under Web Root
    "CWE-264": "A01",   # Permissions, Privileges, and Access Controls
    "CWE-275": "A01",   # Permission Issues
    "CWE-276": "A01",   # Incorrect Default Permissions
    "CWE-284": "A01",   # Improper Access Control
    "CWE-285": "A01",   # Improper Authorization
    "CWE-352": "A01",   # CSRF
    "CWE-359": "A01",   # Exposure of Private Personal Information
    "CWE-377": "A01",   # Insecure Temporary File
    "CWE-402": "A01",   # Transmission of Private Resources into a New Sphere
    "CWE-425": "A01",   # Direct Request (Forced Browsing)
    "CWE-441": "A01",   # Unintended Proxy or Intermediary
    "CWE-497": "A01",   # Exposure of Sensitive System Information
    "CWE-538": "A01",   # File and Directory Information Exposure
    "CWE-540": "A01",   # Information Exposure Through Source Code
    "CWE-548": "A01",   # Exposure of Information Through Directory Listing
    "CWE-552": "A01",   # Files or Directories Accessible to External Parties
    "CWE-566": "A01",   # Authorization Bypass Through User-Controlled SQL PK
    "CWE-601": "A01",   # Open Redirect
    "CWE-639": "A01",   # Authorization Bypass (IDOR)
    "CWE-651": "A01",   # Information Exposure Through WSDL
    "CWE-668": "A01",   # Exposure of Resource to Wrong Sphere
    "CWE-706": "A01",   # Use of Incorrectly-Resolved Name
    "CWE-862": "A01",   # Missing Authorization
    "CWE-863": "A01",   # Incorrect Authorization
    "CWE-913": "A01",   # Improper Control of Dynamically-Managed Code Resources
    "CWE-922": "A01",   # Insecure Storage of Sensitive Information
    "CWE-1275": "A01",  # Sensitive Cookie with Improper SameSite Attribute

    # A02: Cryptographic Failures
    "CWE-261": "A02",   # Weak Encoding for Password
    "CWE-296": "A02",   # Improper Following of Certificate Chain of Trust
    "CWE-310": "A02",   # Cryptographic Issues
    "CWE-319": "A02",   # Cleartext Transmission
    "CWE-321": "A02",   # Use of Hard-coded Cryptographic Key
    "CWE-322": "A02",   # Key Exchange without Entity Authentication
    "CWE-323": "A02",   # Reusing a Nonce/IV
    "CWE-324": "A02",   # Use of Key Past Expiration Date
    "CWE-325": "A02",   # Missing Cryptographic Step
    "CWE-326": "A02",   # Inadequate Encryption Strength
    "CWE-327": "A02",   # Use of Broken Crypto Algorithm
    "CWE-328": "A02",   # Reversible One-Way Hash
    "CWE-329": "A02",   # Not Using Random IV with CBC
    "CWE-330": "A02",   # Use of Insufficiently Random Values
    "CWE-331": "A02",   # Insufficient Entropy
    "CWE-335": "A02",   # Incorrect Usage of Seeds in PRNG
    "CWE-336": "A02",   # Same Seed in PRNG
    "CWE-338": "A02",   # Use of Weak PRNG
    "CWE-340": "A02",   # Generation of Predictable Numbers
    "CWE-347": "A02",   # Improper Verification of Cryptographic Signature
    "CWE-523": "A02",   # Unprotected Transport of Credentials
    "CWE-720": "A02",   # OWASP Top 10 2007 A9

    # A03: Injection
    "CWE-20": "A03",    # Improper Input Validation
    "CWE-74": "A03",    # Injection
    "CWE-75": "A03",    # Failure to Sanitize Special Elements into Output
    "CWE-77": "A03",    # Command Injection
    "CWE-78": "A03",    # OS Command Injection
    "CWE-79": "A03",    # XSS
    "CWE-80": "A03",    # Basic XSS
    "CWE-83": "A03",    # XSS in Attributes
    "CWE-87": "A03",    # Alternate XSS Syntax
    "CWE-88": "A03",    # Argument Injection
    "CWE-89": "A03",    # SQL Injection
    "CWE-90": "A03",    # LDAP Injection
    "CWE-91": "A03",    # XML Injection
    "CWE-93": "A03",    # CRLF Injection
    "CWE-94": "A03",    # Code Injection
    "CWE-95": "A03",    # Eval Injection
    "CWE-96": "A03",    # Improper Neutralization of Directives
    "CWE-97": "A03",    # Server-Side Includes Injection
    "CWE-98": "A03",    # Remote File Inclusion
    "CWE-99": "A03",    # Resource Injection
    "CWE-100": "A03",   # Technology-Specific Input Validation
    "CWE-113": "A03",   # HTTP Response Splitting
    "CWE-116": "A03",   # Improper Encoding or Escaping of Output
    "CWE-138": "A03",   # Improper Neutralization of Special Elements
    "CWE-184": "A03",   # Incomplete List of Disallowed Inputs
    "CWE-470": "A03",   # Unsafe Reflection
    "CWE-471": "A03",   # Modification of Assumed-Immutable Data
    "CWE-564": "A03",   # SQL Injection (Hibernate)
    "CWE-610": "A03",   # Externally Controlled Reference
    "CWE-643": "A03",   # XPath Injection
    "CWE-644": "A03",   # Improper Neutralization of HTTP Headers
    "CWE-652": "A03",   # XQuery Injection
    "CWE-917": "A03",   # Expression Language Injection

    # A04: Insecure Design
    "CWE-73": "A04",    # External Control of File Name
    "CWE-183": "A04",   # Permissive List of Allowed Inputs
    "CWE-209": "A04",   # Information Exposure Through Error Message
    "CWE-213": "A04",   # Exposure of Sensitive Information Due to Incompatible Policies
    "CWE-235": "A04",   # Improper Handling of Extra Parameters
    "CWE-256": "A04",   # Plaintext Storage of Password
    "CWE-257": "A04",   # Storing Passwords in a Recoverable Format
    "CWE-266": "A04",   # Incorrect Privilege Assignment
    "CWE-269": "A04",   # Improper Privilege Management
    "CWE-280": "A04",   # Improper Handling of Insufficient Permissions
    "CWE-311": "A04",   # Missing Encryption of Sensitive Data
    "CWE-312": "A04",   # Cleartext Storage of Sensitive Information
    "CWE-313": "A04",   # Cleartext Storage in a File
    "CWE-316": "A04",   # Cleartext Storage in Memory
    "CWE-419": "A04",   # Unprotected Primary Channel
    "CWE-430": "A04",   # Deployment of Wrong Handler
    "CWE-434": "A04",   # Unrestricted File Upload
    "CWE-444": "A04",   # HTTP Request Smuggling
    "CWE-501": "A04",   # Trust Boundary Violation
    "CWE-522": "A04",   # Insufficiently Protected Credentials
    "CWE-525": "A04",   # Information Exposure Through Browser Caching
    "CWE-539": "A04",   # Persistent Cookie Containing Sensitive Information
    "CWE-602": "A04",   # Client-Side Enforcement of Server-Side Security
    "CWE-642": "A04",   # External Control of Critical State Data
    "CWE-656": "A04",   # Reliance on Security Through Obscurity
    "CWE-799": "A04",   # Improper Control of Interaction Frequency
    "CWE-841": "A04",   # Improper Enforcement of Behavioral Workflow

    # A05: Security Misconfiguration
    "CWE-2": "A05",     # Environment Issues
    "CWE-11": "A05",    # ASP.NET Misconfiguration
    "CWE-13": "A05",    # ASP.NET Misconfiguration: Password in Config
    "CWE-15": "A05",    # External Control of System Setting
    "CWE-16": "A05",    # Configuration
    "CWE-260": "A05",   # Password in Configuration File
    "CWE-315": "A05",   # Cleartext Storage in Cookie
    "CWE-520": "A05",   # .NET Misconfiguration
    "CWE-526": "A05",   # Sensitive Information in Environment Variables
    "CWE-537": "A05",   # Runtime Error Information Leak
    "CWE-541": "A05",   # Information Exposure Through Include Source Code
    "CWE-547": "A05",   # Use of Hard-coded Security-Relevant Constants
    "CWE-611": "A05",   # XXE
    "CWE-614": "A05",   # Sensitive Cookie Without Secure Flag
    "CWE-756": "A05",   # Missing Custom Error Page
    "CWE-776": "A05",   # Recursive Entity Reference (Billion Laughs)
    "CWE-942": "A05",   # Permissive CORS

    # A06: Vulnerable and Outdated Components
    "CWE-937": "A06",   # Using Components with Known Vulnerabilities
    "CWE-1035": "A06",  # OWASP Top 10 2017 A9
    "CWE-1104": "A06",  # Use of Unmaintained Third-Party Components

    # A07: Identification and Authentication Failures
    "CWE-255": "A07",   # Credentials Management Errors
    "CWE-259": "A07",   # Use of Hard-coded Password
    "CWE-287": "A07",   # Improper Authentication
    "CWE-288": "A07",   # Authentication Bypass Using Alternative Path
    "CWE-290": "A07",   # Authentication Bypass by Spoofing
    "CWE-294": "A07",   # Authentication Bypass by Capture-Replay
    "CWE-295": "A07",   # Improper Certificate Validation
    "CWE-297": "A07",   # Improper Validation of Certificate with Host Mismatch
    "CWE-300": "A07",   # Channel Accessible by Non-Endpoint
    "CWE-302": "A07",   # Authentication Bypass Assumed-Immutable Data
    "CWE-304": "A07",   # Missing Critical Step in Authentication
    "CWE-306": "A07",   # Missing Authentication for Critical Function
    "CWE-307": "A07",   # Improper Restriction of Excessive Auth Attempts
    "CWE-346": "A07",   # Origin Validation Error
    "CWE-384": "A07",   # Session Fixation
    "CWE-521": "A07",   # Weak Password Requirements
    "CWE-613": "A07",   # Insufficient Session Expiration
    "CWE-620": "A07",   # Unverified Password Change
    "CWE-640": "A07",   # Weak Password Recovery Mechanism
    "CWE-798": "A07",   # Use of Hard-coded Credentials

    # A08: Software and Data Integrity Failures
    "CWE-345": "A08",   # Insufficient Verification of Data Authenticity
    "CWE-353": "A08",   # Missing Support for Integrity Check
    "CWE-426": "A08",   # Untrusted Search Path
    "CWE-494": "A08",   # Download of Code Without Integrity Check
    "CWE-502": "A08",   # Deserialization of Untrusted Data
    "CWE-565": "A08",   # Reliance on Cookies without Integrity Check
    "CWE-784": "A08",   # Reliance on Cookies without Integrity Check (2)
    "CWE-829": "A08",   # Inclusion of Functionality from Untrusted Control Sphere
    "CWE-830": "A08",   # Inclusion of Web Functionality from Untrusted Source
    "CWE-915": "A08",   # Improperly Controlled Modification of Dynamically-Determined Object Attributes

    # A09: Security Logging and Monitoring Failures
    "CWE-117": "A09",   # Improper Output Neutralization for Logs
    "CWE-223": "A09",   # Omission of Security-Relevant Information
    "CWE-532": "A09",   # Information Exposure Through Log Files
    "CWE-778": "A09",   # Insufficient Logging

    # A10: Server-Side Request Forgery
    "CWE-918": "A10",   # SSRF
}

# ── CWE Top 25 (2023) ───────────────────────────────────────────────

CWE_TOP25_2023: list[dict[str, Any]] = [
    {"rank": 1,  "cwe": "CWE-787", "name": "Out-of-bounds Write"},
    {"rank": 2,  "cwe": "CWE-79",  "name": "Cross-site Scripting (XSS)"},
    {"rank": 3,  "cwe": "CWE-89",  "name": "SQL Injection"},
    {"rank": 4,  "cwe": "CWE-416", "name": "Use After Free"},
    {"rank": 5,  "cwe": "CWE-78",  "name": "OS Command Injection"},
    {"rank": 6,  "cwe": "CWE-20",  "name": "Improper Input Validation"},
    {"rank": 7,  "cwe": "CWE-125", "name": "Out-of-bounds Read"},
    {"rank": 8,  "cwe": "CWE-22",  "name": "Path Traversal"},
    {"rank": 9,  "cwe": "CWE-352", "name": "Cross-Site Request Forgery (CSRF)"},
    {"rank": 10, "cwe": "CWE-434", "name": "Unrestricted Upload of File with Dangerous Type"},
    {"rank": 11, "cwe": "CWE-862", "name": "Missing Authorization"},
    {"rank": 12, "cwe": "CWE-476", "name": "NULL Pointer Dereference"},
    {"rank": 13, "cwe": "CWE-287", "name": "Improper Authentication"},
    {"rank": 14, "cwe": "CWE-190", "name": "Integer Overflow or Wraparound"},
    {"rank": 15, "cwe": "CWE-502", "name": "Deserialization of Untrusted Data"},
    {"rank": 16, "cwe": "CWE-77",  "name": "Command Injection"},
    {"rank": 17, "cwe": "CWE-119", "name": "Improper Restriction of Operations within Memory Buffer"},
    {"rank": 18, "cwe": "CWE-798", "name": "Use of Hard-coded Credentials"},
    {"rank": 19, "cwe": "CWE-918", "name": "Server-Side Request Forgery (SSRF)"},
    {"rank": 20, "cwe": "CWE-306", "name": "Missing Authentication for Critical Function"},
    {"rank": 21, "cwe": "CWE-362", "name": "Concurrent Execution Using Shared Resource (Race Condition)"},
    {"rank": 22, "cwe": "CWE-269", "name": "Improper Privilege Management"},
    {"rank": 23, "cwe": "CWE-94",  "name": "Improper Control of Generation of Code (Code Injection)"},
    {"rank": 24, "cwe": "CWE-863", "name": "Incorrect Authorization"},
    {"rank": 25, "cwe": "CWE-276", "name": "Incorrect Default Permissions"},
]

CWE_TOP25_IDS: set[str] = {entry["cwe"] for entry in CWE_TOP25_2023}

# ── PCI DSS v4.0 Requirement 6 Sub-requirements ─────────────────────

PCI_DSS_REQ6: dict[str, dict[str, Any]] = {
    "6.2.1": {
        "title": "Bespoke and custom software are developed securely",
        "cwes": {
            "CWE-89", "CWE-79", "CWE-78", "CWE-94", "CWE-502", "CWE-611",
            "CWE-20", "CWE-74", "CWE-77",
        },
    },
    "6.2.2": {
        "title": "Software development personnel are trained in secure coding",
        "cwes": set(),  # Procedural — no direct CWE mapping
    },
    "6.2.3": {
        "title": "Bespoke and custom software is reviewed prior to release",
        "cwes": set(),  # Procedural
    },
    "6.2.4": {
        "title": "Software engineering techniques prevent or mitigate common attacks",
        "cwes": {
            "CWE-89", "CWE-79", "CWE-78", "CWE-22", "CWE-352", "CWE-434",
            "CWE-918", "CWE-502", "CWE-287", "CWE-306", "CWE-862", "CWE-863",
            "CWE-798", "CWE-327", "CWE-326", "CWE-311",
        },
    },
    "6.3.1": {
        "title": "Security vulnerabilities are identified and managed",
        "cwes": {"CWE-937", "CWE-1035", "CWE-1104"},
    },
    "6.3.2": {
        "title": "An inventory of bespoke and custom software is maintained",
        "cwes": set(),
    },
    "6.3.3": {
        "title": "Security patches are installed within applicable timeframes",
        "cwes": {"CWE-937", "CWE-1035"},
    },
    "6.4.1": {
        "title": "Public-facing web applications are protected against attacks",
        "cwes": {
            "CWE-79", "CWE-89", "CWE-352", "CWE-918", "CWE-22", "CWE-78",
            "CWE-94", "CWE-611", "CWE-502",
        },
    },
    "6.4.2": {
        "title": "Automated technical solutions detect and prevent web-based attacks",
        "cwes": {"CWE-79", "CWE-89"},
    },
    "6.5.1": {
        "title": "Changes to production systems are properly managed",
        "cwes": set(),
    },
    "6.5.2": {
        "title": "Deployed software is maintained to support PCI DSS requirements",
        "cwes": set(),
    },
    "6.5.3": {
        "title": "Pre-production environments are separated from production",
        "cwes": {"CWE-16", "CWE-2"},
    },
    "6.5.4": {
        "title": "Test/development accounts and data are removed before production",
        "cwes": {"CWE-798", "CWE-259", "CWE-547"},
    },
    "6.5.5": {
        "title": "Live PANs are not used in test environments",
        "cwes": {"CWE-312", "CWE-311"},
    },
    "6.5.6": {
        "title": "Test data and accounts are removed before production",
        "cwes": {"CWE-798"},
    },
}

# ── SOC 2 Controls ───────────────────────────────────────────────────

SOC2_CONTROLS: dict[str, dict[str, Any]] = {
    "CC4.1": {
        "title": "COSO Principle 16 — Ongoing evaluation of controls",
        "description": "The entity selects, develops, and performs ongoing evaluations to ascertain whether the components of internal control are present and functioning.",
        "relevant_categories": {"vulnerability_scanning", "code_review", "sca"},
    },
    "CC7.1": {
        "title": "To meet its objectives, the entity uses detection and monitoring procedures to identify changes to configurations that result in the introduction of new vulnerabilities",
        "description": "Detect configuration changes, new vulnerabilities, and security incidents.",
        "relevant_categories": {"vulnerability_scanning", "sca", "iac", "secrets", "monitoring"},
    },
    "CC7.2": {
        "title": "Security incident monitoring",
        "description": "Monitor system components for anomalies indicative of security incidents.",
        "relevant_categories": {"monitoring", "logging"},
    },
    "CC8.1": {
        "title": "Change management",
        "description": "Changes to infrastructure and software are managed through a change management process.",
        "relevant_categories": {"code_review", "policy"},
    },
}

# ── NIST 800-53 SA-11 Family ────────────────────────────────────────

NIST_80053_SA11: dict[str, dict[str, Any]] = {
    "SA-11": {
        "title": "Developer Testing and Evaluation",
        "description": "Require developers to create and implement a security assessment plan, produce evidence of execution, and correct flaws identified during testing.",
        "enhancements": {
            "SA-11(1)": "Static Code Analysis",
            "SA-11(2)": "Threat Modeling and Vulnerability Analysis",
            "SA-11(4)": "Manual Code Reviews",
            "SA-11(5)": "Penetration Testing",
            "SA-11(7)": "Verify Scope of Testing",
            "SA-11(8)": "Dynamic Code Analysis",
        },
    },
    "SA-15": {
        "title": "Development Process, Standards, and Tools",
        "description": "Require developer to follow a documented development process that addresses security requirements.",
    },
    "RA-5": {
        "title": "Vulnerability Monitoring and Scanning",
        "description": "Monitor and scan for vulnerabilities and remediate per organizational assessment of risk.",
    },
    "SI-10": {
        "title": "Information Input Validation",
        "description": "Check the validity of information inputs.",
        "cwes": {"CWE-20", "CWE-74", "CWE-79", "CWE-89", "CWE-78"},
    },
    "SI-11": {
        "title": "Error Handling",
        "description": "Generate error messages that provide information necessary for corrective actions without revealing sensitive information.",
        "cwes": {"CWE-209", "CWE-532"},
    },
}

# ── EU Cyber Resilience Act Categories ───────────────────────────────

EU_CRA_CATEGORIES: dict[str, dict[str, Any]] = {
    "vulnerability_handling": {
        "title": "Vulnerability Handling Process",
        "article": "Article 10(6)",
        "description": "Manufacturers shall identify and document vulnerabilities, apply effective and regular tests and reviews.",
    },
    "sbom_requirement": {
        "title": "Software Bill of Materials",
        "article": "Article 10(7)",
        "description": "Manufacturers shall draw up an SBOM in a commonly used and machine-readable format.",
    },
    "secure_by_default": {
        "title": "Secure by Default",
        "article": "Annex I, Part I (1)",
        "description": "Products shall be delivered without known exploitable vulnerabilities and with a secure default configuration.",
    },
    "data_protection": {
        "title": "Data Protection",
        "article": "Annex I, Part I (2)",
        "description": "Products shall protect confidentiality, integrity, and availability of data.",
    },
    "access_control": {
        "title": "Access Control",
        "article": "Annex I, Part I (3)",
        "description": "Products shall implement appropriate access control mechanisms.",
    },
    "update_mechanism": {
        "title": "Security Updates",
        "article": "Annex I, Part I (7)",
        "description": "Products shall support security updates and notify users of available patches.",
    },
}


# ── Helper Functions ─────────────────────────────────────────────────


def _extract_cwe(finding: dict) -> str | None:
    """Extract the CWE ID from a finding dict, normalizing format."""
    cwe = finding.get("cwe_id") or ""
    if not cwe:
        # Try rule_id or owasp_category
        rule = finding.get("rule_id", "")
        if "CWE" in rule.upper():
            import re as _re
            m = _re.search(r"CWE-\d+", rule, _re.IGNORECASE)
            if m:
                cwe = m.group(0).upper()
    if cwe and not cwe.startswith("CWE-"):
        cwe = f"CWE-{cwe}"
    return cwe if cwe else None


def _categorize_finding(finding: dict) -> set[str]:
    """Return a set of category tags for a finding."""
    cats: set[str] = set()
    rule_source = finding.get("rule_source", "")
    rule_id = finding.get("rule_id", "")
    title = (finding.get("title", "") or "").lower()

    source_map = {
        "semgrep": "code_review",
        "sca": "sca",
        "iac": "iac",
        "secret_scan": "secrets",
        "claude_review": "code_review",
        "container": "container",
        "license": "license",
    }
    if rule_source in source_map:
        cats.add(source_map[rule_source])

    cats.add("vulnerability_scanning")

    if any(kw in title for kw in ("inject", "xss", "sqli", "command", "traversal")):
        cats.add("injection")
    if any(kw in title for kw in ("auth", "password", "credential", "session")):
        cats.add("authentication")
    if any(kw in rule_id for kw in ("crypto", "tls", "ssl", "hash")):
        cats.add("cryptography")

    return cats


def _severity_sort_key(finding: dict) -> int:
    """Sort key for findings by severity (critical first)."""
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return order.get(finding.get("severity", "info"), 4)


def _report_header(framework: str, project_name: str | None = None) -> dict:
    """Build a standard report header."""
    return {
        "framework": framework,
        "generated_at": datetime.utcnow().isoformat(),
        "generator": "Navigator SAST Compliance Reporter",
        "project_name": project_name or "Unknown",
    }


class ComplianceReporter:
    """Generate compliance reports mapping findings to regulatory frameworks.

    All ``generate_*`` methods return structured dicts ready for JSON/PDF
    export.

    Usage::

        reporter = ComplianceReporter(project_name="MyApp")
        owasp_report = reporter.generate_owasp_top10_report(findings)
        pci_report = reporter.generate_pci_dss_report(findings)
    """

    def __init__(self, project_name: str | None = None):
        self.project_name = project_name

    # ── OWASP Top 10 2021 ───────────────────────────────────────────

    def generate_owasp_top10_report(self, findings: list[dict]) -> dict:
        """Map findings to the OWASP Top 10 2021 categories.

        Returns a dict with one entry per A01-A10 category showing matched
        findings, severity distribution, and overall pass/fail.
        """
        categories: dict[str, list[dict]] = {cat: [] for cat in OWASP_TOP10_2021}
        unmapped: list[dict] = []

        for f in findings:
            cwe = _extract_cwe(f)
            if cwe and cwe in CWE_TO_OWASP:
                cat = CWE_TO_OWASP[cwe]
                categories[cat].append(f)
            else:
                # Try heuristic mapping via OWASP category field
                owasp_cat = (f.get("owasp_category") or "").upper()
                matched = False
                for key in OWASP_TOP10_2021:
                    if key in owasp_cat:
                        categories[key].append(f)
                        matched = True
                        break
                if not matched:
                    unmapped.append(f)

        report_categories = []
        total_findings = 0
        for cat_key, cat_info in OWASP_TOP10_2021.items():
            cat_findings = categories[cat_key]
            total_findings += len(cat_findings)
            sev_dist = defaultdict(int)
            for cf in cat_findings:
                sev_dist[cf.get("severity", "info")] += 1

            report_categories.append({
                "category": cat_info["id"],
                "name": cat_info["name"],
                "finding_count": len(cat_findings),
                "severity_distribution": dict(sev_dist),
                "status": "fail" if cat_findings else "pass",
                "findings": sorted(
                    [
                        {
                            "title": cf.get("title", ""),
                            "severity": cf.get("severity", ""),
                            "cwe_id": _extract_cwe(cf),
                            "file_path": cf.get("file_path", ""),
                            "line_start": cf.get("line_start"),
                            "status": cf.get("status", "open"),
                        }
                        for cf in cat_findings
                    ],
                    key=_severity_sort_key,
                ),
            })

        passed = sum(1 for c in report_categories if c["status"] == "pass")

        return {
            **_report_header("OWASP Top 10 2021", self.project_name),
            "summary": {
                "categories_assessed": 10,
                "categories_passed": passed,
                "categories_failed": 10 - passed,
                "total_findings": total_findings,
                "unmapped_findings": len(unmapped),
                "overall_status": "pass" if passed == 10 else "fail",
            },
            "categories": report_categories,
        }

    # ── CWE Top 25 2023 ─────────────────────────────────────────────

    def generate_cwe_top25_report(self, findings: list[dict]) -> dict:
        """Map findings to the CWE Top 25 Most Dangerous Software Weaknesses."""
        cwe_matches: dict[str, list[dict]] = {e["cwe"]: [] for e in CWE_TOP25_2023}

        for f in findings:
            cwe = _extract_cwe(f)
            if cwe and cwe in CWE_TOP25_IDS:
                cwe_matches[cwe].append(f)

        entries = []
        total_findings = 0
        for entry in CWE_TOP25_2023:
            matched = cwe_matches[entry["cwe"]]
            total_findings += len(matched)
            sev_dist = defaultdict(int)
            for mf in matched:
                sev_dist[mf.get("severity", "info")] += 1

            entries.append({
                "rank": entry["rank"],
                "cwe": entry["cwe"],
                "name": entry["name"],
                "finding_count": len(matched),
                "severity_distribution": dict(sev_dist),
                "status": "fail" if matched else "pass",
                "findings": sorted(
                    [
                        {
                            "title": mf.get("title", ""),
                            "severity": mf.get("severity", ""),
                            "file_path": mf.get("file_path", ""),
                            "line_start": mf.get("line_start"),
                        }
                        for mf in matched
                    ],
                    key=_severity_sort_key,
                ),
            })

        affected = sum(1 for e in entries if e["status"] == "fail")

        return {
            **_report_header("CWE Top 25 2023", self.project_name),
            "summary": {
                "weaknesses_assessed": 25,
                "weaknesses_found": affected,
                "weaknesses_clear": 25 - affected,
                "total_findings": total_findings,
                "overall_status": "pass" if affected == 0 else "fail",
            },
            "entries": entries,
        }

    # ── PCI DSS v4.0 ────────────────────────────────────────────────

    def generate_pci_dss_report(self, findings: list[dict]) -> dict:
        """Map findings to PCI DSS v4.0 Requirement 6 sub-requirements."""
        req_findings: dict[str, list[dict]] = {req: [] for req in PCI_DSS_REQ6}

        for f in findings:
            cwe = _extract_cwe(f)
            if not cwe:
                continue
            for req_id, req_info in PCI_DSS_REQ6.items():
                if cwe in req_info["cwes"]:
                    req_findings[req_id].append(f)

        requirements = []
        total_findings = 0
        for req_id, req_info in PCI_DSS_REQ6.items():
            matched = req_findings[req_id]
            total_findings += len(matched)
            has_technical_cwes = bool(req_info["cwes"])

            if not has_technical_cwes:
                # Procedural requirement — not assessed by SAST
                status = "not_assessed"
            elif matched:
                status = "fail"
            else:
                status = "pass"

            requirements.append({
                "requirement": req_id,
                "title": req_info["title"],
                "status": status,
                "finding_count": len(matched),
                "applicable_cwes": sorted(req_info["cwes"]) if req_info["cwes"] else [],
                "findings": sorted(
                    [
                        {
                            "title": mf.get("title", ""),
                            "severity": mf.get("severity", ""),
                            "cwe_id": _extract_cwe(mf),
                            "file_path": mf.get("file_path", ""),
                        }
                        for mf in matched
                    ],
                    key=_severity_sort_key,
                ),
            })

        assessed = [r for r in requirements if r["status"] != "not_assessed"]
        passed = sum(1 for r in assessed if r["status"] == "pass")

        return {
            **_report_header("PCI DSS v4.0 Requirement 6", self.project_name),
            "summary": {
                "requirements_total": len(requirements),
                "requirements_assessed": len(assessed),
                "requirements_passed": passed,
                "requirements_failed": len(assessed) - passed,
                "requirements_not_assessed": len(requirements) - len(assessed),
                "total_findings": total_findings,
                "overall_status": "pass" if passed == len(assessed) else "fail",
            },
            "requirements": requirements,
        }

    # ── SOC 2 ────────────────────────────────────────────────────────

    def generate_soc2_report(self, findings: list[dict]) -> dict:
        """Map findings to SOC 2 Trust Services Criteria (CC4.1, CC7.1, etc.)."""
        control_findings: dict[str, list[dict]] = {c: [] for c in SOC2_CONTROLS}

        for f in findings:
            f_cats = _categorize_finding(f)
            for ctrl_id, ctrl_info in SOC2_CONTROLS.items():
                relevant = ctrl_info["relevant_categories"]
                if f_cats & relevant:
                    control_findings[ctrl_id].append(f)

        controls = []
        total_findings_mapped = 0
        for ctrl_id, ctrl_info in SOC2_CONTROLS.items():
            matched = control_findings[ctrl_id]
            total_findings_mapped += len(matched)
            sev_dist = defaultdict(int)
            for mf in matched:
                sev_dist[mf.get("severity", "info")] += 1

            # For SOC 2, findings SUPPORT the control assessment (scanning IS the control)
            # Having findings means the scanning is working, but unresolved criticals
            # may indicate the control is not effective.
            unresolved_critical = sum(
                1 for mf in matched
                if mf.get("severity") in ("critical", "high")
                and mf.get("status") in ("open", "confirmed")
            )

            controls.append({
                "control": ctrl_id,
                "title": ctrl_info["title"],
                "description": ctrl_info.get("description", ""),
                "finding_count": len(matched),
                "severity_distribution": dict(sev_dist),
                "unresolved_critical_high": unresolved_critical,
                "effectiveness": (
                    "effective" if unresolved_critical == 0
                    else "partially_effective" if unresolved_critical < 5
                    else "ineffective"
                ),
                "evidence": {
                    "scan_performed": len(matched) > 0 or True,
                    "findings_tracked": True,
                    "remediation_in_progress": any(
                        mf.get("status") == "in_progress" for mf in matched
                    ),
                },
            })

        return {
            **_report_header("SOC 2 Type II", self.project_name),
            "summary": {
                "controls_assessed": len(controls),
                "effective": sum(1 for c in controls if c["effectiveness"] == "effective"),
                "partially_effective": sum(1 for c in controls if c["effectiveness"] == "partially_effective"),
                "ineffective": sum(1 for c in controls if c["effectiveness"] == "ineffective"),
                "total_findings_mapped": total_findings_mapped,
            },
            "controls": controls,
        }

    # ── NIST 800-53 ─────────────────────────────────────────────────

    def generate_nist_report(self, findings: list[dict]) -> dict:
        """Map findings to NIST 800-53 controls (SA-11, RA-5, SI-10/11)."""
        control_findings: dict[str, list[dict]] = {c: [] for c in NIST_80053_SA11}

        for f in findings:
            cwe = _extract_cwe(f)

            # SA-11: all findings from code scanning
            rule_source = f.get("rule_source", "")
            if rule_source in ("semgrep", "custom", "claude_review", "ai", "js_deep"):
                control_findings["SA-11"].append(f)
            # RA-5: all vulnerability findings (including SCA)
            if rule_source in ("sca", "semgrep", "custom", "claude_review", "ai", "container"):
                control_findings["RA-5"].append(f)
            # SA-15: all findings relate to development process
            control_findings["SA-15"].append(f)

            # SI-10 and SI-11: CWE-based mapping
            if cwe:
                for ctrl_id, ctrl_info in NIST_80053_SA11.items():
                    ctrl_cwes = ctrl_info.get("cwes", set())
                    if cwe in ctrl_cwes:
                        if f not in control_findings[ctrl_id]:
                            control_findings[ctrl_id].append(f)

        controls = []
        for ctrl_id, ctrl_info in NIST_80053_SA11.items():
            matched = control_findings[ctrl_id]
            sev_dist = defaultdict(int)
            for mf in matched:
                sev_dist[mf.get("severity", "info")] += 1

            ctrl_entry: dict[str, Any] = {
                "control": ctrl_id,
                "title": ctrl_info["title"],
                "description": ctrl_info["description"],
                "finding_count": len(matched),
                "severity_distribution": dict(sev_dist),
                "status": "assessed",
            }

            if "enhancements" in ctrl_info:
                ctrl_entry["enhancements"] = ctrl_info["enhancements"]

            controls.append(ctrl_entry)

        return {
            **_report_header("NIST 800-53 Rev. 5", self.project_name),
            "summary": {
                "controls_assessed": len(controls),
                "total_findings": len(findings),
                "total_unique_cwes": len(
                    {_extract_cwe(f) for f in findings if _extract_cwe(f)}
                ),
            },
            "controls": controls,
        }

    # ── EU Cyber Resilience Act (CRA) ────────────────────────────────

    def generate_eu_cra_report(
        self,
        findings: list[dict],
        sbom: dict | None = None,
    ) -> dict:
        """Generate an EU Cyber Resilience Act readiness assessment.

        Args:
            findings: List of SAST/SCA finding dicts.
            sbom: Optional SBOM dict (CycloneDX or SPDX format).

        Returns:
            Structured report assessing CRA compliance readiness.
        """
        # Assess each CRA category
        assessments: list[dict] = []

        # 1. Vulnerability handling
        open_vulns = [
            f for f in findings
            if f.get("status") in ("open", "confirmed")
        ]
        critical_open = [f for f in open_vulns if f.get("severity") == "critical"]
        vuln_status = (
            "compliant" if not critical_open
            else "non_compliant" if len(critical_open) > 5
            else "partially_compliant"
        )
        assessments.append({
            "category": "vulnerability_handling",
            **EU_CRA_CATEGORIES["vulnerability_handling"],
            "status": vuln_status,
            "metrics": {
                "total_open_vulnerabilities": len(open_vulns),
                "critical_open": len(critical_open),
                "high_open": len([f for f in open_vulns if f.get("severity") == "high"]),
            },
            "recommendation": (
                "No critical vulnerabilities remain open."
                if not critical_open
                else f"Resolve {len(critical_open)} critical vulnerability(ies) before release."
            ),
        })

        # 2. SBOM requirement
        has_sbom = sbom is not None and bool(sbom)
        sbom_format = ""
        component_count = 0
        if has_sbom:
            sbom_format = sbom.get("format", sbom.get("bomFormat", "unknown"))
            components = sbom.get("components", sbom.get("packages", []))
            component_count = len(components) if isinstance(components, list) else 0

        assessments.append({
            "category": "sbom_requirement",
            **EU_CRA_CATEGORIES["sbom_requirement"],
            "status": "compliant" if has_sbom else "non_compliant",
            "metrics": {
                "sbom_available": has_sbom,
                "sbom_format": sbom_format,
                "component_count": component_count,
            },
            "recommendation": (
                f"SBOM available in {sbom_format} format with {component_count} components."
                if has_sbom
                else "Generate and maintain an SBOM in CycloneDX or SPDX format."
            ),
        })

        # 3. Secure by default
        hardcoded_creds = [
            f for f in findings
            if _extract_cwe(f) in ("CWE-798", "CWE-259", "CWE-321")
        ]
        default_config_issues = [
            f for f in findings
            if _extract_cwe(f) in ("CWE-276", "CWE-16", "CWE-2")
        ]
        secure_default_status = (
            "compliant" if not hardcoded_creds and not default_config_issues
            else "non_compliant"
        )
        assessments.append({
            "category": "secure_by_default",
            **EU_CRA_CATEGORIES["secure_by_default"],
            "status": secure_default_status,
            "metrics": {
                "hardcoded_credentials": len(hardcoded_creds),
                "default_config_issues": len(default_config_issues),
            },
            "recommendation": (
                "No hardcoded credentials or insecure defaults detected."
                if secure_default_status == "compliant"
                else "Remove hardcoded credentials and review default configurations."
            ),
        })

        # 4. Data protection
        data_issues = [
            f for f in findings
            if _extract_cwe(f) in (
                "CWE-311", "CWE-312", "CWE-319", "CWE-326", "CWE-327",
                "CWE-523",
            )
        ]
        data_status = "compliant" if not data_issues else "non_compliant"
        assessments.append({
            "category": "data_protection",
            **EU_CRA_CATEGORIES["data_protection"],
            "status": data_status,
            "metrics": {
                "encryption_issues": len(data_issues),
            },
        })

        # 5. Access control
        access_issues = [
            f for f in findings
            if _extract_cwe(f) in (
                "CWE-284", "CWE-285", "CWE-862", "CWE-863", "CWE-287",
                "CWE-306",
            )
        ]
        access_status = "compliant" if not access_issues else "non_compliant"
        assessments.append({
            "category": "access_control",
            **EU_CRA_CATEGORIES["access_control"],
            "status": access_status,
            "metrics": {
                "access_control_issues": len(access_issues),
            },
        })

        # 6. Update mechanism (assessed based on SCA findings)
        outdated_deps = [
            f for f in findings
            if f.get("rule_source") == "sca"
            and _extract_cwe(f) in ("CWE-937", "CWE-1035", "CWE-1104")
        ]
        update_status = (
            "compliant" if not outdated_deps
            else "partially_compliant" if len(outdated_deps) < 10
            else "non_compliant"
        )
        assessments.append({
            "category": "update_mechanism",
            **EU_CRA_CATEGORIES["update_mechanism"],
            "status": update_status,
            "metrics": {
                "vulnerable_dependencies": len(outdated_deps),
            },
        })

        # Overall CRA readiness
        statuses = [a["status"] for a in assessments]
        if all(s == "compliant" for s in statuses):
            overall = "ready"
        elif any(s == "non_compliant" for s in statuses):
            overall = "not_ready"
        else:
            overall = "partially_ready"

        return {
            **_report_header("EU Cyber Resilience Act (CRA)", self.project_name),
            "summary": {
                "overall_readiness": overall,
                "categories_assessed": len(assessments),
                "compliant": sum(1 for s in statuses if s == "compliant"),
                "partially_compliant": sum(1 for s in statuses if s == "partially_compliant"),
                "non_compliant": sum(1 for s in statuses if s == "non_compliant"),
                "total_findings": len(findings),
            },
            "assessments": assessments,
        }
