"""DAST Automation Engine — HTTP-based security checks without external tools.

Runs automated security checks using only HTTP requests (httpx).
No external tools (Burp, ZAP, nuclei) required.
"""
import httpx
import ssl
import json
import time
import logging
import re
from typing import Any
from urllib.parse import urlparse, urljoin

logger = logging.getLogger(__name__)

TIMEOUT = httpx.Timeout(10.0, connect=5.0)
HEADERS = {"User-Agent": "AppSecD-DAST/1.0 (Automated Security Testing)"}


class DastResult:
    """Result of a single DAST check."""
    def __init__(self, check_id: str, title: str, status: str = "not_started",
                 severity: str = "info", description: str = "", details: dict = None,
                 evidence: str = "", remediation: str = "", cwe_id: str = "",
                 owasp_ref: str = "", reproduction_steps: str = ""):
        self.check_id = check_id
        self.title = title
        self.status = status  # passed, failed, error, not_started
        self.severity = severity
        self.description = description
        self.details = details or {}
        self.evidence = evidence
        self.remediation = remediation
        self.cwe_id = cwe_id
        self.owasp_ref = owasp_ref
        self.reproduction_steps = reproduction_steps

    def to_dict(self) -> dict:
        return {
            "check_id": self.check_id,
            "title": self.title,
            "status": self.status,
            "severity": self.severity,
            "description": self.description,
            "details": self.details,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "cwe_id": self.cwe_id,
            "owasp_ref": self.owasp_ref,
            "reproduction_steps": self.reproduction_steps,
        }


def _safe_get(url: str, **kwargs) -> httpx.Response | None:
    try:
        with httpx.Client(timeout=TIMEOUT, headers=HEADERS, verify=False, follow_redirects=True) as client:
            return client.get(url, **kwargs)
    except Exception as e:
        logger.warning("DAST request failed for %s: %s", url, e)
        return None


def _safe_request(method: str, url: str, **kwargs) -> httpx.Response | None:
    try:
        with httpx.Client(timeout=TIMEOUT, headers=HEADERS, verify=False, follow_redirects=False) as client:
            return client.request(method, url, **kwargs)
    except Exception as e:
        logger.warning("DAST %s request failed for %s: %s", method, url, e)
        return None


# ─── Check 1: Security Headers ───

def check_security_headers(target_url: str) -> DastResult:
    """Check for missing or misconfigured security headers."""
    result = DastResult(
        check_id="DAST-HDR-01",
        title="Security Headers Analysis",
        owasp_ref="A05:2021",
        cwe_id="CWE-693",
    )
    resp = _safe_get(target_url)
    if not resp:
        result.status = "error"
        result.description = "Could not reach target URL"
        return result

    headers = {k.lower(): v for k, v in resp.headers.items()}
    missing = []
    findings = []

    required_headers = {
        "x-frame-options": {"severity": "medium", "remediation": "Add X-Frame-Options: DENY or SAMEORIGIN header"},
        "x-content-type-options": {"severity": "low", "remediation": "Add X-Content-Type-Options: nosniff header"},
        "strict-transport-security": {"severity": "high", "remediation": "Add Strict-Transport-Security: max-age=31536000; includeSubDomains"},
        "content-security-policy": {"severity": "medium", "remediation": "Implement Content-Security-Policy header with restrictive directives"},
        "x-xss-protection": {"severity": "low", "remediation": "Add X-XSS-Protection: 1; mode=block (or rely on CSP)"},
        "referrer-policy": {"severity": "low", "remediation": "Add Referrer-Policy: strict-origin-when-cross-origin"},
        "permissions-policy": {"severity": "low", "remediation": "Add Permissions-Policy to restrict browser features"},
    }

    for header, info in required_headers.items():
        if header not in headers:
            missing.append({"header": header, **info})
        else:
            findings.append({"header": header, "value": headers[header], "status": "present"})

    # Check for dangerous headers
    dangerous = []
    if "server" in headers and any(v in headers["server"].lower() for v in ["apache/", "nginx/", "iis/", "express"]):
        dangerous.append({"header": "Server", "value": headers["server"], "issue": "Server version disclosed"})
    if "x-powered-by" in headers:
        dangerous.append({"header": "X-Powered-By", "value": headers["x-powered-by"], "issue": "Technology stack disclosed"})

    if missing:
        worst_severity = "high" if any(m["severity"] == "high" for m in missing) else "medium"
        result.status = "failed"
        result.severity = worst_severity
        result.description = f"{len(missing)} security header(s) missing"
        result.evidence = f"Missing headers: {', '.join(m['header'] for m in missing)}"
        result.remediation = "; ".join(m["remediation"] for m in missing[:3])
        result.reproduction_steps = f"1. Send GET request to {target_url}\n2. Inspect response headers\n3. Verify missing headers: {', '.join(m['header'] for m in missing)}"
    else:
        result.status = "passed"
        result.description = "All security headers present"

    result.details = {"missing": missing, "present": findings, "dangerous": dangerous, "response_code": resp.status_code}
    return result


# ─── Check 2: SSL/TLS Configuration ───

def check_ssl_tls(target_url: str) -> DastResult:
    """Check SSL/TLS configuration."""
    result = DastResult(
        check_id="DAST-SSL-01",
        title="SSL/TLS Configuration",
        owasp_ref="A02:2021",
        cwe_id="CWE-326",
    )
    parsed = urlparse(target_url)
    if parsed.scheme != "https":
        result.status = "failed"
        result.severity = "high"
        result.description = "Target does not use HTTPS"
        result.remediation = "Enable HTTPS with a valid TLS certificate"
        result.reproduction_steps = f"1. Navigate to {target_url}\n2. Observe protocol is HTTP, not HTTPS"
        result.evidence = f"URL scheme: {parsed.scheme}"
        return result

    host = parsed.hostname
    port = parsed.port or 443
    try:
        import socket
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                protocol = ssock.version()
                cipher = ssock.cipher()
                
                issues = []
                if protocol and "TLSv1.0" in protocol:
                    issues.append("TLS 1.0 is deprecated")
                if protocol and "TLSv1.1" in protocol:
                    issues.append("TLS 1.1 is deprecated")
                if cipher and cipher[0] and "RC4" in cipher[0]:
                    issues.append("RC4 cipher is insecure")
                
                result.details = {"protocol": protocol, "cipher": cipher[0] if cipher else "", "cert_subject": str(cert.get("subject", ""))}
                
                if issues:
                    result.status = "failed"
                    result.severity = "medium"
                    result.description = f"SSL/TLS issues: {'; '.join(issues)}"
                    result.remediation = "Upgrade to TLS 1.2+ and use strong cipher suites"
                else:
                    result.status = "passed"
                    result.description = f"SSL/TLS configuration OK (Protocol: {protocol})"
    except ssl.SSLCertVerificationError as e:
        result.status = "failed"
        result.severity = "high"
        result.description = f"SSL certificate verification failed: {str(e)[:200]}"
        result.remediation = "Install a valid SSL certificate from a trusted CA"
    except Exception as e:
        result.status = "error"
        result.description = f"SSL check error: {str(e)[:200]}"
    return result


# ─── Check 3: Cookie Security ───

def check_cookie_security(target_url: str) -> DastResult:
    """Check cookie security flags."""
    result = DastResult(
        check_id="DAST-COOK-01",
        title="Cookie Security Flags",
        owasp_ref="A05:2021",
        cwe_id="CWE-614",
    )
    resp = _safe_get(target_url)
    if not resp:
        result.status = "error"
        result.description = "Could not reach target"
        return result

    cookies = resp.headers.get_list("set-cookie")
    if not cookies:
        result.status = "passed"
        result.description = "No cookies set on this page"
        result.details = {"cookies_found": 0}
        return result

    issues = []
    cookie_details = []
    for cookie_str in cookies:
        cookie_lower = cookie_str.lower()
        name = cookie_str.split("=")[0].strip()
        cookie_info = {"name": name, "issues": []}
        if "secure" not in cookie_lower:
            cookie_info["issues"].append("Missing Secure flag")
        if "httponly" not in cookie_lower:
            cookie_info["issues"].append("Missing HttpOnly flag")
        if "samesite" not in cookie_lower:
            cookie_info["issues"].append("Missing SameSite attribute")
        if cookie_info["issues"]:
            issues.extend([f"{name}: {i}" for i in cookie_info["issues"]])
        cookie_details.append(cookie_info)

    result.details = {"cookies": cookie_details, "total_cookies": len(cookies)}
    if issues:
        result.status = "failed"
        result.severity = "medium"
        result.description = f"{len(issues)} cookie security issue(s) found"
        result.evidence = "; ".join(issues[:5])
        result.remediation = "Set Secure, HttpOnly, and SameSite=Strict/Lax on all session cookies"
        result.reproduction_steps = f"1. Send GET to {target_url}\n2. Inspect Set-Cookie headers\n3. Check for missing Secure/HttpOnly/SameSite flags"
    else:
        result.status = "passed"
        result.description = "All cookies have proper security flags"
    return result


# ─── Check 4: CORS Misconfiguration ───

def check_cors(target_url: str) -> DastResult:
    """Check for CORS misconfiguration."""
    result = DastResult(
        check_id="DAST-CORS-01",
        title="CORS Configuration",
        owasp_ref="A05:2021",
        cwe_id="CWE-942",
    )
    evil_origin = "https://evil-attacker.com"
    resp = _safe_request("GET", target_url, headers={"Origin": evil_origin})
    if not resp:
        result.status = "error"
        result.description = "Could not reach target"
        return result

    acao = resp.headers.get("access-control-allow-origin", "")
    acac = resp.headers.get("access-control-allow-credentials", "")

    issues = []
    if acao == "*":
        issues.append("Wildcard (*) Access-Control-Allow-Origin")
    if acao == evil_origin:
        issues.append(f"Reflects arbitrary origin: {evil_origin}")
    if acac.lower() == "true" and (acao == "*" or acao == evil_origin):
        issues.append("Credentials allowed with permissive origin — critical")

    result.details = {"acao": acao, "acac": acac, "tested_origin": evil_origin}
    if issues:
        sev = "critical" if "critical" in " ".join(issues) else "high"
        result.status = "failed"
        result.severity = sev
        result.description = f"CORS misconfiguration: {'; '.join(issues)}"
        result.remediation = "Restrict Access-Control-Allow-Origin to trusted domains. Never use * with credentials."
        result.reproduction_steps = f"1. Send GET to {target_url} with header Origin: {evil_origin}\n2. Check Access-Control-Allow-Origin in response\n3. Observed: {acao}"
        result.evidence = f"ACAO: {acao}, ACAC: {acac}"
    else:
        result.status = "passed"
        result.description = "CORS properly configured (does not reflect arbitrary origins)"
    return result


# ─── Check 5: Information Disclosure ───

def check_info_disclosure(target_url: str) -> DastResult:
    """Check for information disclosure in headers and error pages."""
    result = DastResult(
        check_id="DAST-INFO-01",
        title="Information Disclosure",
        owasp_ref="A05:2021",
        cwe_id="CWE-200",
    )
    resp = _safe_get(target_url)
    if not resp:
        result.status = "error"
        return result

    issues = []
    headers = {k.lower(): v for k, v in resp.headers.items()}

    if "server" in headers:
        issues.append(f"Server header discloses: {headers['server']}")
    if "x-powered-by" in headers:
        issues.append(f"X-Powered-By discloses: {headers['x-powered-by']}")
    if "x-aspnet-version" in headers:
        issues.append(f"ASP.NET version disclosed: {headers['x-aspnet-version']}")

    # Check error page
    error_resp = _safe_get(urljoin(target_url, "/this-page-does-not-exist-404-test"))
    if error_resp:
        body = error_resp.text[:5000].lower()
        if "stack trace" in body or "traceback" in body:
            issues.append("Stack trace in error page")
        if "debug" in body and ("true" in body or "mode" in body):
            issues.append("Debug mode may be enabled")
        for pattern in [r"django", r"laravel", r"express", r"spring boot", r"flask"]:
            if re.search(pattern, body):
                issues.append(f"Framework disclosed in error page: {pattern}")
                break

    result.details = {"server_header": headers.get("server", ""), "powered_by": headers.get("x-powered-by", ""), "issue_count": len(issues)}
    if issues:
        result.status = "failed"
        result.severity = "low"
        result.description = f"{len(issues)} information disclosure issue(s)"
        result.evidence = "; ".join(issues)
        result.remediation = "Remove version information from Server/X-Powered-By headers. Disable debug mode. Use custom error pages."
        result.reproduction_steps = f"1. Send GET to {target_url}\n2. Inspect Server and X-Powered-By headers\n3. Request non-existent page and check error output"
    else:
        result.status = "passed"
        result.description = "No significant information disclosure detected"
    return result


# ─── Check 6: HTTP Methods ───

def check_http_methods(target_url: str) -> DastResult:
    """Check for dangerous HTTP methods."""
    result = DastResult(
        check_id="DAST-METH-01",
        title="HTTP Methods Check",
        owasp_ref="A05:2021",
        cwe_id="CWE-749",
    )
    dangerous_methods = ["TRACE", "PUT", "DELETE", "CONNECT"]
    allowed = []
    
    options_resp = _safe_request("OPTIONS", target_url)
    if options_resp:
        allow_header = options_resp.headers.get("allow", "")
        if allow_header:
            allowed = [m.strip().upper() for m in allow_header.split(",")]

    # Also test TRACE directly
    trace_resp = _safe_request("TRACE", target_url)
    if trace_resp and trace_resp.status_code == 200:
        if "TRACE" not in allowed:
            allowed.append("TRACE")

    dangerous_found = [m for m in allowed if m in dangerous_methods]
    result.details = {"allowed_methods": allowed, "dangerous": dangerous_found}
    
    if dangerous_found:
        result.status = "failed"
        result.severity = "medium" if "TRACE" in dangerous_found else "low"
        result.description = f"Dangerous HTTP methods enabled: {', '.join(dangerous_found)}"
        result.remediation = f"Disable {', '.join(dangerous_found)} methods on the web server"
        result.reproduction_steps = f"1. Send OPTIONS request to {target_url}\n2. Check Allow header\n3. Dangerous methods found: {', '.join(dangerous_found)}"
    else:
        result.status = "passed"
        result.description = "No dangerous HTTP methods enabled"
    return result


# ─── Check 7: robots.txt Analysis ───

def check_robots_txt(target_url: str) -> DastResult:
    """Analyze robots.txt for sensitive paths."""
    result = DastResult(
        check_id="DAST-ROBO-01",
        title="robots.txt Analysis",
        owasp_ref="A05:2021",
        cwe_id="CWE-200",
    )
    robots_url = urljoin(target_url, "/robots.txt")
    resp = _safe_get(robots_url)
    if not resp or resp.status_code != 200:
        result.status = "passed"
        result.description = "No robots.txt found"
        return result

    content = resp.text
    sensitive_patterns = ["admin", "login", "api", "config", "backup", "debug", "test", "internal", "dashboard", "secret", "private", "wp-admin", "phpmyadmin", ".env", ".git"]
    disallowed = [line.split(":", 1)[1].strip() for line in content.split("\n") if line.lower().startswith("disallow:") and line.split(":", 1)[1].strip()]
    sensitive_found = [d for d in disallowed if any(p in d.lower() for p in sensitive_patterns)]

    result.details = {"disallowed_paths": disallowed, "sensitive_paths": sensitive_found, "raw_content": content[:2000]}
    if sensitive_found:
        result.status = "failed"
        result.severity = "low"
        result.description = f"robots.txt reveals {len(sensitive_found)} sensitive path(s)"
        result.evidence = f"Sensitive paths: {', '.join(sensitive_found[:10])}"
        result.remediation = "Do not rely on robots.txt for security. Implement proper access controls."
        result.reproduction_steps = f"1. GET {robots_url}\n2. Review Disallow entries\n3. Sensitive paths found: {', '.join(sensitive_found[:5])}"
    else:
        result.status = "passed"
        result.description = f"robots.txt found with {len(disallowed)} disallowed path(s), none appear sensitive"
    return result


# ─── Check 8: Directory Listing ───

def check_directory_listing(target_url: str) -> DastResult:
    """Check for enabled directory listing."""
    result = DastResult(
        check_id="DAST-DIR-01",
        title="Directory Listing",
        owasp_ref="A05:2021",
        cwe_id="CWE-548",
    )
    common_dirs = ["/", "/images/", "/static/", "/assets/", "/uploads/", "/css/", "/js/", "/media/", "/files/"]
    listing_found = []

    for d in common_dirs:
        test_url = urljoin(target_url, d)
        resp = _safe_get(test_url)
        if resp and resp.status_code == 200:
            body = resp.text[:3000].lower()
            if "index of" in body or "directory listing" in body or ("<pre>" in body and "parent directory" in body):
                listing_found.append(d)

    result.details = {"checked_dirs": common_dirs, "listing_enabled": listing_found}
    if listing_found:
        result.status = "failed"
        result.severity = "medium"
        result.description = f"Directory listing enabled on {len(listing_found)} path(s)"
        result.evidence = f"Listing found at: {', '.join(listing_found)}"
        result.remediation = "Disable directory listing in web server configuration"
        result.reproduction_steps = f"1. Browse to {urljoin(target_url, listing_found[0])}\n2. Observe directory listing output"
    else:
        result.status = "passed"
        result.description = "No directory listing detected"
    return result


# ─── Check 9: Open Redirect ───

def check_open_redirect(target_url: str) -> DastResult:
    """Check for open redirect vulnerabilities."""
    result = DastResult(
        check_id="DAST-REDIR-01",
        title="Open Redirect Detection",
        owasp_ref="A01:2021",
        cwe_id="CWE-601",
    )
    evil_url = "https://evil-attacker.com"
    redirect_params = ["redirect", "url", "next", "return", "returnUrl", "redirect_uri", "continue", "dest", "goto", "target"]
    
    found = []
    parsed = urlparse(target_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    
    for param in redirect_params:
        test_url = f"{base}/login?{param}={evil_url}"
        try:
            with httpx.Client(timeout=TIMEOUT, headers=HEADERS, verify=False, follow_redirects=False) as client:
                resp = client.get(test_url)
                location = resp.headers.get("location", "")
                if evil_url in location:
                    found.append({"param": param, "url": test_url, "redirect_to": location})
        except Exception:
            pass

    result.details = {"tested_params": redirect_params, "redirects_found": found}
    if found:
        result.status = "failed"
        result.severity = "medium"
        result.description = f"Open redirect via parameter: {', '.join(f['param'] for f in found)}"
        result.evidence = f"Redirect to {evil_url} via: {found[0]['url']}"
        result.remediation = "Validate redirect URLs against an allowlist. Only allow relative redirects."
        result.reproduction_steps = f"1. Request {found[0]['url']}\n2. Observe Location header redirects to {evil_url}"
    else:
        result.status = "passed"
        result.description = "No open redirect detected"
    return result


# ─── Check 10: Rate Limiting ───

def check_rate_limiting(target_url: str) -> DastResult:
    """Check if rate limiting is enforced."""
    result = DastResult(
        check_id="DAST-RATE-01",
        title="Rate Limiting Check",
        owasp_ref="A04:2021",
        cwe_id="CWE-770",
    )
    # Send 20 rapid requests
    statuses = []
    try:
        with httpx.Client(timeout=TIMEOUT, headers=HEADERS, verify=False) as client:
            for _ in range(20):
                resp = client.get(target_url)
                statuses.append(resp.status_code)
                if resp.status_code == 429:
                    break
    except Exception:
        pass

    rate_limited = 429 in statuses
    result.details = {"requests_sent": len(statuses), "rate_limited": rate_limited, "status_codes": list(set(statuses))}
    if rate_limited:
        result.status = "passed"
        result.description = f"Rate limiting active (429 after {statuses.index(429) + 1} requests)"
    else:
        result.status = "failed"
        result.severity = "low"
        result.description = f"No rate limiting detected after {len(statuses)} rapid requests"
        result.remediation = "Implement rate limiting (e.g., 100 requests/minute per IP)"
        result.reproduction_steps = f"1. Send 20 rapid GET requests to {target_url}\n2. No 429 status received\n3. All responses: {list(set(statuses))}"
    return result


# ─── DAST Runner ───

ALL_CHECKS = [
    ("security_headers", check_security_headers),
    ("ssl_tls", check_ssl_tls),
    ("cookie_security", check_cookie_security),
    ("cors", check_cors),
    ("info_disclosure", check_info_disclosure),
    ("http_methods", check_http_methods),
    ("robots_txt", check_robots_txt),
    ("directory_listing", check_directory_listing),
    ("open_redirect", check_open_redirect),
    ("rate_limiting", check_rate_limiting),
]


def run_dast_scan(target_url: str, checks: list[str] | None = None) -> dict:
    """Run DAST scan with selected or all checks. Returns structured results."""
    results = []
    selected = ALL_CHECKS if not checks else [(n, f) for n, f in ALL_CHECKS if n in checks]
    
    start = time.time()
    for name, check_fn in selected:
        try:
            r = check_fn(target_url)
            results.append(r.to_dict())
        except Exception as e:
            results.append(DastResult(
                check_id=f"DAST-ERR-{name}",
                title=f"Error in {name}",
                status="error",
                description=str(e)[:200],
            ).to_dict())
    
    duration = round(time.time() - start, 2)
    passed = sum(1 for r in results if r["status"] == "passed")
    failed = sum(1 for r in results if r["status"] == "failed")
    errors = sum(1 for r in results if r["status"] == "error")
    
    return {
        "target_url": target_url,
        "total_checks": len(results),
        "passed": passed,
        "failed": failed,
        "errors": errors,
        "duration_seconds": duration,
        "results": results,
    }
