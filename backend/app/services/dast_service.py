"""DAST Automation Engine — HTTP-based security checks.

Runs automated security checks using httpx. Optional ffuf for directory discovery.
Uses SecLists/IntruderPayloads wordlists when available.
"""
import httpx
import ssl
import json
import time
import logging
import re
import os
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urljoin

logger = logging.getLogger(__name__)

DATA_ROOT = Path(__file__).resolve().parents[2] / "data"
WORDLIST_PATHS = [
    DATA_ROOT / "IntruderPayloads" / "FuzzLists" / "dirbuster-quick.txt",
    DATA_ROOT / "SecLists" / "Discovery" / "Web-Content" / "DirBuster-2007_directory-list-2.3-small.txt",
    DATA_ROOT / "IntruderPayloads" / "FuzzLists" / "dirbuster-top1000.txt",
]

def _load_discovery_wordlist(max_paths: int = 150) -> list[str]:
    """Load directory discovery wordlist from SecLists/IntruderPayloads."""
    for p in WORDLIST_PATHS:
        if p.exists():
            try:
                lines = [ln.strip() for ln in open(p, encoding="utf-8", errors="ignore").readlines() if ln.strip() and not ln.startswith("#")]
                return list(dict.fromkeys(lines))[:max_paths]  # dedupe, limit
            except Exception as e:
                logger.debug("Could not load wordlist %s: %s", p, e)
    return ["admin", "login", "api", "config", "backup", "static", "assets", "uploads", "images", "css", "js", "wp-admin", ".git", ".env", "debug", "test", "dev", "staging", "dashboard", "panel"]

TIMEOUT = httpx.Timeout(15.0, connect=8.0)
HEADERS = {"User-Agent": "AppSecD-DAST/1.0 (Automated Security Testing)"}


class DastResult:
    """Result of a single DAST check."""
    def __init__(self, check_id: str, title: str, status: str = "not_started",
                 severity: str = "info", description: str = "", details: dict = None,
                 evidence: str = "", remediation: str = "", cwe_id: str = "",
                 owasp_ref: str = "", reproduction_steps: str = "",
                 request_raw: str = "", response_raw: str = ""):
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
        self.request_raw = request_raw
        self.response_raw = response_raw

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
            "request_raw": self.request_raw,
            "response_raw": self.response_raw,
        }


def _url_variants(url: str) -> list[str]:
    """Return URL and fallbacks. Try scheme flip early (http before www) for dev/staging."""
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}{parsed.query and '?' + parsed.query or ''}"
    urls = [url]
    # Try opposite scheme early — many targets use HTTP only (dev/staging)
    if parsed.scheme == "https":
        u2 = base.replace("https://", "http://")
        if u2 not in urls:
            urls.append(u2)
    elif parsed.scheme == "http":
        u2 = base.replace("http://", "https://")
        if u2 not in urls:
            urls.append(u2)
    # www variants
    netloc = parsed.netloc or ""
    if "www." not in netloc and netloc:
        for u in list(urls):
            u_www = u.replace(netloc, f"www.{netloc}", 1)
            if u_www not in urls:
                urls.append(u_www)
    return urls


def _safe_get(url: str, **kwargs) -> httpx.Response | None:
    for u in _url_variants(url):
        try:
            with httpx.Client(timeout=TIMEOUT, headers=HEADERS, verify=False, follow_redirects=True) as client:
                return client.get(u, **kwargs)
        except Exception as e:
            logger.debug("DAST GET %s failed: %s", u, e)
    logger.warning("DAST request failed for all variants of %s", url)
    return None


def _safe_request(method: str, url: str, **kwargs) -> httpx.Response | None:
    for u in _url_variants(url):
        try:
            with httpx.Client(timeout=TIMEOUT, headers=HEADERS, verify=False, follow_redirects=False) as client:
                return client.request(method, u, **kwargs)
        except Exception as e:
            logger.debug("DAST %s %s failed: %s", method, u, e)
    logger.warning("DAST %s request failed for all variants of %s", method, url)
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
    result.request_raw = f"GET {target_url} HTTP/1.1\nHost: {urlparse(target_url).netloc}\nUser-Agent: {HEADERS.get('User-Agent', '')}"
    result.response_raw = f"HTTP/1.1 {resp.status_code} {resp.reason_phrase}\n" + "\n".join(f"{k}: {v}" for k, v in resp.headers.items()) + "\n\n" + (resp.text[:2000] if resp.text else "")
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
    result.request_raw = f"GET {target_url} HTTP/1.1\nHost: {urlparse(target_url).netloc}"
    result.response_raw = f"HTTP/1.1 {resp.status_code}\n" + "\n".join(f"{k}: {v}" for k, v in resp.headers.items()) + "\n\n" + (resp.text[:1500] if resp.text else "")
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
    result.request_raw = f"GET {target_url} HTTP/1.1\nOrigin: {evil_origin}\nHost: {urlparse(target_url).netloc}"
    result.response_raw = f"HTTP/1.1 {resp.status_code}\n" + "\n".join(f"{k}: {v}" for k, v in resp.headers.items()) + "\n\n" + (resp.text[:1500] if resp.text else "")
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
        result.description = "Could not reach target"
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
    result.request_raw = f"GET {target_url} HTTP/1.1\nHost: {urlparse(target_url).netloc}"
    result.response_raw = f"HTTP/1.1 {resp.status_code}\n" + "\n".join(f"{k}: {v}" for k, v in resp.headers.items()) + "\n\n" + (resp.text[:2000] if resp.text else "")
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
    trace_resp = _safe_request("TRACE", target_url)
    if not options_resp and not trace_resp:
        result.status = "error"
        result.description = "Could not reach target"
        return result
    if options_resp:
        allow_header = options_resp.headers.get("allow", "")
        if allow_header:
            allowed = [m.strip().upper() for m in allow_header.split(",")]

    # Also test TRACE directly
    if trace_resp and trace_resp.status_code == 200:
        if "TRACE" not in allowed:
            allowed.append("TRACE")

    dangerous_found = [m for m in allowed if m in dangerous_methods]
    result.details = {"allowed_methods": allowed, "dangerous": dangerous_found}
    if options_resp:
        result.request_raw = f"OPTIONS {target_url} HTTP/1.1\nHost: {urlparse(target_url).netloc}"
        result.response_raw = f"HTTP/1.1 {options_resp.status_code}\n" + "\n".join(f"{k}: {v}" for k, v in options_resp.headers.items()) + "\nAllow: " + (options_resp.headers.get("allow", "") or "")
    
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
    if resp:
        result.request_raw = f"GET {robots_url} HTTP/1.1\nHost: {urlparse(target_url).netloc}"
        result.response_raw = f"HTTP/1.1 {resp.status_code}\n" + "\n".join(f"{k}: {v}" for k, v in resp.headers.items()) + "\n\n" + (content[:1500] if content else "")
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
    first_resp = _safe_get(urljoin(target_url, common_dirs[0])) if common_dirs else None
    if first_resp:
        result.request_raw = f"GET {urljoin(target_url, common_dirs[0])} HTTP/1.1\nHost: {urlparse(target_url).netloc}"
        result.response_raw = f"HTTP/1.1 {first_resp.status_code}\n" + "\n".join(f"{k}: {v}" for k, v in first_resp.headers.items()) + "\n\n" + (first_resp.text[:1500] if first_resp.text else "")
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
    try:
        with httpx.Client(timeout=TIMEOUT, headers=HEADERS, verify=False) as client:
            r = client.get(target_url)
            result.request_raw = f"GET {target_url} HTTP/1.1\nHost: {urlparse(target_url).netloc}"
            result.response_raw = f"HTTP/1.1 {r.status_code}\n" + "\n".join(f"{k}: {v}" for k, v in r.headers.items()) + "\n\n" + (r.text[:1000] if r.text else "")
    except Exception:
        pass
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


# ─── Check 11: Basic Reflected XSS ───

def check_xss_basic(target_url: str) -> DastResult:
    """Check for reflected XSS in common query parameters."""
    result = DastResult(
        check_id="DAST-XSS-01",
        title="Basic Reflected XSS Check",
        owasp_ref="A03:2021",
        cwe_id="CWE-79",
    )
    parsed = urlparse(target_url)
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}"
    payload = '<script>alert(1)</script>'
    params = ["q", "search", "query", "keyword", "s", "name", "id", "ref", "redirect"]
    reflected = []
    resp = None
    for param in params:
        test_url = f"{base}?{param}={payload}"
        r = _safe_get(test_url)
        if r and payload in (r.text or ""):
            reflected.append({"param": param, "url": test_url})
            if not resp:
                resp = r
    result.details = {"tested_params": params, "reflected_unencoded": reflected}
    if resp:
        result.request_raw = f"GET {base}?q={payload} HTTP/1.1\nHost: {urlparse(target_url).netloc}"
        result.response_raw = f"HTTP/1.1 {resp.status_code}\n" + "\n".join(f"{k}: {v}" for k, v in resp.headers.items()) + "\n\n" + (resp.text[:2000] if resp.text else "")
    if reflected:
        result.status = "failed"
        result.severity = "high"
        result.description = f"Reflected XSS: input reflected unencoded in {len(reflected)} param(s)"
        result.evidence = f"Param(s): {', '.join(r['param'] for r in reflected)}"
        result.remediation = "Encode all user input in HTML context. Use CSP to mitigate."
    else:
        result.status = "passed"
        result.description = "No reflected XSS in common params (basic check)"
    return result


# ─── Check 12: SQL Error Detection ───

def check_sqli_error(target_url: str) -> DastResult:
    """Check for SQL error messages in response indicating potential injection."""
    result = DastResult(
        check_id="DAST-SQLI-01",
        title="SQL Error Detection",
        owasp_ref="A03:2021",
        cwe_id="CWE-89",
    )
    payloads = ["'", "1'", "1 OR 1=1", "1' OR '1'='1"]
    errors = ["sql syntax", "mysql_fetch", "pg_query", "sqlite", "ora-01", "sqlstate", "unclosed quotation", "syntax error in query", "odbc", "microsoft ole db"]
    found = []
    resp = _safe_get(target_url)
    if not resp:
        result.status = "error"
        result.description = "Could not reach target"
        return result
    body = (resp.text or "").lower()
    for p in payloads:
        r = _safe_get(f"{target_url}{'&' if '?' in target_url else '?'}id={p}")
        if r:
            rb = (r.text or "").lower()
            for err in errors:
                if err in rb:
                    found.append({"payload": p, "error": err})
                    break
    result.details = {"payloads_tested": payloads, "errors_found": found}
    result.request_raw = f"GET {target_url} HTTP/1.1\nHost: {urlparse(target_url).netloc}"
    result.response_raw = f"HTTP/1.1 {resp.status_code}\n" + "\n".join(f"{k}: {v}" for k, v in resp.headers.items()) + "\n\n" + (resp.text[:2000] if resp.text else "")
    if found:
        result.status = "failed"
        result.severity = "high"
        result.description = f"SQL error in response: {found[0].get('error', '')}"
        result.evidence = f"Payload: {found[0].get('payload', '')} triggered SQL error"
        result.remediation = "Use parameterized queries. Never concatenate user input into SQL."
    else:
        result.status = "passed"
        result.description = "No SQL error leakage in response (basic check)"
    return result


# ─── Check 13: API Docs Exposure ───

def check_api_docs_exposure(target_url: str) -> DastResult:
    """Check for exposed Swagger/OpenAPI/GraphQL endpoints."""
    result = DastResult(
        check_id="DAST-API-01",
        title="API Documentation Exposure",
        owasp_ref="A05:2021",
        cwe_id="CWE-200",
    )
    paths = ["/swagger", "/swagger.json", "/swagger-ui", "/api-docs", "/openapi.json", "/graphql", "/graphiql", "/v1/api-docs", "/v2/api-docs", "/api/swagger"]
    exposed = []
    base = f"{urlparse(target_url).scheme}://{urlparse(target_url).netloc}"
    for path in paths:
        r = _safe_get(urljoin(base, path))
        if r and r.status_code == 200:
            body = (r.text or "").lower()
            if "swagger" in body or "openapi" in body or "graphql" in body or "graphiql" in body:
                exposed.append(path)
    result.details = {"paths_checked": paths, "exposed": exposed}
    if exposed:
        result.status = "failed"
        result.severity = "medium"
        result.description = f"API documentation exposed at: {', '.join(exposed[:5])}"
        result.evidence = f"Exposed: {', '.join(exposed)}"
        result.remediation = "Disable or restrict API docs in production. Require authentication."
    else:
        result.status = "passed"
        result.description = "No exposed API documentation detected"
    return result


# ─── Check 14: Host Header Injection ───

def check_host_header_injection(target_url: str) -> DastResult:
    """Check for Host header injection leading to redirect/SSRF."""
    result = DastResult(
        check_id="DAST-HOST-01",
        title="Host Header Injection",
        owasp_ref="A01:2021",
        cwe_id="CWE-644",
    )
    evil_host = "evil-attacker.com"
    r = _safe_request("GET", target_url, headers={"Host": evil_host})
    if not r:
        result.status = "error"
        result.description = "Could not reach target"
        return result
    loc = r.headers.get("location", "")
    if evil_host in loc or evil_host in (r.text or ""):
        result.status = "failed"
        result.severity = "high"
        result.description = "Host header reflected in response/redirect"
        result.evidence = f"Host: {evil_host} reflected in Location: {loc[:200]}"
        result.remediation = "Validate Host header against allowlist. Don't use it in redirects."
    else:
        result.status = "passed"
        result.description = "Host header not reflected in response"
    result.details = {"tested_host": evil_host, "location": loc[:200]}
    result.request_raw = f"GET {target_url} HTTP/1.1\nHost: {evil_host}"
    result.response_raw = f"HTTP/1.1 {r.status_code}\n" + "\n".join(f"{k}: {v}" for k, v in r.headers.items()) + "\n\n" + (r.text[:1500] if r.text else "")
    return result


# ─── Check 15: CRLF Injection ───

def check_crlf_injection(target_url: str) -> DastResult:
    """Check for CRLF injection in redirect parameters."""
    result = DastResult(
        check_id="DAST-CRLF-01",
        title="CRLF Injection",
        owasp_ref="A01:2021",
        cwe_id="CWE-93",
    )
    payload = "%0d%0aSet-Cookie:crlf=injected"
    parsed = urlparse(target_url)
    test_url = f"{parsed.scheme}://{parsed.netloc}/?redirect={payload}"
    r = _safe_request("GET", test_url)
    if not r:
        result.status = "error"
        result.description = "Could not reach target"
        return result
    set_cookie = r.headers.get("set-cookie", "")
    vuln = "crlf=injected" in set_cookie.lower()
    result.details = {"payload": payload, "set_cookie_header": set_cookie[:200]}
    if vuln:
        result.status = "failed"
        result.severity = "high"
        result.description = "CRLF injection: header injection via redirect param"
        result.evidence = f"Set-Cookie reflected: {set_cookie[:150]}"
        result.remediation = "Sanitize redirect params. Reject CRLF sequences."
    else:
        result.status = "passed"
        result.description = "No CRLF injection detected"
    return result


# ─── Check 16: Sensitive Data Exposure ───

def check_sensitive_data(target_url: str) -> DastResult:
    """Check for PII/sensitive patterns in response."""
    result = DastResult(
        check_id="DAST-PII-01",
        title="Sensitive Data Exposure",
        owasp_ref="A02:2021",
        cwe_id="CWE-200",
    )
    resp = _safe_get(target_url)
    if not resp:
        result.status = "error"
        result.description = "Could not reach target"
        return result
    body = resp.text or ""
    patterns = [
        (r"\b\d{16}\b", "Credit card pattern"),
        (r"\b\d{3}-\d{2}-\d{4}\b", "SSN pattern"),
        (r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "Email addresses"),
        (r"password\s*[=:]\s*['\"]?[\w]+", "Password in response"),
        (r"api[_-]?key\s*[=:]\s*['\"]?[\w-]+", "API key pattern"),
    ]
    found = []
    for pat, label in patterns:
        m = re.search(pat, body, re.I)
        if m:
            found.append({"pattern": label, "sample": m.group(0)[:50]})
    result.details = {"patterns_checked": [p[1] for p in patterns], "found": found}
    if found:
        result.status = "failed"
        result.severity = "medium"
        result.description = f"Sensitive data patterns: {', '.join(f['pattern'] for f in found[:3])}"
        result.evidence = f"Sample: {found[0].get('sample', '')}"
        result.remediation = "Never expose PII or secrets in client-side responses."
    else:
        result.status = "passed"
        result.description = "No obvious PII patterns in response"
    return result


# ─── Check 17: Subresource Integrity ───

def check_sri(target_url: str) -> DastResult:
    """Check for missing SRI on external scripts."""
    result = DastResult(
        check_id="DAST-SRI-01",
        title="Subresource Integrity (SRI)",
        owasp_ref="A08:2021",
        cwe_id="CWE-353",
    )
    resp = _safe_get(target_url)
    if not resp:
        result.status = "error"
        result.description = "Could not reach target"
        return result
    body = resp.text or ""
    script_tags = re.findall(r'<script[^>]*src=["\']([^"\']+)["\'][^>]*>', body, re.I)
    no_sri = []
    for src in script_tags:
        if src.startswith("http") or src.startswith("//"):
            idx = body.find(src)
            if idx >= 0 and "integrity=" not in body[max(0, idx - 150):idx + 250]:
                no_sri.append(src[:80])
    result.details = {"external_scripts": [s[:80] for s in script_tags if (s.startswith("http") or s.startswith("//"))][:20], "missing_sri": no_sri[:10]}
    if no_sri:
        result.status = "failed"
        result.severity = "low"
        result.description = f"{len(no_sri)} external script(s) without SRI"
        result.evidence = f"Scripts: {', '.join(no_sri[:3])}"
        result.remediation = "Add integrity attribute to external scripts for SRI."
    else:
        result.status = "passed"
        result.description = "No external scripts without SRI (or no external scripts)"
    return result


# ─── Check 18: Cache Control ───

def check_cache_control(target_url: str) -> DastResult:
    """Check Cache-Control on sensitive-looking paths."""
    result = DastResult(
        check_id="DAST-CACHE-01",
        title="Cache Control on Sensitive Pages",
        owasp_ref="A05:2021",
        cwe_id="CWE-524",
    )
    paths = ["/", "/login", "/dashboard", "/api/user", "/profile", "/admin"]
    base = f"{urlparse(target_url).scheme}://{urlparse(target_url).netloc}"
    issues = []
    for path in paths:
        r = _safe_get(urljoin(base, path))
        if r and r.status_code == 200:
            cc = r.headers.get("cache-control", "").lower()
            if "no-store" not in cc and "no-cache" not in cc and "private" not in cc:
                issues.append({"path": path, "cache_control": cc or "(none)"})
    result.details = {"paths_checked": paths, "missing_no_store": issues}
    if issues:
        result.status = "failed"
        result.severity = "low"
        result.description = f"Missing no-store on {len(issues)} path(s)"
        result.evidence = f"Paths: {', '.join(i['path'] for i in issues[:5])}"
        result.remediation = "Set Cache-Control: no-store on sensitive pages."
    else:
        result.status = "passed"
        result.description = "Cache headers adequate on checked paths"
    return result


# ─── Check 19: Form Autocomplete ───

def check_form_autocomplete(target_url: str) -> DastResult:
    """Check for autocomplete on password fields."""
    result = DastResult(
        check_id="DAST-FORM-01",
        title="Password Autocomplete",
        owasp_ref="A07:2021",
        cwe_id="CWE-525",
    )
    resp = _safe_get(target_url)
    if not resp:
        result.status = "error"
        result.description = "Could not reach target"
        return result
    body = resp.text or ""
    pwd_inputs = re.findall(r'<input[^>]*type=["\']?password["\']?[^>]*>', body, re.I)
    bad = []
    for inp in pwd_inputs:
        if "autocomplete" not in inp.lower() or "autocomplete=\"on\"" in inp.lower() or "autocomplete='on'" in inp.lower():
            bad.append(inp[:100])
    result.details = {"password_inputs": len(pwd_inputs), "missing_off": len(bad)}
    if bad and pwd_inputs:
        result.status = "failed"
        result.severity = "low"
        result.description = "Password field(s) without autocomplete=off"
        result.remediation = "Add autocomplete='off' to password inputs."
    else:
        result.status = "passed"
        result.description = "Password fields have autocomplete=off or no password inputs"
    return result


# ─── Check 20: Backup File Disclosure ───

def check_backup_files(target_url: str) -> DastResult:
    """Check for common backup/config file exposure."""
    result = DastResult(
        check_id="DAST-BACKUP-01",
        title="Backup File Disclosure",
        owasp_ref="A05:2021",
        cwe_id="CWE-530",
    )
    paths = ["/.git/config", "/.env", "/config.php.bak", "/web.config.bak", "/.htaccess.bak", "/backup.sql", "/db.sql", "/dump.sql"]
    base = f"{urlparse(target_url).scheme}://{urlparse(target_url).netloc}"
    exposed = []
    for path in paths:
        r = _safe_get(urljoin(base, path))
        if r and r.status_code == 200 and len(r.text or "") > 0:
            if "root" in (r.text or "").lower() or "password" in (r.text or "").lower() or "[core]" in (r.text or "") or "database" in (r.text or "").lower():
                exposed.append(path)
    result.details = {"paths_checked": paths, "exposed": exposed}
    if exposed:
        result.status = "failed"
        result.severity = "high"
        result.description = f"Backup/config file(s) exposed: {', '.join(exposed)}"
        result.evidence = f"Exposed: {', '.join(exposed)}"
        result.remediation = "Remove backup files from web root. Restrict .git, .env access."
    else:
        result.status = "passed"
        result.description = "No backup/config files exposed"
    return result


# ─── Check 21: Directory/Path Discovery ───

def _run_ffuf_discovery(target_url: str, wordlist_path: str, max_paths: int) -> list[dict]:
    """Run ffuf for directory discovery if available. Returns list of {path, status}."""
    import subprocess
    import tempfile
    try:
        parsed = urlparse(target_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        u = f"{base.rstrip('/')}/FUZZ"
        fd, outpath = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        try:
            proc = subprocess.run(
                ["ffuf", "-u", u, "-w", wordlist_path, "-mc", "200,201,301,302,401,403", "-fc", "404", "-t", "20", "-o", outpath, "-of", "json"],
                capture_output=True, timeout=90, env={**os.environ}
            )
            if proc.returncode != 0:
                return []
            with open(outpath, "rb") as f:
                data = json.loads(f.read().decode("utf-8", errors="ignore"))
        finally:
            try:
                os.unlink(outpath)
            except OSError:
                pass
        results = data.get("results", [])[:max_paths]
        return [{"path": "/" + str(r.get("input", {}).get("FUZZ", "")), "status": r.get("status", 0)} for r in results]
    except (FileNotFoundError, subprocess.TimeoutExpired, json.JSONDecodeError, KeyError, OSError) as e:
        logger.debug("ffuf discovery skipped: %s", e)
        return []


def check_directory_discovery(target_url: str) -> DastResult:
    """Discover hidden paths using SecLists/IntruderPayloads (httpx) or ffuf when available."""
    result = DastResult(
        check_id="DAST-DIR-02",
        title="Directory & Path Discovery",
        owasp_ref="A05:2021",
        cwe_id="CWE-548",
    )
    base_resp = _safe_get(target_url)
    if not base_resp:
        result.status = "error"
        result.description = "Could not reach target"
        return result

    base = urlparse(target_url)
    root = f"{base.scheme}://{base.netloc}"
    discovered = []
    wordlist = _load_discovery_wordlist(100)
    wordlist_source = "SecLists/IntruderPayloads"

    # Try ffuf first if wordlist file exists
    for wp in WORDLIST_PATHS:
        if wp.exists():
            ffuf_results = _run_ffuf_discovery(target_url, str(wp), 50)
            if ffuf_results:
                discovered = ffuf_results
                wordlist_source = f"ffuf+{wp.name}"
                break

    # Fallback: httpx-based discovery
    if not discovered:
        discard_codes = {404, 410}
        for path in wordlist:
            path = path.strip().lstrip("/")
            if not path:
                continue
            test_url = urljoin(root + "/", path)
            try:
                with httpx.Client(timeout=httpx.Timeout(4.0, connect=3.0), headers=HEADERS, verify=False, follow_redirects=True) as client:
                    r = client.get(test_url)
            except Exception:
                continue
            if r.status_code not in discard_codes:
                discovered.append({"path": f"/{path}", "status": r.status_code})
            if len(discovered) >= 25:
                break

    result.details = {"paths_checked": len(wordlist), "discovered": discovered, "wordlist_source": wordlist_source}
    if base_resp:
        result.request_raw = f"GET {target_url} HTTP/1.1\nHost: {base.netloc}"
        result.response_raw = f"HTTP/1.1 {base_resp.status_code}\n" + "\n".join(f"{k}: {v}" for k, v in base_resp.headers.items()) + "\n\n" + (base_resp.text[:1500] if base_resp.text else "")
    if discovered:
        result.status = "failed"
        result.severity = "low"
        result.description = f"Discovered {len(discovered)} path(s) on target"
        result.evidence = ", ".join(f"{d['path']} ({d['status']})" for d in discovered[:10])
        result.remediation = "Restrict access to sensitive paths. Disable directory listing."
        result.reproduction_steps = f"1. Fuzz base URL with wordlist\n2. Paths found: {', '.join(d['path'] for d in discovered[:8])}"
    else:
        result.status = "passed"
        result.description = f"No additional paths discovered ({len(wordlist)} paths checked)"
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
    ("xss_basic", check_xss_basic),
    ("sqli_error", check_sqli_error),
    ("api_docs_exposure", check_api_docs_exposure),
    ("host_header_injection", check_host_header_injection),
    ("crlf_injection", check_crlf_injection),
    ("sensitive_data", check_sensitive_data),
    ("sri", check_sri),
    ("cache_control", check_cache_control),
    ("form_autocomplete", check_form_autocomplete),
    ("backup_files", check_backup_files),
    ("directory_discovery", check_directory_discovery),
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
