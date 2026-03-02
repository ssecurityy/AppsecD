"""DAST Automation Engine — WAF-aware, rate-limit-safe scanning.

Uses throttling, UA rotation, reachability probe. Optional ffuf for discovery.
SecLists/IntruderPayloads wordlists when available.
"""
import base64
import httpx
import ssl
import json
import time
import logging
import re
import os
import random
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse, urljoin

logger = logging.getLogger(__name__)

# Realistic browser User-Agents — rotate to evade WAF/blocking
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
]
BROWSER_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
}
HEADERS = {**BROWSER_HEADERS, "User-Agent": USER_AGENTS[0]}

DATA_ROOT = Path(__file__).resolve().parents[2] / "data"

# Multiple wordlists for full recon coverage — quick first, then comprehensive
WORDLIST_PATHS = [
    DATA_ROOT / "IntruderPayloads" / "FuzzLists" / "dirbuster-quick.txt",
    DATA_ROOT / "SecLists" / "Discovery" / "Web-Content" / "DirBuster-2007_directory-list-2.3-small.txt",
    DATA_ROOT / "IntruderPayloads" / "FuzzLists" / "dirbuster-top1000.txt",
    DATA_ROOT / "IntruderPayloads" / "FuzzLists" / "dirbuster-dirs.txt",
    DATA_ROOT / "SecLists" / "Discovery" / "Web-Content" / "DirBuster-2007_directory-list-lowercase-2.3-small.txt",
    DATA_ROOT / "SecLists" / "Discovery" / "Web-Content" / "Common-DB-Backups.txt",
    DATA_ROOT / "SecLists" / "Discovery" / "Web-Content" / "Logins.fuzz.txt",
]

# Full wordlists for "Run Full Wordlist" button (large files)
FULL_WORDLIST_PATHS = [
    ("small", DATA_ROOT / "SecLists" / "Discovery" / "Web-Content" / "DirBuster-2007_directory-list-2.3-small.txt"),
    ("medium", DATA_ROOT / "SecLists" / "Discovery" / "Web-Content" / "DirBuster-2007_directory-list-2.3-medium.txt"),
    ("dirbuster-dirs", DATA_ROOT / "IntruderPayloads" / "FuzzLists" / "dirbuster-dirs.txt"),
    ("api-common", DATA_ROOT / "SecLists" / "Discovery" / "Web-Content" / "Logins.fuzz.txt"),
]


def _load_discovery_wordlist(max_paths: int = 400) -> list[str]:
    """Load and merge from multiple wordlists for full recon coverage."""
    seen = set()
    merged: list[str] = []
    for p in WORDLIST_PATHS:
        if not p.exists():
            continue
        try:
            with open(p, encoding="utf-8", errors="ignore") as f:
                for ln in f:
                    w = ln.strip()
                    if not w or w.startswith("#"):
                        continue
                    w = w.lstrip("/")
                    if w and w not in seen:
                        seen.add(w)
                        merged.append(w)
                        if len(merged) >= max_paths:
                            return merged
        except Exception as e:
            logger.debug("Could not load wordlist %s: %s", p, e)
    if not merged:
        merged = ["admin", "login", "api", "config", "backup", "static", "assets", "uploads", "images", "css", "js", "wp-admin", ".git", ".env", "debug", "test", "dev", "staging", "dashboard", "panel"]
    return merged

TIMEOUT = httpx.Timeout(20.0, connect=10.0)
MIN_DELAY_BETWEEN_REQUESTS = 1.2
MAX_DELAY_BETWEEN_REQUESTS = 2.8
PROBE_DELAY = 2.0  # delay between probe attempts
_scan_ctx: "ScanContext | None" = None


class ScanContext:
    """WAF-aware scan context: resolved base URL, throttling, UA rotation."""
    def __init__(self, base_url: str | None):
        self.base_url = base_url
        self.ua_index = 0
        self.last_request = 0.0

    def _headers(self) -> dict:
        h = dict(BROWSER_HEADERS)
        h["User-Agent"] = USER_AGENTS[self.ua_index % len(USER_AGENTS)]
        self.ua_index += 1
        return h

    def throttle(self) -> None:
        elapsed = time.time() - self.last_request
        delay = random.uniform(MIN_DELAY_BETWEEN_REQUESTS, MAX_DELAY_BETWEEN_REQUESTS)
        if elapsed < delay:
            time.sleep(delay - elapsed)
        self.last_request = time.time()

    def _rewrite_url(self, url: str) -> str:
        """Use resolved base scheme+netloc when same host to avoid re-failing."""
        if not self.base_url:
            return url
        p_url = urlparse(url)
        p_base = urlparse(self.base_url)
        if p_url.netloc and p_url.netloc.lower() == p_base.netloc.lower():
            return f"{p_base.scheme}://{p_base.netloc}{p_url.path or '/'}{p_url.query and '?' + p_url.query or ''}"
        return url

    def safe_get(self, url: str, **kwargs) -> httpx.Response | None:
        self.throttle()
        url = self._rewrite_url(url)
        urls_to_try = _url_variants(url)
        for attempt in range(2):  # retry with different UA
            for u in urls_to_try:
                try:
                    h = self._headers()
                    h.update(kwargs.pop("headers", {}))
                    with httpx.Client(timeout=TIMEOUT, headers=h, verify=False, follow_redirects=True) as client:
                        r = client.get(u, **kwargs)
                        if r.status_code == 429:
                            time.sleep(random.uniform(5, 10))
                            continue
                        return r
                except Exception as e:
                    logger.debug("DAST GET %s failed: %s", u, e)
            time.sleep(PROBE_DELAY)
        logger.warning("DAST request failed for %s", url)
        return None

    def safe_request(self, method: str, url: str, **kwargs) -> httpx.Response | None:
        self.throttle()
        url = self._rewrite_url(url)
        urls_to_try = _url_variants(url)
        for attempt in range(2):
            for u in urls_to_try:
                try:
                    h = self._headers()
                    h.update(kwargs.pop("headers", {}))
                    with httpx.Client(timeout=TIMEOUT, headers=h, verify=False, follow_redirects=False) as client:
                        r = client.request(method, u, **kwargs)
                        if r.status_code == 429:
                            time.sleep(random.uniform(5, 10))
                            continue
                        return r
                except Exception as e:
                    logger.debug("DAST %s %s failed: %s", method, u, e)
            time.sleep(PROBE_DELAY)
        logger.warning("DAST %s failed for %s", method, url)
        return None


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
    if _scan_ctx:
        return _scan_ctx.safe_get(url, **kwargs)
    for u in _url_variants(url):
        try:
            h = {**BROWSER_HEADERS, "User-Agent": USER_AGENTS[0]}
            with httpx.Client(timeout=TIMEOUT, headers=h, verify=False, follow_redirects=True) as client:
                return client.get(u, **kwargs)
        except Exception as e:
            logger.debug("DAST GET %s failed: %s", u, e)
    return None


def _safe_request(method: str, url: str, **kwargs) -> httpx.Response | None:
    if _scan_ctx:
        return _scan_ctx.safe_request(method, url, **kwargs)
    for u in _url_variants(url):
        try:
            h = {**BROWSER_HEADERS, "User-Agent": USER_AGENTS[0]}
            with httpx.Client(timeout=TIMEOUT, headers=h, verify=False, follow_redirects=False) as client:
                return client.request(method, u, **kwargs)
        except Exception as e:
            logger.debug("DAST %s %s failed: %s", method, u, e)
    return None


def _resolve_base_url(target_url: str) -> str | None:
    """Probe URL variants with rotating UA; return first reachable base URL. Slow, WAF-safe."""
    parsed = urlparse(target_url)
    variants = _url_variants(target_url)
    for _ in range(2):  # two passes with different UAs
        for ua in USER_AGENTS:
            for u in variants:
                try:
                    time.sleep(PROBE_DELAY)
                    with httpx.Client(
                        timeout=TIMEOUT,
                        headers={**BROWSER_HEADERS, "User-Agent": ua},
                        verify=False,
                        follow_redirects=True,
                    ) as client:
                        r = client.get(u)
                        if r.status_code < 500:
                            p = urlparse(str(r.url))
                            return f"{p.scheme}://{p.netloc}/"
                except Exception as e:
                    logger.debug("Probe %s failed: %s", u, e)
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
        resp = _safe_get(target_url)
        result.status = "failed"
        result.severity = "high"
        result.description = "Target does not use HTTPS"
        result.remediation = "Enable HTTPS with a valid TLS certificate"
        result.reproduction_steps = f"1. Navigate to {target_url}\n2. Observe protocol is HTTP, not HTTPS"
        result.evidence = f"URL scheme: {parsed.scheme}"
        if resp:
            result.request_raw = f"GET {target_url} HTTP/1.1\nHost: {parsed.netloc}"
            result.response_raw = f"HTTP/1.1 {resp.status_code}\n" + "\n".join(f"{k}: {v}" for k, v in resp.headers.items()) + "\n\n" + (resp.text[:1500] if resp.text else "")
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
                result.request_raw = f"TLS connect to {host}:{port}\nSNI: {host}"
                result.response_raw = f"Protocol: {protocol}\nCipher: {cipher[0] if cipher else 'N/A'}\nCert subject: {cert.get('subject', '')}"
    except ssl.SSLCertVerificationError as e:
        result.status = "failed"
        result.severity = "high"
        result.description = f"SSL certificate verification failed: {str(e)[:200]}"
        result.remediation = "Install a valid SSL certificate from a trusted CA"
        result.request_raw = f"TLS connect to {parsed.hostname}:{parsed.port or 443}\nSNI: {parsed.hostname}"
        result.response_raw = f"Error: SSL certificate verification failed\n{str(e)[:500]}"
    except Exception as e:
        result.status = "error"
        result.description = f"SSL check error: {str(e)[:200]}"
        result.request_raw = f"TLS connect to {parsed.hostname}:{parsed.port or 443}"
        result.response_raw = f"Error: {str(e)[:500]}"
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
        result.request_raw = f"GET {target_url} HTTP/1.1\nHost: {urlparse(target_url).netloc}"
        result.response_raw = f"HTTP/1.1 {resp.status_code}\n" + "\n".join(f"{k}: {v}" for k, v in resp.headers.items()) + "\n\n" + (resp.text[:1500] if resp.text else "")
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


# ─── Check 6b: Tech Fingerprint (Wappalyzer/WhatWeb-style) ───

def check_tech_fingerprint(target_url: str) -> DastResult:
    """Technology fingerprinting (Wappalyzer/WhatWeb-style) — detect frameworks, server, WAF."""
    result = DastResult(
        check_id="DAST-RECON-01",
        title="Tech Fingerprint",
        owasp_ref="A05:2021",
        cwe_id="CWE-200",
    )
    try:
        from app.services.tech_detection_service import detect_technology
        stack = detect_technology(target_url)
    except Exception as e:
        logger.debug("Tech fingerprint failed: %s", e)
        result.status = "error"
        result.description = "Technology detection unavailable"
        return result

    detected = stack.get("stack_profile", {}) or {}
    flat = []
    for cat, items in detected.items():
        if isinstance(items, list):
            flat.extend(str(x) for x in items if x)
        elif isinstance(items, str) and items:
            flat.append(items)
    flat = list(dict.fromkeys(flat))
    waf = detected.get("waf") or []

    result.details = {"stack_profile": detected, "technologies": flat, "waf": waf}
    if stack.get("effective_url"):
        result.request_raw = f"GET {stack['effective_url']} — Tech scan"
    if flat or waf:
        result.status = "failed"
        result.severity = "info"
        result.description = f"Detected: {', '.join(flat[:12])}" + (f" | WAF: {', '.join(waf)}" if waf else "")
        result.evidence = f"Technologies: {', '.join(flat)}\nWAF: {', '.join(waf) or 'None'}"
        result.remediation = "Minimize technology disclosure in headers and HTML"
    else:
        result.status = "passed"
        result.description = "Minimal technology disclosure"
    return result


# ─── Check 6c: sitemap.xml ───

def check_sitemap_xml(target_url: str) -> DastResult:
    """Check sitemap.xml for sensitive paths and indexability."""
    result = DastResult(
        check_id="DAST-RECON-02",
        title="sitemap.xml Analysis",
        owasp_ref="A05:2021",
        cwe_id="CWE-200",
    )
    parsed = urlparse(target_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    sitemap_url = urljoin(base, "/sitemap.xml")
    resp = _safe_get(sitemap_url)
    if not resp or resp.status_code != 200:
        result.status = "passed"
        result.description = "No sitemap.xml found"
        return result

    content = resp.text or ""
    sensitive = ["admin", "login", "config", "backup", "api/", "internal", "debug", "test"]
    urls_found = re.findall(r"<loc>([^<]+)</loc>", content, re.I)
    sensitive_found = [u for u in urls_found if any(s in u.lower() for s in sensitive)]

    result.details = {"urls_count": len(urls_found), "sensitive_paths": sensitive_found}
    if resp:
        result.request_raw = f"GET {sitemap_url} HTTP/1.1\nHost: {parsed.netloc}"
        result.response_raw = f"HTTP/1.1 {resp.status_code}\n\n{content[:2000]}"
    if sensitive_found:
        result.status = "failed"
        result.severity = "low"
        result.description = f"sitemap.xml exposes {len(sensitive_found)} sensitive path(s)"
        result.evidence = ", ".join(sensitive_found[:8])
        result.remediation = "Exclude sensitive URLs from sitemap.xml"
    else:
        result.status = "passed"
        result.description = f"sitemap.xml found with {len(urls_found)} URL(s), no sensitive paths"
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
        if _scan_ctx:
            _scan_ctx.throttle()
        try:
            with httpx.Client(timeout=TIMEOUT, headers={**HEADERS, "User-Agent": USER_AGENTS[hash(param) % len(USER_AGENTS)]}, verify=False, follow_redirects=False) as client:
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


def run_ffuf_full_scan(target_url: str, base_path: str = "/", wordlist_key: str = "small", max_results: int = 200) -> dict:
    """
    Run full ffuf wordlist scan on a base path. For "Run Full Wordlist" button.
    Returns {success, discovered, wordlist_used, error}.
    """
    import subprocess
    import tempfile
    parsed = urlparse(target_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    path = (base_path or "/").rstrip("/")
    base_url = f"{base}{path}/"
    fuzz_url = f"{base_url.rstrip('/')}/FUZZ"

    wordlist_path = None
    for key, wp in FULL_WORDLIST_PATHS:
        if key == wordlist_key and wp.exists():
            wordlist_path = str(wp)
            break
    if not wordlist_path:
        for key, wp in FULL_WORDLIST_PATHS:
            if wp.exists():
                wordlist_path = str(wp)
                wordlist_key = key
                break
    if not wordlist_path:
        return {"success": False, "discovered": [], "wordlist_used": "", "error": "No wordlist available"}

    fd, outpath = None, None
    try:
        fd, outpath = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        proc = subprocess.run(
            ["ffuf", "-u", fuzz_url, "-w", wordlist_path, "-mc", "200,201,204,301,302,307,401,403,405", "-fc", "404", "-t", "25", "-o", outpath, "-of", "json"],
            capture_output=True, timeout=180, env={**os.environ}
        )
        if proc.returncode != 0:
            stderr = (proc.stderr or b"").decode("utf-8", errors="ignore")[:500]
            return {"success": False, "discovered": [], "wordlist_used": wordlist_key, "error": f"ffuf exit {proc.returncode}: {stderr}"}
        with open(outpath, "rb") as f:
            data = json.loads(f.read().decode("utf-8", errors="ignore"))
        results = data.get("results", [])[:max_results]
        discovered = [{"path": f"{path}/{r.get('input', {}).get('FUZZ', '')}".replace("//", "/"), "status": r.get("status", 0)} for r in results]
        return {"success": True, "discovered": discovered, "wordlist_used": wordlist_key, "error": ""}
    except subprocess.TimeoutExpired:
        return {"success": False, "discovered": [], "wordlist_used": wordlist_key, "error": "ffuf timeout (180s)"}
    except FileNotFoundError:
        return {"success": False, "discovered": [], "wordlist_used": "", "error": "ffuf not installed"}
    except Exception as e:
        return {"success": False, "discovered": [], "wordlist_used": "", "error": str(e)}
    finally:
        if outpath and os.path.exists(outpath):
            try:
                os.unlink(outpath)
            except OSError:
                pass


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
    wordlist = _load_discovery_wordlist(400)
    wordlist_source = "SecLists/IntruderPayloads (merged)"

    # Try ffuf first with multiple wordlists for full coverage
    for wp in WORDLIST_PATHS:
        if wp.exists():
            ffuf_results = _run_ffuf_discovery(target_url, str(wp), 80)
            if ffuf_results:
                discovered.extend(ffuf_results)
                wordlist_source = f"ffuf+{wp.name}"
                break

    # Dedupe by path
    if discovered:
        by_path: dict[str, dict] = {}
        for d in discovered:
            p = d.get("path", "")
            if p and p not in by_path:
                by_path[p] = d
        discovered = list(by_path.values())

    # Fallback: httpx-based discovery (throttled to avoid WAF/rate limit)
    if not discovered:
        discard_codes = {404, 410}
        for i, path in enumerate(wordlist):
            path = path.strip().lstrip("/")
            if not path:
                continue
            if i > 0:
                time.sleep(random.uniform(0.15, 0.4))  # throttle
            test_url = urljoin(root + "/", path)
            try:
                with httpx.Client(timeout=httpx.Timeout(5.0, connect=3.0), headers={**HEADERS, "User-Agent": USER_AGENTS[i % len(USER_AGENTS)]}, verify=False, follow_redirects=True) as client:
                    r = client.get(test_url)
            except Exception:
                continue
            if r.status_code not in discard_codes:
                discovered.append({"path": f"/{path}", "status": r.status_code})
            if len(discovered) >= 50:
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


# ─── Check 22: Security.txt (RFC 9116) ───

def check_security_txt(target_url: str) -> DastResult:
    """Verify presence and format of /.well-known/security.txt for coordinated disclosure."""
    result = DastResult(
        check_id="DAST-SECTXT-01",
        title="Security.txt (RFC 9116)",
        owasp_ref="A05:2021",
        cwe_id="CWE-200",
    )
    parsed = urlparse(target_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    url = urljoin(base, "/.well-known/security.txt")
    resp = _safe_get(url)
    if not resp:
        result.status = "error"
        result.description = "Could not reach target"
        return result
    body = (resp.text or "").strip()
    if resp.status_code == 404:
        result.status = "failed"
        result.severity = "info"
        result.description = "security.txt not found at /.well-known/security.txt"
        result.remediation = "Add /.well-known/security.txt per RFC 9116 with Contact, Expires, and optional Canonical"
        result.reproduction_steps = f"1. GET {url}\n2. Received 404"
    elif resp.status_code != 200:
        result.status = "failed"
        result.severity = "low"
        result.description = f"security.txt returned {resp.status_code}"
        result.remediation = "Ensure /.well-known/security.txt returns 200 OK"
    else:
        has_contact = "contact:" in body.lower() or "mailto:" in body.lower()
        if not has_contact:
            result.status = "failed"
            result.severity = "low"
            result.description = "security.txt exists but missing required Contact field"
            result.remediation = "Add Contact field per RFC 9116 (e.g., Contact: mailto:security@example.com)"
        else:
            result.status = "passed"
            result.description = "security.txt present and valid (contains Contact)"
    result.request_raw = f"GET {url} HTTP/1.1\nHost: {parsed.netloc}"
    result.response_raw = f"HTTP/1.1 {resp.status_code}\n" + "\n".join(f"{k}: {v}" for k, v in resp.headers.items()) + "\n\n" + (body[:1500] if body else "")
    result.details = {"url": url, "status_code": resp.status_code}
    return result


# ─── Check 23: HTTP to HTTPS Redirect ───

def check_http_redirect_https(target_url: str) -> DastResult:
    """Verify HTTP requests redirect to HTTPS."""
    result = DastResult(
        check_id="DAST-REDIR-02",
        title="HTTP to HTTPS Redirect",
        owasp_ref="A02:2021",
        cwe_id="CWE-319",
    )
    parsed = urlparse(target_url)
    if parsed.scheme != "https":
        result.status = "passed"
        result.description = "Target is HTTP-only; redirect check N/A"
        result.details = {"reason": "target_not_https"}
        return result
    http_url = f"http://{parsed.netloc}{parsed.path or '/'}{parsed.query and '?' + parsed.query or ''}"
    resp = _safe_request("GET", http_url)  # Do not follow redirects - we need to see 301/302
    if not resp:
        result.status = "error"
        result.description = "Could not reach HTTP endpoint"
        return result
    if resp.status_code in (301, 302, 307, 308):
        loc = resp.headers.get("location", "")
        if loc.lower().startswith("https://"):
            result.status = "passed"
            result.description = "HTTP redirects to HTTPS"
            result.details = {"redirect_to": loc[:100]}
        else:
            result.status = "failed"
            result.severity = "high"
            result.description = f"HTTP redirects to non-HTTPS: {loc[:80]}"
            result.remediation = "Ensure HTTP redirects to HTTPS (301/302 Location: https://...)"
            result.reproduction_steps = f"1. GET {http_url}\n2. Observe Location: {loc[:100]}"
    else:
        result.status = "failed"
        result.severity = "high"
        result.description = f"HTTP does not redirect to HTTPS (status {resp.status_code})"
        result.remediation = "Configure HTTP to redirect (301/302) to HTTPS"
        result.reproduction_steps = f"1. GET {http_url}\n2. Received {resp.status_code} instead of redirect"
    result.request_raw = f"GET {http_url} HTTP/1.1\nHost: {parsed.netloc}"
    result.response_raw = f"HTTP/1.1 {resp.status_code}\n" + "\n".join(f"{k}: {v}" for k, v in resp.headers.items()) + "\n\n"
    result.evidence = resp.headers.get("location", "No Location header")
    return result


# ─── Check 24: HSTS Preload Readiness ───

def check_hsts_preload(target_url: str) -> DastResult:
    """Check HSTS header is preload-ready (max-age>=31536000, includeSubDomains, preload)."""
    result = DastResult(
        check_id="DAST-HSTS-01",
        title="HSTS Preload Readiness",
        owasp_ref="A02:2021",
        cwe_id="CWE-319",
    )
    resp = _safe_get(target_url)
    if not resp:
        result.status = "error"
        result.description = "Could not reach target"
        return result
    parsed = urlparse(target_url)
    if parsed.scheme != "https":
        result.status = "passed"
        result.description = "Target is HTTP; HSTS N/A"
        result.details = {"reason": "http_target"}
        return result
    hsts = resp.headers.get("strict-transport-security", resp.headers.get("Strict-Transport-Security", ""))
    result.request_raw = f"GET {target_url} HTTP/1.1\nHost: {parsed.netloc}"
    result.response_raw = f"HTTP/1.1 {resp.status_code}\n" + "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
    if not hsts:
        result.status = "failed"
        result.severity = "medium"
        result.description = "HSTS header missing"
        result.remediation = "Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
        result.reproduction_steps = f"1. GET {target_url}\n2. Check response headers for Strict-Transport-Security"
    else:
        hsts_lower = hsts.lower()
        max_age_match = re.search(r"max-age=(\d+)", hsts_lower)
        max_age = int(max_age_match.group(1)) if max_age_match else 0
        has_preload = "preload" in hsts_lower
        has_subdomains = "includesubdomains" in hsts_lower
        issues = []
        if max_age < 31536000:
            issues.append(f"max-age={max_age} (need >= 31536000 for preload)")
        if not has_preload:
            issues.append("missing preload directive")
        if not has_subdomains:
            issues.append("missing includeSubDomains")
        result.details = {"hsts_value": hsts[:200], "max_age": max_age, "has_preload": has_preload}
        if issues:
            result.status = "failed"
            result.severity = "low"
            result.description = f"HSTS not preload-ready: {'; '.join(issues)}"
            result.remediation = "Use Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
        else:
            result.status = "passed"
            result.description = "HSTS preload-ready"
    return result


# ─── Check 25: Additional Version Headers ───

def check_version_headers(target_url: str) -> DastResult:
    """Check for version disclosure in X-Generator, X-Runtime, X-Varnish, X-Drupal-Cache, etc."""
    result = DastResult(
        check_id="DAST-VER-01",
        title="Version Header Disclosure",
        owasp_ref="A05:2021",
        cwe_id="CWE-200",
    )
    resp = _safe_get(target_url)
    if not resp:
        result.status = "error"
        result.description = "Could not reach target"
        return result
    version_headers = ["x-generator", "x-runtime", "x-aspnetmvc-version", "x-drupal-cache", "x-varnish", "x-request-id", "x-version", "x-build", "x-revision"]
    headers = {k.lower(): v for k, v in resp.headers.items()}
    found = {h: headers[h] for h in version_headers if h in headers}
    result.details = {"found": found}
    result.request_raw = f"GET {target_url} HTTP/1.1\nHost: {urlparse(target_url).netloc}"
    result.response_raw = f"HTTP/1.1 {resp.status_code}\n" + "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
    if found:
        result.status = "failed"
        result.severity = "low"
        result.description = f"Version headers disclosed: {', '.join(found.keys())}"
        result.evidence = "; ".join(f"{k}: {v}" for k, v in list(found.items())[:5])
        result.remediation = "Remove or genericize X-Generator, X-Runtime, and similar version headers"
        result.reproduction_steps = f"1. GET {target_url}\n2. Inspect response headers\n3. Found: {list(found.keys())}"
    else:
        result.status = "passed"
        result.description = "No additional version headers disclosed"
    return result


# ─── Check 26: COOP/COEP Headers ───

def check_coop_coep(target_url: str) -> DastResult:
    """Check Cross-Origin-Opener-Policy and Cross-Origin-Embedder-Policy for Spectre mitigation."""
    result = DastResult(
        check_id="DAST-COOP-01",
        title="COOP/COEP Headers",
        owasp_ref="A05:2021",
        cwe_id="CWE-1021",
    )
    resp = _safe_get(target_url)
    if not resp:
        result.status = "error"
        result.description = "Could not reach target"
        return result
    headers = {k.lower(): v for k, v in resp.headers.items()}
    coop = headers.get("cross-origin-opener-policy", "")
    coep = headers.get("cross-origin-embedder-policy", "")
    result.details = {"coop": coop, "coep": coep}
    result.request_raw = f"GET {target_url} HTTP/1.1\nHost: {urlparse(target_url).netloc}"
    result.response_raw = f"HTTP/1.1 {resp.status_code}\n" + "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
    if not coop and not coep:
        result.status = "failed"
        result.severity = "info"
        result.description = "COOP/COEP headers not set"
        result.remediation = "Consider Cross-Origin-Opener-Policy: same-origin and Cross-Origin-Embedder-Policy: require-corp for sensitive apps"
    else:
        result.status = "passed"
        result.description = f"COOP/COEP present" if (coop and coep) else "Partial COOP/COEP"
    return result


# ─── Check 27: Weak Referrer-Policy ───

def check_weak_referrer(target_url: str) -> DastResult:
    """Check for weak or missing Referrer-Policy (unsafe-url, no-referrer-when-downgrade)."""
    result = DastResult(
        check_id="DAST-REF-01",
        title="Referrer-Policy Strength",
        owasp_ref="A05:2021",
        cwe_id="CWE-200",
    )
    resp = _safe_get(target_url)
    if not resp:
        result.status = "error"
        result.description = "Could not reach target"
        return result
    ref = resp.headers.get("referrer-policy", resp.headers.get("Referrer-Policy", ""))
    ref_lower = ref.lower().strip()
    weak = ["unsafe-url", "no-referrer-when-downgrade", ""]
    result.details = {"value": ref or "(not set)"}
    result.request_raw = f"GET {target_url} HTTP/1.1\nHost: {urlparse(target_url).netloc}"
    result.response_raw = f"HTTP/1.1 {resp.status_code}\n" + "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
    if not ref_lower:
        result.status = "failed"
        result.severity = "low"
        result.description = "Referrer-Policy header missing"
        result.remediation = "Set Referrer-Policy: strict-origin-when-cross-origin or stricter"
    elif ref_lower in weak or "unsafe" in ref_lower:
        result.status = "failed"
        result.severity = "low"
        result.description = f"Weak Referrer-Policy: {ref}"
        result.remediation = "Use strict-origin-when-cross-origin, strict-origin, or no-referrer"
    else:
        result.status = "passed"
        result.description = f"Referrer-Policy adequate: {ref}"
    return result


# ─── Check 28: Debug/Stack Trace in Response ───

def check_debug_response(target_url: str) -> DastResult:
    """Check for stack traces, debug output, or exception messages in response body."""
    result = DastResult(
        check_id="DAST-DEBUG-01",
        title="Debug/Stack Trace in Response",
        owasp_ref="A05:2021",
        cwe_id="CWE-209",
    )
    resp = _safe_get(target_url)
    if not resp:
        result.status = "error"
        result.description = "Could not reach target"
        return result
    body = (resp.text or "")[:8000].lower()
    patterns = [
        (r"traceback\s*\(|traceback\s*:", "Traceback"),
        (r"at\s+\S+\.(\w+)\s*\(", "Stack frame"),
        (r"fatal error|php fatal|uncaught exception", "Fatal error"),
        (r"exception\s+in\s+thread|exception\s+in\s+main", "Exception message"),
        (r"\.pyc\s+in\s+line|file\s+\".*?\"\s+line", "Python trace"),
        (r"sqlstate\[|pdoexception|mysqli_", "Database error"),
        (r"java\.lang\.|nullpointerexception|stacktrace", "Java stack trace"),
    ]
    found = []
    for pat, label in patterns:
        if re.search(pat, body):
            found.append(label)
    result.details = {"patterns_checked": len(patterns), "found": found}
    result.request_raw = f"GET {target_url} HTTP/1.1\nHost: {urlparse(target_url).netloc}"
    result.response_raw = f"HTTP/1.1 {resp.status_code}\n" + "\n".join(f"{k}: {v}" for k, v in resp.headers.items()) + "\n\n" + (resp.text or "")[:2500]
    if found:
        result.status = "failed"
        result.severity = "medium"
        result.description = f"Debug/stack trace detected: {', '.join(found)}"
        result.evidence = f"Matched: {', '.join(found)}"
        result.remediation = "Disable debug mode in production. Use generic error pages. Log stack traces server-side only."
        result.reproduction_steps = f"1. GET {target_url}\n2. Inspect response body for debug output"
    else:
        result.status = "passed"
        result.description = "No debug/stack trace in response"
    return result


# ─── Check 29: .env / .git/HEAD Exposure ───

def check_dotenv_git(target_url: str) -> DastResult:
    """Check for .env or .git/HEAD exposure (critical secrets/config)."""
    result = DastResult(
        check_id="DAST-ENV-01",
        title=".env / .git Exposure",
        owasp_ref="A05:2021",
        cwe_id="CWE-798",
    )
    parsed = urlparse(target_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    paths = [("/.env", ["password", "secret", "api_key", "key=", "database"]), ("/.git/HEAD", ["ref:", "refs/heads/"])]
    exposed = []
    for path, indicators in paths:
        r = _safe_get(urljoin(base, path))
        if r and r.status_code == 200:
            txt = (r.text or "").lower()
            if any(ind in txt for ind in indicators) or (path == "/.git/HEAD" and len(txt) < 200):
                exposed.append(path)
    result.details = {"paths_checked": [p[0] for p in paths], "exposed": exposed}
    if exposed:
        result.status = "failed"
        result.severity = "critical"
        result.description = f"Critical file(s) exposed: {', '.join(exposed)}"
        result.evidence = f"Exposed: {', '.join(exposed)}"
        result.remediation = "Immediately remove .env and .git from web root. Add to .gitignore. Use environment variables."
        result.reproduction_steps = f"1. GET {base}{exposed[0]}\n2. Observe 200 with sensitive content"
    else:
        result.status = "passed"
        result.description = "No .env or .git/HEAD exposure"
    result.request_raw = f"GET {base}/.env HTTP/1.1\nHost: {parsed.netloc}"
    result.response_raw = "See details"
    return result


# ─── Check 30: Content-Type Sniffing Risk ───

def check_content_type_sniffing(target_url: str) -> DastResult:
    """Check for missing X-Content-Type-Options or JSON served as text/html."""
    result = DastResult(
        check_id="DAST-CT-01",
        title="Content-Type Sniffing / MIME Mismatch",
        owasp_ref="A05:2021",
        cwe_id="CWE-16",
    )
    resp = _safe_get(target_url)
    if not resp:
        result.status = "error"
        result.description = "Could not reach target"
        return result
    ct = resp.headers.get("content-type", "").lower()
    xcto = resp.headers.get("x-content-type-options", resp.headers.get("X-Content-Type-Options", ""))
    body = (resp.text or "").strip()[:500]
    looks_json = body.startswith("{") or body.startswith("[")
    result.details = {"content_type": ct, "x_content_type_options": xcto or "(not set)", "body_start": body[:100]}
    result.request_raw = f"GET {target_url} HTTP/1.1\nHost: {urlparse(target_url).netloc}"
    result.response_raw = f"HTTP/1.1 {resp.status_code}\n" + "\n".join(f"{k}: {v}" for k, v in resp.headers.items()) + "\n\n" + body[:1000]
    issues = []
    if not xcto or "nosniff" not in xcto.lower():
        issues.append("X-Content-Type-Options: nosniff missing")
    if looks_json and "application/json" not in ct and "text/html" in ct:
        issues.append("JSON-like response served as text/html (XSS risk)")
    if issues:
        result.status = "failed"
        result.severity = "medium" if "nosniff" in str(issues).lower() else "low"
        result.description = "; ".join(issues)
        result.remediation = "Add X-Content-Type-Options: nosniff. Serve JSON with Content-Type: application/json"
        result.reproduction_steps = f"1. GET {target_url}\n2. Check Content-Type and X-Content-Type-Options"
    else:
        result.status = "passed"
        result.description = "Content-Type and X-Content-Type-Options adequate"
    return result


# ─── Check 31: Clickjacking Protection ───

def check_clickjacking(target_url: str) -> DastResult:
    """Verify X-Frame-Options or CSP frame-ancestors for clickjacking protection."""
    result = DastResult(
        check_id="DAST-FRAME-01",
        title="Clickjacking Protection",
        owasp_ref="A05:2021",
        cwe_id="CWE-1021",
    )
    resp = _safe_get(target_url)
    if not resp:
        result.status = "error"
        result.description = "Could not reach target"
        return result
    headers = {k.lower(): v for k, v in resp.headers.items()}
    xfo = headers.get("x-frame-options", "")
    csp = headers.get("content-security-policy", headers.get("content-security-policy-report-only", ""))
    has_xfo = bool(xfo and xfo.strip())
    has_frame_ancestors = "frame-ancestors" in csp.lower()
    result.details = {"x_frame_options": xfo or "(not set)", "csp_frame_ancestors": has_frame_ancestors}
    result.request_raw = f"GET {target_url} HTTP/1.1\nHost: {urlparse(target_url).netloc}"
    result.response_raw = f"HTTP/1.1 {resp.status_code}\n" + "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
    if has_xfo or has_frame_ancestors:
        result.status = "passed"
        result.description = "Clickjacking protection present (X-Frame-Options or frame-ancestors)"
    else:
        result.status = "failed"
        result.severity = "medium"
        result.description = "No clickjacking protection (X-Frame-Options or CSP frame-ancestors missing)"
        result.remediation = "Add X-Frame-Options: DENY or SAMEORIGIN, or CSP frame-ancestors 'none'"
        result.reproduction_steps = f"1. GET {target_url}\n2. Check for X-Frame-Options or Content-Security-Policy frame-ancestors"
    return result


# ─── Check 32: TRACE Method (XST) ───

def check_trace_xst(target_url: str) -> DastResult:
    """Check if TRACE method is enabled (Cross-Site Tracing)."""
    result = DastResult(
        check_id="DAST-TRACE-01",
        title="TRACE Method (XST)",
        owasp_ref="A05:2021",
        cwe_id="CWE-693",
    )
    resp = _safe_request("TRACE", target_url)
    if not resp:
        result.status = "error"
        result.description = "Could not reach target"
        return result
    parsed = urlparse(target_url)
    result.request_raw = f"TRACE {target_url} HTTP/1.1\nHost: {parsed.netloc}"
    result.response_raw = f"HTTP/1.1 {resp.status_code}\n" + "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
    if resp.status_code == 200 and (resp.text or "").strip():
        result.status = "failed"
        result.severity = "low"
        result.description = "TRACE method enabled; reflects request back (XST)"
        result.remediation = "Disable TRACE method on web server"
    else:
        result.status = "passed"
        result.description = "TRACE method disabled or not reflecting"
    return result


# ─── Check 33: Expect-CT ───

def check_expect_ct(target_url: str) -> DastResult:
    """Check for Expect-CT header (certificate transparency)."""
    result = DastResult(
        check_id="DAST-ECT-01",
        title="Expect-CT Header",
        owasp_ref="A02:2021",
        cwe_id="CWE-295",
    )
    resp = _safe_get(target_url)
    if not resp:
        result.status = "error"
        result.description = "Could not reach target"
        return result
    parsed = urlparse(target_url)
    if parsed.scheme != "https":
        result.status = "passed"
        result.description = "Target is HTTP; Expect-CT N/A"
        return result
    ect = resp.headers.get("expect-ct", "")
    result.details = {"expect_ct": ect or "(not set)"}
    result.request_raw = f"GET {target_url} HTTP/1.1\nHost: {parsed.netloc}"
    result.response_raw = f"HTTP/1.1 {resp.status_code}\n" + "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
    if not ect:
        result.status = "failed"
        result.severity = "info"
        result.description = "Expect-CT header missing"
        result.remediation = "Consider Expect-CT: max-age=86400 for certificate transparency"
    else:
        result.status = "passed"
        result.description = "Expect-CT header present"
    return result


# ─── Check 34: Permissions-Policy ───

def check_permissions_policy(target_url: str) -> DastResult:
    """Check Permissions-Policy (formerly Feature-Policy)."""
    result = DastResult(
        check_id="DAST-PERM-01",
        title="Permissions-Policy",
        owasp_ref="A05:2021",
        cwe_id="CWE-1021",
    )
    resp = _safe_get(target_url)
    if not resp:
        result.status = "error"
        result.description = "Could not reach target"
        return result
    headers = {k.lower(): v for k, v in resp.headers.items()}
    pp = headers.get("permissions-policy", headers.get("feature-policy", ""))
    result.details = {"value": pp or "(not set)"}
    result.request_raw = f"GET {target_url} HTTP/1.1\nHost: {urlparse(target_url).netloc}"
    result.response_raw = f"HTTP/1.1 {resp.status_code}\n" + "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
    if not pp or not pp.strip():
        result.status = "failed"
        result.severity = "low"
        result.description = "Permissions-Policy (or Feature-Policy) not set"
        result.remediation = "Add Permissions-Policy to restrict browser features (camera, geolocation, etc.)"
    else:
        result.status = "passed"
        result.description = "Permissions-Policy present"
    return result


# ─── Check 35: X-XSS-Protection ───

def check_xss_protection_header(target_url: str) -> DastResult:
    """Check X-XSS-Protection header (legacy; 0 = disabled is bad)."""
    result = DastResult(
        check_id="DAST-XSSP-01",
        title="X-XSS-Protection Header",
        owasp_ref="A03:2021",
        cwe_id="CWE-79",
    )
    resp = _safe_get(target_url)
    if not resp:
        result.status = "error"
        result.description = "Could not reach target"
        return result
    xxss = resp.headers.get("x-xss-protection", "")
    result.details = {"value": xxss or "(not set)"}
    result.request_raw = f"GET {target_url} HTTP/1.1\nHost: {urlparse(target_url).netloc}"
    result.response_raw = f"HTTP/1.1 {resp.status_code}\n" + "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
    if "0" in xxss:
        result.status = "failed"
        result.severity = "low"
        result.description = "X-XSS-Protection: 0 (explicitly disabled)"
        result.remediation = "Remove X-XSS-Protection: 0 or set to 1; prefer CSP for XSS protection"
    elif not xxss:
        result.status = "failed"
        result.severity = "info"
        result.description = "X-XSS-Protection header missing"
        result.remediation = "Consider X-XSS-Protection: 1; mode=block (or rely on CSP)"
    else:
        result.status = "passed"
        result.description = "X-XSS-Protection adequate"
    return result


# ─── Check 36: CSP Report-URI ───

def check_csp_reporting(target_url: str) -> DastResult:
    """Check CSP has report-uri or report-to for violation reporting."""
    result = DastResult(
        check_id="DAST-CSPR-01",
        title="CSP Report-URI / report-to",
        owasp_ref="A05:2021",
        cwe_id="CWE-755",
    )
    resp = _safe_get(target_url)
    if not resp:
        result.status = "error"
        result.description = "Could not reach target"
        return result
    csp = resp.headers.get("content-security-policy", "") or resp.headers.get("content-security-policy-report-only", "")
    csp_lower = csp.lower()
    has_report = "report-uri" in csp_lower or "report-to" in csp_lower
    result.details = {"csp_length": len(csp), "has_reporting": has_report}
    result.request_raw = f"GET {target_url} HTTP/1.1\nHost: {urlparse(target_url).netloc}"
    result.response_raw = f"HTTP/1.1 {resp.status_code}\n" + "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
    if csp and not has_report:
        result.status = "failed"
        result.severity = "info"
        result.description = "CSP present but no report-uri or report-to"
        result.remediation = "Add report-uri or report-to to CSP for violation monitoring"
    elif not csp:
        result.status = "passed"
        result.description = "No CSP; reporting N/A"
    else:
        result.status = "passed"
        result.description = "CSP with reporting configured"
    return result


# ─── Check 37: Server-Timing ───

def check_server_timing(target_url: str) -> DastResult:
    """Check Server-Timing header (may leak internal metrics)."""
    result = DastResult(
        check_id="DAST-ST-01",
        title="Server-Timing Header",
        owasp_ref="A05:2021",
        cwe_id="CWE-200",
    )
    resp = _safe_get(target_url)
    if not resp:
        result.status = "error"
        result.description = "Could not reach target"
        return result
    st = resp.headers.get("server-timing", "")
    result.details = {"value": st[:300] if st else "(not set)"}
    result.request_raw = f"GET {target_url} HTTP/1.1\nHost: {urlparse(target_url).netloc}"
    result.response_raw = f"HTTP/1.1 {resp.status_code}\n" + "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
    if st:
        result.status = "failed"
        result.severity = "info"
        result.description = "Server-Timing header exposes internal metrics"
        result.remediation = "Remove Server-Timing in production or restrict to debug mode"
    else:
        result.status = "passed"
        result.description = "No Server-Timing header"
    return result


# ─── Check 38: Via Header ───

def check_via_header(target_url: str) -> DastResult:
    """Check Via header (proxy disclosure)."""
    result = DastResult(
        check_id="DAST-VIA-01",
        title="Via Header Disclosure",
        owasp_ref="A05:2021",
        cwe_id="CWE-200",
    )
    resp = _safe_get(target_url)
    if not resp:
        result.status = "error"
        result.description = "Could not reach target"
        return result
    via = resp.headers.get("via", "")
    result.details = {"value": via[:200] if via else "(not set)"}
    result.request_raw = f"GET {target_url} HTTP/1.1\nHost: {urlparse(target_url).netloc}"
    result.response_raw = f"HTTP/1.1 {resp.status_code}\n" + "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
    if via:
        result.status = "failed"
        result.severity = "low"
        result.description = "Via header discloses proxy/CDN"
        result.remediation = "Configure proxy to strip or anonymize Via header"
    else:
        result.status = "passed"
        result.description = "No Via header"
    return result


# ─── Check 39: X-Forwarded Disclosure ───

def check_x_forwarded_disclosure(target_url: str) -> DastResult:
    """Check X-Forwarded-For, X-Real-IP headers (internal IP disclosure)."""
    result = DastResult(
        check_id="DAST-XFF-01",
        title="X-Forwarded-For / X-Real-IP",
        owasp_ref="A05:2021",
        cwe_id="CWE-200",
    )
    resp = _safe_get(target_url)
    if not resp:
        result.status = "error"
        result.description = "Could not reach target"
        return result
    headers = {k.lower(): v for k, v in resp.headers.items()}
    xff = headers.get("x-forwarded-for", "")
    xri = headers.get("x-real-ip", "")
    result.details = {"x_forwarded_for": xff[:100] if xff else "(not set)", "x_real_ip": xri or "(not set)"}
    result.request_raw = f"GET {target_url} HTTP/1.1\nHost: {urlparse(target_url).netloc}"
    result.response_raw = f"HTTP/1.1 {resp.status_code}\n" + "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
    if xff or xri:
        result.status = "failed"
        result.severity = "low"
        result.description = "X-Forwarded-For or X-Real-IP header present"
        result.remediation = "Ensure app does not trust/reflect client-controlled forwarding headers"
    else:
        result.status = "passed"
        result.description = "No X-Forwarded-For or X-Real-IP in response"
    return result


# ─── Check 40: Allow Header Dangerous Methods ───

def check_allow_dangerous(target_url: str) -> DastResult:
    """Check Allow header for dangerous methods."""
    result = DastResult(
        check_id="DAST-ALLOW-01",
        title="Allow Header Dangerous Methods",
        owasp_ref="A05:2021",
        cwe_id="CWE-749",
    )
    resp = _safe_request("OPTIONS", target_url)
    if not resp:
        result.status = "error"
        result.description = "Could not reach target"
        return result
    allow = resp.headers.get("allow", "").upper()
    dangerous = ["TRACE", "PUT", "DELETE", "CONNECT"]
    found = [m for m in dangerous if m in allow]
    result.details = {"allow": allow or "(not set)", "dangerous_found": found}
    result.request_raw = f"OPTIONS {target_url} HTTP/1.1\nHost: {urlparse(target_url).netloc}"
    result.response_raw = f"HTTP/1.1 {resp.status_code}\n" + "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
    if found:
        result.status = "failed"
        result.severity = "low"
        result.description = f"Allow header includes dangerous methods: {', '.join(found)}"
        result.remediation = "Restrict Allow header to safe methods (GET, POST, HEAD)"
    else:
        result.status = "passed"
        result.description = "Allow header does not expose dangerous methods"
    return result


# ─── Check 41: Cross-Origin-Resource-Policy ───

def check_corp(target_url: str) -> DastResult:
    """Check Cross-Origin-Resource-Policy header."""
    result = DastResult(
        check_id="DAST-CORP-01",
        title="Cross-Origin-Resource-Policy",
        owasp_ref="A05:2021",
        cwe_id="CWE-942",
    )
    resp = _safe_get(target_url)
    if not resp:
        result.status = "error"
        result.description = "Could not reach target"
        return result
    corp = resp.headers.get("cross-origin-resource-policy", "")
    result.details = {"value": corp or "(not set)"}
    result.request_raw = f"GET {target_url} HTTP/1.1\nHost: {urlparse(target_url).netloc}"
    result.response_raw = f"HTTP/1.1 {resp.status_code}\n" + "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
    if not corp or corp.strip() == "":
        result.status = "failed"
        result.severity = "info"
        result.description = "Cross-Origin-Resource-Policy not set"
        result.remediation = "Consider Cross-Origin-Resource-Policy: same-origin for sensitive resources"
    else:
        result.status = "passed"
        result.description = f"Cross-Origin-Resource-Policy: {corp}"
    return result


# ─── Check 42: Clear-Site-Data ───

def check_clear_site_data(target_url: str) -> DastResult:
    """Check Clear-Site-Data on logout/sensitive paths (best practice)."""
    result = DastResult(
        check_id="DAST-CSD-01",
        title="Clear-Site-Data Header",
        owasp_ref="A07:2021",
        cwe_id="CWE-613",
    )
    resp = _safe_get(target_url)
    if not resp:
        result.status = "error"
        result.description = "Could not reach target"
        return result
    csd = resp.headers.get("clear-site-data", "")
    result.details = {"value": csd or "(not set)"}
    result.request_raw = f"GET {target_url} HTTP/1.1\nHost: {urlparse(target_url).netloc}"
    result.response_raw = f"HTTP/1.1 {resp.status_code}\n" + "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
    result.status = "passed"
    result.description = "Clear-Site-Data check (informational; typically on logout)"
    return result


# ─── Check 43: Cache Age ───

def check_cache_age(target_url: str) -> DastResult:
    """Check Age header for overly long cache (stale content)."""
    result = DastResult(
        check_id="DAST-AGE-01",
        title="Cache Age Header",
        owasp_ref="A05:2021",
        cwe_id="CWE-525",
    )
    resp = _safe_get(target_url)
    if not resp:
        result.status = "error"
        result.description = "Could not reach target"
        return result
    age_val = resp.headers.get("age", "")
    age_int = int(age_val) if age_val and age_val.isdigit() else 0
    result.details = {"age": age_val or "(not set)", "seconds": age_int}
    result.request_raw = f"GET {target_url} HTTP/1.1\nHost: {urlparse(target_url).netloc}"
    result.response_raw = f"HTTP/1.1 {resp.status_code}\n" + "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
    if age_int > 86400:
        result.status = "failed"
        result.severity = "low"
        result.description = f"Age header very high ({age_int}s) — content may be stale"
        result.remediation = "Reduce cache TTL for dynamic content"
    else:
        result.status = "passed"
        result.description = "Cache age acceptable"
    return result


# ─── Check 44: Upgrade-Insecure-Requests ───

def check_upgrade_insecure(target_url: str) -> DastResult:
    """Check CSP upgrade-insecure-requests for mixed content mitigation."""
    result = DastResult(
        check_id="DAST-UIR-01",
        title="Upgrade-Insecure-Requests",
        owasp_ref="A05:2021",
        cwe_id="CWE-319",
    )
    resp = _safe_get(target_url)
    if not resp:
        result.status = "error"
        result.description = "Could not reach target"
        return result
    parsed = urlparse(target_url)
    if parsed.scheme != "https":
        result.status = "passed"
        result.description = "Target is HTTP; upgrade N/A"
        return result
    csp = resp.headers.get("content-security-policy", "").lower()
    has_uir = "upgrade-insecure-requests" in csp
    result.details = {"has_upgrade_insecure_requests": has_uir}
    result.request_raw = f"GET {target_url} HTTP/1.1\nHost: {parsed.netloc}"
    result.response_raw = f"HTTP/1.1 {resp.status_code}\n" + "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
    if not csp:
        result.status = "passed"
        result.description = "No CSP; upgrade-insecure-requests N/A"
    elif has_uir:
        result.status = "passed"
        result.description = "CSP upgrade-insecure-requests present"
    else:
        result.status = "failed"
        result.severity = "info"
        result.description = "CSP present but no upgrade-insecure-requests"
        result.remediation = "Add upgrade-insecure-requests to CSP for mixed content mitigation"
    return result


# ─── Check 45: Cookie __Host- __Secure- Prefix ───

def check_cookie_prefix(target_url: str) -> DastResult:
    """Check if cookies use __Host- or __Secure- prefix on HTTPS."""
    result = DastResult(
        check_id="DAST-COOKP-01",
        title="Cookie __Host- / __Secure- Prefix",
        owasp_ref="A05:2021",
        cwe_id="CWE-614",
    )
    resp = _safe_get(target_url)
    if not resp:
        result.status = "error"
        result.description = "Could not reach target"
        return result
    parsed = urlparse(target_url)
    if parsed.scheme != "https":
        result.status = "passed"
        result.description = "Target is HTTP; cookie prefix N/A"
        return result
    cookies = resp.headers.get_list("set-cookie")
    if not cookies:
        result.status = "passed"
        result.description = "No cookies set"
        return result
    sensitive_names = ["session", "auth", "token", "jwt", "sid", "csrf"]
    missing_prefix = []
    for c in cookies:
        name = c.split("=")[0].strip() if "=" in c else ""
        lower = name.lower()
        if any(s in lower for s in sensitive_names) and not (name.startswith("__Host-") or name.startswith("__Secure-")):
            missing_prefix.append(name)
    result.details = {"cookies": len(cookies), "missing_prefix": missing_prefix[:5]}
    result.request_raw = f"GET {target_url} HTTP/1.1\nHost: {parsed.netloc}"
    result.response_raw = f"HTTP/1.1 {resp.status_code}\n" + "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
    if missing_prefix:
        result.status = "failed"
        result.severity = "low"
        result.description = f"Sensitive cookies missing __Host-/__Secure- prefix: {', '.join(missing_prefix[:3])}"
        result.remediation = "Use __Host- or __Secure- prefix for sensitive cookies on HTTPS"
    else:
        result.status = "passed"
        result.description = "Sensitive cookies use appropriate prefix or no sensitive cookies"
    return result


# ─── Check 46: Redirect Chain Length ───

def check_redirect_chain(target_url: str) -> DastResult:
    """Check for excessive redirect chain."""
    result = DastResult(
        check_id="DAST-REDIR-03",
        title="Redirect Chain Length",
        owasp_ref="A05:2021",
        cwe_id="CWE-601",
    )
    parsed = urlparse(target_url)
    url = target_url
    seen = set()
    chain = []
    for _ in range(10):
        if url in seen:
            break
        seen.add(url)
        r = _safe_request("GET", url)
        if not r:
            break
        chain.append({"url": url[:80], "status": r.status_code})
        if r.status_code not in (301, 302, 307, 308):
            break
        loc = r.headers.get("location", "")
        if not loc:
            break
        url = urljoin(url, loc)
    result.details = {"chain_length": len(chain), "chain": chain}
    result.request_raw = f"GET {target_url}\nChain: {len(chain)} redirects"
    result.response_raw = str(chain)[:500]
    if len(chain) > 5:
        result.status = "failed"
        result.severity = "low"
        result.description = f"Redirect chain length {len(chain)} (excessive)"
        result.remediation = "Reduce redirect chain; use direct URLs"
    else:
        result.status = "passed"
        result.description = f"Redirect chain length {len(chain)} (acceptable)"
    return result


# ─── Check 47: Timing-Allow-Origin ───

def check_timing_allow_origin(target_url: str) -> DastResult:
    """Check Timing-Allow-Origin for resource timing API."""
    result = DastResult(
        check_id="DAST-TAO-01",
        title="Timing-Allow-Origin",
        owasp_ref="A05:2021",
        cwe_id="CWE-200",
    )
    resp = _safe_get(target_url)
    if not resp:
        result.status = "error"
        result.description = "Could not reach target"
        return result
    tao = resp.headers.get("timing-allow-origin", "")
    result.details = {"value": tao or "(not set)"}
    result.request_raw = f"GET {target_url} HTTP/1.1\nHost: {urlparse(target_url).netloc}"
    result.response_raw = f"HTTP/1.1 {resp.status_code}\n" + "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
    result.status = "passed"
    result.description = "Timing-Allow-Origin check (informational)"
    return result


# ─── Check 48: Alt-Svc Header ───

def check_alt_svc(target_url: str) -> DastResult:
    """Check Alt-Svc header (protocol upgrade)."""
    result = DastResult(
        check_id="DAST-ALTSVC-01",
        title="Alt-Svc Header",
        owasp_ref="A02:2021",
        cwe_id="CWE-319",
    )
    resp = _safe_get(target_url)
    if not resp:
        result.status = "error"
        result.description = "Could not reach target"
        return result
    alt = resp.headers.get("alt-svc", "")
    result.details = {"value": alt[:200] if alt else "(not set)"}
    result.request_raw = f"GET {target_url} HTTP/1.1\nHost: {urlparse(target_url).netloc}"
    result.response_raw = f"HTTP/1.1 {resp.status_code}\n" + "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
    result.status = "passed"
    result.description = "Alt-Svc check (informational)"
    return result


# ─── Check 49: Strict-Transport-Security includeSubDomains ───

def check_hsts_subdomains(target_url: str) -> DastResult:
    """Check HSTS includeSubDomains directive."""
    result = DastResult(
        check_id="DAST-HSTS-02",
        title="HSTS includeSubDomains",
        owasp_ref="A02:2021",
        cwe_id="CWE-319",
    )
    resp = _safe_get(target_url)
    if not resp:
        result.status = "error"
        result.description = "Could not reach target"
        return result
    parsed = urlparse(target_url)
    if parsed.scheme != "https":
        result.status = "passed"
        result.description = "Target is HTTP; HSTS N/A"
        return result
    hsts = resp.headers.get("strict-transport-security", "").lower()
    has_sub = "includesubdomains" in hsts
    result.details = {"hsts": hsts[:150], "has_include_subdomains": has_sub}
    result.request_raw = f"GET {target_url} HTTP/1.1\nHost: {parsed.netloc}"
    result.response_raw = f"HTTP/1.1 {resp.status_code}\n" + "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
    if not hsts:
        result.status = "passed"
        result.description = "No HSTS; see hsts_preload check"
    elif not has_sub:
        result.status = "failed"
        result.severity = "low"
        result.description = "HSTS missing includeSubDomains"
        result.remediation = "Add includeSubDomains to Strict-Transport-Security"
    else:
        result.status = "passed"
        result.description = "HSTS includeSubDomains present"
    return result


# ─── Check 50: Content-Disposition ───

def check_content_disposition(target_url: str) -> DastResult:
    """Check Content-Disposition for download/inline security."""
    result = DastResult(
        check_id="DAST-CD-01",
        title="Content-Disposition",
        owasp_ref="A05:2021",
        cwe_id="CWE-434",
    )
    resp = _safe_get(target_url)
    if not resp:
        result.status = "error"
        result.description = "Could not reach target"
        return result
    cd = resp.headers.get("content-disposition", "")
    result.details = {"value": cd[:150] if cd else "(not set)"}
    result.request_raw = f"GET {target_url} HTTP/1.1\nHost: {urlparse(target_url).netloc}"
    result.response_raw = f"HTTP/1.1 {resp.status_code}\n" + "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
    result.status = "passed"
    result.description = "Content-Disposition check (informational)"
    return result


# ─── Check 51: Pragma No-Cache ───

def check_pragma_no_cache(target_url: str) -> DastResult:
    """Check Pragma: no-cache on sensitive responses."""
    result = DastResult(
        check_id="DAST-PRAGMA-01",
        title="Pragma No-Cache",
        owasp_ref="A05:2021",
        cwe_id="CWE-525",
    )
    resp = _safe_get(target_url)
    if not resp:
        result.status = "error"
        result.description = "Could not reach target"
        return result
    cc = resp.headers.get("cache-control", "").lower()
    pragma = resp.headers.get("pragma", "").lower()
    has_no_store = "no-store" in cc or "no-cache" in cc
    has_pragma = "no-cache" in pragma
    result.details = {"cache_control": cc[:100], "pragma": pragma[:50]}
    result.request_raw = f"GET {target_url} HTTP/1.1\nHost: {urlparse(target_url).netloc}"
    result.response_raw = f"HTTP/1.1 {resp.status_code}\n" + "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
    ct = resp.headers.get("content-type", "").lower()
    is_html = "text/html" in ct
    if is_html and not has_no_store and not has_pragma:
        result.status = "failed"
        result.severity = "low"
        result.description = "HTML page lacks Cache-Control no-store and Pragma no-cache"
        result.remediation = "Add Cache-Control: no-store or Pragma: no-cache for dynamic HTML"
    else:
        result.status = "passed"
        result.description = "Caching headers adequate"
    return result


# ─── Check 52: Padding Oracle (WSTG-CRYP-02) ───

# Known padding error signatures — high-confidence true positive indicators
PADDING_ORACLE_SIGNATURES = [
    "padding is invalid",
    "invalid padding",
    "badpaddingexception",
    "bad padding",
    "padding error",
    "padding exception",
    "decryption failed",
    "decrypt failed",
    "cryptographicexception",
    "invalid padding bytes",
    "padding oracle",
    "corrupted padding",
    "pkcs7",
    "padding verification failed",
]


def _is_base64_block_cipher_candidate(val: str) -> tuple[bool, int]:
    """Check if value decodes to block-size aligned bytes (8 or 16). Returns (valid, block_len)."""
    if not val or len(val) < 16:
        return False, 0
    try:
        raw = base64.urlsafe_b64decode(val + "==")
        if len(raw) < 8:
            return False, 0
        if len(raw) % 16 == 0:
            return True, 16
        if len(raw) % 8 == 0:
            return True, 8
        return False, 0
    except Exception:
        try:
            raw = base64.b64decode(val)
            if len(raw) < 8:
                return False, 0
            if len(raw) % 16 == 0:
                return True, 16
            if len(raw) % 8 == 0:
                return True, 8
            return False, 0
        except Exception:
            return False, 0


def _flip_bit(data: bytearray, idx: int) -> None:
    """Flip LSB at byte index idx."""
    if 0 <= idx < len(data):
        data[idx] ^= 1


def _encode_cookie_val(raw: bytes) -> str:
    """Base64 encode for cookie (standard base64)."""
    return base64.b64encode(raw).decode("ascii", errors="replace").rstrip("=")


def _response_fingerprint(resp: httpx.Response) -> str:
    """Fingerprint for response comparison: status + length + padding-related snippets."""
    body = (resp.text or "").lower()
    snippets = []
    for sig in PADDING_ORACLE_SIGNATURES:
        if sig in body:
            snippets.append(sig[:20])
    return f"{resp.status_code}|{len(resp.content)}|{','.join(sorted(snippets))}"


def check_padding_oracle(target_url: str) -> DastResult:
    """Check for padding oracle in encrypted client-side data (WSTG-CRYP-02).
    Identifies encrypted cookies/session state, flips bits per block-cipher spec,
    and detects distinct responses that leak padding validity (true positive).
    """
    result = DastResult(
        check_id="DAST-CRYP-02",
        title="Padding Oracle (WSTG-CRYP-02)",
        owasp_ref="WSTG-CRYP-02",
        cwe_id="CWE-209",
    )
    resp = _safe_get(target_url)
    if not resp:
        result.status = "error"
        result.description = "Could not reach target"
        return result

    # Collect candidate encrypted values from cookies
    candidates: list[tuple[str, str, int]] = []  # (cookie_name, value, block_len)
    cookies = resp.headers.get_list("set-cookie") or []
    for cookie_str in cookies:
        if "=" not in cookie_str:
            continue
        name = cookie_str.split("=")[0].strip()
        val_part = cookie_str.split("=", 1)[1]
        if ";" in val_part:
            val_part = val_part.split(";")[0].strip()
        val = val_part.strip()
        valid, blen = _is_base64_block_cipher_candidate(val)
        if valid and blen:
            candidates.append((name, val, blen))

    if not candidates:
        result.status = "passed"
        result.description = "No encrypted client-side data (base64, block-aligned) found to test"
        result.details = {"cookies_checked": len(cookies), "candidates": 0}
        result.request_raw = f"GET {target_url} HTTP/1.1\nHost: {urlparse(target_url).netloc}"
        result.response_raw = f"HTTP/1.1 {resp.status_code}\n" + "\n".join(f"{k}: {v}" for k, v in resp.headers.items())[:2000]
        result.remediation = "Ensure any encrypted client data uses integrity verification (HMAC, GCM/CCM)."
        return result

    # Test each candidate for padding oracle
    padding_oracle_found = False
    evidence_parts: list[str] = []
    tested_cookie = ""

    for cname, cval, block_len in candidates[:3]:  # Limit to 3 candidates to avoid rate-limit
        try:
            raw = base64.b64decode(cval)
        except Exception:
            try:
                raw = base64.urlsafe_b64decode(cval + "==")
            except Exception:
                continue
        if len(raw) < block_len * 2:
            continue

        tested_cookie = cname
        n_blocks = len(raw) // block_len
        # Flip last bit of second-to-last block (y-n-1) and block b-2 (y-2*n-1)
        indices_to_flip = [
            len(raw) - block_len - 1,
            len(raw) - 2 * block_len - 1,
        ]
        fingerprints: set[str] = set()
        has_padding_error = False

        # Baseline
        base_fp = _response_fingerprint(resp)
        fingerprints.add(base_fp)

        # Build Cookie header with original value for follow-up requests
        cookie_val_orig = cval

        for flip_idx in indices_to_flip:
            data = bytearray(raw)
            _flip_bit(data, flip_idx)
            tampered = _encode_cookie_val(bytes(data))
            headers = {**BROWSER_HEADERS, "User-Agent": USER_AGENTS[0], "Cookie": f"{cname}={tampered}"}
            time.sleep(0.5)
            r2 = _safe_request("GET", target_url, headers=headers)
            if not r2:
                continue
            fp = _response_fingerprint(r2)
            fingerprints.add(fp)
            body_lower = (r2.text or "").lower()
            for sig in PADDING_ORACLE_SIGNATURES:
                if sig in body_lower:
                    has_padding_error = True
                    evidence_parts.append(f"{cname}: padding error signature '{sig}' in response")
                    break
            if has_padding_error:
                break

        if has_padding_error and len(fingerprints) >= 2:
            padding_oracle_found = True
            break
        if len(fingerprints) >= 3:
            # Three distinct responses: valid, garbled, padding error (implicit)
            evidence_parts.append(f"{cname}: 3+ distinct responses observed (possible oracle)")
            padding_oracle_found = True
            break

    result.details = {"candidates_tested": len(candidates[:3]), "tested_cookie": tested_cookie}
    result.request_raw = f"GET {target_url} HTTP/1.1\nHost: {urlparse(target_url).netloc}\nCookie: {tested_cookie}=..."
    result.response_raw = f"HTTP/1.1 {resp.status_code}\n" + "\n".join(f"{k}: {v}" for k, v in resp.headers.items())[:2000]

    if padding_oracle_found:
        result.status = "failed"
        result.severity = "medium"
        result.description = "Padding oracle likely present: application leaks padding validity"
        result.evidence = "; ".join(evidence_parts) if evidence_parts else f"Cookie '{tested_cookie}' showed distinct responses on bit-flip"
        result.remediation = "Add integrity verification (HMAC) before decrypt. Use authenticated encryption (GCM, CCM). Unify error handling."
        result.reproduction_steps = (
            f"1. GET {target_url} to obtain encrypted cookie\n"
            "2. Decode base64, flip LSB of second-to-last block\n"
            "3. Re-encode and send with tampered Cookie header\n"
            "4. Compare response: padding-specific error indicates oracle"
        )
    else:
        result.status = "passed"
        result.description = "No padding oracle detected; encrypted data either absent or properly protected"
        result.remediation = "Ensure encrypted client data uses HMAC or GCM/CCM; avoid leaking padding errors."

    return result


# ─── DAST Runner ───

ALL_CHECKS = [
    ("security_headers", check_security_headers),
    ("ssl_tls", check_ssl_tls),
    ("cookie_security", check_cookie_security),
    ("cors", check_cors),
    ("info_disclosure", check_info_disclosure),
    ("tech_fingerprint", check_tech_fingerprint),
    ("sitemap_xml", check_sitemap_xml),
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
    ("security_txt", check_security_txt),
    ("http_redirect_https", check_http_redirect_https),
    ("hsts_preload", check_hsts_preload),
    ("version_headers", check_version_headers),
    ("coop_coep", check_coop_coep),
    ("weak_referrer", check_weak_referrer),
    ("debug_response", check_debug_response),
    ("dotenv_git", check_dotenv_git),
    ("content_type_sniffing", check_content_type_sniffing),
    ("clickjacking", check_clickjacking),
    ("trace_xst", check_trace_xst),
    ("expect_ct", check_expect_ct),
    ("permissions_policy", check_permissions_policy),
    ("xss_protection_header", check_xss_protection_header),
    ("csp_reporting", check_csp_reporting),
    ("server_timing", check_server_timing),
    ("via_header", check_via_header),
    ("x_forwarded_disclosure", check_x_forwarded_disclosure),
    ("allow_dangerous", check_allow_dangerous),
    ("corp", check_corp),
    ("clear_site_data", check_clear_site_data),
    ("cache_age", check_cache_age),
    ("upgrade_insecure", check_upgrade_insecure),
    ("cookie_prefix", check_cookie_prefix),
    ("redirect_chain", check_redirect_chain),
    ("timing_allow_origin", check_timing_allow_origin),
    ("alt_svc", check_alt_svc),
    ("hsts_subdomains", check_hsts_subdomains),
    ("content_disposition", check_content_disposition),
    ("pragma_no_cache", check_pragma_no_cache),
    ("padding_oracle", check_padding_oracle),
]


_redis_sync = None
_redis_lock = __import__("threading").Lock()
DAST_PROGRESS_TTL = 3600  # 1 hour


def _get_redis_sync():
    """Sync Redis client for DAST progress — shared across workers."""
    global _redis_sync
    if _redis_sync is None:
        from app.core.config import get_settings
        import redis as redis_lib
        _redis_sync = redis_lib.from_url(get_settings().redis_url, decode_responses=True)
    return _redis_sync


def _dast_progress_set(scan_id: str, data: dict) -> None:
    key = f"dast:scan:{scan_id}"
    try:
        r = _get_redis_sync()
        import json
        r.setex(key, DAST_PROGRESS_TTL, json.dumps(data, default=str))
    except Exception as e:
        logger.warning("DAST progress redis set failed: %s", e)


def _dast_progress_get(scan_id: str) -> dict | None:
    key = f"dast:scan:{scan_id}"
    try:
        r = _get_redis_sync()
        raw = r.get(key)
        if raw:
            import json
            return json.loads(raw)
    except Exception as e:
        logger.warning("DAST progress redis get failed: %s", e)
    return None


def run_dast_scan(
    target_url: str,
    checks: list[str] | None = None,
    progress_scan_id: str | None = None,
    progress_meta: dict | None = None,
    on_progress: Callable | None = None,
) -> dict:
    """Run DAST scan with optional progress callback for UI streaming."""
    global _scan_ctx
    results = []
    selected = ALL_CHECKS if not checks else [(n, f) for n, f in ALL_CHECKS if n in checks]
    total = len(selected)

    def _emit(index: int, check_name: str, result_dict: dict | None) -> None:
        if on_progress:
            on_progress(index, total, check_name, result_dict)
        if progress_scan_id:
            entry = {
                "status": "completed" if index >= total else "running",
                "current_index": index,
                "current_check": check_name if index < total else None,
                "completed_count": index,
                "total": total,
                "results": results,
                "last_updated": time.time(),
            }
            if progress_meta:
                entry.update(progress_meta)
            _dast_progress_set(progress_scan_id, entry)

    # Phase 1: Resolve reachable base URL (slow, evades WAF)
    if progress_scan_id:
        entry = {
            "status": "running",
            "current_check": "Resolving target URL...",
            "completed_count": 0,
            "total": total,
            "results": [],
            "last_updated": time.time(),
        }
        if progress_meta:
            entry.update(progress_meta)
        _dast_progress_set(progress_scan_id, entry)
    resolved = _resolve_base_url(target_url)
    effective_url = (resolved or target_url).rstrip("/") or target_url
    _scan_ctx = ScanContext(resolved)

    start = time.time()
    try:
        for i, (name, check_fn) in enumerate(selected):
            if progress_scan_id:
                cur = _dast_progress_get(progress_scan_id)
                if cur:
                    cur["current_check"] = name
                    cur["last_updated"] = time.time()
                    _dast_progress_set(progress_scan_id, cur)
            try:
                r = check_fn(effective_url)
                rd = r.to_dict()
                results.append(rd)
                _emit(i + 1, name, rd)
            except Exception as e:
                rd = DastResult(
                    check_id=f"DAST-ERR-{name}",
                    title=f"Error in {name}",
                    status="error",
                    description=str(e)[:200],
                ).to_dict()
                results.append(rd)
                _emit(i + 1, name, rd)
    finally:
        _scan_ctx = None

    duration = round(time.time() - start, 2)
    passed = sum(1 for r in results if r["status"] == "passed")
    failed = sum(1 for r in results if r["status"] == "failed")
    errors = sum(1 for r in results if r["status"] == "error")
    final = {
        "target_url": target_url,
        "total_checks": len(results),
        "passed": passed,
        "failed": failed,
        "errors": errors,
        "duration_seconds": duration,
        "results": results,
    }
    if progress_scan_id:
        _dast_progress_set(progress_scan_id, {
            "status": "completed",
            "current_check": None,
            "completed_count": total,
            "total": total,
            "results": results,
            "last_updated": time.time(),
            "target_url": target_url,
            "passed": passed,
            "failed": failed,
            "errors": errors,
            "duration_seconds": duration,
        })
    return final


def get_dast_progress(scan_id: str) -> dict | None:
    """Return current progress for a scan. None if unknown."""
    return _dast_progress_get(scan_id)


def list_dast_progress(max_age_sec: float = 3600) -> list[dict]:
    """Return all scans (active + recent) for dashboard."""
    try:
        r = _get_redis_sync()
        keys = r.keys("dast:scan:*")
        out = []
        now = time.time()
        for key in keys or []:
            raw = r.get(key)
            if raw:
                import json
                v = json.loads(raw)
                if isinstance(v, dict) and (now - v.get("last_updated", 0)) <= max_age_sec:
                    sid = key.replace("dast:scan:", "")
                    out.append({"scan_id": sid, **v})
        return out
    except Exception as e:
        logger.warning("list_dast_progress failed: %s", e)
        return []
