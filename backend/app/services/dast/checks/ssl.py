"""DAST checks: SSL/TLS, HTTP→HTTPS redirect, HSTS."""
import re
import ssl
import socket
from urllib.parse import urlparse

from ..base import DastResult, safe_get, safe_request


def check_ssl_tls(target_url: str) -> DastResult:
    """Check SSL/TLS configuration."""
    result = DastResult(
        check_id="DAST-SSL-01", title="SSL/TLS Configuration",
        owasp_ref="A02:2021", cwe_id="CWE-326",
    )
    parsed = urlparse(target_url)
    if parsed.scheme != "https":
        resp = safe_get(target_url)
        result.status = "failed"
        result.severity = "high"
        result.description = "Target does not use HTTPS"
        result.remediation = "Enable HTTPS with a valid TLS certificate"
        result.reproduction_steps = f"1. Navigate to {target_url}\n2. Protocol is HTTP"
        result.evidence = f"URL scheme: {parsed.scheme}"
        if resp:
            result.request_raw = f"GET {target_url} HTTP/1.1\nHost: {parsed.netloc}"
            result.response_raw = f"HTTP/1.1 {resp.status_code}\n" + "\n".join(f"{k}: {v}" for k, v in resp.headers.items()) + "\n\n" + (resp.text[:1500] if resp.text else "")
        return result
    host = parsed.hostname
    port = parsed.port or 443
    try:
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
                    result.description = f"SSL/TLS OK (Protocol: {protocol})"
                result.request_raw = f"TLS connect to {host}:{port}\nSNI: {host}"
                result.response_raw = f"Protocol: {protocol}\nCipher: {cipher[0] if cipher else 'N/A'}"
    except ssl.SSLCertVerificationError as e:
        result.status = "failed"
        result.severity = "high"
        result.description = f"SSL certificate verification failed: {str(e)[:200]}"
        result.remediation = "Install a valid SSL certificate"
    except Exception as e:
        result.status = "error"
        result.description = f"SSL check error: {str(e)[:200]}"
    return result


def check_http_redirect_https(target_url: str) -> DastResult:
    """Verify HTTP redirects to HTTPS."""
    result = DastResult(
        check_id="DAST-REDIR-02", title="HTTP to HTTPS Redirect",
        owasp_ref="A02:2021", cwe_id="CWE-319",
    )
    parsed = urlparse(target_url)
    if parsed.scheme != "https":
        result.status = "passed"
        result.description = "Target is HTTP-only; redirect check N/A"
        result.details = {"reason": "target_not_https"}
        return result
    http_url = f"http://{parsed.netloc}{parsed.path or '/'}{parsed.query and '?' + parsed.query or ''}"
    resp = safe_request("GET", http_url)
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
            result.remediation = "Ensure HTTP redirects to HTTPS"
    else:
        result.status = "failed"
        result.severity = "high"
        result.description = f"HTTP does not redirect (status {resp.status_code})"
        result.remediation = "Configure HTTP to redirect (301/302) to HTTPS"
    result.request_raw = f"GET {http_url} HTTP/1.1\nHost: {parsed.netloc}"
    result.response_raw = f"HTTP/1.1 {resp.status_code}\n" + "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
    result.evidence = resp.headers.get("location", "No Location header")
    return result


def check_hsts_preload(target_url: str) -> DastResult:
    """Check HSTS preload readiness."""
    result = DastResult(
        check_id="DAST-HSTS-01", title="HSTS Preload Readiness",
        owasp_ref="A02:2021", cwe_id="CWE-319",
    )
    resp = safe_get(target_url)
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
    else:
        hsts_lower = hsts.lower()
        max_age_match = re.search(r"max-age=(\d+)", hsts_lower)
        max_age = int(max_age_match.group(1)) if max_age_match else 0
        has_preload = "preload" in hsts_lower
        has_subdomains = "includesubdomains" in hsts_lower
        issues = []
        if max_age < 31536000:
            issues.append(f"max-age={max_age} (need >= 31536000)")
        if not has_preload:
            issues.append("missing preload directive")
        if not has_subdomains:
            issues.append("missing includeSubDomains")
        result.details = {"hsts_value": hsts[:200], "max_age": max_age, "has_preload": has_preload}
        if issues:
            result.status = "failed"
            result.severity = "low"
            result.description = f"HSTS not preload-ready: {'; '.join(issues)}"
            result.remediation = "Use max-age=31536000; includeSubDomains; preload"
        else:
            result.status = "passed"
            result.description = "HSTS preload-ready"
    return result


def check_hsts_subdomains(target_url: str) -> DastResult:
    """Check HSTS includeSubDomains."""
    result = DastResult(
        check_id="DAST-HSTS-02", title="HSTS includeSubDomains",
        owasp_ref="A02:2021", cwe_id="CWE-319",
    )
    resp = safe_get(target_url)
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
    if "includesubdomains" in hsts:
        result.status = "passed"
        result.description = "HSTS includes includeSubDomains"
    elif hsts:
        result.status = "failed"
        result.severity = "info"
        result.description = "HSTS missing includeSubDomains"
        result.remediation = "Add includeSubDomains to HSTS"
    else:
        result.status = "passed"
        result.description = "No HSTS; subdomain check N/A"
    result.details = {"hsts": hsts[:100]}
    return result
