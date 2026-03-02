"""DAST checks: cookie security, cookie prefix."""
import re
from urllib.parse import urlparse

from ..base import DastResult, safe_get


def check_cookie_security(target_url: str) -> DastResult:
    """Check cookie security flags."""
    result = DastResult(
        check_id="DAST-COOK-01", title="Cookie Security Flags",
        owasp_ref="A05:2021", cwe_id="CWE-614",
    )
    resp = safe_get(target_url)
    if not resp:
        result.status = "error"
        result.description = "Could not reach target"
        return result
    cookies = resp.headers.get_list("set-cookie")
    if not cookies:
        result.status = "passed"
        result.description = "No cookies set"
        result.details = {"cookies_found": 0}
        result.request_raw = f"GET {target_url} HTTP/1.1\nHost: {urlparse(target_url).netloc}"
        result.response_raw = f"HTTP/1.1 {resp.status_code}\n" + "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
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
    result.details = {"cookies": cookie_details, "total_cookies": len(cookies), "payload_tested": "Set-Cookie headers for Secure, HttpOnly, SameSite"}
    result.request_raw = f"GET {target_url} HTTP/1.1\nHost: {urlparse(target_url).netloc}"
    result.response_raw = f"HTTP/1.1 {resp.status_code}\n" + "\n".join(f"{k}: {v}" for k, v in resp.headers.items()) + "\n\n" + (resp.text[:1500] if resp.text else "")
    if issues:
        result.status = "failed"
        result.severity = "medium"
        result.description = f"{len(issues)} cookie security issue(s)"
        result.evidence = "; ".join(issues[:5])
        result.remediation = "Set Secure, HttpOnly, SameSite=Strict/Lax on session cookies"
        result.reproduction_steps = f"1. GET {target_url}\n2. Inspect Set-Cookie headers"
    else:
        result.status = "passed"
        result.description = "All cookies have proper security flags"
    return result


def check_cookie_prefix(target_url: str) -> DastResult:
    """Check __Host- / __Secure- prefix on cookies."""
    result = DastResult(
        check_id="DAST-COOK-02", title="Cookie Prefix (__Host- / __Secure-)",
        owasp_ref="A05:2021", cwe_id="CWE-614",
    )
    resp = safe_get(target_url)
    if not resp:
        result.status = "error"
        result.description = "Could not reach target"
        return result
    cookies = resp.headers.get_list("set-cookie")
    session_like = []
    for cookie_str in cookies:
        name = cookie_str.split("=")[0].strip()
        if "session" in name.lower() or "auth" in name.lower() or "token" in name.lower() or "sid" in name.lower():
            session_like.append(name)
    unprefixed = [n for n in session_like if not (n.startswith("__Host-") or n.startswith("__Secure-"))]
    result.details = {"session_like": session_like, "unprefixed": unprefixed, "payload_tested": "Cookie names for __Host-/__Secure- prefix"}
    if unprefixed:
        result.status = "failed"
        result.severity = "low"
        result.description = f"Session-like cookies without __Host-/__Secure-: {', '.join(unprefixed[:5])}"
        result.remediation = "Use __Host- or __Secure- prefix for sensitive cookies"
    else:
        result.status = "passed"
        result.description = "Session cookies use __Host-/__Secure- prefix or none found"
    result.request_raw = f"GET {target_url} HTTP/1.1\nHost: {urlparse(target_url).netloc}"
    result.response_raw = f"HTTP/1.1 {resp.status_code}\n" + "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
    return result
