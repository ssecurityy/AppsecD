"""DAST checks: security headers, cache, SRI, COOP/COEP, etc."""
import re
from urllib.parse import urlparse, urljoin

from ..base import DastResult, safe_get, safe_request, HEADERS


def check_security_headers(target_url: str) -> DastResult:
    """Check for missing or misconfigured security headers."""
    result = DastResult(
        check_id="DAST-HDR-01", title="Security Headers Analysis",
        owasp_ref="A05:2021", cwe_id="CWE-693",
    )
    resp = safe_get(target_url)
    if not resp:
        result.status = "error"
        result.description = "Could not reach target URL"
        return result
    headers = {k.lower(): v for k, v in resp.headers.items()}
    missing = []
    findings = []
    required = {
        "x-frame-options": {"severity": "medium", "remediation": "Add X-Frame-Options: DENY or SAMEORIGIN"},
        "x-content-type-options": {"severity": "low", "remediation": "Add X-Content-Type-Options: nosniff"},
        "strict-transport-security": {"severity": "high", "remediation": "Add Strict-Transport-Security: max-age=31536000; includeSubDomains"},
        "content-security-policy": {"severity": "medium", "remediation": "Implement Content-Security-Policy"},
        "x-xss-protection": {"severity": "low", "remediation": "Add X-XSS-Protection: 1; mode=block"},
        "referrer-policy": {"severity": "low", "remediation": "Add Referrer-Policy: strict-origin-when-cross-origin"},
        "permissions-policy": {"severity": "low", "remediation": "Add Permissions-Policy"},
    }
    for header, info in required.items():
        if header not in headers:
            missing.append({"header": header, **info})
        else:
            findings.append({"header": header, "value": headers[header], "status": "present"})
    dangerous = []
    if "server" in headers and any(v in headers["server"].lower() for v in ["apache/", "nginx/", "iis/", "express"]):
        dangerous.append({"header": "Server", "value": headers["server"], "issue": "Server version disclosed"})
    if "x-powered-by" in headers:
        dangerous.append({"header": "X-Powered-By", "value": headers["x-powered-by"], "issue": "Technology disclosed"})
    if missing:
        result.status = "failed"
        result.severity = "high" if any(m["severity"] == "high" for m in missing) else "medium"
        result.description = f"{len(missing)} security header(s) missing"
        result.evidence = ", ".join(m["header"] for m in missing)
        result.remediation = "; ".join(m["remediation"] for m in missing[:3])
        result.reproduction_steps = f"1. GET {target_url}\n2. Inspect headers\n3. Missing: {', '.join(m['header'] for m in missing)}"
    else:
        result.status = "passed"
        result.description = "All security headers present"
    result.details = {"missing": missing, "present": findings, "dangerous": dangerous, "response_code": resp.status_code, "payload_tested": "Headers: x-frame-options, x-content-type-options, strict-transport-security, content-security-policy, x-xss-protection, referrer-policy, permissions-policy"}
    result.request_raw = f"GET {target_url} HTTP/1.1\nHost: {urlparse(target_url).netloc}"
    result.response_raw = f"HTTP/1.1 {resp.status_code}\n" + "\n".join(f"{k}: {v}" for k, v in resp.headers.items()) + "\n\n" + (resp.text[:2000] if resp.text else "")
    return result


def check_cache_control(target_url: str) -> DastResult:
    """Check Cache-Control on sensitive paths."""
    result = DastResult(
        check_id="DAST-CACHE-01", title="Cache Control on Sensitive Pages",
        owasp_ref="A05:2021", cwe_id="CWE-524",
    )
    paths = ["/", "/login", "/dashboard", "/api/user", "/profile", "/admin"]
    base = f"{urlparse(target_url).scheme}://{urlparse(target_url).netloc}"
    issues = []
    sample_resp = None
    for path in paths:
        r = safe_get(urljoin(base, path))
        if not sample_resp and r:
            sample_resp = r
        if r and r.status_code == 200:
            cc = r.headers.get("cache-control", "").lower()
            if "no-store" not in cc and "no-cache" not in cc and "private" not in cc:
                issues.append({"path": path, "cache_control": cc or "(none)"})
    result.details = {"paths_checked": paths, "missing_no_store": issues, "payload_tested": f"GET {paths}"}
    if sample_resp:
        result.request_raw = f"GET {base}/ HTTP/1.1\nHost: {urlparse(target_url).netloc}\n(Checked paths: {', '.join(paths)})"
        result.response_raw = f"HTTP/1.1 {sample_resp.status_code}\n" + "\n".join(f"{k}: {v}" for k, v in sample_resp.headers.items()) + "\n\n(Cache-Control: " + (sample_resp.headers.get("cache-control") or "(none)") + ")"
    if issues:
        result.status = "failed"
        result.severity = "low"
        result.description = f"Missing no-store on {len(issues)} path(s)"
        result.evidence = ", ".join(i["path"] for i in issues[:5])
        result.remediation = "Set Cache-Control: no-store on sensitive pages."
    else:
        result.status = "passed"
        result.description = "Cache headers adequate on checked paths"
    return result


def check_sri(target_url: str) -> DastResult:
    """Check for missing SRI on external scripts."""
    result = DastResult(
        check_id="DAST-SRI-01", title="Subresource Integrity (SRI)",
        owasp_ref="A08:2021", cwe_id="CWE-353",
    )
    resp = safe_get(target_url)
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
            if idx >= 0 and "integrity=" not in body[max(0, idx - 150) : idx + 250]:
                no_sri.append(src[:80])
    result.details = {"external_scripts": [s[:80] for s in script_tags if (s.startswith("http") or s.startswith("//"))][:20], "missing_sri": no_sri[:10], "payload_tested": "External <script src> tags for missing integrity= attribute"}
    result.request_raw = f"GET {target_url} HTTP/1.1\nHost: {urlparse(target_url).netloc}"
    result.response_raw = f"HTTP/1.1 {resp.status_code}\n" + "\n".join(f"{k}: {v}" for k, v in resp.headers.items()) + "\n\n" + (body[:2000] if body else "")
    if no_sri:
        result.status = "failed"
        result.severity = "low"
        result.description = f"{len(no_sri)} external script(s) without SRI"
        result.evidence = ", ".join(no_sri[:3])
        result.remediation = "Add integrity attribute to external scripts."
    else:
        result.status = "passed"
        result.description = "No external scripts without SRI"
    return result


def check_version_headers(target_url: str) -> DastResult:
    """Check for version disclosure in X-Generator, X-Runtime, etc."""
    result = DastResult(
        check_id="DAST-VER-01", title="Version Header Disclosure",
        owasp_ref="A05:2021", cwe_id="CWE-200",
    )
    resp = safe_get(target_url)
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
        result.remediation = "Remove version headers"
    else:
        result.status = "passed"
        result.description = "No additional version headers disclosed"
    return result


def check_coop_coep(target_url: str) -> DastResult:
    """Check COOP/COEP headers."""
    result = DastResult(
        check_id="DAST-COOP-01", title="COOP/COEP Headers",
        owasp_ref="A05:2021", cwe_id="CWE-1021",
    )
    resp = safe_get(target_url)
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
        result.remediation = "Consider COOP: same-origin and COEP: require-corp"
    else:
        result.status = "passed"
        result.description = "COOP/COEP present" if (coop and coep) else "Partial COOP/COEP"
    return result


def check_xss_protection_header(target_url: str) -> DastResult:
    """Check X-XSS-Protection header."""
    result = DastResult(
        check_id="DAST-XSS-HDR-01", title="X-XSS-Protection Header",
        owasp_ref="A05:2021", cwe_id="CWE-79",
    )
    resp = safe_get(target_url)
    if not resp:
        result.status = "error"
        result.description = "Could not reach target"
        return result
    xss = resp.headers.get("x-xss-protection", "").lower()
    result.details = {"value": xss or "(not set)", "payload_tested": "Response header X-XSS-Protection"}
    result.request_raw = f"GET {target_url} HTTP/1.1\nHost: {urlparse(target_url).netloc}"
    result.response_raw = f"HTTP/1.1 {resp.status_code}\n" + "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
    if "1; mode=block" in xss or "1" in xss:
        result.status = "passed"
        result.description = "X-XSS-Protection present"
    else:
        result.status = "failed"
        result.severity = "low"
        result.description = "X-XSS-Protection missing or weak"
        result.remediation = "Add X-XSS-Protection: 1; mode=block (or rely on CSP)"
    return result


def check_csp_reporting(target_url: str) -> DastResult:
    """Check CSP report-uri / report-to."""
    result = DastResult(
        check_id="DAST-CSP-01", title="CSP Reporting",
        owasp_ref="A05:2021", cwe_id="CWE-693",
    )
    resp = safe_get(target_url)
    if not resp:
        result.status = "error"
        result.description = "Could not reach target"
        return result
    csp = resp.headers.get("content-security-policy", "") or resp.headers.get("content-security-policy-report-only", "")
    has_report = "report-uri" in csp or "report-to" in csp
    result.details = {"has_report": has_report, "payload_tested": "CSP header for report-uri/report-to"}
    result.request_raw = f"GET {target_url} HTTP/1.1\nHost: {urlparse(target_url).netloc}"
    result.response_raw = f"HTTP/1.1 {resp.status_code}\n" + "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
    if not csp:
        result.status = "passed"
        result.description = "No CSP (reporting N/A)"
    elif has_report:
        result.status = "passed"
        result.description = "CSP reporting configured"
    else:
        result.status = "failed"
        result.severity = "info"
        result.description = "CSP present but no report-uri/report-to"
        result.remediation = "Add report-uri or report-to to CSP"
    return result


def check_expect_ct(target_url: str) -> DastResult:
    """Check Expect-CT header."""
    result = DastResult(
        check_id="DAST-ECT-01", title="Expect-CT Header",
        owasp_ref="A02:2021", cwe_id="CWE-295",
    )
    resp = safe_get(target_url)
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
    result.details = {"expect_ct": ect or "(not set)", "payload_tested": "Response header Expect-CT"}
    result.request_raw = f"GET {target_url} HTTP/1.1\nHost: {parsed.netloc}"
    result.response_raw = f"HTTP/1.1 {resp.status_code}\n" + "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
    if not ect:
        result.status = "failed"
        result.severity = "info"
        result.description = "Expect-CT header missing"
        result.remediation = "Consider Expect-CT: max-age=86400"
    else:
        result.status = "passed"
        result.description = "Expect-CT header present"
    return result


def check_permissions_policy(target_url: str) -> DastResult:
    """Check Permissions-Policy."""
    result = DastResult(
        check_id="DAST-PERM-01", title="Permissions-Policy",
        owasp_ref="A05:2021", cwe_id="CWE-1021",
    )
    resp = safe_get(target_url)
    if not resp:
        result.status = "error"
        result.description = "Could not reach target"
        return result
    headers = {k.lower(): v for k, v in resp.headers.items()}
    pp = headers.get("permissions-policy", headers.get("feature-policy", ""))
    result.details = {"value": pp or "(not set)", "payload_tested": "Response header Permissions-Policy"}
    result.request_raw = f"GET {target_url} HTTP/1.1\nHost: {urlparse(target_url).netloc}"
    result.response_raw = f"HTTP/1.1 {resp.status_code}\n" + "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
    if not pp:
        result.status = "failed"
        result.severity = "low"
        result.description = "Permissions-Policy missing"
        result.remediation = "Add Permissions-Policy to restrict browser features"
    else:
        result.status = "passed"
        result.description = "Permissions-Policy present"
    return result


def check_content_type_sniffing(target_url: str) -> DastResult:
    """Check X-Content-Type-Options and MIME."""
    result = DastResult(
        check_id="DAST-CT-01", title="Content-Type Sniffing / MIME Mismatch",
        owasp_ref="A05:2021", cwe_id="CWE-16",
    )
    resp = safe_get(target_url)
    if not resp:
        result.status = "error"
        result.description = "Could not reach target"
        return result
    ct = resp.headers.get("content-type", "").lower()
    xcto = resp.headers.get("x-content-type-options", "").lower()
    body = (resp.text or "").strip()[:500]
    looks_json = body.startswith("{") or body.startswith("[")
    result.details = {"content_type": ct, "x_content_type_options": xcto or "(not set)", "body_start": body[:100], "payload_tested": "X-Content-Type-Options: nosniff; Content-Type vs body"}
    issues = []
    if not xcto or "nosniff" not in xcto:
        issues.append("X-Content-Type-Options: nosniff missing")
    if looks_json and "application/json" not in ct and "text/html" in ct:
        issues.append("JSON served as text/html")
    if issues:
        result.status = "failed"
        result.severity = "medium" if "nosniff" in str(issues).lower() else "low"
        result.description = "; ".join(issues)
        result.remediation = "Add X-Content-Type-Options: nosniff"
    else:
        result.status = "passed"
        result.description = "Content-Type and X-Content-Type-Options adequate"
    result.request_raw = f"GET {target_url} HTTP/1.1\nHost: {urlparse(target_url).netloc}"
    result.response_raw = f"HTTP/1.1 {resp.status_code}\n" + "\n".join(f"{k}: {v}" for k, v in resp.headers.items()) + "\n\n" + body[:1000]
    return result


def check_clickjacking(target_url: str) -> DastResult:
    """Check X-Frame-Options / frame-ancestors."""
    result = DastResult(
        check_id="DAST-FRAME-01", title="Clickjacking Protection",
        owasp_ref="A05:2021", cwe_id="CWE-1021",
    )
    resp = safe_get(target_url)
    if not resp:
        result.status = "error"
        result.description = "Could not reach target"
        return result
    headers = {k.lower(): v for k, v in resp.headers.items()}
    xfo = headers.get("x-frame-options", "")
    csp = headers.get("content-security-policy", headers.get("content-security-policy-report-only", ""))
    has_xfo = bool(xfo and xfo.strip())
    has_frame_ancestors = "frame-ancestors" in csp.lower()
    result.details = {"x_frame_options": xfo or "(not set)", "csp_frame_ancestors": has_frame_ancestors, "payload_tested": "X-Frame-Options or CSP frame-ancestors"}
    if has_xfo or has_frame_ancestors:
        result.status = "passed"
        result.description = "Clickjacking protection present"
    else:
        result.status = "failed"
        result.severity = "medium"
        result.description = "No clickjacking protection"
        result.remediation = "Add X-Frame-Options: DENY or CSP frame-ancestors 'none'"
    result.request_raw = f"GET {target_url} HTTP/1.1\nHost: {urlparse(target_url).netloc}"
    result.response_raw = f"HTTP/1.1 {resp.status_code}\n" + "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
    return result
