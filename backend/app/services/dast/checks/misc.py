"""DAST checks: weak referrer, cache age, upgrade insecure, redirect chain, etc."""
import re
from urllib.parse import urlparse

from ..base import DastResult, safe_get, safe_request


def check_weak_referrer(target_url: str) -> DastResult:
    """Check Referrer-Policy strength."""
    result = DastResult(
        check_id="DAST-REF-01", title="Referrer-Policy Strength",
        owasp_ref="A05:2021", cwe_id="CWE-200",
    )
    resp = safe_get(target_url)
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
        result.remediation = "Set Referrer-Policy: strict-origin-when-cross-origin"
    elif ref_lower in weak or "unsafe" in ref_lower:
        result.status = "failed"
        result.severity = "low"
        result.description = f"Weak Referrer-Policy: {ref}"
        result.remediation = "Use strict-origin-when-cross-origin or stricter"
    else:
        result.status = "passed"
        result.description = f"Referrer-Policy adequate: {ref}"
    return result


def check_cache_age(target_url: str) -> DastResult:
    """Check cache max-age on static assets."""
    result = DastResult(
        check_id="DAST-CACHE-02", title="Cache max-age",
        owasp_ref="A05:2021", cwe_id="CWE-524",
    )
    resp = safe_get(target_url)
    if not resp:
        result.status = "error"
        result.description = "Could not reach target"
        return result
    cc = resp.headers.get("cache-control", "").lower()
    result.details = {"cache_control": cc or "(not set)"}
    if "max-age" in cc:
        m = re.search(r"max-age=(\d+)", cc)
        if m:
            age = int(m.group(1))
            if age > 31536000:
                result.status = "failed"
                result.severity = "info"
                result.description = f"Long cache max-age: {age}s (>1 year)"
            else:
                result.status = "passed"
                result.description = f"Cache max-age: {age}s"
    else:
        result.status = "passed"
        result.description = "No long cache (or no cache-control)"
    return result


def check_upgrade_insecure(target_url: str) -> DastResult:
    """Check Upgrade-Insecure-Requests / mixed content."""
    result = DastResult(
        check_id="DAST-UPGRADE-01", title="Upgrade Insecure Requests",
        owasp_ref="A05:2021", cwe_id="CWE-319",
    )
    resp = safe_get(target_url)
    if not resp:
        result.status = "error"
        result.description = "Could not reach target"
        return result
    body = (resp.text or "")[:10000]
    http_resources = re.findall(r'src=["\'](http://[^"\']+)["\']', body, re.I) + re.findall(r'href=["\'](http://[^"\']+)["\']', body, re.I)
    result.details = {"http_resources": len(http_resources), "sample": http_resources[:5]}
    if http_resources:
        result.status = "failed"
        result.severity = "low"
        result.description = f"Mixed content: {len(http_resources)} HTTP resource(s)"
        result.evidence = ", ".join(http_resources[:3])
        result.remediation = "Use HTTPS for all resources"
    else:
        result.status = "passed"
        result.description = "No mixed content detected"
    return result


def check_redirect_chain(target_url: str) -> DastResult:
    """Check for excessive redirect chains."""
    result = DastResult(
        check_id="DAST-REDIR-03", title="Redirect Chain",
        owasp_ref="A05:2021", cwe_id="CWE-601",
    )
    resp = safe_get(target_url)
    if not resp:
        result.status = "error"
        result.description = "Could not reach target"
        return result
    hops = 0
    r = resp
    seen = set()
    while r and r.status_code in (301, 302, 307, 308) and hops < 10:
        loc = r.headers.get("location", "")
        if not loc or loc in seen:
            break
        seen.add(loc)
        hops += 1
        from urllib.parse import urljoin
        next_url = urljoin(str(r.url), loc)
        try:
            import httpx
            r = httpx.get(next_url, follow_redirects=False, timeout=5)
        except Exception:
            break
    result.details = {"redirect_hops": hops}
    if hops > 5:
        result.status = "failed"
        result.severity = "low"
        result.description = f"Long redirect chain: {hops} hop(s)"
        result.remediation = "Shorten redirect chain"
    else:
        result.status = "passed"
        result.description = f"Redirect chain OK ({hops} hop(s))"
    return result


def check_timing_allow_origin(target_url: str) -> DastResult:
    """Check Timing-Allow-Origin header."""
    result = DastResult(
        check_id="DAST-TAO-01", title="Timing-Allow-Origin",
        owasp_ref="A05:2021", cwe_id="CWE-200",
    )
    resp = safe_get(target_url)
    if not resp:
        result.status = "error"
        result.description = "Could not reach target"
        return result
    tao = resp.headers.get("timing-allow-origin", "")
    result.details = {"value": tao or "(not set)"}
    result.status = "passed"
    result.description = "Timing-Allow-Origin check (info only)"
    return result


def check_alt_svc(target_url: str) -> DastResult:
    """Check Alt-Svc header."""
    result = DastResult(
        check_id="DAST-ALT-01", title="Alt-Svc Header",
        owasp_ref="A05:2021", cwe_id="CWE-200",
    )
    resp = safe_get(target_url)
    if not resp:
        result.status = "error"
        result.description = "Could not reach target"
        return result
    alt = resp.headers.get("alt-svc", "")
    result.details = {"value": alt[:200] if alt else "(not set)"}
    result.status = "passed"
    result.description = "Alt-Svc header check (info only)"
    return result


def check_content_disposition(target_url: str) -> DastResult:
    """Check Content-Disposition on downloads."""
    result = DastResult(
        check_id="DAST-CD-01", title="Content-Disposition",
        owasp_ref="A05:2021", cwe_id="CWE-200",
    )
    resp = safe_get(target_url)
    if not resp:
        result.status = "error"
        result.description = "Could not reach target"
        return result
    cd = resp.headers.get("content-disposition", "")
    result.details = {"value": cd or "(not set)"}
    result.status = "passed"
    result.description = "Content-Disposition check (info only)"
    return result


def check_pragma_no_cache(target_url: str) -> DastResult:
    """Check Pragma: no-cache for sensitive responses."""
    result = DastResult(
        check_id="DAST-PRAGMA-01", title="Pragma no-cache",
        owasp_ref="A05:2021", cwe_id="CWE-524",
    )
    resp = safe_get(target_url)
    if not resp:
        result.status = "error"
        result.description = "Could not reach target"
        return result
    pragma = resp.headers.get("pragma", "").lower()
    cc = resp.headers.get("cache-control", "").lower()
    result.details = {"pragma": pragma or "(not set)", "cache_control": cc or "(not set)"}
    result.status = "passed"
    result.description = "Pragma/Cache-Control check (info only)"
    return result


def check_server_timing(target_url: str) -> DastResult:
    """Check Server-Timing header disclosure."""
    result = DastResult(
        check_id="DAST-SRV-01", title="Server-Timing Header",
        owasp_ref="A05:2021", cwe_id="CWE-200",
    )
    resp = safe_get(target_url)
    if not resp:
        result.status = "error"
        result.description = "Could not reach target"
        return result
    st = resp.headers.get("server-timing", "")
    result.details = {"value": st[:300] if st else "(not set)"}
    if st:
        result.status = "failed"
        result.severity = "info"
        result.description = "Server-Timing header may leak timing info"
        result.remediation = "Disable Server-Timing in production"
    else:
        result.status = "passed"
        result.description = "No Server-Timing header"
    return result


def check_via_header(target_url: str) -> DastResult:
    """Check Via header disclosure."""
    result = DastResult(
        check_id="DAST-VIA-01", title="Via Header",
        owasp_ref="A05:2021", cwe_id="CWE-200",
    )
    resp = safe_get(target_url)
    if not resp:
        result.status = "error"
        result.description = "Could not reach target"
        return result
    via = resp.headers.get("via", "")
    result.details = {"value": via[:200] if via else "(not set)"}
    if via:
        result.status = "failed"
        result.severity = "info"
        result.description = "Via header may leak proxy info"
    else:
        result.status = "passed"
        result.description = "No Via header"
    return result


def check_x_forwarded_disclosure(target_url: str) -> DastResult:
    """Check X-Forwarded-* headers."""
    result = DastResult(
        check_id="DAST-XFWD-01", title="X-Forwarded Disclosure",
        owasp_ref="A05:2021", cwe_id="CWE-200",
    )
    resp = safe_get(target_url)
    if not resp:
        result.status = "error"
        result.description = "Could not reach target"
        return result
    headers = {k.lower(): v for k, v in resp.headers.items()}
    xfwd = {k: v for k, v in headers.items() if k.startswith("x-forwarded")}
    result.details = {"x_forwarded_headers": xfwd}
    if xfwd:
        result.status = "failed"
        result.severity = "info"
        result.description = f"X-Forwarded headers disclosed: {', '.join(xfwd.keys())}"
    else:
        result.status = "passed"
        result.description = "No X-Forwarded headers"
    return result


def check_allow_dangerous(target_url: str) -> DastResult:
    """Check Allow header for dangerous methods."""
    result = DastResult(
        check_id="DAST-ALLOW-01", title="Allow Header",
        owasp_ref="A05:2021", cwe_id="CWE-749",
    )
    resp = safe_request("OPTIONS", target_url)
    if not resp:
        result.status = "error"
        result.description = "Could not reach target"
        return result
    allow = resp.headers.get("allow", "")
    result.details = {"allow": allow}
    result.status = "passed"
    result.description = "Allow header check (info only)"
    return result


def check_corp(target_url: str) -> DastResult:
    """Check Cross-Origin-Resource-Policy."""
    result = DastResult(
        check_id="DAST-CORP-01", title="Cross-Origin-Resource-Policy",
        owasp_ref="A05:2021", cwe_id="CWE-942",
    )
    resp = safe_get(target_url)
    if not resp:
        result.status = "error"
        result.description = "Could not reach target"
        return result
    corp = resp.headers.get("cross-origin-resource-policy", "")
    result.details = {"value": corp or "(not set)"}
    result.status = "passed"
    result.description = "CORP header check (info only)"
    return result


def check_clear_site_data(target_url: str) -> DastResult:
    """Check Clear-Site-Data header."""
    result = DastResult(
        check_id="DAST-CSD-01", title="Clear-Site-Data",
        owasp_ref="A05:2021", cwe_id="CWE-525",
    )
    resp = safe_get(target_url)
    if not resp:
        result.status = "error"
        result.description = "Could not reach target"
        return result
    csd = resp.headers.get("clear-site-data", "")
    result.details = {"value": csd or "(not set)"}
    result.status = "passed"
    result.description = "Clear-Site-Data check (info only)"
    return result


def check_trace_xst(target_url: str) -> DastResult:
    """Check TRACE method (XST)."""
    result = DastResult(
        check_id="DAST-TRACE-01", title="TRACE Method (XST)",
        owasp_ref="A05:2021", cwe_id="CWE-693",
    )
    resp = safe_request("TRACE", target_url)
    if not resp:
        result.status = "error"
        result.description = "Could not reach target"
        return result
    result.request_raw = f"TRACE {target_url} HTTP/1.1\nHost: {urlparse(target_url).netloc}"
    result.response_raw = f"HTTP/1.1 {resp.status_code}\n" + "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
    if resp.status_code == 200 and (resp.text or "").strip():
        result.status = "failed"
        result.severity = "low"
        result.description = "TRACE method enabled (XST)"
        result.remediation = "Disable TRACE on web server"
    else:
        result.status = "passed"
        result.description = "TRACE disabled or not reflecting"
    return result
