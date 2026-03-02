"""DAST checks: CORS, open redirect, host header injection, CRLF, XSS, SQLi."""
from urllib.parse import urlparse, urljoin

import httpx

from ..base import DastResult, safe_get, safe_request, HEADERS, USER_AGENTS, TIMEOUT, get_scan_ctx


def check_cors(target_url: str) -> DastResult:
    """Check for CORS misconfiguration."""
    result = DastResult(
        check_id="DAST-CORS-01", title="CORS Configuration",
        owasp_ref="A05:2021", cwe_id="CWE-942",
    )
    evil_origin = "https://evil-attacker.com"
    resp = safe_request("GET", target_url, headers={"Origin": evil_origin})
    if not resp:
        result.status = "error"
        result.description = "Could not reach target"
        return result
    acao = resp.headers.get("access-control-allow-origin", "")
    acac = resp.headers.get("access-control-allow-credentials", "")
    issues = []
    if acao == "*":
        issues.append("Wildcard Access-Control-Allow-Origin")
    if acao == evil_origin:
        issues.append(f"Reflects arbitrary origin: {evil_origin}")
    if acac.lower() == "true" and (acao == "*" or acao == evil_origin):
        issues.append("Credentials allowed with permissive origin — critical")
    result.details = {"acao": acao, "acac": acac, "tested_origin": evil_origin, "payload_tested": f"GET with Origin: {evil_origin}"}
    result.request_raw = f"GET {target_url} HTTP/1.1\nOrigin: {evil_origin}\nHost: {urlparse(target_url).netloc}"
    result.response_raw = f"HTTP/1.1 {resp.status_code}\n" + "\n".join(f"{k}: {v}" for k, v in resp.headers.items()) + "\n\n" + (resp.text[:1500] if resp.text else "")
    if issues:
        result.status = "failed"
        result.severity = "critical" if "critical" in " ".join(issues) else "high"
        result.description = f"CORS misconfiguration: {'; '.join(issues)}"
        result.remediation = "Restrict ACAO to trusted domains"
        result.reproduction_steps = f"1. GET {target_url} with Origin: {evil_origin}\n2. ACAO: {acao}"
        result.evidence = f"ACAO: {acao}, ACAC: {acac}"
    else:
        result.status = "passed"
        result.description = "CORS properly configured"
    return result


def check_open_redirect(target_url: str) -> DastResult:
    """Check for open redirect."""
    result = DastResult(
        check_id="DAST-REDIR-01", title="Open Redirect Detection",
        owasp_ref="A01:2021", cwe_id="CWE-601",
    )
    evil_url = "https://evil-attacker.com"
    redirect_params = ["redirect", "url", "next", "return", "returnUrl", "redirect_uri", "continue", "dest", "goto", "target"]
    found = []
    parsed = urlparse(target_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    ctx = get_scan_ctx()
    for param in redirect_params:
        test_url = f"{base}/login?{param}={evil_url}"
        if ctx:
            ctx.throttle()
        try:
            with httpx.Client(timeout=TIMEOUT, headers={**HEADERS, "User-Agent": USER_AGENTS[hash(param) % len(USER_AGENTS)]}, verify=False, follow_redirects=False) as client:
                resp = client.get(test_url)
                location = resp.headers.get("location", "")
                if evil_url in location:
                    found.append({"param": param, "url": test_url, "redirect_to": location})
        except Exception:
            pass
    result.details = {"tested_params": redirect_params, "redirects_found": found, "payload_tested": f"GET /login?param={evil_url} for params: {', '.join(redirect_params[:5])}"}
    if found:
        result.status = "failed"
        result.severity = "medium"
        result.description = f"Open redirect via: {', '.join(f['param'] for f in found)}"
        result.evidence = f"Redirect to {evil_url} via: {found[0]['url']}"
        result.remediation = "Validate redirect URLs against allowlist"
    else:
        result.status = "passed"
        result.description = "No open redirect detected"
    return result


def check_host_header_injection(target_url: str) -> DastResult:
    """Check Host header injection."""
    result = DastResult(
        check_id="DAST-HOST-01", title="Host Header Injection",
        owasp_ref="A01:2021", cwe_id="CWE-644",
    )
    evil_host = "evil-attacker.com"
    r = safe_request("GET", target_url, headers={"Host": evil_host})
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
        result.remediation = "Validate Host header against allowlist"
    else:
        result.status = "passed"
        result.description = "Host header not reflected"
    result.details = {"tested_host": evil_host, "location": loc[:200], "payload_tested": f"GET with Host: {evil_host}"}
    result.request_raw = f"GET {target_url} HTTP/1.1\nHost: {evil_host}"
    result.response_raw = f"HTTP/1.1 {r.status_code}\n" + "\n".join(f"{k}: {v}" for k, v in r.headers.items()) + "\n\n" + (r.text[:1500] if r.text else "")
    return result


def check_crlf_injection(target_url: str) -> DastResult:
    """Check CRLF injection."""
    result = DastResult(
        check_id="DAST-CRLF-01", title="CRLF Injection",
        owasp_ref="A01:2021", cwe_id="CWE-93",
    )
    payload = "%0d%0aSet-Cookie:crlf=injected"
    parsed = urlparse(target_url)
    test_url = f"{parsed.scheme}://{parsed.netloc}/?redirect={payload}"
    r = safe_request("GET", test_url)
    if not r:
        result.status = "error"
        result.description = "Could not reach target"
        return result
    set_cookie = r.headers.get("set-cookie", "")
    vuln = "crlf=injected" in set_cookie.lower()
    result.details = {"payload": payload, "set_cookie_header": set_cookie[:200], "payload_tested": f"CRLF injection: ?redirect={payload}"}
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


def check_xss_basic(target_url: str) -> DastResult:
    """Check for reflected XSS in common params."""
    result = DastResult(
        check_id="DAST-XSS-01", title="Basic Reflected XSS Check",
        owasp_ref="A03:2021", cwe_id="CWE-79",
    )
    parsed = urlparse(target_url)
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}"
    payload = '<script>alert(1)</script>'
    params = ["q", "search", "query", "keyword", "s", "name", "id", "ref", "redirect"]
    reflected = []
    resp = None
    for param in params:
        test_url = f"{base}?{param}={payload}"
        r = safe_get(test_url)
        if r and payload in (r.text or ""):
            reflected.append({"param": param, "url": test_url})
            if not resp:
                resp = r
    result.details = {"tested_params": params, "reflected_unencoded": reflected, "payload_tested": f"XSS payload '<script>alert(1)</script>' in params: {', '.join(params)}"}
    if resp:
        result.request_raw = f"GET {base}?q={payload} HTTP/1.1\nHost: {urlparse(target_url).netloc}"
        result.response_raw = f"HTTP/1.1 {resp.status_code}\n" + "\n".join(f"{k}: {v}" for k, v in resp.headers.items()) + "\n\n" + (resp.text[:2000] if resp.text else "")
    if reflected:
        result.status = "failed"
        result.severity = "high"
        result.description = f"Reflected XSS in {len(reflected)} param(s)"
        result.evidence = f"Param(s): {', '.join(r['param'] for r in reflected)}"
        result.remediation = "Encode user input. Use CSP."
    else:
        result.status = "passed"
        result.description = "No reflected XSS in common params"
    return result


def check_sqli_error(target_url: str) -> DastResult:
    """Check for SQL error messages."""
    result = DastResult(
        check_id="DAST-SQLI-01", title="SQL Error Detection",
        owasp_ref="A03:2021", cwe_id="CWE-89",
    )
    payloads = ["'", "1'", "1 OR 1=1", "1' OR '1'='1"]
    errors = ["sql syntax", "mysql_fetch", "pg_query", "sqlite", "ora-01", "sqlstate", "unclosed quotation", "syntax error in query", "odbc", "microsoft ole db"]
    found = []
    resp = safe_get(target_url)
    if not resp:
        result.status = "error"
        result.description = "Could not reach target"
        return result
    for p in payloads:
        r = safe_get(f"{target_url}{'&' if '?' in target_url else '?'}id={p}")
        if r:
            rb = (r.text or "").lower()
            for err in errors:
                if err in rb:
                    found.append({"payload": p, "error": err})
                    break
    result.details = {"payloads_tested": payloads, "errors_found": found, "payload_tested": f"SQLi payloads in ?id=: {payloads}"}
    result.request_raw = f"GET {target_url} HTTP/1.1\nHost: {urlparse(target_url).netloc}"
    result.response_raw = f"HTTP/1.1 {resp.status_code}\n" + "\n".join(f"{k}: {v}" for k, v in resp.headers.items()) + "\n\n" + (resp.text[:2000] if resp.text else "")
    if found:
        result.status = "failed"
        result.severity = "high"
        result.description = f"SQL error in response: {found[0].get('error', '')}"
        result.evidence = f"Payload: {found[0].get('payload', '')} triggered SQL error"
        result.remediation = "Use parameterized queries"
    else:
        result.status = "passed"
        result.description = "No SQL error leakage"
    return result
