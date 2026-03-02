"""DAST checks: HTTP methods, rate limiting, sensitive data, form autocomplete, debug response."""
import re
from urllib.parse import urlparse

from ..base import DastResult, safe_get, safe_request, HEADERS, TIMEOUT


def check_http_methods(target_url: str) -> DastResult:
    """Check for dangerous HTTP methods."""
    result = DastResult(
        check_id="DAST-METH-01", title="HTTP Methods Check",
        owasp_ref="A05:2021", cwe_id="CWE-749",
    )
    dangerous_methods = ["TRACE", "PUT", "DELETE", "CONNECT"]
    allowed = []
    options_resp = safe_request("OPTIONS", target_url)
    trace_resp = safe_request("TRACE", target_url)
    if not options_resp and not trace_resp:
        result.status = "error"
        result.description = "Could not reach target"
        return result
    if options_resp:
        allow_header = options_resp.headers.get("allow", "")
        if allow_header:
            allowed = [m.strip().upper() for m in allow_header.split(",")]
    if trace_resp and trace_resp.status_code == 200:
        if "TRACE" not in allowed:
            allowed.append("TRACE")
    dangerous_found = [m for m in allowed if m in dangerous_methods]
    result.details = {"allowed_methods": allowed, "dangerous": dangerous_found}
    if options_resp:
        result.request_raw = f"OPTIONS {target_url} HTTP/1.1\nHost: {urlparse(target_url).netloc}"
        result.response_raw = f"HTTP/1.1 {options_resp.status_code}\nAllow: {options_resp.headers.get('allow', '')}"
    if dangerous_found:
        result.status = "failed"
        result.severity = "medium" if "TRACE" in dangerous_found else "low"
        result.description = f"Dangerous HTTP methods: {', '.join(dangerous_found)}"
        result.remediation = f"Disable {', '.join(dangerous_found)}"
    else:
        result.status = "passed"
        result.description = "No dangerous HTTP methods enabled"
    return result


def check_rate_limiting(target_url: str) -> DastResult:
    """Check if rate limiting is enforced."""
    result = DastResult(
        check_id="DAST-RATE-01", title="Rate Limiting Check",
        owasp_ref="A04:2021", cwe_id="CWE-770",
    )
    statuses = []
    try:
        with __import__("httpx").Client(timeout=TIMEOUT, headers=HEADERS, verify=False) as client:
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
        with __import__("httpx").Client(timeout=TIMEOUT, headers=HEADERS, verify=False) as client:
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
        result.description = f"No rate limiting after {len(statuses)} rapid requests"
        result.remediation = "Implement rate limiting"
    return result


def check_sensitive_data(target_url: str) -> DastResult:
    """Check for PII/sensitive patterns."""
    result = DastResult(
        check_id="DAST-PII-01", title="Sensitive Data Exposure",
        owasp_ref="A02:2021", cwe_id="CWE-200",
    )
    resp = safe_get(target_url)
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
        result.description = f"Sensitive data: {', '.join(f['pattern'] for f in found[:3])}"
        result.evidence = f"Sample: {found[0].get('sample', '')}"
        result.remediation = "Never expose PII or secrets in client responses"
    else:
        result.status = "passed"
        result.description = "No obvious PII patterns"
    return result


def check_form_autocomplete(target_url: str) -> DastResult:
    """Check autocomplete on password fields."""
    result = DastResult(
        check_id="DAST-FORM-01", title="Password Autocomplete",
        owasp_ref="A07:2021", cwe_id="CWE-525",
    )
    resp = safe_get(target_url)
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
        result.remediation = "Add autocomplete='off' to password inputs"
    else:
        result.status = "passed"
        result.description = "Password fields have autocomplete=off or no password inputs"
    return result


def check_debug_response(target_url: str) -> DastResult:
    """Check for stack traces / debug output."""
    result = DastResult(
        check_id="DAST-DEBUG-01", title="Debug/Stack Trace in Response",
        owasp_ref="A05:2021", cwe_id="CWE-209",
    )
    resp = safe_get(target_url)
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
        result.description = f"Debug/stack trace: {', '.join(found)}"
        result.evidence = f"Matched: {', '.join(found)}"
        result.remediation = "Disable debug mode. Use generic error pages."
    else:
        result.status = "passed"
        result.description = "No debug/stack trace in response"
    return result
