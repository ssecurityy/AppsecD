"""Advanced DAST checks: JWT, CSRF, CSP deep, path traversal, SSRF, command injection, CORS deep, HTTP smuggling."""
import base64
import hashlib
import hmac
import json
import logging
import re
import time
from urllib.parse import urlparse, urljoin, parse_qs, urlencode

import httpx

from ..base import DastResult, HEADERS, TIMEOUT, safe_get, safe_request, USER_AGENTS

logger = logging.getLogger(__name__)

_COMMON_JWT_SECRETS = [
    "secret", "password", "123456", "admin", "test", "key",
    "jwt_secret", "changeme", "supersecret", "your-256-bit-secret",
]


def _decode_jwt_part(part: str) -> dict | None:
    padded = part + "=" * (4 - len(part) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(padded))
    except Exception:
        return None


def _sign_hs256(header_b64: str, payload_b64: str, secret: str) -> str:
    signing_input = f"{header_b64}.{payload_b64}".encode()
    sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(sig).rstrip(b"=").decode()


def _extract_jwt_from_response(resp: httpx.Response) -> str | None:
    for header in ("authorization", "set-cookie", "x-auth-token", "x-access-token"):
        val = resp.headers.get(header, "")
        for token in re.findall(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', val):
            return token
    body = (resp.text or "")[:5000]
    tokens = re.findall(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', body)
    return tokens[0] if tokens else None


# ─── JWT Security ───────────────────────────────────────────

def check_jwt_security(target_url: str) -> DastResult:
    """JWT security analysis: algorithm confusion, weak secrets, missing claims, exposure in URL."""
    result = DastResult(
        check_id="DAST-JWT-01",
        title="JWT Security Analysis",
        owasp_ref="A07:2021",
        cwe_id="CWE-347",
    )

    issues = []
    jwt_token = None

    resp = safe_get(target_url)
    if resp:
        jwt_token = _extract_jwt_from_response(resp)

    if not jwt_token:
        for path in ["/login", "/auth/login", "/api/auth", "/api/login", "/api/v1/auth/login"]:
            try:
                r = safe_get(f"{target_url.rstrip('/')}{path}")
                if r:
                    jwt_token = _extract_jwt_from_response(r)
                    if jwt_token:
                        break
            except Exception:
                pass

    parsed_url = urlparse(target_url)
    query_params = parse_qs(parsed_url.query)
    for key, values in query_params.items():
        for v in values:
            if re.match(r'^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$', v):
                issues.append({"type": "jwt_in_url", "severity": "high", "detail": f"JWT token exposed in URL parameter '{key}'"})
                jwt_token = jwt_token or v

    if not jwt_token:
        result.status = "passed"
        result.description = "No JWT tokens found in responses or URLs"
        return result

    parts = jwt_token.split(".")
    if len(parts) != 3:
        result.status = "passed"
        result.description = "Token found but not a valid JWT format"
        return result

    header = _decode_jwt_part(parts[0])
    payload = _decode_jwt_part(parts[1])

    if header:
        alg = header.get("alg", "").upper()
        if alg == "NONE" or alg == "":
            issues.append({"type": "alg_none", "severity": "critical", "detail": "JWT uses alg:none — signature bypass possible"})
        if alg in ("HS256", "HS384", "HS512"):
            for secret in _COMMON_JWT_SECRETS:
                try:
                    computed = _sign_hs256(parts[0], parts[1], secret)
                    if computed == parts[2]:
                        issues.append({"type": "weak_secret", "severity": "critical", "detail": f"JWT signed with weak secret: '{secret}'"})
                        break
                except Exception:
                    pass

    if payload:
        if "exp" not in payload:
            issues.append({"type": "missing_exp", "severity": "medium", "detail": "JWT missing 'exp' claim — token never expires"})
        if "iat" not in payload:
            issues.append({"type": "missing_iat", "severity": "low", "detail": "JWT missing 'iat' (issued-at) claim"})
        if "nbf" not in payload and "exp" in payload:
            pass
        exp = payload.get("exp")
        if isinstance(exp, (int, float)):
            now = time.time()
            if exp > now + 86400 * 365:
                issues.append({"type": "long_expiry", "severity": "medium", "detail": f"JWT expiry is more than 1 year from now"})

    if issues:
        result.status = "failed"
        max_sev = "low"
        for i in issues:
            if i["severity"] == "critical":
                max_sev = "critical"
            elif i["severity"] == "high" and max_sev != "critical":
                max_sev = "high"
            elif i["severity"] == "medium" and max_sev not in ("critical", "high"):
                max_sev = "medium"
        result.severity = max_sev
        result.description = f"Found {len(issues)} JWT security issue(s)"
        result.evidence = "; ".join(i["detail"] for i in issues)
        result.details = {"issues": issues, "header": header, "payload_claims": list((payload or {}).keys())}
        result.remediation = "Use strong JWT secrets (256+ bit random), set short expiry, use RS256, never expose tokens in URLs"
        result.reproduction_steps = "1. Extract JWT from response headers/body\n2. Decode and analyze header/payload\n3. Test for algorithm confusion and weak secrets"
    else:
        result.status = "passed"
        result.description = "JWT token found with acceptable security configuration"

    return result


# ─── CSRF Detection ──────────────────────────────────────────

def check_csrf_protection(target_url: str) -> DastResult:
    """CSRF protection: check POST forms for anti-CSRF tokens."""
    result = DastResult(
        check_id="DAST-CSRF-01",
        title="CSRF Protection",
        owasp_ref="A01:2021",
        cwe_id="CWE-352",
    )

    resp = safe_get(target_url)
    if not resp:
        result.status = "error"
        result.description = "Could not reach target"
        return result

    csrf_token_names = {
        "csrf_token", "csrfmiddlewaretoken", "_csrf", "csrf", "authenticity_token",
        "_token", "anti-csrf-token", "x-csrf-token", "__requestverificationtoken",
        "xsrf_token", "_xsrf",
    }

    pages_to_check = [target_url]
    for path in ["/login", "/register", "/signup", "/contact", "/settings", "/profile", "/account"]:
        pages_to_check.append(f"{target_url.rstrip('/')}{path}")

    vulnerable_forms = []
    checked = 0

    for page_url in pages_to_check[:5]:
        try:
            r = safe_get(page_url)
            if not r or r.status_code >= 400:
                continue
            html = r.text or ""
            if "text/html" not in r.headers.get("content-type", ""):
                continue

            forms = re.findall(r'<form[^>]*method\s*=\s*["\']?post[^>]*>(.*?)</form>', html, re.IGNORECASE | re.DOTALL)
            for form_html in forms:
                checked += 1
                input_names = set(re.findall(r'name\s*=\s*["\']([^"\']+)', form_html, re.IGNORECASE))
                has_csrf = bool(input_names & csrf_token_names)
                has_csrf_meta = bool(re.search(r'<meta[^>]*csrf', html, re.IGNORECASE))
                if not has_csrf and not has_csrf_meta:
                    action = re.search(r'action\s*=\s*["\']([^"\']+)', form_html)
                    vulnerable_forms.append({
                        "page": page_url,
                        "action": action.group(1) if action else "(self)",
                        "inputs": list(input_names)[:10],
                    })
        except Exception:
            continue

    samesite = "unknown"
    if resp.headers.get("set-cookie"):
        cookies_str = resp.headers.get("set-cookie", "").lower()
        if "samesite=strict" in cookies_str:
            samesite = "strict"
        elif "samesite=lax" in cookies_str:
            samesite = "lax"
        elif "samesite=none" in cookies_str:
            samesite = "none"

    result.details = {"forms_checked": checked, "vulnerable_forms": vulnerable_forms, "samesite": samesite}

    if vulnerable_forms:
        result.status = "failed"
        result.severity = "high"
        result.description = f"Found {len(vulnerable_forms)} POST form(s) without CSRF token"
        result.evidence = "; ".join(f"{f['page']} → {f['action']}" for f in vulnerable_forms[:5])
        result.remediation = "Add anti-CSRF tokens to all state-changing forms. Use SameSite=Strict cookies."
        result.reproduction_steps = "1. Visit each page with POST forms\n2. Check for hidden CSRF token inputs\n3. Submit form without token to confirm vulnerability"
    else:
        result.status = "passed"
        result.description = f"CSRF protection adequate ({checked} form(s) checked, SameSite: {samesite})"

    return result


# ─── CSP Deep Analysis ───────────────────────────────────────

def check_csp_deep(target_url: str) -> DastResult:
    """Content Security Policy deep analysis: unsafe-inline, unsafe-eval, wildcards, missing directives."""
    result = DastResult(
        check_id="DAST-CSP-01",
        title="Content Security Policy Analysis",
        owasp_ref="A05:2021",
        cwe_id="CWE-693",
    )

    resp = safe_get(target_url)
    if not resp:
        result.status = "error"
        result.description = "Could not reach target"
        return result

    csp = resp.headers.get("content-security-policy", "")
    csp_ro = resp.headers.get("content-security-policy-report-only", "")
    effective_csp = csp or csp_ro

    if not effective_csp:
        result.status = "failed"
        result.severity = "high"
        result.description = "No Content-Security-Policy header found"
        result.remediation = "Implement a strict CSP. Start with: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;"
        return result

    issues = []
    directives = {}
    for part in effective_csp.split(";"):
        part = part.strip()
        if not part:
            continue
        tokens = part.split()
        if tokens:
            directives[tokens[0].lower()] = tokens[1:] if len(tokens) > 1 else []

    script_src = directives.get("script-src", directives.get("default-src", []))

    if "'unsafe-inline'" in script_src:
        issues.append({"type": "unsafe_inline", "severity": "high", "detail": "script-src allows 'unsafe-inline' — XSS via inline scripts"})
    if "'unsafe-eval'" in script_src:
        issues.append({"type": "unsafe_eval", "severity": "high", "detail": "script-src allows 'unsafe-eval' — XSS via eval()"})
    if "*" in script_src:
        issues.append({"type": "wildcard_script", "severity": "critical", "detail": "script-src contains wildcard '*' — any domain can inject scripts"})
    if "data:" in script_src:
        issues.append({"type": "data_uri", "severity": "high", "detail": "script-src allows data: URIs — XSS via data:text/html"})
    if "http:" in " ".join(script_src):
        issues.append({"type": "http_scheme", "severity": "medium", "detail": "script-src allows HTTP scheme — MITM can inject scripts"})

    if "object-src" not in directives and "default-src" not in directives:
        issues.append({"type": "missing_object_src", "severity": "medium", "detail": "No object-src directive — Flash/plugin injection possible"})
    elif "object-src" in directives and "'none'" not in directives["object-src"]:
        issues.append({"type": "permissive_object_src", "severity": "medium", "detail": "object-src is not 'none'"})

    if "base-uri" not in directives:
        issues.append({"type": "missing_base_uri", "severity": "medium", "detail": "No base-uri directive — base tag injection possible"})

    if "frame-ancestors" not in directives:
        issues.append({"type": "missing_frame_ancestors", "severity": "low", "detail": "No frame-ancestors — clickjacking via CSP not addressed"})

    if csp_ro and not csp:
        issues.append({"type": "report_only", "severity": "medium", "detail": "CSP is report-only — not enforced"})

    result.details = {"directives": directives, "issues": issues, "raw_csp": effective_csp[:500]}

    if issues:
        result.status = "failed"
        max_sev = max(({"critical": 4, "high": 3, "medium": 2, "low": 1}.get(i["severity"], 0) for i in issues), default=0)
        result.severity = {4: "critical", 3: "high", 2: "medium", 1: "low"}.get(max_sev, "medium")
        result.description = f"CSP has {len(issues)} weakness(es)"
        result.evidence = "; ".join(i["detail"] for i in issues[:5])
        result.remediation = "Remove 'unsafe-inline' and 'unsafe-eval' from script-src. Add object-src 'none', base-uri 'self', frame-ancestors 'self'."
    else:
        result.status = "passed"
        result.description = "CSP is properly configured"

    return result


# ─── Path Traversal / LFI ───────────────────────────────────

def check_path_traversal(target_url: str) -> DastResult:
    """Path traversal / LFI: test file inclusion parameters for directory traversal."""
    result = DastResult(
        check_id="DAST-LFI-01",
        title="Path Traversal / Local File Inclusion",
        owasp_ref="A01:2021",
        cwe_id="CWE-22",
    )

    lfi_params = ["file", "path", "page", "include", "doc", "document", "folder", "root",
                  "pg", "style", "pdf", "template", "php_path", "name", "cat", "dir", "action",
                  "board", "date", "detail", "download", "prefix", "include_path", "url", "img", "filename"]

    lfi_payloads = [
        ("../../../etc/passwd", [b"root:", b"nobody:", b"/bin/", b"/sbin/"]),
        ("....//....//....//etc/passwd", [b"root:", b"nobody:"]),
        ("..%2f..%2f..%2fetc%2fpasswd", [b"root:", b"nobody:"]),
        ("..\\..\\..\\windows\\win.ini", [b"[fonts]", b"[extensions]"]),
        ("/etc/passwd", [b"root:", b"nobody:"]),
    ]

    parsed = urlparse(target_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    vulnerable = []

    for param in lfi_params[:10]:
        for payload, indicators in lfi_payloads[:3]:
            test_url = f"{base}/?{param}={payload}"
            try:
                with httpx.Client(timeout=httpx.Timeout(10.0), headers=HEADERS, verify=False, follow_redirects=True) as client:
                    r = client.get(test_url)
                    if r.status_code == 200:
                        content = r.content
                        for indicator in indicators:
                            if indicator in content:
                                vulnerable.append({"param": param, "payload": payload, "indicator": indicator.decode()})
                                break
            except Exception:
                pass
            if vulnerable:
                break
        if vulnerable:
            break

    result.details = {"params_tested": min(len(lfi_params), 10), "payloads_tested": len(lfi_payloads)}

    if vulnerable:
        result.status = "failed"
        result.severity = "critical"
        result.description = f"Path traversal vulnerability found via '{vulnerable[0]['param']}' parameter"
        result.evidence = f"Payload: {vulnerable[0]['payload']} → found '{vulnerable[0]['indicator']}' in response"
        result.remediation = "Never use user input for file paths. Use allowlists for permitted files. Sanitize path separators."
        result.reproduction_steps = f"1. GET {base}/?{vulnerable[0]['param']}={vulnerable[0]['payload']}\n2. Check response for file content"
    else:
        result.status = "passed"
        result.description = "No path traversal vulnerabilities detected"

    return result


# ─── SSRF Detection ──────────────────────────────────────────

def check_ssrf(target_url: str) -> DastResult:
    """SSRF: test URL parameters for internal network access."""
    result = DastResult(
        check_id="DAST-SSRF-01",
        title="Server-Side Request Forgery (SSRF)",
        owasp_ref="A10:2021",
        cwe_id="CWE-918",
    )

    ssrf_params = ["url", "uri", "link", "src", "source", "redirect", "target", "dest",
                   "destination", "rurl", "return_url", "next", "callback", "feed", "fetch", "proxy", "request"]

    ssrf_payloads = [
        ("http://169.254.169.254/latest/meta-data/", ["ami-id", "instance-id", "hostname", "local-ipv4"]),
        ("http://127.0.0.1:22/", ["SSH", "OpenSSH"]),
        ("http://[::1]/", []),
        ("http://0177.0.0.1/", []),
        ("http://localhost/server-status", ["Apache", "Server", "Total"]),
    ]

    parsed = urlparse(target_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    vulnerable = []

    for param in ssrf_params[:8]:
        for payload, indicators in ssrf_payloads[:3]:
            test_url = f"{base}/?{param}={payload}"
            try:
                with httpx.Client(timeout=httpx.Timeout(8.0), headers=HEADERS, verify=False, follow_redirects=False) as client:
                    r = client.get(test_url)
                    if r.status_code == 200:
                        body = r.text or ""
                        for ind in indicators:
                            if ind.lower() in body.lower():
                                vulnerable.append({"param": param, "payload": payload, "indicator": ind})
                                break
            except Exception:
                pass
            if vulnerable:
                break
        if vulnerable:
            break

    if vulnerable:
        result.status = "failed"
        result.severity = "critical"
        result.description = f"SSRF vulnerability found via '{vulnerable[0]['param']}' parameter"
        result.evidence = f"Payload: {vulnerable[0]['payload']} → internal content leaked"
        result.remediation = "Block requests to internal IPs (169.254.x, 127.x, 10.x, 172.16-31.x, 192.168.x). Use allowlists for permitted domains."
    else:
        result.status = "passed"
        result.description = "No SSRF vulnerabilities detected"

    return result


# ─── Command Injection ──────────────────────────────────────

def check_command_injection(target_url: str) -> DastResult:
    """Command injection: test parameters for OS command execution."""
    result = DastResult(
        check_id="DAST-CMDI-01",
        title="OS Command Injection",
        owasp_ref="A03:2021",
        cwe_id="CWE-78",
    )

    cmd_params = ["cmd", "exec", "command", "execute", "ping", "query", "jump", "code",
                  "reg", "do", "func", "arg", "option", "load", "process", "step", "read", "ip", "host"]

    time_payloads = [
        (";sleep 5", 5),
        ("|sleep 5", 5),
        ("$(sleep 5)", 5),
        ("`sleep 5`", 5),
    ]

    id_payloads = [
        (";id", [b"uid=", b"gid="]),
        ("|id", [b"uid=", b"gid="]),
        ("$(id)", [b"uid=", b"gid="]),
        (";cat /etc/hostname", []),
    ]

    parsed = urlparse(target_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    vulnerable = []

    for param in cmd_params[:6]:
        for payload, indicators in id_payloads[:2]:
            test_url = f"{base}/?{param}=test{payload}"
            try:
                with httpx.Client(timeout=httpx.Timeout(10.0), headers=HEADERS, verify=False, follow_redirects=True) as client:
                    r = client.get(test_url)
                    if r.status_code == 200:
                        for ind in indicators:
                            if ind in r.content:
                                vulnerable.append({"param": param, "payload": payload, "method": "output"})
                                break
            except Exception:
                pass
            if vulnerable:
                break

        if not vulnerable:
            for payload, delay in time_payloads[:2]:
                test_url = f"{base}/?{param}=test{payload}"
                try:
                    start = time.time()
                    with httpx.Client(timeout=httpx.Timeout(15.0), headers=HEADERS, verify=False, follow_redirects=True) as client:
                        r = client.get(test_url)
                    elapsed = time.time() - start
                    if elapsed >= delay - 1:
                        baseline_start = time.time()
                        with httpx.Client(timeout=httpx.Timeout(15.0), headers=HEADERS, verify=False, follow_redirects=True) as client:
                            client.get(f"{base}/?{param}=test")
                        baseline = time.time() - baseline_start
                        if elapsed > baseline + 3:
                            vulnerable.append({"param": param, "payload": payload, "method": "timing", "delay": round(elapsed, 2)})
                except Exception:
                    pass
                if vulnerable:
                    break
        if vulnerable:
            break

    if vulnerable:
        result.status = "failed"
        result.severity = "critical"
        result.description = f"Command injection via '{vulnerable[0]['param']}' ({vulnerable[0]['method']} detection)"
        result.evidence = f"Payload: {vulnerable[0]['payload']}"
        result.remediation = "Never pass user input to system commands. Use parameterized APIs. Sanitize special characters."
    else:
        result.status = "passed"
        result.description = "No command injection vulnerabilities detected"

    return result


# ─── CORS Deep Checks ────────────────────────────────────────

def check_cors_deep(target_url: str) -> DastResult:
    """Deep CORS misconfiguration: null origin, regex bypass, credential reflection."""
    result = DastResult(
        check_id="DAST-CORS-02",
        title="CORS Advanced Misconfiguration",
        owasp_ref="A01:2021",
        cwe_id="CWE-942",
    )

    issues = []
    parsed = urlparse(target_url)
    domain = parsed.netloc

    test_origins = [
        ("null", "null origin"),
        (f"https://evil-{domain}", "subdomain-prefix bypass"),
        (f"https://{domain}.evil.com", "suffix bypass"),
        (f"https://{domain}%60.evil.com", "backtick bypass"),
    ]

    for origin, desc in test_origins:
        try:
            with httpx.Client(timeout=httpx.Timeout(10.0), headers={**HEADERS, "Origin": origin}, verify=False, follow_redirects=True) as client:
                r = client.get(target_url)
                acao = r.headers.get("access-control-allow-origin", "")
                acac = r.headers.get("access-control-allow-credentials", "")
                if acao == origin or (acao == "null" and origin == "null"):
                    sev = "critical" if acac.lower() == "true" else "high"
                    issues.append({"origin": origin, "reflected": acao, "credentials": acac, "type": desc, "severity": sev})
        except Exception:
            pass

    if issues:
        result.status = "failed"
        max_sev = "high"
        if any(i["severity"] == "critical" for i in issues):
            max_sev = "critical"
        result.severity = max_sev
        result.description = f"CORS misconfiguration: {len(issues)} bypass(es) found"
        result.evidence = "; ".join(f"{i['type']}: Origin={i['origin']} reflected with credentials={i['credentials']}" for i in issues[:3])
        result.remediation = "Use strict origin allowlists. Never reflect arbitrary origins. Never allow credentials with wildcards."
    else:
        result.status = "passed"
        result.description = "CORS configuration is robust against bypass attempts"

    return result


# ─── HTTP Request Smuggling ──────────────────────────────────

def check_http_smuggling(target_url: str) -> DastResult:
    """HTTP request smuggling: CL.TE and TE.CL probe."""
    result = DastResult(
        check_id="DAST-SMUGGLE-01",
        title="HTTP Request Smuggling Probe",
        owasp_ref="A05:2021",
        cwe_id="CWE-444",
    )

    issues = []
    parsed = urlparse(target_url)

    try:
        import socket, ssl as ssl_mod

        host = parsed.netloc.split(":")[0]
        port = int(parsed.netloc.split(":")[1]) if ":" in parsed.netloc else (443 if parsed.scheme == "https" else 80)

        cl_te_payload = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Length: 6\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"0\r\n"
            f"\r\n"
            f"G"
        )

        try:
            sock = socket.create_connection((host, port), timeout=10)
            if parsed.scheme == "https":
                ctx = ssl_mod.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl_mod.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=host)

            sock.sendall(cl_te_payload.encode())
            sock.settimeout(5)
            try:
                resp_data = sock.recv(4096)
                resp_str = resp_data.decode("utf-8", errors="ignore")
                if "HTTP/1.1 400" in resp_str or "Bad Request" in resp_str:
                    pass
                elif "HTTP/1.1 200" in resp_str or "HTTP/1.1 302" in resp_str:
                    issues.append({"type": "CL.TE", "severity": "high", "detail": "Server may be vulnerable to CL.TE smuggling"})
            except socket.timeout:
                issues.append({"type": "CL.TE_timeout", "severity": "medium", "detail": "CL.TE probe caused timeout — possible desync"})
            finally:
                sock.close()
        except Exception as e:
            logger.debug("Smuggling probe failed: %s", e)

    except Exception as e:
        logger.debug("Smuggling check error: %s", e)

    if issues:
        result.status = "failed"
        result.severity = issues[0]["severity"]
        result.description = f"HTTP request smuggling: {issues[0]['detail']}"
        result.evidence = "; ".join(i["detail"] for i in issues)
        result.remediation = "Normalize Content-Length and Transfer-Encoding handling. Use HTTP/2 where possible. Configure reverse proxy to reject ambiguous requests."
    else:
        result.status = "passed"
        result.description = "No HTTP request smuggling indicators detected"

    return result
