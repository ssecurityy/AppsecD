"""DAST checks: modern OWASP 2021-2025 — deserialization, SSRF advanced, BAC, mass assignment, API misconfig, SSTI, prototype pollution, DNS rebinding, cache poisoning, CORS null origin."""
from ..base import DastResult, HEADERS, TIMEOUT, safe_get, safe_request, USER_AGENTS
import httpx, logging, re, json, time
from urllib.parse import urlparse, urljoin

logger = logging.getLogger(__name__)


# ─── Insecure Deserialization ────────────────────────────────

def check_insecure_deserialization(target_url: str) -> DastResult:
    """Check for Java/PHP/Python deserialization markers in responses and cookies."""
    result = DastResult(
        check_id="DAST-DESER-01",
        title="Insecure Deserialization Detection",
        owasp_ref="A08:2021",
        cwe_id="CWE-502",
    )

    java_markers = ["rO0AB", "aced0005"]
    php_markers = ["O:4:", "O:8:", "O:6:", "a:2:", "s:4:"]
    python_markers = ["pickle", "__reduce__", "cos\nsystem", "cposix", "__builtin__"]

    findings = []
    parsed = urlparse(target_url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    pages_to_check = [
        target_url,
        f"{base}/api/session",
        f"{base}/api/user",
        f"{base}/login",
        f"{base}/api/data",
    ]

    for page_url in pages_to_check:
        try:
            with httpx.Client(timeout=TIMEOUT, headers=HEADERS, verify=False, follow_redirects=True) as client:
                resp = client.get(page_url)
                if resp.status_code >= 500:
                    continue

                # Check cookies for serialized data
                for cookie_name, cookie_value in resp.cookies.items():
                    for marker in java_markers:
                        if marker in cookie_value:
                            findings.append({"type": "java_serialized_cookie", "location": f"Cookie: {cookie_name}", "marker": marker, "url": page_url})
                    for marker in php_markers:
                        if marker in cookie_value:
                            findings.append({"type": "php_serialized_cookie", "location": f"Cookie: {cookie_name}", "marker": marker, "url": page_url})

                # Check Set-Cookie headers
                set_cookie = resp.headers.get("set-cookie", "")
                for marker in java_markers + php_markers:
                    if marker in set_cookie:
                        findings.append({"type": "serialized_set_cookie", "location": "Set-Cookie header", "marker": marker, "url": page_url})

                # Check response body
                body = (resp.text or "")[:10000]
                for marker in java_markers:
                    if marker in body:
                        findings.append({"type": "java_serialized_body", "location": "Response body", "marker": marker, "url": page_url})
                for marker in python_markers:
                    if marker in body:
                        findings.append({"type": "python_serialized_body", "location": "Response body", "marker": marker, "url": page_url})

                # Check Content-Type for serialization formats
                ct = resp.headers.get("content-type", "")
                if "application/x-java-serialized-object" in ct:
                    findings.append({"type": "java_content_type", "location": "Content-Type header", "marker": ct, "url": page_url})

        except Exception:
            continue

    result.details = {"pages_checked": len(pages_to_check), "findings": findings[:10]}

    if findings:
        result.status = "failed"
        result.severity = "high"
        result.description = f"Insecure deserialization markers found in {len(findings)} location(s)"
        result.evidence = "; ".join(f"{f['type']} at {f['location']} ({f['marker']})" for f in findings[:5])
        result.remediation = "Avoid deserializing untrusted data. Use safe serialization formats (JSON). Implement integrity checks on serialized objects. Use allowlists for deserialization classes."
        result.reproduction_steps = f"1. GET {findings[0]['url']}\n2. Inspect cookies and response body for serialization markers\n3. Found: {findings[0]['marker']}"
    else:
        result.status = "passed"
        result.description = "No insecure deserialization markers detected"

    return result


# ─── SSRF Advanced ───────────────────────────────────────────

def check_ssrf_advanced(target_url: str) -> DastResult:
    """Advanced SSRF: DNS rebinding, cloud metadata (AWS/GCP/Azure), URL parameter injection."""
    result = DastResult(
        check_id="DAST-SSRF-02",
        title="Advanced SSRF Detection (Cloud Metadata)",
        owasp_ref="A10:2021",
        cwe_id="CWE-918",
    )

    ssrf_params = ["url", "redirect", "proxy", "fetch", "src", "dest", "uri", "link"]

    cloud_payloads = [
        ("http://169.254.169.254/latest/meta-data/", ["ami-id", "instance-id", "hostname", "iam"]),
        ("http://metadata.google.internal/computeMetadata/v1/", ["project", "instance", "attributes"]),
        ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", ["compute", "network", "vmId"]),
    ]

    dns_rebinding_payloads = [
        ("http://127.0.0.1/", []),
        ("http://0x7f000001/", []),
        ("http://2130706433/", []),
        ("http://[::ffff:127.0.0.1]/", []),
        ("http://0177.0.0.1/", []),
    ]

    parsed = urlparse(target_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    vulnerable = []

    # Test cloud metadata endpoints via URL params
    for param in ssrf_params:
        for payload, indicators in cloud_payloads:
            test_url = f"{base}/?{param}={payload}"
            try:
                with httpx.Client(timeout=httpx.Timeout(8.0), headers=HEADERS, verify=False, follow_redirects=False) as client:
                    r = client.get(test_url)
                    if r.status_code == 200:
                        body = (r.text or "").lower()
                        for ind in indicators:
                            if ind.lower() in body:
                                vulnerable.append({"param": param, "payload": payload, "indicator": ind, "type": "cloud_metadata"})
                                break
            except Exception:
                pass
            if vulnerable:
                break
        if vulnerable:
            break

    # Test DNS rebinding / internal IP access
    if not vulnerable:
        for param in ssrf_params[:4]:
            for payload, _ in dns_rebinding_payloads:
                test_url = f"{base}/?{param}={payload}"
                try:
                    with httpx.Client(timeout=httpx.Timeout(8.0), headers=HEADERS, verify=False, follow_redirects=False) as client:
                        r = client.get(test_url)
                        if r.status_code == 200 and len(r.text or "") > 0:
                            body = (r.text or "").lower()
                            if any(kw in body for kw in ["root:", "localhost", "127.0.0.1", "server", "apache", "nginx"]):
                                vulnerable.append({"param": param, "payload": payload, "type": "dns_rebinding"})
                                break
                except Exception:
                    pass
            if vulnerable:
                break

    result.details = {"params_tested": ssrf_params, "cloud_payloads": len(cloud_payloads), "dns_payloads": len(dns_rebinding_payloads), "findings": vulnerable[:5]}

    if vulnerable:
        result.status = "failed"
        result.severity = "critical"
        vuln = vulnerable[0]
        result.description = f"Advanced SSRF via '{vuln['param']}' parameter ({vuln['type']})"
        result.evidence = f"Payload: {vuln['payload']} → internal content leaked"
        result.remediation = "Block requests to internal IPs and cloud metadata endpoints. Use allowlists for outbound requests. Disable HTTP redirects in server-side requests."
        result.reproduction_steps = f"1. GET {base}/?{vuln['param']}={vuln['payload']}\n2. Check response for internal/cloud data"
    else:
        result.status = "passed"
        result.description = "No advanced SSRF vulnerabilities detected"

    return result


# ─── Broken Access Control ───────────────────────────────────

def check_broken_access_control(target_url: str) -> DastResult:
    """Test IDOR via UUID manipulation and unauthorized admin access."""
    result = DastResult(
        check_id="DAST-BAC-01",
        title="Broken Access Control (IDOR/Admin Access)",
        owasp_ref="A01:2021",
        cwe_id="CWE-639",
    )

    parsed = urlparse(target_url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    idor_paths = [
        "/api/users/1",
        "/api/users/2",
        "/api/users/100",
        "/api/user/1",
        "/api/user/2",
        "/api/accounts/1",
        "/api/orders/1",
        "/api/invoices/1",
    ]

    admin_paths = [
        "/admin",
        "/api/admin",
        "/api/admin/users",
        "/admin/dashboard",
        "/api/v1/admin",
        "/management",
        "/internal/api",
    ]

    idor_findings = []
    admin_findings = []

    # Test IDOR endpoints
    for path in idor_paths:
        test_url = f"{base}{path}"
        try:
            with httpx.Client(timeout=TIMEOUT, headers=HEADERS, verify=False, follow_redirects=True) as client:
                r = client.get(test_url)
                if r.status_code == 200:
                    body = (r.text or "").lower()
                    ct = r.headers.get("content-type", "")
                    if "application/json" in ct or "email" in body or "username" in body or "password" in body:
                        idor_findings.append({"path": path, "status": r.status_code, "content_type": ct})
        except Exception:
            continue

    # Test admin access without authentication
    for path in admin_paths:
        test_url = f"{base}{path}"
        try:
            with httpx.Client(timeout=TIMEOUT, headers=HEADERS, verify=False, follow_redirects=True) as client:
                r = client.get(test_url)
                if r.status_code == 200:
                    body = (r.text or "").lower()
                    if any(kw in body for kw in ["dashboard", "admin panel", "management", "configuration", "users list", "settings"]):
                        admin_findings.append({"path": path, "status": r.status_code})
        except Exception:
            continue

    result.details = {"idor_paths_tested": len(idor_paths), "admin_paths_tested": len(admin_paths), "idor_findings": idor_findings[:5], "admin_findings": admin_findings[:5]}

    if idor_findings or admin_findings:
        result.status = "failed"
        issues = []
        if idor_findings:
            issues.append(f"IDOR: {len(idor_findings)} endpoint(s) return user data without auth")
            result.severity = "high"
        if admin_findings:
            issues.append(f"Admin access: {len(admin_findings)} admin endpoint(s) accessible without auth")
            result.severity = "critical"
        result.description = "; ".join(issues)
        evidence_parts = []
        for f in idor_findings[:3]:
            evidence_parts.append(f"IDOR: {f['path']} returned {f['status']}")
        for f in admin_findings[:3]:
            evidence_parts.append(f"Admin: {f['path']} returned {f['status']}")
        result.evidence = "; ".join(evidence_parts)
        result.remediation = "Implement proper authorization checks on all endpoints. Use indirect object references. Validate user permissions server-side for every request."
        result.reproduction_steps = "1. Access API endpoints without authentication\n2. Try accessing other users' data by changing IDs\n3. Try accessing admin endpoints directly"
    else:
        result.status = "passed"
        result.description = "No broken access control issues detected"

    return result


# ─── Mass Assignment ─────────────────────────────────────────

def check_mass_assignment(target_url: str) -> DastResult:
    """Send extra fields (is_admin, role, admin) in POST/PUT to detect mass assignment."""
    result = DastResult(
        check_id="DAST-MASS-01",
        title="Mass Assignment Vulnerability",
        owasp_ref="A04:2021",
        cwe_id="CWE-915",
    )

    parsed = urlparse(target_url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    endpoints = [
        "/api/users",
        "/api/profile",
        "/api/account",
        "/api/user",
        "/api/settings",
        "/api/register",
        "/api/signup",
    ]

    malicious_fields = {
        "is_admin": True,
        "role": "admin",
        "admin": 1,
        "verified": True,
        "is_superuser": True,
        "permissions": "all",
        "user_type": "administrator",
    }

    findings = []

    for endpoint in endpoints:
        test_url = f"{base}{endpoint}"
        for method in ["POST", "PUT"]:
            try:
                payload = {"username": "testuser", "email": "test@test.com"}
                payload.update(malicious_fields)
                with httpx.Client(timeout=TIMEOUT, headers={**HEADERS, "Content-Type": "application/json"}, verify=False, follow_redirects=True) as client:
                    r = client.request(method, test_url, json=payload)
                    if r.status_code in (200, 201, 204):
                        body = (r.text or "").lower()
                        try:
                            resp_json = r.json()
                            for field in ["is_admin", "role", "admin", "verified", "is_superuser", "permissions", "user_type"]:
                                if field in resp_json:
                                    val = resp_json[field]
                                    if val in (True, "admin", 1, "all", "administrator", "true"):
                                        findings.append({"endpoint": endpoint, "method": method, "field": field, "value": val})
                        except Exception:
                            for field in ["is_admin", "role", "admin", "is_superuser"]:
                                if f'"{field}"' in body and ("true" in body or '"admin"' in body):
                                    findings.append({"endpoint": endpoint, "method": method, "field": field, "value": "reflected"})
            except Exception:
                continue

    result.details = {"endpoints_tested": len(endpoints), "malicious_fields": list(malicious_fields.keys()), "findings": findings[:10]}

    if findings:
        result.status = "failed"
        result.severity = "high"
        result.description = f"Mass assignment vulnerability: {len(findings)} field(s) accepted"
        result.evidence = "; ".join(f"{f['method']} {f['endpoint']} accepted {f['field']}={f['value']}" for f in findings[:5])
        result.remediation = "Use allowlists for accepted fields. Never bind request data directly to models. Implement DTOs with explicit field definitions."
        result.reproduction_steps = f"1. {findings[0]['method']} {base}{findings[0]['endpoint']} with extra fields (is_admin, role, etc.)\n2. Check if privileged fields are accepted and reflected"
    else:
        result.status = "passed"
        result.description = "No mass assignment vulnerabilities detected"

    return result


# ─── API Security Misconfiguration ───────────────────────────

def check_api_security_misconfiguration(target_url: str) -> DastResult:
    """Check GraphQL introspection, REST excessive data, Swagger/OpenAPI exposure."""
    result = DastResult(
        check_id="DAST-APIMISC-01",
        title="API Security Misconfiguration",
        owasp_ref="A05:2021",
        cwe_id="CWE-16",
    )

    parsed = urlparse(target_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    issues = []

    # Check GraphQL introspection
    graphql_paths = ["/graphql", "/api/graphql", "/graphql/console", "/v1/graphql"]
    introspection_query = '{"query":"{ __schema { types { name } } }"}'
    for gql_path in graphql_paths:
        try:
            with httpx.Client(timeout=TIMEOUT, headers={**HEADERS, "Content-Type": "application/json"}, verify=False, follow_redirects=True) as client:
                r = client.post(f"{base}{gql_path}", content=introspection_query)
                if r.status_code == 200:
                    body = r.text or ""
                    if "__schema" in body or "__type" in body:
                        issues.append({"type": "graphql_introspection", "path": gql_path, "severity": "medium"})
                        break
        except Exception:
            continue

    # Check Swagger/OpenAPI exposure
    swagger_paths = ["/swagger.json", "/openapi.json", "/api-docs", "/swagger-ui.html", "/swagger-ui/", "/v2/api-docs", "/v3/api-docs"]
    for sw_path in swagger_paths:
        try:
            with httpx.Client(timeout=TIMEOUT, headers=HEADERS, verify=False, follow_redirects=True) as client:
                r = client.get(f"{base}{sw_path}")
                if r.status_code == 200:
                    body = (r.text or "").lower()
                    if "swagger" in body or "openapi" in body or "paths" in body:
                        issues.append({"type": "swagger_exposed", "path": sw_path, "severity": "medium"})
                        break
        except Exception:
            continue

    # Check REST excessive data — large response sizes
    api_paths = ["/api/users", "/api/data", "/api/list", "/api/items", "/api/v1/users"]
    for api_path in api_paths:
        try:
            with httpx.Client(timeout=TIMEOUT, headers=HEADERS, verify=False, follow_redirects=True) as client:
                r = client.get(f"{base}{api_path}")
                if r.status_code == 200:
                    body_len = len(r.text or "")
                    if body_len > 50000:
                        issues.append({"type": "excessive_data", "path": api_path, "size_bytes": body_len, "severity": "low"})
                        break
        except Exception:
            continue

    result.details = {"graphql_paths_tested": len(graphql_paths), "swagger_paths_tested": len(swagger_paths), "issues": issues}

    if issues:
        result.status = "failed"
        max_sev = max(({"critical": 4, "high": 3, "medium": 2, "low": 1}.get(i["severity"], 0) for i in issues), default=0)
        result.severity = {4: "critical", 3: "high", 2: "medium", 1: "low"}.get(max_sev, "medium")
        result.description = f"API misconfiguration: {len(issues)} issue(s) found"
        result.evidence = "; ".join(f"{i['type']} at {i['path']}" for i in issues[:5])
        result.remediation = "Disable GraphQL introspection in production. Restrict API documentation access. Implement pagination and field filtering to prevent excessive data exposure."
    else:
        result.status = "passed"
        result.description = "No API security misconfigurations detected"

    return result


# ─── Server-Side Template Injection ──────────────────────────

def check_server_side_template_injection(target_url: str) -> DastResult:
    """Test parameters for SSTI with {{7*7}}, ${7*7}, <%=7*7%>, #{7*7}, {{config}}."""
    result = DastResult(
        check_id="DAST-SSTI-01",
        title="Server-Side Template Injection (SSTI)",
        owasp_ref="A03:2021",
        cwe_id="CWE-1336",
    )

    parsed = urlparse(target_url)
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}"

    ssti_payloads = [
        ("{{7*7}}", "49"),
        ("${7*7}", "49"),
        ("<%=7*7%>", "49"),
        ("#{7*7}", "49"),
        ("{{7*'7'}}", "7777777"),
        ("{{config}}", "SECRET_KEY"),
    ]

    test_params = ["q", "search", "name", "template", "page", "view", "msg", "message", "text", "input"]

    vulnerable = []

    for param in test_params:
        for payload, indicator in ssti_payloads[:4]:
            test_url = f"{base}?{param}={payload}"
            try:
                with httpx.Client(timeout=TIMEOUT, headers=HEADERS, verify=False, follow_redirects=True) as client:
                    r = client.get(test_url)
                    if r.status_code == 200:
                        body = r.text or ""
                        if indicator in body and payload not in body:
                            vulnerable.append({"param": param, "payload": payload, "indicator": indicator, "url": test_url})
                            break
            except Exception:
                continue
        if vulnerable:
            break

    # Test {{config}} for framework info leak
    if not vulnerable:
        for param in test_params[:5]:
            test_url = f"{base}?{param}={{{{config}}}}"
            try:
                with httpx.Client(timeout=TIMEOUT, headers=HEADERS, verify=False, follow_redirects=True) as client:
                    r = client.get(test_url)
                    if r.status_code == 200:
                        body = r.text or ""
                        if "SECRET_KEY" in body or "DEBUG" in body or "DATABASE" in body:
                            vulnerable.append({"param": param, "payload": "{{config}}", "indicator": "config object", "url": test_url})
                            break
            except Exception:
                continue

    result.details = {"params_tested": test_params, "payloads_tested": [p[0] for p in ssti_payloads], "findings": vulnerable[:5]}

    if vulnerable:
        result.status = "failed"
        result.severity = "critical"
        vuln = vulnerable[0]
        result.description = f"SSTI vulnerability via '{vuln['param']}' parameter"
        result.evidence = f"Payload: {vuln['payload']} → rendered as {vuln['indicator']}"
        result.remediation = "Never render user input in templates. Use sandboxed template engines. Validate and sanitize all template inputs."
        result.reproduction_steps = f"1. GET {vuln['url']}\n2. Check if template expression is evaluated (found '{vuln['indicator']}' in response)"
    else:
        result.status = "passed"
        result.description = "No server-side template injection detected"

    return result


# ─── Prototype Pollution ─────────────────────────────────────

def check_prototype_pollution(target_url: str) -> DastResult:
    """Test JSON bodies with __proto__ and constructor.prototype payloads."""
    result = DastResult(
        check_id="DAST-PROTO-01",
        title="Prototype Pollution Detection",
        owasp_ref="A03:2021",
        cwe_id="CWE-1321",
    )

    parsed = urlparse(target_url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    proto_payloads = [
        {"__proto__": {"polluted": "true", "isAdmin": True}},
        {"constructor": {"prototype": {"polluted": "true"}}},
        {"__proto__": {"status": 200, "role": "admin"}},
    ]

    api_endpoints = ["/api/users", "/api/data", "/api/settings", "/api/profile", "/api/update", "/api/config"]

    findings = []

    for endpoint in api_endpoints:
        test_url = f"{base}{endpoint}"
        for payload in proto_payloads:
            for method in ["POST", "PUT"]:
                try:
                    with httpx.Client(timeout=TIMEOUT, headers={**HEADERS, "Content-Type": "application/json"}, verify=False, follow_redirects=True) as client:
                        r = client.request(method, test_url, json=payload)
                        if r.status_code in (200, 201, 204):
                            body = r.text or ""
                            try:
                                resp_json = r.json()
                                if isinstance(resp_json, dict):
                                    if resp_json.get("polluted") == "true" or resp_json.get("isAdmin") is True:
                                        findings.append({"endpoint": endpoint, "method": method, "payload_type": "__proto__" if "__proto__" in payload else "constructor", "reflected": True})
                            except Exception:
                                if '"polluted"' in body or '"isAdmin"' in body:
                                    findings.append({"endpoint": endpoint, "method": method, "payload_type": "__proto__" if "__proto__" in payload else "constructor", "reflected": True})
                except Exception:
                    continue
            if findings:
                break
        if findings:
            break

    result.details = {"endpoints_tested": len(api_endpoints), "payloads_tested": len(proto_payloads), "findings": findings[:5]}

    if findings:
        result.status = "failed"
        result.severity = "high"
        f = findings[0]
        result.description = f"Prototype pollution via {f['method']} {f['endpoint']}"
        result.evidence = f"{f['payload_type']} payload accepted and reflected at {f['endpoint']}"
        result.remediation = "Sanitize JSON input to strip __proto__ and constructor keys. Use Object.create(null) for dictionaries. Freeze prototypes where possible."
        result.reproduction_steps = f"1. {f['method']} {base}{f['endpoint']} with __proto__ payload\n2. Check if polluted properties are reflected in response"
    else:
        result.status = "passed"
        result.description = "No prototype pollution vulnerabilities detected"

    return result


# ─── DNS Rebinding ───────────────────────────────────────────

def check_dns_rebinding(target_url: str) -> DastResult:
    """Check DNS rebinding protections via Host header manipulation."""
    result = DastResult(
        check_id="DAST-DNSREBIND-01",
        title="DNS Rebinding Protection",
        owasp_ref="A05:2021",
        cwe_id="CWE-350",
    )

    parsed = urlparse(target_url)
    original_host = parsed.netloc

    rebinding_hosts = [
        "127.0.0.1",
        "localhost",
        "0.0.0.0",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.1",
        "[::1]",
        "169.254.169.254",
    ]

    findings = []

    for host in rebinding_hosts:
        try:
            with httpx.Client(timeout=TIMEOUT, headers={**HEADERS, "Host": host}, verify=False, follow_redirects=False) as client:
                r = client.get(target_url)
                if r.status_code == 200:
                    body = (r.text or "")[:5000]
                    # Check if server accepted the spoofed Host without rejecting
                    original_resp = safe_get(target_url)
                    if original_resp and original_resp.status_code == 200:
                        orig_body = (original_resp.text or "")[:5000]
                        # If responses are similar, server is not validating Host header
                        if len(body) > 100 and abs(len(body) - len(orig_body)) < len(orig_body) * 0.3:
                            findings.append({"host": host, "status": r.status_code, "body_length": len(body)})
                elif r.status_code in (301, 302):
                    location = r.headers.get("location", "")
                    if host in location:
                        findings.append({"host": host, "status": r.status_code, "redirect": location[:200]})
        except Exception:
            continue

    result.details = {"original_host": original_host, "hosts_tested": rebinding_hosts, "findings": findings[:5]}

    if findings:
        result.status = "failed"
        result.severity = "medium"
        result.description = f"DNS rebinding: server accepts {len(findings)} spoofed Host header(s)"
        result.evidence = "; ".join(f"Host: {f['host']} → status {f['status']}" for f in findings[:3])
        result.remediation = "Validate the Host header against an allowlist. Reject requests with unexpected Host values. Use DNS pinning."
    else:
        result.status = "passed"
        result.description = "DNS rebinding protections are in place"

    return result


# ─── Web Cache Poisoning ─────────────────────────────────────

def check_cache_poisoning(target_url: str) -> DastResult:
    """Web cache poisoning via X-Forwarded-Host, X-Original-URL, X-Rewrite-URL headers."""
    result = DastResult(
        check_id="DAST-CACHEPOIS-01",
        title="Web Cache Poisoning Detection",
        owasp_ref="A05:2021",
        cwe_id="CWE-444",
    )

    parsed = urlparse(target_url)
    evil_domain = "evil-cache-poison.com"

    poison_headers = [
        ("X-Forwarded-Host", evil_domain),
        ("X-Original-URL", "/admin"),
        ("X-Rewrite-URL", "/admin"),
        ("X-Forwarded-Scheme", "nothttps"),
        ("X-Forwarded-Proto", "nothttps"),
        ("X-Host", evil_domain),
        ("X-Forwarded-Server", evil_domain),
    ]

    findings = []

    for header_name, header_value in poison_headers:
        try:
            cache_buster = f"?cachebust={int(time.time())}"
            test_url = f"{target_url.rstrip('/')}{cache_buster}"
            with httpx.Client(timeout=TIMEOUT, headers={**HEADERS, header_name: header_value}, verify=False, follow_redirects=False) as client:
                r = client.get(test_url)
                body = r.text or ""
                all_headers = dict(r.headers)

                # Check if header value is reflected in response
                if evil_domain in body:
                    findings.append({"header": header_name, "value": header_value, "reflected_in": "body", "severity": "high"})
                elif evil_domain in str(all_headers):
                    findings.append({"header": header_name, "value": header_value, "reflected_in": "headers", "severity": "high"})

                # Check if X-Original-URL / X-Rewrite-URL causes path override
                if header_name in ("X-Original-URL", "X-Rewrite-URL"):
                    if r.status_code == 200 and ("admin" in body.lower() or "dashboard" in body.lower()):
                        findings.append({"header": header_name, "value": header_value, "reflected_in": "path_override", "severity": "high"})

                # Check if Location header reflects poisoned host
                location = r.headers.get("location", "")
                if evil_domain in location:
                    findings.append({"header": header_name, "value": header_value, "reflected_in": "location", "severity": "high"})
        except Exception:
            continue

    result.details = {"headers_tested": [h[0] for h in poison_headers], "findings": findings[:10]}

    if findings:
        result.status = "failed"
        result.severity = "high"
        result.description = f"Web cache poisoning: {len(findings)} header(s) reflected in response"
        result.evidence = "; ".join(f"{f['header']}: {f['value']} reflected in {f['reflected_in']}" for f in findings[:5])
        result.remediation = "Do not use unkeyed headers in responses. Strip or ignore X-Forwarded-Host and similar headers. Configure cache to key on relevant headers."
        result.reproduction_steps = f"1. GET {target_url} with {findings[0]['header']}: {findings[0]['value']}\n2. Check if value is reflected in response {findings[0]['reflected_in']}"
    else:
        result.status = "passed"
        result.description = "No web cache poisoning vectors detected"

    return result


# ─── CORS Null Origin ────────────────────────────────────────

def check_cors_null_origin(target_url: str) -> DastResult:
    """CORS null origin + credentials response check."""
    result = DastResult(
        check_id="DAST-CORSNULL-01",
        title="CORS Null Origin Bypass",
        owasp_ref="A01:2021",
        cwe_id="CWE-942",
    )

    parsed = urlparse(target_url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    test_urls = [
        target_url,
        f"{base}/api/",
        f"{base}/api/users",
        f"{base}/api/data",
        f"{base}/api/v1/",
    ]

    findings = []

    for test_url_item in test_urls:
        try:
            with httpx.Client(timeout=TIMEOUT, headers={**HEADERS, "Origin": "null"}, verify=False, follow_redirects=True) as client:
                r = client.get(test_url_item)
                acao = r.headers.get("access-control-allow-origin", "")
                acac = r.headers.get("access-control-allow-credentials", "")

                if acao == "null":
                    if acac.lower() == "true":
                        findings.append({"url": test_url_item, "acao": acao, "acac": acac, "severity": "critical"})
                    else:
                        findings.append({"url": test_url_item, "acao": acao, "acac": acac, "severity": "high"})
        except Exception:
            continue

    result.details = {"urls_tested": test_urls, "findings": findings[:10]}
    result.request_raw = f"GET {target_url} HTTP/1.1\nHost: {parsed.netloc}\nOrigin: null"

    if findings:
        result.status = "failed"
        has_critical = any(f["severity"] == "critical" for f in findings)
        result.severity = "critical" if has_critical else "high"
        if has_critical:
            result.description = f"CORS null origin with credentials enabled — critical bypass on {len(findings)} endpoint(s)"
        else:
            result.description = f"CORS null origin reflected on {len(findings)} endpoint(s)"
        result.evidence = "; ".join(f"{f['url']}: ACAO={f['acao']}, ACAC={f['acac']}" for f in findings[:3])
        result.remediation = "Never allow 'null' as a valid origin. Use strict origin allowlists. Avoid Access-Control-Allow-Credentials with permissive origins."
        result.reproduction_steps = "1. Send request with Origin: null header\n2. Check if Access-Control-Allow-Origin: null is returned\n3. Check if Access-Control-Allow-Credentials: true is also set"
    else:
        result.status = "passed"
        result.description = "CORS does not allow null origin"

    return result
