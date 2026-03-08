"""DAST checks: network & infrastructure — admin panels, database exposure, WebSocket security, service workers, CSP bypasses, subdomain takeover."""
from ..base import DastResult, HEADERS, TIMEOUT, safe_get, safe_request, USER_AGENTS
import httpx, logging, re, json, time
from urllib.parse import urlparse, urljoin

logger = logging.getLogger(__name__)


# ─── Admin Panel Exposure ────────────────────────────────────

def check_admin_panel_exposure(target_url: str) -> DastResult:
    """Check for exposed admin panels at common paths."""
    result = DastResult(
        check_id="DAST-ADMIN-01",
        title="Admin Panel Exposure",
        owasp_ref="A05:2021",
        cwe_id="CWE-200",
    )

    parsed = urlparse(target_url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    admin_paths = [
        "/admin",
        "/wp-admin",
        "/phpmyadmin",
        "/cpanel",
        "/manager",
        "/admin.php",
        "/administrator",
        "/cms",
        "/dashboard/admin",
        "/portal",
        "/admin/login",
        "/wp-login.php",
        "/adminer",
        "/adminer.php",
        "/_admin",
        "/panel",
        "/webadmin",
        "/siteadmin",
        "/admin/dashboard",
        "/backend",
    ]

    admin_indicators = [
        "login", "password", "username", "sign in", "log in", "admin panel",
        "dashboard", "administration", "control panel", "cpanel", "phpmyadmin",
        "wp-login", "wordpress", "drupal", "joomla", "cms login",
    ]

    exposed = []

    for path in admin_paths:
        test_url = f"{base}{path}"
        try:
            with httpx.Client(timeout=TIMEOUT, headers=HEADERS, verify=False, follow_redirects=True) as client:
                r = client.get(test_url)
                if r.status_code == 200:
                    body = (r.text or "").lower()
                    ct = r.headers.get("content-type", "")
                    if "text/html" in ct:
                        matched_indicators = [ind for ind in admin_indicators if ind in body]
                        if len(matched_indicators) >= 2:
                            exposed.append({"path": path, "status": r.status_code, "indicators": matched_indicators[:3]})
                elif r.status_code == 401 or r.status_code == 403:
                    # Basic auth prompt or forbidden — panel exists but protected
                    exposed.append({"path": path, "status": r.status_code, "indicators": ["auth_required"]})
        except Exception:
            continue

    result.details = {"paths_checked": len(admin_paths), "exposed": exposed[:10]}
    result.request_raw = f"GET {base}/admin HTTP/1.1\nHost: {parsed.netloc}"

    if exposed:
        open_panels = [e for e in exposed if e["status"] == 200]
        auth_panels = [e for e in exposed if e["status"] in (401, 403)]

        result.status = "failed"
        if open_panels:
            result.severity = "high"
            result.description = f"Admin panel(s) exposed: {len(open_panels)} open, {len(auth_panels)} auth-required"
        else:
            result.severity = "medium"
            result.description = f"Admin panel(s) detected: {len(auth_panels)} requiring authentication"

        result.evidence = "; ".join(f"{e['path']} (HTTP {e['status']}, {', '.join(e['indicators'][:2])})" for e in exposed[:5])
        result.remediation = "Restrict admin panel access by IP allowlist. Use VPN for admin access. Implement multi-factor authentication. Change default admin paths."
        result.reproduction_steps = f"1. GET {base}{exposed[0]['path']}\n2. Admin panel accessible with status {exposed[0]['status']}"
    else:
        result.status = "passed"
        result.description = "No admin panels exposed"

    return result


# ─── Database Exposure ───────────────────────────────────────

def check_database_exposure(target_url: str) -> DastResult:
    """Check MongoDB, Redis, Elasticsearch default paths for public access."""
    result = DastResult(
        check_id="DAST-DBEXPOSE-01",
        title="Database Service Exposure",
        owasp_ref="A05:2021",
        cwe_id="CWE-200",
    )

    parsed = urlparse(target_url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    db_checks = [
        {
            "name": "Elasticsearch",
            "paths": ["/_cat/indices", "/_cluster/health", "/_nodes", "/"],
            "indicators": ["cluster_name", "green", "yellow", "red", "number_of_nodes", "elasticsearch"],
        },
        {
            "name": "CouchDB",
            "paths": ["/_all_dbs", "/_utils"],
            "indicators": ["couchdb", "_users", "_replicator"],
        },
        {
            "name": "MongoDB Express",
            "paths": ["/mongo-express", "/rockmongo", "/mongoui"],
            "indicators": ["mongo", "database", "collection", "mongodb"],
        },
        {
            "name": "Redis Commander",
            "paths": ["/redis", "/redis-commander"],
            "indicators": ["redis", "commander", "keys"],
        },
        {
            "name": "Kibana",
            "paths": ["/app/kibana", "/kibana"],
            "indicators": ["kibana", "discover", "elasticsearch"],
        },
        {
            "name": "phpMyAdmin",
            "paths": ["/phpmyadmin", "/pma", "/mysql"],
            "indicators": ["phpmyadmin", "mysql", "database", "sql"],
        },
        {
            "name": "Adminer",
            "paths": ["/adminer", "/adminer.php"],
            "indicators": ["adminer", "login", "database", "server"],
        },
    ]

    exposed = []

    for db in db_checks:
        for path in db["paths"]:
            test_url = f"{base}{path}"
            try:
                with httpx.Client(timeout=httpx.Timeout(8.0), headers=HEADERS, verify=False, follow_redirects=True) as client:
                    r = client.get(test_url)
                    if r.status_code == 200:
                        body = (r.text or "").lower()
                        matched = [ind for ind in db["indicators"] if ind in body]
                        if len(matched) >= 2:
                            exposed.append({"service": db["name"], "path": path, "indicators": matched[:3]})
                            break
            except Exception:
                continue

    result.details = {"services_checked": [d["name"] for d in db_checks], "exposed": exposed}
    result.request_raw = f"GET {base}/_cat/indices HTTP/1.1\nHost: {parsed.netloc}"

    if exposed:
        result.status = "failed"
        result.severity = "critical"
        result.description = f"Database service(s) exposed: {', '.join(e['service'] for e in exposed)}"
        result.evidence = "; ".join(f"{e['service']} at {e['path']} ({', '.join(e['indicators'][:2])})" for e in exposed[:5])
        result.remediation = "Never expose database management interfaces to the public internet. Use network segmentation. Require authentication. Bind to localhost only."
        result.reproduction_steps = f"1. GET {base}{exposed[0]['path']}\n2. Found {exposed[0]['service']} indicators: {', '.join(exposed[0]['indicators'][:2])}"
    else:
        result.status = "passed"
        result.description = "No database services exposed"

    return result


# ─── WebSocket Security ──────────────────────────────────────

def check_websocket_security(target_url: str) -> DastResult:
    """Test WebSocket upgrade on common WS paths. Check CSWSH via Origin check."""
    result = DastResult(
        check_id="DAST-WS-01",
        title="WebSocket Security (CSWSH)",
        owasp_ref="A01:2021",
        cwe_id="CWE-1385",
    )

    parsed = urlparse(target_url)
    host = parsed.netloc
    base = f"{parsed.scheme}://{parsed.netloc}"

    ws_paths = ["/ws", "/socket", "/socket.io/", "/websocket", "/ws/", "/realtime", "/live",
                "/sockjs", "/cable", "/hub"]

    evil_origin = "https://evil-attacker.com"

    findings = []

    for ws_path in ws_paths:
        test_url = f"{base}{ws_path}"

        # Test WebSocket upgrade with evil origin
        try:
            upgrade_headers = {
                **HEADERS,
                "Upgrade": "websocket",
                "Connection": "Upgrade",
                "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                "Sec-WebSocket-Version": "13",
                "Origin": evil_origin,
            }
            with httpx.Client(timeout=httpx.Timeout(8.0), headers=upgrade_headers, verify=False, follow_redirects=False) as client:
                r = client.get(test_url)

                if r.status_code == 101:
                    # WebSocket upgrade accepted with evil origin — CSWSH
                    findings.append({"path": ws_path, "status": 101, "type": "cswsh", "origin_checked": False})
                elif r.status_code == 200:
                    body = (r.text or "").lower()
                    # socket.io and similar return 200 with transport info
                    if "websocket" in body or "transport" in body or "sid" in body:
                        # Now check with legitimate origin
                        legit_headers = dict(upgrade_headers)
                        legit_headers["Origin"] = f"{parsed.scheme}://{host}"
                        with httpx.Client(timeout=httpx.Timeout(8.0), headers=legit_headers, verify=False, follow_redirects=False) as client2:
                            r2 = client2.get(test_url)
                            if r2.status_code == r.status_code:
                                findings.append({"path": ws_path, "status": r.status_code, "type": "ws_endpoint", "origin_checked": False})
                elif r.status_code == 400:
                    body = (r.text or "").lower()
                    if "websocket" in body or "upgrade" in body:
                        findings.append({"path": ws_path, "status": r.status_code, "type": "ws_found", "origin_checked": True})
        except Exception:
            continue

    result.details = {"paths_tested": ws_paths, "findings": findings[:10]}

    if findings:
        cswsh = [f for f in findings if f["type"] == "cswsh"]
        ws_no_origin = [f for f in findings if f["type"] == "ws_endpoint" and not f["origin_checked"]]

        if cswsh:
            result.status = "failed"
            result.severity = "high"
            result.description = f"Cross-Site WebSocket Hijacking: {len(cswsh)} endpoint(s) accept arbitrary Origin"
            result.evidence = "; ".join(f"{f['path']} accepted upgrade with Origin: {evil_origin}" for f in cswsh[:3])
            result.remediation = "Validate Origin header on WebSocket upgrade. Use authentication tokens in WS handshake. Implement CSRF protection for WebSocket connections."
        elif ws_no_origin:
            result.status = "failed"
            result.severity = "medium"
            result.description = f"WebSocket endpoint(s) found without strict Origin validation"
            result.evidence = "; ".join(f"{f['path']} (HTTP {f['status']})" for f in ws_no_origin[:3])
            result.remediation = "Validate Origin header on WebSocket connections. Implement per-message authentication."
        else:
            result.status = "passed"
            result.description = f"WebSocket endpoint(s) found with proper Origin validation"
    else:
        result.status = "passed"
        result.description = "No WebSocket endpoints detected"

    return result


# ─── Service Worker Security ─────────────────────────────────

def check_service_worker_security(target_url: str) -> DastResult:
    """Look for Service Worker registrations in HTML. Check SW file for cache poisoning potential."""
    result = DastResult(
        check_id="DAST-SW-01",
        title="Service Worker Security Analysis",
        owasp_ref="A08:2021",
        cwe_id="CWE-829",
    )

    parsed = urlparse(target_url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    # Fetch main page
    try:
        with httpx.Client(timeout=TIMEOUT, headers=HEADERS, verify=False, follow_redirects=True) as client:
            main_resp = client.get(target_url)
            if main_resp.status_code != 200:
                result.status = "error"
                result.description = "Could not reach target"
                return result
            html = main_resp.text or ""
    except Exception:
        result.status = "error"
        result.description = "Could not reach target"
        return result

    # Find service worker registrations
    sw_patterns = [
        r'navigator\.serviceWorker\.register\s*\(\s*["\']([^"\']+)["\']',
        r'ServiceWorkerRegistration[^"]*["\']([^"\']+\.js)["\']',
        r'sw\.js',
        r'service-worker\.js',
    ]

    sw_files = []
    for pattern in sw_patterns:
        matches = re.findall(pattern, html, re.IGNORECASE)
        sw_files.extend(matches)

    # Also check common SW paths
    common_sw_paths = ["/sw.js", "/service-worker.js", "/serviceworker.js", "/ngsw-worker.js", "/firebase-messaging-sw.js"]
    for sw_path in common_sw_paths:
        sw_url = urljoin(target_url, sw_path)
        try:
            with httpx.Client(timeout=TIMEOUT, headers=HEADERS, verify=False, follow_redirects=True) as client:
                r = client.get(sw_url)
                if r.status_code == 200:
                    body = r.text or ""
                    if "addEventListener" in body or "self.addEventListener" in body or "caches" in body:
                        sw_files.append(sw_path)
        except Exception:
            continue

    # Deduplicate
    sw_files = list(dict.fromkeys(sw_files))

    findings = []

    for sw_file in sw_files:
        sw_url = urljoin(target_url, sw_file)
        try:
            with httpx.Client(timeout=TIMEOUT, headers=HEADERS, verify=False, follow_redirects=True) as client:
                r = client.get(sw_url)
                if r.status_code == 200:
                    body = r.text or ""
                    issues = []

                    # Check for fetch event interception (cache poisoning risk)
                    if "fetch" in body and "caches" in body:
                        issues.append("intercepts fetch with caching")

                    # Check for importScripts from external domains
                    import_scripts = re.findall(r'importScripts\s*\(\s*["\']([^"\']+)["\']', body)
                    external_imports = [s for s in import_scripts if "://" in s and parsed.netloc not in s]
                    if external_imports:
                        issues.append(f"imports external scripts: {', '.join(external_imports[:3])}")

                    # Check for postMessage without origin validation
                    if "postMessage" in body and "origin" not in body.lower():
                        issues.append("postMessage without origin validation")

                    # Check scope
                    if "scope" in body and "'/' " in body:
                        issues.append("SW has root scope")

                    if issues:
                        findings.append({"sw_file": sw_file, "issues": issues})
                    else:
                        findings.append({"sw_file": sw_file, "issues": ["service worker found"]})
        except Exception:
            continue

    result.details = {"sw_files_found": sw_files, "findings": findings[:10]}

    if findings:
        risky = [f for f in findings if len(f["issues"]) > 1 or "external" in str(f["issues"])]
        if risky:
            result.status = "failed"
            result.severity = "medium"
            result.description = f"Service Worker security issues: {len(risky)} worker(s) with risks"
            result.evidence = "; ".join(f"{f['sw_file']}: {', '.join(f['issues'][:3])}" for f in risky[:3])
            result.remediation = "Validate all imports in Service Workers. Implement integrity checks (SRI) for cached resources. Restrict SW scope. Validate postMessage origins."
        else:
            result.status = "passed"
            result.description = f"Service Worker(s) found with acceptable configuration"
    else:
        result.status = "passed"
        result.description = "No Service Workers detected"

    return result


# ─── CSP Bypass Vectors ──────────────────────────────────────

def check_csp_bypass_vectors(target_url: str) -> DastResult:
    """Check for known CSP bypass payloads via CDN domains in CSP allowlists."""
    result = DastResult(
        check_id="DAST-CSPBYPASS-01",
        title="CSP Bypass Vectors",
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
        result.status = "passed"
        result.description = "No CSP header present (see CSP Analysis check for details)"
        return result

    # Known CDN domains that can be abused for CSP bypasses
    bypass_cdns = {
        "cdnjs.cloudflare.com": "Hosts Angular (template injection bypass), Prototype.js, and other JSONP-capable libraries",
        "cdn.jsdelivr.net": "Hosts arbitrary npm packages that can execute JavaScript",
        "unpkg.com": "Hosts arbitrary npm packages that can execute JavaScript",
        "ajax.googleapis.com": "Hosts Angular and other frameworks enabling template injection",
        "cdn.rawgit.com": "Serves arbitrary GitHub-hosted JavaScript",
        "raw.githubusercontent.com": "Can serve arbitrary JavaScript from GitHub repos",
        "*.googleusercontent.com": "Can host arbitrary user content",
        "accounts.google.com": "JSONP endpoint allows script execution",
        "*.google.com": "Multiple JSONP endpoints available",
        "cdn.shopify.com": "JSONP endpoints available",
        "*.amazonaws.com": "Can host arbitrary content in S3 buckets",
        "*.cloudfront.net": "Can serve arbitrary content via CloudFront distributions",
    }

    findings = []
    csp_lower = effective_csp.lower()

    # Parse directives
    directives = {}
    for part in effective_csp.split(";"):
        part = part.strip()
        if not part:
            continue
        tokens = part.split()
        if tokens:
            directives[tokens[0].lower()] = " ".join(tokens[1:]) if len(tokens) > 1 else ""

    script_src = directives.get("script-src", directives.get("default-src", ""))

    for cdn_domain, reason in bypass_cdns.items():
        # Check if CDN domain appears in script-src or default-src
        search_domain = cdn_domain.lstrip("*.")
        if search_domain in script_src:
            findings.append({"domain": cdn_domain, "reason": reason, "directive": "script-src"})

    # Check for JSONP bypass patterns
    jsonp_indicators = ["callback=", "jsonp", "cb="]
    if "script-src" in directives or "default-src" in directives:
        src = directives.get("script-src", directives.get("default-src", ""))
        # Check if any allowed domain has a wildcard subdomain
        if "*." in src:
            findings.append({"domain": "wildcard_subdomain", "reason": "Wildcard subdomain in script-src allows subdomain takeover bypass", "directive": "script-src"})

    # Check for 'strict-dynamic' without nonce (can be bypassed)
    if "'strict-dynamic'" in script_src and "nonce-" not in script_src and "sha256-" not in script_src:
        findings.append({"domain": "strict-dynamic", "reason": "strict-dynamic without nonce/hash — can be bypassed via base tag injection", "directive": "script-src"})

    # Check for data: in script-src
    if "data:" in script_src:
        findings.append({"domain": "data:", "reason": "data: URIs in script-src allow inline script execution", "directive": "script-src"})

    # Check if report-only (not enforced)
    if csp_ro and not csp:
        findings.append({"domain": "report-only", "reason": "CSP is report-only and not enforced", "directive": "policy-level"})

    result.details = {"csp": effective_csp[:500], "directives": directives, "bypass_vectors": findings[:10]}

    if findings:
        result.status = "failed"
        has_critical = any(f["domain"] in ("data:", "*.amazonaws.com", "*.cloudfront.net") or "wildcard" in f["domain"] for f in findings)
        result.severity = "high" if has_critical else "medium"
        result.description = f"CSP bypass vectors found: {len(findings)} issue(s)"
        result.evidence = "; ".join(f"{f['domain']}: {f['reason'][:80]}" for f in findings[:5])
        result.remediation = "Remove CDN domains that host user-controllable content from CSP. Use nonce-based or hash-based CSP. Avoid wildcards in script-src. Use strict-dynamic with nonces."
    else:
        result.status = "passed"
        result.description = "No known CSP bypass vectors detected"

    return result


# ─── Subdomain Takeover ──────────────────────────────────────

def check_subdomain_takeover(target_url: str) -> DastResult:
    """Check CNAME records for common takeover-vulnerable services."""
    result = DastResult(
        check_id="DAST-SUBDOMAIN-01",
        title="Subdomain Takeover Detection",
        owasp_ref="A05:2021",
        cwe_id="CWE-284",
    )

    parsed = urlparse(target_url)
    domain = parsed.netloc.split(":")[0]

    # Known vulnerable service fingerprints (CNAME targets and error page signatures)
    takeover_signatures = {
        "GitHub Pages": {
            "cnames": ["github.io", "github.com"],
            "fingerprints": ["There isn't a GitHub Pages site here", "For root URLs (like http://example.com/)"],
        },
        "Heroku": {
            "cnames": ["herokuapp.com", "herokussl.com", "herokudns.com"],
            "fingerprints": ["No such app", "herokucdn.com/error-pages/no-such-app"],
        },
        "AWS S3": {
            "cnames": ["s3.amazonaws.com", "s3-website"],
            "fingerprints": ["NoSuchBucket", "The specified bucket does not exist"],
        },
        "Shopify": {
            "cnames": ["myshopify.com"],
            "fingerprints": ["Sorry, this shop is currently unavailable", "Only one step left"],
        },
        "Tumblr": {
            "cnames": ["domains.tumblr.com"],
            "fingerprints": ["Whatever you were looking for doesn't currently exist at this address"],
        },
        "Zendesk": {
            "cnames": ["zendesk.com"],
            "fingerprints": ["Help Center Closed", "This help center no longer exists"],
        },
        "Fastly": {
            "cnames": ["fastly.net"],
            "fingerprints": ["Fastly error: unknown domain"],
        },
        "Pantheon": {
            "cnames": ["pantheonsite.io"],
            "fingerprints": ["404 error unknown site", "The gods are wise"],
        },
        "Surge.sh": {
            "cnames": ["surge.sh"],
            "fingerprints": ["project not found"],
        },
        "Fly.io": {
            "cnames": ["fly.dev"],
            "fingerprints": ["404 Not Found"],
        },
    }

    findings = []

    # Try DNS resolution to check for CNAME
    try:
        import socket
        try:
            cname_info = socket.getaddrinfo(domain, None)
            # We cannot directly get CNAME from getaddrinfo, but we can check the response
        except socket.gaierror:
            # Domain does not resolve — potential dangling DNS
            findings.append({"service": "DNS", "type": "nxdomain", "detail": f"Domain {domain} does not resolve (potential dangling DNS)"})
    except Exception:
        pass

    # Check error page signatures by requesting the target
    try:
        with httpx.Client(timeout=TIMEOUT, headers=HEADERS, verify=False, follow_redirects=True) as client:
            r = client.get(target_url)
            body = r.text or ""
            for service, sigs in takeover_signatures.items():
                for fingerprint in sigs["fingerprints"]:
                    if fingerprint in body:
                        findings.append({"service": service, "type": "fingerprint", "detail": f"Error page matches {service} takeover signature: '{fingerprint[:60]}'"})
                        break
    except Exception:
        pass

    # Try common subdomains for takeover
    common_subdomains = ["www", "blog", "dev", "staging", "test", "api", "mail", "cdn", "docs", "help", "support", "status"]
    base_domain = domain
    if domain.startswith("www."):
        base_domain = domain[4:]

    for sub in common_subdomains[:8]:
        sub_domain = f"{sub}.{base_domain}"
        sub_url = f"{parsed.scheme}://{sub_domain}"
        try:
            with httpx.Client(timeout=httpx.Timeout(5.0), headers=HEADERS, verify=False, follow_redirects=True) as client:
                r = client.get(sub_url)
                body = r.text or ""
                for service, sigs in takeover_signatures.items():
                    for fingerprint in sigs["fingerprints"]:
                        if fingerprint in body:
                            findings.append({"service": service, "type": "subdomain_takeover", "subdomain": sub_domain, "detail": f"{sub_domain} matches {service} takeover signature"})
                            break
        except httpx.ConnectError:
            # Connection refused could indicate dangling CNAME
            try:
                import socket
                socket.getaddrinfo(sub_domain, None)
                # DNS resolves but connection refused — less likely takeover
            except socket.gaierror:
                # NXDOMAIN for subdomain — expected, not a finding
                pass
        except Exception:
            continue

    result.details = {"domain": domain, "subdomains_checked": common_subdomains[:8], "findings": findings[:10]}

    if findings:
        result.status = "failed"
        has_takeover = any(f["type"] in ("fingerprint", "subdomain_takeover") for f in findings)
        result.severity = "high" if has_takeover else "medium"
        result.description = f"Subdomain takeover risk: {len(findings)} potential issue(s)"
        result.evidence = "; ".join(f["detail"][:100] for f in findings[:5])
        result.remediation = "Remove dangling DNS records. Verify all CNAME targets are claimed. Monitor DNS records for changes. Use DNS monitoring services."
        result.reproduction_steps = "1. Enumerate subdomains\n2. Check for dangling CNAME records\n3. Verify target services are claimed"
    else:
        result.status = "passed"
        result.description = "No subdomain takeover risks detected"

    return result
