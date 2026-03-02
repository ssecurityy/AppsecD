"""DAST checks: recon — info disclosure, tech fingerprint, sitemap, robots, directory listing, backup files, API docs, security.txt, .env/.git."""
import re
from urllib.parse import urlparse, urljoin

from ..base import DastResult, safe_get


def check_info_disclosure(target_url: str) -> DastResult:
    """Check for information disclosure in headers and error pages."""
    result = DastResult(
        check_id="DAST-INFO-01", title="Information Disclosure",
        owasp_ref="A05:2021", cwe_id="CWE-200",
    )
    resp = safe_get(target_url)
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
    error_resp = safe_get(urljoin(target_url, "/this-page-does-not-exist-404-test"))
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
    result.details = {"server_header": headers.get("server", ""), "powered_by": headers.get("x-powered-by", ""), "issue_count": len(issues), "payload_tested": "GET target + error page for Server, X-Powered-By, stack traces"}
    result.request_raw = f"GET {target_url} HTTP/1.1\nHost: {urlparse(target_url).netloc}"
    result.response_raw = f"HTTP/1.1 {resp.status_code}\n" + "\n".join(f"{k}: {v}" for k, v in resp.headers.items()) + "\n\n" + (resp.text[:2000] if resp.text else "")
    if issues:
        result.status = "failed"
        result.severity = "low"
        result.description = f"{len(issues)} information disclosure issue(s)"
        result.evidence = "; ".join(issues)
        result.remediation = "Remove version info. Disable debug mode. Use custom error pages."
    else:
        result.status = "passed"
        result.description = "No significant information disclosure"
    return result


def check_tech_fingerprint(target_url: str) -> DastResult:
    """Technology fingerprinting."""
    result = DastResult(
        check_id="DAST-RECON-01", title="Tech Fingerprint",
        owasp_ref="A05:2021", cwe_id="CWE-200",
    )
    try:
        from app.services.tech_detection_service import detect_technology
        stack = detect_technology(target_url)
    except Exception:
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
    result.details = {"stack_profile": detected, "technologies": flat, "waf": waf, "payload_tested": "Tech fingerprint (headers, HTML, JS)"}
    if stack.get("effective_url"):
        result.request_raw = f"GET {stack['effective_url']} — Tech scan"
    if flat or waf:
        result.status = "failed"
        result.severity = "info"
        result.description = f"Detected: {', '.join(flat[:12])}" + (f" | WAF: {', '.join(waf)}" if waf else "")
        result.evidence = f"Technologies: {', '.join(flat)}\nWAF: {', '.join(waf) or 'None'}"
        result.remediation = "Minimize technology disclosure"
    else:
        result.status = "passed"
        result.description = "Minimal technology disclosure"
    return result


def check_sitemap_xml(target_url: str) -> DastResult:
    """Check sitemap.xml for sensitive paths."""
    result = DastResult(
        check_id="DAST-RECON-02", title="sitemap.xml Analysis",
        owasp_ref="A05:2021", cwe_id="CWE-200",
    )
    parsed = urlparse(target_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    sitemap_url = urljoin(base, "/sitemap.xml")
    resp = safe_get(sitemap_url)
    if not resp or resp.status_code != 200:
        result.status = "passed"
        result.description = "No sitemap.xml found"
        return result
    content = resp.text or ""
    sensitive = ["admin", "login", "config", "backup", "api/", "internal", "debug", "test"]
    urls_found = re.findall(r"<loc>([^<]+)</loc>", content, re.I)
    sensitive_found = [u for u in urls_found if any(s in u.lower() for s in sensitive)]
    result.details = {"urls_count": len(urls_found), "sensitive_paths": sensitive_found, "payload_tested": "GET /sitemap.xml"}
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


def check_robots_txt(target_url: str) -> DastResult:
    """Analyze robots.txt."""
    result = DastResult(
        check_id="DAST-ROBO-01", title="robots.txt Analysis",
        owasp_ref="A05:2021", cwe_id="CWE-200",
    )
    robots_url = urljoin(target_url, "/robots.txt")
    resp = safe_get(robots_url)
    if not resp or resp.status_code != 200:
        result.status = "passed"
        result.description = "No robots.txt found"
        return result
    content = resp.text
    sensitive_patterns = ["admin", "login", "api", "config", "backup", "debug", "test", "internal", "dashboard", "secret", "private", "wp-admin", "phpmyadmin", ".env", ".git"]
    disallowed = [line.split(":", 1)[1].strip() for line in content.split("\n") if line.lower().startswith("disallow:") and ":" in line and line.split(":", 1)[1].strip()]
    sensitive_found = [d for d in disallowed if any(p in d.lower() for p in sensitive_patterns)]
    result.details = {"disallowed_paths": disallowed, "sensitive_paths": sensitive_found, "raw_content": content[:2000], "payload_tested": "GET /robots.txt"}
    result.request_raw = f"GET {robots_url} HTTP/1.1\nHost: {urlparse(target_url).netloc}"
    result.response_raw = f"HTTP/1.1 {resp.status_code}\n" + "\n".join(f"{k}: {v}" for k, v in resp.headers.items()) + "\n\n" + (content[:1500] if content else "")
    if sensitive_found:
        result.status = "failed"
        result.severity = "low"
        result.description = f"robots.txt reveals {len(sensitive_found)} sensitive path(s)"
        result.evidence = f"Sensitive paths: {', '.join(sensitive_found[:10])}"
        result.remediation = "Do not rely on robots.txt for security"
    else:
        result.status = "passed"
        result.description = f"robots.txt found with {len(disallowed)} disallowed path(s)"
    return result


def check_directory_listing(target_url: str) -> DastResult:
    """Check for enabled directory listing."""
    result = DastResult(
        check_id="DAST-DIR-01", title="Directory Listing",
        owasp_ref="A05:2021", cwe_id="CWE-548",
    )
    common_dirs = ["/", "/images/", "/static/", "/assets/", "/uploads/", "/css/", "/js/", "/media/", "/files/"]
    listing_found = []
    for d in common_dirs:
        test_url = urljoin(target_url, d)
        resp = safe_get(test_url)
        if resp and resp.status_code == 200:
            body = resp.text[:3000].lower()
            if "index of" in body or "directory listing" in body or ("<pre>" in body and "parent directory" in body):
                listing_found.append(d)
    result.details = {"checked_dirs": common_dirs, "listing_enabled": listing_found, "payload_tested": f"GET dirs: {', '.join(common_dirs)}"}
    first_resp = safe_get(urljoin(target_url, common_dirs[0])) if common_dirs else None
    if first_resp:
        result.request_raw = f"GET {urljoin(target_url, common_dirs[0])} HTTP/1.1\nHost: {urlparse(target_url).netloc}"
        result.response_raw = f"HTTP/1.1 {first_resp.status_code}\n" + "\n".join(f"{k}: {v}" for k, v in first_resp.headers.items()) + "\n\n" + (first_resp.text[:1500] if first_resp.text else "")
    if listing_found:
        result.status = "failed"
        result.severity = "medium"
        result.description = f"Directory listing enabled on {len(listing_found)} path(s)"
        result.evidence = f"Listing at: {', '.join(listing_found)}"
        result.remediation = "Disable directory listing"
    else:
        result.status = "passed"
        result.description = "No directory listing detected"
    return result


def check_backup_files(target_url: str) -> DastResult:
    """Check for backup/config file exposure."""
    result = DastResult(
        check_id="DAST-BACKUP-01", title="Backup File Disclosure",
        owasp_ref="A05:2021", cwe_id="CWE-530",
    )
    paths = ["/.git/config", "/.env", "/config.php.bak", "/web.config.bak", "/.htaccess.bak", "/backup.sql", "/db.sql", "/dump.sql"]
    base = f"{urlparse(target_url).scheme}://{urlparse(target_url).netloc}"
    exposed = []
    for path in paths:
        r = safe_get(urljoin(base, path))
        if r and r.status_code == 200 and len(r.text or "") > 0:
            txt = (r.text or "").lower()
            if "root" in txt or "password" in txt or "[core]" in txt or "database" in txt:
                exposed.append(path)
    result.details = {"paths_checked": paths, "exposed": exposed, "payload_tested": f"GET backup paths: {paths[:4]}"}
    sample = safe_get(urljoin(base, paths[0])) if paths else None
    if sample:
        result.request_raw = f"GET {base}{paths[0]} HTTP/1.1\nHost: {urlparse(target_url).netloc}"
        result.response_raw = f"HTTP/1.1 {sample.status_code}\n" + "\n".join(f"{k}: {v}" for k, v in sample.headers.items()) + "\n\n" + ((sample.text or "")[:1500])
    if exposed:
        result.status = "failed"
        result.severity = "high"
        result.description = f"Backup/config file(s) exposed: {', '.join(exposed)}"
        result.evidence = f"Exposed: {', '.join(exposed)}"
        result.remediation = "Remove backup files from web root"
    else:
        result.status = "passed"
        result.description = "No backup/config files exposed"
    return result


def check_api_docs_exposure(target_url: str) -> DastResult:
    """Check for exposed Swagger/OpenAPI/GraphQL."""
    result = DastResult(
        check_id="DAST-API-01", title="API Documentation Exposure",
        owasp_ref="A05:2021", cwe_id="CWE-200",
    )
    paths = ["/swagger", "/swagger.json", "/swagger-ui", "/api-docs", "/openapi.json", "/graphql", "/graphiql", "/v1/api-docs", "/v2/api-docs", "/api/swagger"]
    base = f"{urlparse(target_url).scheme}://{urlparse(target_url).netloc}"
    exposed = []
    for path in paths:
        r = safe_get(urljoin(base, path))
        if r and r.status_code == 200:
            body = (r.text or "").lower()
            if "swagger" in body or "openapi" in body or "graphql" in body or "graphiql" in body:
                exposed.append(path)
    result.details = {"paths_checked": paths, "exposed": exposed, "payload_tested": f"GET paths: {', '.join(paths[:5])}..."}
    sample = safe_get(urljoin(base, paths[0])) if paths else None
    if sample:
        result.request_raw = f"GET {base}{paths[0]} HTTP/1.1\nHost: {urlparse(target_url).netloc}\n(Checked: {', '.join(paths[:5])})"
        result.response_raw = f"HTTP/1.1 {sample.status_code}\n" + "\n".join(f"{k}: {v}" for k, v in sample.headers.items()) + "\n\n" + ((sample.text or "")[:1500])
    if exposed:
        result.status = "failed"
        result.severity = "medium"
        result.description = f"API docs exposed at: {', '.join(exposed[:5])}"
        result.evidence = f"Exposed: {', '.join(exposed)}"
        result.remediation = "Disable or restrict API docs in production"
    else:
        result.status = "passed"
        result.description = "No exposed API documentation"
    return result


def check_security_txt(target_url: str) -> DastResult:
    """Verify /.well-known/security.txt."""
    result = DastResult(
        check_id="DAST-SECTXT-01", title="Security.txt (RFC 9116)",
        owasp_ref="A05:2021", cwe_id="CWE-200",
    )
    parsed = urlparse(target_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    url = urljoin(base, "/.well-known/security.txt")
    resp = safe_get(url)
    if not resp:
        result.status = "error"
        result.description = "Could not reach target"
        return result
    body = (resp.text or "").strip()
    result.request_raw = f"GET {url} HTTP/1.1\nHost: {parsed.netloc}"
    result.response_raw = f"HTTP/1.1 {resp.status_code}\n" + "\n".join(f"{k}: {v}" for k, v in resp.headers.items()) + "\n\n" + (body[:1500] if body else "")
    result.details = {"url": url, "status_code": resp.status_code, "payload_tested": "GET /.well-known/security.txt"}
    if resp.status_code == 404:
        result.status = "failed"
        result.severity = "info"
        result.description = "security.txt not found"
        result.remediation = "Add /.well-known/security.txt per RFC 9116"
    elif resp.status_code != 200:
        result.status = "failed"
        result.severity = "low"
        result.description = f"security.txt returned {resp.status_code}"
    else:
        has_contact = "contact:" in body.lower() or "mailto:" in body.lower()
        if not has_contact:
            result.status = "failed"
            result.severity = "low"
            result.description = "security.txt missing required Contact field"
            result.remediation = "Add Contact field per RFC 9116"
        else:
            result.status = "passed"
            result.description = "security.txt present and valid"
    return result


def check_dotenv_git(target_url: str) -> DastResult:
    """Check for .env or .git/HEAD exposure."""
    result = DastResult(
        check_id="DAST-ENV-01", title=".env / .git Exposure",
        owasp_ref="A05:2021", cwe_id="CWE-798",
    )
    parsed = urlparse(target_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    paths = [("/.env", ["password", "secret", "api_key", "key=", "database"]), ("/.git/HEAD", ["ref:", "refs/heads/"])]
    exposed = []
    for path, indicators in paths:
        r = safe_get(urljoin(base, path))
        if r and r.status_code == 200:
            txt = (r.text or "").lower()
            if any(ind in txt for ind in indicators) or (path == "/.git/HEAD" and len(txt) < 200):
                exposed.append(path)
    result.details = {"paths_checked": [p[0] for p in paths], "exposed": exposed, "payload_tested": "GET /.env and /.git/HEAD"}
    if exposed:
        result.status = "failed"
        result.severity = "critical"
        result.description = f"Critical file(s) exposed: {', '.join(exposed)}"
        result.evidence = f"Exposed: {', '.join(exposed)}"
        result.remediation = "Remove .env and .git from web root"
    else:
        result.status = "passed"
        result.description = "No .env or .git/HEAD exposure"
    result.request_raw = f"GET {base}/.env HTTP/1.1\nHost: {parsed.netloc}"
    result.response_raw = "See details"
    return result
