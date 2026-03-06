"""Claude DAST Crawler — AI-powered crawling tools for endpoint/path/parameter discovery."""
import json
import logging
import re
import time
from urllib.parse import urljoin, urlparse

logger = logging.getLogger(__name__)


def browse_url(url: str, actions: list | None = None, scope_domain: str = "") -> dict:
    """Browse a URL using Playwright (headless) or httpx fallback.

    Returns page HTML, links, forms, scripts, cookies, network requests.
    """
    from app.core.ssrf import is_ssrf_blocked_url
    if is_ssrf_blocked_url(url):
        return {"error": "URL blocked by SSRF protection", "url": url}

    # Try Playwright first
    try:
        return _browse_playwright(url, actions or [])
    except Exception as pw_err:
        logger.debug("Playwright browse failed for %s: %s, falling back to httpx", url, pw_err)

    # Fallback: httpx + BeautifulSoup
    return _browse_httpx(url)


def _browse_playwright(url: str, actions: list) -> dict:
    """Browse with Playwright headless browser."""
    from playwright.sync_api import sync_playwright

    result = {
        "url": url, "status_code": 0, "content_type": "", "title": "",
        "html_preview": "", "links": [], "forms": [], "scripts": [],
        "cookies": [], "network_requests": [],
    }

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, args=["--no-sandbox", "--disable-gpu"])
        context = browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            ignore_https_errors=True,
        )
        page = context.new_page()

        # Capture network requests
        captured_requests = []
        page.on("request", lambda req: captured_requests.append({
            "url": req.url, "method": req.method, "resource_type": req.resource_type,
        }))

        try:
            resp = page.goto(url, timeout=15000, wait_until="domcontentloaded")
            if resp:
                result["status_code"] = resp.status
                result["content_type"] = resp.headers.get("content-type", "")

            result["title"] = page.title()

            # Execute actions
            for action in actions[:10]:
                action_type = action.get("type", "")
                try:
                    if action_type == "click" and action.get("selector"):
                        page.click(action["selector"], timeout=5000)
                        page.wait_for_timeout(500)
                    elif action_type == "scroll":
                        page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                        page.wait_for_timeout(500)
                    elif action_type == "type" and action.get("selector") and action.get("text"):
                        page.fill(action["selector"], action["text"])
                    elif action_type == "wait":
                        page.wait_for_timeout(int(action.get("ms", 1000)))
                except Exception:
                    pass

            html = page.content()
            result["html_preview"] = html[:5000]

            # Extract links
            links = page.eval_on_selector_all("a[href]", "els => els.map(e => ({href: e.href, text: (e.textContent||'').trim().slice(0,100)}))")
            result["links"] = links[:200]

            # Extract forms
            forms = page.eval_on_selector_all("form", """els => els.map(f => ({
                action: f.action, method: f.method || 'GET',
                fields: Array.from(f.querySelectorAll('input,select,textarea')).map(i => ({
                    name: i.name, type: i.type || 'text', value: i.value || ''
                }))
            }))""")
            result["forms"] = forms[:50]

            # Extract scripts
            scripts = page.eval_on_selector_all("script[src]", "els => els.map(e => e.src)")
            result["scripts"] = scripts[:100]

            # Cookies
            result["cookies"] = [
                {"name": c["name"], "domain": c.get("domain", ""), "secure": c.get("secure", False),
                 "httpOnly": c.get("httpOnly", False), "sameSite": c.get("sameSite", "")}
                for c in context.cookies()
            ]

            result["network_requests"] = captured_requests[:200]

        except Exception as e:
            result["error"] = str(e)[:300]
        finally:
            browser.close()

    return result


def _browse_httpx(url: str) -> dict:
    """Fallback browser using httpx + BeautifulSoup."""
    import httpx
    from bs4 import BeautifulSoup

    result = {
        "url": url, "status_code": 0, "content_type": "", "title": "",
        "html_preview": "", "links": [], "forms": [], "scripts": [],
        "cookies": [], "network_requests": [],
    }

    try:
        with httpx.Client(verify=False, follow_redirects=True, timeout=15) as client:
            resp = client.get(url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"})
            result["status_code"] = resp.status_code
            result["content_type"] = resp.headers.get("content-type", "")
            html = resp.text
            result["html_preview"] = html[:5000]

            soup = BeautifulSoup(html, "html.parser")
            result["title"] = (soup.title.string or "") if soup.title else ""

            # Links
            for a in soup.find_all("a", href=True)[:200]:
                result["links"].append({"href": urljoin(url, a["href"]), "text": a.get_text(strip=True)[:100]})

            # Forms
            for form in soup.find_all("form")[:50]:
                fields = []
                for inp in form.find_all(["input", "select", "textarea"]):
                    fields.append({"name": inp.get("name", ""), "type": inp.get("type", "text"), "value": inp.get("value", "")})
                result["forms"].append({
                    "action": urljoin(url, form.get("action", "")),
                    "method": (form.get("method") or "GET").upper(),
                    "fields": fields,
                })

            # Scripts
            for script in soup.find_all("script", src=True)[:100]:
                result["scripts"].append(urljoin(url, script["src"]))

            # Cookies
            for name, value in resp.cookies.items():
                result["cookies"].append({"name": name, "domain": urlparse(url).hostname})

    except Exception as e:
        result["error"] = str(e)[:300]

    return result


def crawl_sitemap(target_url: str) -> dict:
    """Parse sitemap.xml and robots.txt for URL discovery."""
    import httpx

    parsed = urlparse(target_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    result = {"urls_from_sitemap": [], "disallowed_paths": [], "interesting_paths": [], "sitemaps": []}

    headers = {"User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)"}

    # robots.txt
    try:
        with httpx.Client(verify=False, timeout=10) as client:
            resp = client.get(f"{base}/robots.txt", headers=headers)
            if resp.status_code == 200:
                for line in resp.text.splitlines():
                    line = line.strip()
                    if line.lower().startswith("disallow:"):
                        path = line.split(":", 1)[1].strip()
                        if path:
                            result["disallowed_paths"].append(path)
                            # Disallowed paths are often interesting
                            if any(k in path.lower() for k in ["admin", "api", "config", "backup", "internal", "debug", "test"]):
                                result["interesting_paths"].append({"path": path, "reason": "Disallowed in robots.txt"})
                    elif line.lower().startswith("sitemap:"):
                        sitemap_url = line.split(":", 1)[1].strip()
                        result["sitemaps"].append(sitemap_url)
    except Exception:
        pass

    # Sitemap.xml
    sitemap_urls_to_check = result["sitemaps"] or [f"{base}/sitemap.xml", f"{base}/sitemap_index.xml"]
    try:
        with httpx.Client(verify=False, timeout=10) as client:
            for sitemap_url in sitemap_urls_to_check[:5]:
                try:
                    resp = client.get(sitemap_url, headers=headers)
                    if resp.status_code == 200 and "<url" in resp.text.lower():
                        # Extract URLs from sitemap
                        urls = re.findall(r"<loc>(.*?)</loc>", resp.text, re.IGNORECASE)
                        result["urls_from_sitemap"].extend(urls[:500])
                except Exception:
                    pass
    except Exception:
        pass

    # Deduplicate
    result["urls_from_sitemap"] = list(set(result["urls_from_sitemap"]))[:500]

    return result


def discover_endpoints(
    base_url: str,
    wordlist_type: str = "common",
    custom_words: list | None = None,
    max_paths: int = 200,
) -> dict:
    """Discover hidden paths via wordlist fuzzing."""
    import httpx
    from app.core.ssrf import is_ssrf_blocked_url

    if is_ssrf_blocked_url(base_url):
        return {"error": "URL blocked by SSRF protection"}

    # Build wordlist based on type
    wordlists = {
        "common": [
            "admin", "api", "login", "dashboard", "config", "backup", ".env", ".git",
            "wp-admin", "phpmyadmin", "debug", "test", "staging", "internal", "console",
            "graphql", "swagger", "api-docs", "openapi.json", "health", "status",
            "metrics", "actuator", "info", ".well-known", "robots.txt", "sitemap.xml",
            "wp-login.php", "wp-json", "xmlrpc.php", "server-status", "server-info",
            ".htaccess", "web.config", "package.json", "composer.json", "Gemfile",
        ],
        "api": [
            "api", "api/v1", "api/v2", "api/v3", "graphql", "rest", "rpc",
            "api-docs", "swagger.json", "openapi.json", "swagger", "swagger-ui",
            "docs", "redoc", "api/auth", "api/login", "api/users", "api/admin",
            "api/health", "api/status", "api/config", "api/settings", "api/search",
            "api/upload", "api/download", "api/export", "api/import", "api/webhook",
            "_api", "v1", "v2", "v3", "rest/v1", "json", "xml", "soap",
        ],
        "admin": [
            "admin", "administrator", "panel", "dashboard", "manage", "management",
            "admin.php", "admin.html", "cp", "control", "controlpanel", "backend",
            "cms", "portal", "wp-admin", "phpmyadmin", "adminer", "pgadmin",
            "kibana", "grafana", "prometheus", "jenkins", "gitlab", "sonarqube",
        ],
        "backup": [
            "backup", "backups", "bak", "db.sql", "dump.sql", "database.sql",
            "site.zip", "backup.zip", "backup.tar.gz", "www.zip", "archive.zip",
            "old", "copy", "temp", "tmp", ".bak", "index.bak", "config.bak",
            ".old", "web.config.old", ".env.bak", ".env.old", ".env.production",
        ],
        "config": [
            ".env", ".env.local", ".env.production", ".env.development",
            "config.json", "config.yml", "config.yaml", "config.xml", "config.php",
            ".git/config", ".git/HEAD", ".gitignore", ".dockerignore", "Dockerfile",
            "docker-compose.yml", "docker-compose.yaml", ".htaccess", "web.config",
            "wp-config.php", "settings.py", "application.yml", "application.properties",
        ],
    }

    words = wordlists.get(wordlist_type, wordlists["common"])
    if custom_words:
        words = list(set(words + custom_words))

    base_url = base_url.rstrip("/")
    found_paths = []

    try:
        with httpx.Client(verify=False, timeout=8, follow_redirects=False) as client:
            for word in words[:max_paths]:
                url = f"{base_url}/{word.lstrip('/')}"
                try:
                    resp = client.get(url, headers={"User-Agent": "Mozilla/5.0"})
                    if resp.status_code not in (404, 502, 503):
                        found_paths.append({
                            "path": f"/{word.lstrip('/')}",
                            "status_code": resp.status_code,
                            "content_type": resp.headers.get("content-type", ""),
                            "size": len(resp.content),
                            "redirect_to": resp.headers.get("location", "") if resp.status_code in (301, 302, 307, 308) else "",
                        })
                except Exception:
                    pass
    except Exception as e:
        return {"error": str(e)[:300], "found_paths": found_paths}

    return {"found_paths": found_paths, "total_checked": len(words), "wordlist_used": wordlist_type}


def enumerate_subdomains(domain: str, methods: list | None = None) -> dict:
    """Discover subdomains via certificate transparency and DNS."""
    import httpx

    methods = methods or ["crt_transparency", "common"]
    subdomains = set()
    results = []

    # Clean domain
    domain = domain.replace("https://", "").replace("http://", "").split("/")[0]

    # Method 1: Certificate Transparency (crt.sh)
    if "crt_transparency" in methods:
        try:
            with httpx.Client(timeout=15) as client:
                resp = client.get(f"https://crt.sh/?q=%25.{domain}&output=json")
                if resp.status_code == 200:
                    for entry in resp.json()[:500]:
                        name = entry.get("name_value", "")
                        for sub in name.split("\n"):
                            sub = sub.strip().lower()
                            if sub.endswith(f".{domain}") and "*" not in sub:
                                subdomains.add(sub)
        except Exception as e:
            logger.debug("crt.sh query failed: %s", e)

    # Method 2: Common subdomain prefixes
    if "common" in methods:
        common_prefixes = [
            "www", "mail", "ftp", "smtp", "pop", "imap", "webmail",
            "api", "dev", "staging", "test", "beta", "alpha", "demo",
            "admin", "portal", "app", "mobile", "m", "cdn", "static",
            "img", "images", "media", "assets", "files", "docs",
            "blog", "forum", "support", "help", "status", "monitor",
            "vpn", "remote", "gateway", "proxy", "ns1", "ns2",
            "db", "database", "mysql", "postgres", "redis", "elastic",
            "git", "gitlab", "github", "bitbucket", "jenkins", "ci",
            "internal", "intranet", "extranet", "uat", "qa", "pre-prod",
        ]
        for prefix in common_prefixes:
            subdomains.add(f"{prefix}.{domain}")

    # Resolve subdomains
    import socket
    for sub in list(subdomains)[:200]:
        try:
            ip = socket.gethostbyname(sub)
            results.append({"subdomain": sub, "ip": ip, "status": "resolved"})
        except socket.gaierror:
            pass  # Doesn't resolve, skip

    return {
        "domain": domain,
        "subdomains": results,
        "total_found": len(results),
        "methods_used": methods,
    }


def analyze_javascript(js_url: str = "", js_content: str = "") -> dict:
    """Deep analysis of JavaScript for secrets, endpoints, libraries."""
    import httpx

    if js_url and not js_content:
        try:
            with httpx.Client(verify=False, timeout=10) as client:
                resp = client.get(js_url, headers={"User-Agent": "Mozilla/5.0"})
                js_content = resp.text
        except Exception as e:
            return {"error": f"Failed to fetch JS: {e}", "js_url": js_url}

    if not js_content:
        return {"error": "No JS content provided"}

    result = {
        "js_url": js_url,
        "size": len(js_content),
        "urls": [],
        "api_endpoints": [],
        "secrets": [],
        "libraries": [],
        "config_objects": [],
        "comments": [],
    }

    # Extract URLs
    url_pattern = re.compile(r'["\']((https?://[^"\'>\s]+)|(/[a-zA-Z0-9_\-./]+(?:\?[^"\'>\s]*)?))["\']')
    for m in url_pattern.finditer(js_content):
        url = m.group(1)
        if len(url) > 3 and not url.endswith(('.css', '.png', '.jpg', '.gif', '.svg', '.ico', '.woff', '.woff2', '.ttf')):
            result["urls"].append(url)

    # Extract API endpoints (fetch/axios patterns)
    api_patterns = [
        re.compile(r'fetch\(["\']([^"\']+)["\']'),
        re.compile(r'axios\.\w+\(["\']([^"\']+)["\']'),
        re.compile(r'\.(?:get|post|put|delete|patch)\(["\']([^"\']+)["\']'),
        re.compile(r'url:\s*["\']([^"\']+)["\']'),
        re.compile(r'endpoint:\s*["\']([^"\']+)["\']'),
    ]
    for pat in api_patterns:
        for m in pat.finditer(js_content):
            ep = m.group(1)
            if ep.startswith(("/", "http")) and len(ep) > 1:
                result["api_endpoints"].append(ep)

    # Extract secrets
    secret_patterns = [
        (r'(?:api[_-]?key|apikey)\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', "API Key"),
        (r'(?:secret|token|password|passwd|pwd)\s*[:=]\s*["\']([^"\']{8,})["\']', "Secret/Token"),
        (r'(?:AWS_ACCESS_KEY_ID|aws_access_key)\s*[:=]\s*["\']([A-Z0-9]{20})["\']', "AWS Access Key"),
        (r'(?:AWS_SECRET_ACCESS_KEY|aws_secret_key)\s*[:=]\s*["\']([a-zA-Z0-9/+=]{40})["\']', "AWS Secret Key"),
        (r'(?:GOOGLE_API_KEY|google_api_key)\s*[:=]\s*["\']([a-zA-Z0-9_\-]{39})["\']', "Google API Key"),
        (r'(?:ghp_|gho_|ghu_|ghs_|ghr_)[A-Za-z0-9_]{36,}', "GitHub Token"),
        (r'sk-[a-zA-Z0-9]{20,}', "OpenAI API Key"),
        (r'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}', "JWT Token"),
    ]
    for pattern, secret_type in secret_patterns:
        for m in re.finditer(pattern, js_content, re.IGNORECASE):
            value = m.group(0)[:50]
            result["secrets"].append({
                "type": secret_type,
                "value_preview": value[:20] + "..." if len(value) > 20 else value,
                "line": js_content[:m.start()].count("\n") + 1,
            })

    # Detect libraries/frameworks
    lib_patterns = [
        (r'React\.createElement|__NEXT_DATA__|_app\.js', "React/Next.js"),
        (r'angular\.module|ng-app|ng-controller', "AngularJS"),
        (r'Vue\.component|createApp|__vue__', "Vue.js"),
        (r'jQuery|\\$\.\w+\(', "jQuery"),
        (r'lodash|_\.map|_\.filter', "Lodash"),
        (r'moment\(\)|moment\.', "Moment.js"),
        (r'axios\.create|axios\.defaults', "Axios"),
        (r'socket\.io|io\.connect', "Socket.IO"),
    ]
    for pattern, lib_name in lib_patterns:
        if re.search(pattern, js_content):
            result["libraries"].append(lib_name)

    # Deduplicate
    result["urls"] = list(set(result["urls"]))[:100]
    result["api_endpoints"] = list(set(result["api_endpoints"]))[:100]

    return result


def discover_api_schema(base_url: str, api_type: str = "rest") -> dict:
    """Discover API schemas (OpenAPI, GraphQL introspection, WSDL)."""
    import httpx

    base_url = base_url.rstrip("/")
    result = {"api_type": api_type, "endpoints": [], "schema_found": False, "schema_url": "", "auth_methods": []}

    headers = {"User-Agent": "Mozilla/5.0", "Accept": "application/json"}

    if api_type == "rest":
        # Try common OpenAPI/Swagger paths
        schema_paths = [
            "/openapi.json", "/swagger.json", "/api-docs", "/swagger/v1/swagger.json",
            "/swagger-ui", "/docs", "/redoc", "/.well-known/openapi", "/api/docs",
            "/api/swagger.json", "/api/openapi.json", "/v1/api-docs", "/v2/api-docs",
        ]
        try:
            with httpx.Client(verify=False, timeout=8, follow_redirects=True) as client:
                for path in schema_paths:
                    try:
                        resp = client.get(f"{base_url}{path}", headers=headers)
                        if resp.status_code == 200 and ("openapi" in resp.text.lower() or "swagger" in resp.text.lower() or "paths" in resp.text.lower()):
                            result["schema_found"] = True
                            result["schema_url"] = f"{base_url}{path}"
                            # Parse basic endpoint info
                            try:
                                schema = resp.json()
                                paths = schema.get("paths", {})
                                for path_key, methods in list(paths.items())[:50]:
                                    for method, details in methods.items():
                                        if method.upper() in ("GET", "POST", "PUT", "DELETE", "PATCH"):
                                            result["endpoints"].append({
                                                "url": f"{base_url}{path_key}",
                                                "method": method.upper(),
                                                "summary": (details.get("summary") or "")[:100],
                                                "params": [p.get("name") for p in details.get("parameters", [])],
                                            })
                                # Auth methods
                                security_schemes = schema.get("components", {}).get("securitySchemes", {})
                                result["auth_methods"] = list(security_schemes.keys())[:10]
                            except Exception:
                                pass
                            break
                    except Exception:
                        pass
        except Exception:
            pass

    elif api_type == "graphql":
        # GraphQL introspection
        graphql_paths = ["/graphql", "/gql", "/api/graphql", "/v1/graphql"]
        introspection_query = '{"query":"{ __schema { types { name kind } queryType { name } mutationType { name } } }"}'
        try:
            with httpx.Client(verify=False, timeout=8) as client:
                for path in graphql_paths:
                    try:
                        resp = client.post(
                            f"{base_url}{path}",
                            content=introspection_query,
                            headers={**headers, "Content-Type": "application/json"},
                        )
                        if resp.status_code == 200 and "__schema" in resp.text:
                            result["schema_found"] = True
                            result["schema_url"] = f"{base_url}{path}"
                            data = resp.json().get("data", {}).get("__schema", {})
                            types = data.get("types", [])
                            result["endpoints"] = [
                                {"name": t["name"], "kind": t["kind"]}
                                for t in types if not t["name"].startswith("__")
                            ][:100]
                            break
                    except Exception:
                        pass
        except Exception:
            pass

    return result


def interact_form(
    form_url: str,
    form_action: str,
    fields: list,
    method: str = "POST",
    submit: bool = True,
) -> dict:
    """Fill and submit a form via HTTP."""
    import httpx
    from app.core.ssrf import is_ssrf_blocked_url

    if is_ssrf_blocked_url(form_action):
        return {"error": "Form action URL blocked by SSRF protection"}

    result = {"form_url": form_url, "form_action": form_action, "submitted": False}

    # Build form data
    form_data = {}
    for field in fields:
        form_data[field.get("name", "")] = field.get("value", "")

    if not submit:
        result["prepared_data"] = form_data
        return result

    try:
        with httpx.Client(verify=False, timeout=15, follow_redirects=False) as client:
            headers = {"User-Agent": "Mozilla/5.0"}
            if method.upper() == "POST":
                resp = client.post(form_action, data=form_data, headers=headers)
            else:
                resp = client.get(form_action, params=form_data, headers=headers)

            result["submitted"] = True
            result["status_code"] = resp.status_code
            result["response_headers"] = dict(resp.headers)
            result["response_body_preview"] = resp.text[:2000]
            result["redirects"] = [str(r.url) for r in resp.history] if hasattr(resp, "history") else []
            result["cookies_set"] = [
                {"name": name, "value": value[:50]}
                for name, value in resp.cookies.items()
            ]
    except Exception as e:
        result["error"] = str(e)[:300]

    return result
