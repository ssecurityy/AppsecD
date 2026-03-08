"""DAST checks: secret & exposure — cloud metadata, git, env files, docker, CI/CD, secrets in response, GraphQL introspection, source maps."""
from ..base import DastResult, HEADERS, TIMEOUT, safe_get, safe_request, USER_AGENTS
import httpx, logging, re, json, time
from urllib.parse import urlparse, urljoin

logger = logging.getLogger(__name__)


# ─── Cloud Metadata Exposure ────────────────────────────────

def check_cloud_metadata_exposure(target_url: str) -> DastResult:
    """Check AWS/GCP/Azure metadata endpoints via URL parameters."""
    result = DastResult(
        check_id="DAST-CLOUD-01",
        title="Cloud Metadata Exposure",
        owasp_ref="A05:2021",
        cwe_id="CWE-918",
    )

    parsed = urlparse(target_url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    metadata_endpoints = [
        {
            "provider": "AWS",
            "url": "http://169.254.169.254/latest/meta-data/",
            "indicators": ["ami-id", "instance-id", "hostname", "local-ipv4", "security-credentials"],
        },
        {
            "provider": "AWS IMDSv2",
            "url": "http://169.254.169.254/latest/api/token",
            "indicators": ["token", "ttl"],
        },
        {
            "provider": "GCP",
            "url": "http://metadata.google.internal/computeMetadata/v1/",
            "indicators": ["project", "instance", "attributes", "zone"],
        },
        {
            "provider": "Azure",
            "url": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            "indicators": ["compute", "network", "vmId", "subscriptionId"],
        },
        {
            "provider": "DigitalOcean",
            "url": "http://169.254.169.254/metadata/v1/",
            "indicators": ["droplet_id", "hostname", "region"],
        },
    ]

    url_params = ["url", "redirect", "proxy", "fetch", "src", "dest", "uri", "link"]
    findings = []

    # Test via URL parameters
    for param in url_params:
        for meta in metadata_endpoints:
            test_url = f"{base}/?{param}={meta['url']}"
            try:
                with httpx.Client(timeout=httpx.Timeout(8.0), headers=HEADERS, verify=False, follow_redirects=False) as client:
                    r = client.get(test_url)
                    if r.status_code == 200:
                        body = (r.text or "").lower()
                        for ind in meta["indicators"]:
                            if ind.lower() in body:
                                findings.append({"provider": meta["provider"], "param": param, "indicator": ind, "url": test_url})
                                break
            except Exception:
                continue
            if findings:
                break
        if findings:
            break

    # Direct metadata endpoint access (in case app is running on cloud)
    if not findings:
        for meta in metadata_endpoints[:3]:
            try:
                extra_headers = {}
                if meta["provider"] == "GCP":
                    extra_headers["Metadata-Flavor"] = "Google"
                with httpx.Client(timeout=httpx.Timeout(3.0), headers={**HEADERS, **extra_headers}, verify=False, follow_redirects=True) as client:
                    r = client.get(meta["url"])
                    if r.status_code == 200:
                        body = (r.text or "").lower()
                        for ind in meta["indicators"]:
                            if ind.lower() in body:
                                findings.append({"provider": meta["provider"], "param": "direct", "indicator": ind, "url": meta["url"]})
                                break
            except Exception:
                continue

    result.details = {"providers_tested": [m["provider"] for m in metadata_endpoints], "params_tested": url_params, "findings": findings[:5]}

    if findings:
        result.status = "failed"
        result.severity = "critical"
        f = findings[0]
        result.description = f"Cloud metadata exposed ({f['provider']}) via {f['param']} parameter"
        result.evidence = f"Provider: {f['provider']}, Indicator: {f['indicator']}"
        result.remediation = "Block requests to metadata IPs (169.254.169.254, metadata.google.internal). Use IMDSv2 on AWS. Implement network-level controls."
        result.reproduction_steps = f"1. GET {f['url']}\n2. Found cloud metadata indicator: {f['indicator']}"
    else:
        result.status = "passed"
        result.description = "No cloud metadata exposure detected"

    return result


# ─── Git Exposure ────────────────────────────────────────────

def check_git_exposure(target_url: str) -> DastResult:
    """Check if .git/HEAD, .git/config, .git/index are accessible."""
    result = DastResult(
        check_id="DAST-GIT-01",
        title="Git Repository Exposure",
        owasp_ref="A05:2021",
        cwe_id="CWE-538",
    )

    parsed = urlparse(target_url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    git_paths = [
        {"path": "/.git/HEAD", "indicators": ["ref:", "refs/heads/"]},
        {"path": "/.git/config", "indicators": ["[core]", "[remote", "repositoryformatversion", "[branch"]},
        {"path": "/.git/index", "indicators": []},
        {"path": "/.git/COMMIT_EDITMSG", "indicators": []},
        {"path": "/.git/description", "indicators": ["unnamed repository"]},
        {"path": "/.git/info/exclude", "indicators": []},
        {"path": "/.git/logs/HEAD", "indicators": ["commit", "clone"]},
    ]

    exposed = []

    for git_item in git_paths:
        test_url = f"{base}{git_item['path']}"
        try:
            with httpx.Client(timeout=TIMEOUT, headers=HEADERS, verify=False, follow_redirects=True) as client:
                r = client.get(test_url)
                if r.status_code == 200 and len(r.text or "") > 0:
                    body = r.text or ""
                    if git_item["indicators"]:
                        for ind in git_item["indicators"]:
                            if ind in body:
                                exposed.append({"path": git_item["path"], "indicator": ind})
                                break
                    else:
                        # For binary files like .git/index, check for non-HTML content
                        ct = r.headers.get("content-type", "")
                        if "text/html" not in ct and len(body) > 10:
                            exposed.append({"path": git_item["path"], "indicator": "non-HTML content"})
        except Exception:
            continue

    result.details = {"paths_checked": [g["path"] for g in git_paths], "exposed": exposed}
    result.request_raw = f"GET {base}/.git/HEAD HTTP/1.1\nHost: {parsed.netloc}"

    if exposed:
        result.status = "failed"
        result.severity = "critical"
        result.description = f"Git repository exposed: {len(exposed)} file(s) accessible"
        result.evidence = "; ".join(f"{e['path']} ({e['indicator']})" for e in exposed[:5])
        result.remediation = "Block access to .git directory in web server configuration. Remove .git from deployed files. Use .gitignore and proper deployment pipelines."
        result.reproduction_steps = f"1. GET {base}{exposed[0]['path']}\n2. Found git file content with indicator: {exposed[0]['indicator']}"
    else:
        result.status = "passed"
        result.description = "No git repository files exposed"

    return result


# ─── Environment File Exposure ───────────────────────────────

def check_env_file_exposure(target_url: str) -> DastResult:
    """Check .env, .env.local, .env.production, .env.development, .env.staging."""
    result = DastResult(
        check_id="DAST-ENVFILE-01",
        title="Environment File Exposure",
        owasp_ref="A05:2021",
        cwe_id="CWE-538",
    )

    parsed = urlparse(target_url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    env_files = [
        "/.env",
        "/.env.local",
        "/.env.production",
        "/.env.development",
        "/.env.staging",
        "/.env.backup",
        "/.env.example",
        "/.env.test",
        "/env",
        "/env.json",
    ]

    env_indicators = ["password", "secret", "api_key", "key=", "database", "db_", "redis", "token=",
                      "aws_", "access_key", "private", "smtp", "mail_password", "jwt_secret"]

    exposed = []

    for env_file in env_files:
        test_url = f"{base}{env_file}"
        try:
            with httpx.Client(timeout=TIMEOUT, headers=HEADERS, verify=False, follow_redirects=True) as client:
                r = client.get(test_url)
                if r.status_code == 200 and len(r.text or "") > 5:
                    body = (r.text or "").lower()
                    ct = r.headers.get("content-type", "").lower()
                    # Avoid false positives from HTML error pages
                    if "text/html" in ct and "<html" in body:
                        continue
                    for ind in env_indicators:
                        if ind in body:
                            exposed.append({"path": env_file, "indicator": ind, "size": len(r.text or "")})
                            break
        except Exception:
            continue

    result.details = {"files_checked": env_files, "exposed": exposed}
    result.request_raw = f"GET {base}/.env HTTP/1.1\nHost: {parsed.netloc}"

    if exposed:
        result.status = "failed"
        result.severity = "critical"
        result.description = f"Environment file(s) exposed: {len(exposed)} file(s) with sensitive data"
        result.evidence = "; ".join(f"{e['path']} contains '{e['indicator']}' ({e['size']} bytes)" for e in exposed[:5])
        result.remediation = "Block access to .env files in web server configuration. Never deploy .env files to production web root. Use server environment variables instead."
        result.reproduction_steps = f"1. GET {base}{exposed[0]['path']}\n2. Found sensitive data indicator: {exposed[0]['indicator']}"
    else:
        result.status = "passed"
        result.description = "No environment files exposed"

    return result


# ─── Docker Exposure ─────────────────────────────────────────

def check_docker_exposure(target_url: str) -> DastResult:
    """Check Dockerfile, docker-compose.yml, docker-compose.yaml, .dockerignore exposure."""
    result = DastResult(
        check_id="DAST-DOCKER-01",
        title="Docker Configuration Exposure",
        owasp_ref="A05:2021",
        cwe_id="CWE-538",
    )

    parsed = urlparse(target_url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    docker_files = [
        {"path": "/Dockerfile", "indicators": ["FROM", "RUN", "COPY", "EXPOSE", "CMD", "ENTRYPOINT"]},
        {"path": "/docker-compose.yml", "indicators": ["services:", "image:", "ports:", "volumes:", "environment:"]},
        {"path": "/docker-compose.yaml", "indicators": ["services:", "image:", "ports:", "volumes:", "environment:"]},
        {"path": "/.dockerignore", "indicators": ["node_modules", ".git", ".env", "*.log"]},
        {"path": "/docker-compose.prod.yml", "indicators": ["services:", "image:", "ports:"]},
        {"path": "/docker-compose.override.yml", "indicators": ["services:", "image:"]},
    ]

    exposed = []

    for docker_file in docker_files:
        test_url = f"{base}{docker_file['path']}"
        try:
            with httpx.Client(timeout=TIMEOUT, headers=HEADERS, verify=False, follow_redirects=True) as client:
                r = client.get(test_url)
                if r.status_code == 200 and len(r.text or "") > 5:
                    body = r.text or ""
                    ct = r.headers.get("content-type", "").lower()
                    if "text/html" in ct and "<html" in body.lower():
                        continue
                    matches = sum(1 for ind in docker_file["indicators"] if ind in body)
                    if matches >= 2:
                        exposed.append({"path": docker_file["path"], "matches": matches})
        except Exception:
            continue

    result.details = {"files_checked": [d["path"] for d in docker_files], "exposed": exposed}
    result.request_raw = f"GET {base}/Dockerfile HTTP/1.1\nHost: {parsed.netloc}"

    if exposed:
        result.status = "failed"
        result.severity = "high"
        result.description = f"Docker configuration exposed: {len(exposed)} file(s) accessible"
        result.evidence = "; ".join(f"{e['path']} ({e['matches']} Docker keywords matched)" for e in exposed[:5])
        result.remediation = "Block access to Docker configuration files in web server. Remove Docker files from deployed artifacts. Use .dockerignore properly."
        result.reproduction_steps = f"1. GET {base}{exposed[0]['path']}\n2. Found Docker configuration content"
    else:
        result.status = "passed"
        result.description = "No Docker configuration files exposed"

    return result


# ─── CI/CD Exposure ──────────────────────────────────────────

def check_ci_cd_exposure(target_url: str) -> DastResult:
    """Check .github/workflows/main.yml, .gitlab-ci.yml, Jenkinsfile, .circleci/config.yml, .travis.yml."""
    result = DastResult(
        check_id="DAST-CICD-01",
        title="CI/CD Configuration Exposure",
        owasp_ref="A05:2021",
        cwe_id="CWE-538",
    )

    parsed = urlparse(target_url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    cicd_files = [
        {"path": "/.github/workflows/main.yml", "indicators": ["on:", "jobs:", "steps:", "runs-on:", "uses:"]},
        {"path": "/.github/workflows/ci.yml", "indicators": ["on:", "jobs:", "steps:", "runs-on:"]},
        {"path": "/.github/workflows/deploy.yml", "indicators": ["on:", "jobs:", "deploy"]},
        {"path": "/.gitlab-ci.yml", "indicators": ["stages:", "script:", "image:", "before_script:"]},
        {"path": "/Jenkinsfile", "indicators": ["pipeline", "agent", "stages", "steps", "stage("]},
        {"path": "/.circleci/config.yml", "indicators": ["version:", "jobs:", "workflows:", "steps:"]},
        {"path": "/.travis.yml", "indicators": ["language:", "script:", "install:", "before_script:"]},
        {"path": "/azure-pipelines.yml", "indicators": ["trigger:", "pool:", "steps:", "task:"]},
        {"path": "/bitbucket-pipelines.yml", "indicators": ["pipelines:", "step:", "script:"]},
    ]

    exposed = []

    for cicd_file in cicd_files:
        test_url = f"{base}{cicd_file['path']}"
        try:
            with httpx.Client(timeout=TIMEOUT, headers=HEADERS, verify=False, follow_redirects=True) as client:
                r = client.get(test_url)
                if r.status_code == 200 and len(r.text or "") > 10:
                    body = r.text or ""
                    ct = r.headers.get("content-type", "").lower()
                    if "text/html" in ct and "<html" in body.lower():
                        continue
                    matches = sum(1 for ind in cicd_file["indicators"] if ind in body)
                    if matches >= 2:
                        # Check for secrets in CI/CD config
                        has_secrets = any(kw in body.lower() for kw in ["secret", "password", "token", "api_key", "access_key"])
                        exposed.append({"path": cicd_file["path"], "matches": matches, "has_secrets": has_secrets})
        except Exception:
            continue

    result.details = {"files_checked": [c["path"] for c in cicd_files], "exposed": exposed}
    result.request_raw = f"GET {base}/.github/workflows/main.yml HTTP/1.1\nHost: {parsed.netloc}"

    if exposed:
        has_secrets = any(e["has_secrets"] for e in exposed)
        result.status = "failed"
        result.severity = "critical" if has_secrets else "high"
        result.description = f"CI/CD configuration exposed: {len(exposed)} file(s) accessible" + (" (contains secret references)" if has_secrets else "")
        result.evidence = "; ".join(f"{e['path']} ({e['matches']} CI/CD keywords" + (", secrets found" if e["has_secrets"] else "") + ")" for e in exposed[:5])
        result.remediation = "Block access to CI/CD configuration files. Remove pipeline configs from web root. Use environment variables for secrets, not hardcoded values."
        result.reproduction_steps = f"1. GET {base}{exposed[0]['path']}\n2. Found CI/CD configuration content"
    else:
        result.status = "passed"
        result.description = "No CI/CD configuration files exposed"

    return result


# ─── Secret in Response ──────────────────────────────────────

def check_secret_in_response(target_url: str) -> DastResult:
    """Scan response HTML/JS for API keys (AKIA, sk-, ghp_, private keys, AWS secrets)."""
    result = DastResult(
        check_id="DAST-SECRET-01",
        title="Secrets Leaked in Response",
        owasp_ref="A02:2021",
        cwe_id="CWE-200",
    )

    parsed = urlparse(target_url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    secret_patterns = [
        ("AWS Access Key", r'AKIA[0-9A-Z]{16}'),
        ("AWS Secret Key", r'(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})'),
        ("OpenAI API Key", r'sk-[A-Za-z0-9]{20,}'),
        ("GitHub Token", r'ghp_[A-Za-z0-9]{36}'),
        ("GitHub OAuth", r'gho_[A-Za-z0-9]{36}'),
        ("GitLab Token", r'glpat-[A-Za-z0-9\-]{20,}'),
        ("Slack Token", r'xox[baprs]-[A-Za-z0-9\-]+'),
        ("Private Key", r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----'),
        ("Stripe Key", r'sk_live_[A-Za-z0-9]{24,}'),
        ("Stripe Publishable", r'pk_live_[A-Za-z0-9]{24,}'),
        ("Google API Key", r'AIza[0-9A-Za-z\-_]{35}'),
        ("Heroku API Key", r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'),
        ("Generic API Key", r'(?:api[_-]?key|apikey)\s*[=:]\s*["\']?([A-Za-z0-9]{20,})["\']?'),
        ("Generic Secret", r'(?:secret|SECRET)\s*[=:]\s*["\']?([A-Za-z0-9/+=]{16,})["\']?'),
        ("Bearer Token", r'[Bb]earer\s+[A-Za-z0-9\-._~+/]+=*'),
    ]

    pages_to_check = [
        target_url,
        f"{base}/",
        f"{base}/login",
        f"{base}/app",
    ]

    findings = []

    for page_url in pages_to_check:
        try:
            with httpx.Client(timeout=TIMEOUT, headers=HEADERS, verify=False, follow_redirects=True) as client:
                r = client.get(page_url)
                if r.status_code != 200:
                    continue
                body = r.text or ""

                # Also check inline scripts and JS files
                script_srcs = re.findall(r'<script[^>]*src\s*=\s*["\']([^"\']+\.js)["\']', body, re.IGNORECASE)

                # Check main page body
                for name, pattern in secret_patterns:
                    matches = re.findall(pattern, body)
                    if matches:
                        for match in matches[:2]:
                            match_str = match if isinstance(match, str) else str(match)
                            # Mask the secret for evidence
                            masked = match_str[:8] + "..." + match_str[-4:] if len(match_str) > 12 else match_str[:4] + "..."
                            findings.append({"type": name, "page": page_url, "masked_value": masked, "source": "html"})

                # Check linked JS files
                for js_src in script_srcs[:5]:
                    js_url = urljoin(page_url, js_src)
                    try:
                        js_resp = safe_get(js_url)
                        if js_resp and js_resp.status_code == 200:
                            js_body = js_resp.text or ""
                            for name, pattern in secret_patterns:
                                js_matches = re.findall(pattern, js_body)
                                if js_matches:
                                    for match in js_matches[:1]:
                                        match_str = match if isinstance(match, str) else str(match)
                                        masked = match_str[:8] + "..." + match_str[-4:] if len(match_str) > 12 else match_str[:4] + "..."
                                        findings.append({"type": name, "page": js_url, "masked_value": masked, "source": "javascript"})
                    except Exception:
                        continue

        except Exception:
            continue

    # Deduplicate by type+page
    seen = set()
    unique_findings = []
    for f in findings:
        key = f"{f['type']}:{f['page']}"
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)

    result.details = {"pages_checked": len(pages_to_check), "patterns_tested": len(secret_patterns), "findings": unique_findings[:15]}

    if unique_findings:
        result.status = "failed"
        has_critical = any(f["type"] in ("AWS Access Key", "AWS Secret Key", "Private Key", "Stripe Key") for f in unique_findings)
        result.severity = "critical" if has_critical else "high"
        result.description = f"Found {len(unique_findings)} secret(s) leaked in responses"
        result.evidence = "; ".join(f"{f['type']}: {f['masked_value']} in {f['source']} at {f['page']}" for f in unique_findings[:5])
        result.remediation = "Remove all hardcoded secrets from client-side code. Use environment variables for server-side secrets. Rotate any exposed credentials immediately."
        result.reproduction_steps = f"1. GET {unique_findings[0]['page']}\n2. Search response for secret patterns\n3. Found: {unique_findings[0]['type']}"
    else:
        result.status = "passed"
        result.description = "No secrets detected in responses"

    return result


# ─── GraphQL Introspection ───────────────────────────────────

def check_graphql_introspection(target_url: str) -> DastResult:
    """Full GraphQL introspection query at /graphql, /api/graphql, /graphql/console."""
    result = DastResult(
        check_id="DAST-GQLINTROSPECT-01",
        title="GraphQL Introspection Enabled",
        owasp_ref="A05:2021",
        cwe_id="CWE-200",
    )

    parsed = urlparse(target_url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    graphql_paths = ["/graphql", "/api/graphql", "/graphql/console", "/v1/graphql", "/api/v1/graphql", "/gql"]

    introspection_query = json.dumps({
        "query": """
            query IntrospectionQuery {
                __schema {
                    queryType { name }
                    mutationType { name }
                    types {
                        name
                        kind
                        fields {
                            name
                            type { name kind }
                        }
                    }
                }
            }
        """
    })

    findings = []

    for gql_path in graphql_paths:
        test_url = f"{base}{gql_path}"

        # POST method
        try:
            with httpx.Client(timeout=TIMEOUT, headers={**HEADERS, "Content-Type": "application/json"}, verify=False, follow_redirects=True) as client:
                r = client.post(test_url, content=introspection_query)
                if r.status_code == 200:
                    body = r.text or ""
                    if "__schema" in body and "queryType" in body:
                        try:
                            resp_json = r.json()
                            types = resp_json.get("data", {}).get("__schema", {}).get("types", [])
                            type_names = [t.get("name", "") for t in types if not t.get("name", "").startswith("__")]
                            findings.append({
                                "path": gql_path,
                                "method": "POST",
                                "types_count": len(type_names),
                                "sample_types": type_names[:10],
                            })
                        except Exception:
                            findings.append({"path": gql_path, "method": "POST", "types_count": 0, "sample_types": []})
        except Exception:
            pass

        # GET method with query param
        try:
            get_query = '{ __schema { types { name } } }'
            with httpx.Client(timeout=TIMEOUT, headers=HEADERS, verify=False, follow_redirects=True) as client:
                r = client.get(test_url, params={"query": get_query})
                if r.status_code == 200:
                    body = r.text or ""
                    if "__schema" in body and "types" in body:
                        findings.append({"path": gql_path, "method": "GET", "types_count": 0, "sample_types": []})
        except Exception:
            pass

        if findings:
            break

    result.details = {"paths_tested": graphql_paths, "findings": findings[:5]}
    result.request_raw = f"POST {base}/graphql HTTP/1.1\nContent-Type: application/json\n\n{introspection_query[:300]}"

    if findings:
        result.status = "failed"
        result.severity = "medium"
        f = findings[0]
        result.description = f"GraphQL introspection enabled at {f['path']} ({f['method']})"
        if f["types_count"] > 0:
            result.evidence = f"Schema exposed with {f['types_count']} types: {', '.join(f['sample_types'][:5])}"
        else:
            result.evidence = f"Introspection query accepted at {f['path']} via {f['method']}"
        result.remediation = "Disable GraphQL introspection in production. Use persisted queries. Implement query depth limiting and complexity analysis."
        result.reproduction_steps = f"1. {f['method']} {base}{f['path']} with introspection query\n2. Schema is fully enumerable"
    else:
        result.status = "passed"
        result.description = "GraphQL introspection is not enabled"

    return result


# ─── Source Map Exposure ─────────────────────────────────────

def check_source_map_exposure(target_url: str) -> DastResult:
    """Check for .js.map files. Parse main page for script tags, check each with .map suffix."""
    result = DastResult(
        check_id="DAST-SRCMAP-01",
        title="JavaScript Source Map Exposure",
        owasp_ref="A05:2021",
        cwe_id="CWE-540",
    )

    parsed = urlparse(target_url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    # Fetch main page to find script tags
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

    # Extract script src attributes
    script_srcs = re.findall(r'<script[^>]*src\s*=\s*["\']([^"\']+\.js)["\']', html, re.IGNORECASE)

    # Also check for sourceMappingURL in inline scripts
    source_map_urls = re.findall(r'//[#@]\s*sourceMappingURL\s*=\s*(\S+)', html)

    exposed_maps = []

    # Check each JS file for .map
    for js_src in script_srcs[:15]:
        js_url = urljoin(target_url, js_src)
        map_url = js_url + ".map"

        try:
            with httpx.Client(timeout=TIMEOUT, headers=HEADERS, verify=False, follow_redirects=True) as client:
                # Check the .map file
                r = client.get(map_url)
                if r.status_code == 200 and len(r.text or "") > 50:
                    body = r.text or ""
                    ct = r.headers.get("content-type", "")
                    if "json" in ct or '"sources"' in body or '"mappings"' in body or '"version"' in body:
                        exposed_maps.append({"js_file": js_src, "map_url": map_url, "size": len(body)})

                # Also check if JS file has sourceMappingURL header
                js_resp = client.get(js_url)
                if js_resp.status_code == 200:
                    sm_header = js_resp.headers.get("sourcemap", "") or js_resp.headers.get("x-sourcemap", "")
                    if sm_header:
                        sm_url = urljoin(js_url, sm_header)
                        exposed_maps.append({"js_file": js_src, "map_url": sm_url, "size": 0, "via": "header"})

                    # Check sourceMappingURL in JS content
                    js_body = js_resp.text or ""
                    sm_matches = re.findall(r'//[#@]\s*sourceMappingURL\s*=\s*(\S+)', js_body)
                    for sm in sm_matches:
                        sm_full_url = urljoin(js_url, sm)
                        try:
                            sm_resp = client.get(sm_full_url)
                            if sm_resp.status_code == 200 and ('"sources"' in (sm_resp.text or "") or '"mappings"' in (sm_resp.text or "")):
                                exposed_maps.append({"js_file": js_src, "map_url": sm_full_url, "size": len(sm_resp.text or ""), "via": "sourceMappingURL"})
                        except Exception:
                            pass
        except Exception:
            continue

    # Check directly referenced source map URLs
    for sm_url in source_map_urls:
        full_url = urljoin(target_url, sm_url)
        try:
            with httpx.Client(timeout=TIMEOUT, headers=HEADERS, verify=False, follow_redirects=True) as client:
                r = client.get(full_url)
                if r.status_code == 200 and ('"sources"' in (r.text or "") or '"mappings"' in (r.text or "")):
                    exposed_maps.append({"js_file": "inline", "map_url": full_url, "size": len(r.text or ""), "via": "inline_reference"})
        except Exception:
            continue

    # Deduplicate
    seen_urls = set()
    unique_maps = []
    for m in exposed_maps:
        if m["map_url"] not in seen_urls:
            seen_urls.add(m["map_url"])
            unique_maps.append(m)

    result.details = {"scripts_found": len(script_srcs), "maps_exposed": unique_maps[:10]}

    if unique_maps:
        result.status = "failed"
        result.severity = "medium"
        result.description = f"Source maps exposed: {len(unique_maps)} .map file(s) accessible"
        result.evidence = "; ".join(f"{m['map_url']} ({m['size']} bytes)" for m in unique_maps[:5])
        result.remediation = "Remove source map files from production. Disable sourceMappingURL comments in production builds. Configure web server to block .map file access."
        result.reproduction_steps = f"1. Find JS files in page HTML\n2. Append .map to each JS URL\n3. Found accessible source map: {unique_maps[0]['map_url']}"
    else:
        result.status = "passed"
        result.description = "No source map files exposed"

    return result
