"""DAST crawler: katana spider, arjun parameter discovery, recursive directory scan."""
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import time
import uuid
from pathlib import Path
from typing import Callable
from urllib.parse import urlparse, urljoin, parse_qs, urlencode

import httpx

from .base import (
    DastResult,
    HEADERS,
    USER_AGENTS,
    TIMEOUT,
    DATA_ROOT,
    BROWSER_HEADERS,
    ScanContext,
)
from .wordlists import get_wordlist_path, FULL_WORDLIST_PATHS

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Tool paths
# ---------------------------------------------------------------------------
def _find_katana() -> str:
    """Find katana binary: /usr/local/bin/katana, /usr/bin/katana, or PATH."""
    for p in ("/usr/local/bin/katana", "/usr/bin/katana"):
        if os.path.isfile(p):
            return p
    found = shutil.which("katana")
    return found or "/usr/local/bin/katana"


def _find_ffuf() -> str:
    """Find ffuf binary: /usr/local/bin/ffuf, /usr/bin/ffuf, or PATH."""
    for p in ("/usr/local/bin/ffuf", "/usr/bin/ffuf"):
        if os.path.isfile(p):
            return p
    found = shutil.which("ffuf")
    return found or "/usr/local/bin/ffuf"


def _find_arjun() -> str:
    """Find arjun: venv bin or PATH."""
    venv_arjun = "/opt/navigator/backend/venv/bin/arjun"
    if os.path.isfile(venv_arjun):
        return venv_arjun
    found = shutil.which("arjun")
    return found or venv_arjun


KATANA_BIN = None  # Set at runtime via _find_katana()
ARJUN_BIN = None   # Set at runtime via _find_arjun()
FFUF_BIN = None    # Set at runtime via _find_ffuf()

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
CRAWL_PROGRESS_TTL = 7200  # 2 hours
DEFAULT_CRAWL_TIMEOUT = 300  # 5 minutes per tool invocation
DEFAULT_ARJUN_TIMEOUT = 120  # 2 minutes per endpoint
DEFAULT_FFUF_TIMEOUT = 180  # 3 minutes per directory level
MAX_ARJUN_ENDPOINTS = 30  # cap endpoints sent to arjun
MAX_URLS_PER_CRAWL = 5000  # hard cap on collected URLs
BODY_PREVIEW_LIMIT = 4096  # bytes for body preview in fetch_url_content

# Patterns for URL classification
_API_PATTERNS = re.compile(
    r"/(api|v[0-9]+|graphql|rest|rpc|json|xml|ws|grpc|oauth|auth|token|callback)"
    r"(/|$|\?)",
    re.IGNORECASE,
)
_JS_EXTENSIONS = re.compile(r"\.(js|mjs|cjs|jsx|ts|tsx|map)(\?|$)", re.IGNORECASE)
_STATIC_EXTENSIONS = re.compile(
    r"\.(png|jpg|jpeg|gif|svg|ico|css|woff|woff2|ttf|eot|otf|mp4|mp3|webm|"
    r"webp|avif|pdf|zip|tar|gz|bz2|rar|7z|dmg|exe|msi|deb|rpm)(\?|$)",
    re.IGNORECASE,
)
_FORM_INDICATORS = {"action=", "method=", "enctype=", "form", "input", "submit"}
_INTERESTING_EXTENSIONS = re.compile(
    r"\.(php|asp|aspx|jsp|do|action|cgi|pl|py|rb|cfm|shtml|json|xml|yaml|"
    r"yml|toml|ini|conf|config|env|bak|old|orig|swp|sql|db|sqlite|log|txt|md|csv)(\?|$)",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Redis helpers (same pattern as runner.py)
# ---------------------------------------------------------------------------
_redis_sync = None
_redis_lock = __import__("threading").Lock()


def _get_redis_sync():
    global _redis_sync
    if _redis_sync is None:
        with _redis_lock:
            if _redis_sync is None:
                try:
                    from app.core.config import get_settings
                    import redis as redis_lib

                    _redis_sync = redis_lib.from_url(
                        get_settings().redis_url, decode_responses=True
                    )
                except Exception as exc:
                    logger.warning("Crawler redis init failed: %s", exc)
    return _redis_sync


def _crawl_progress_set(crawl_id: str, data: dict) -> None:
    key = f"dast:crawl:{crawl_id}"
    try:
        r = _get_redis_sync()
        if r:
            r.setex(key, CRAWL_PROGRESS_TTL, json.dumps(data, default=str))
    except Exception as exc:
        logger.warning("Crawl progress redis set failed: %s", exc)


def _crawl_progress_get(crawl_id: str) -> dict | None:
    key = f"dast:crawl:{crawl_id}"
    try:
        r = _get_redis_sync()
        if r:
            raw = r.get(key)
            if raw:
                return json.loads(raw)
    except Exception as exc:
        logger.warning("Crawl progress redis get failed: %s", exc)
    return None


def get_crawl_progress(crawl_id: str) -> dict | None:
    """Public accessor for crawl progress."""
    return _crawl_progress_get(crawl_id)


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------


def _build_auth_headers(auth_config: dict | None) -> dict[str, str]:
    """Convert auth_config dict into HTTP headers suitable for tools and httpx."""
    if not auth_config:
        return {}
    auth_type = auth_config.get("type", "")
    headers: dict[str, str] = {}

    if auth_type == "header":
        name = auth_config.get("name", "Authorization")
        value = auth_config.get("value", "")
        if value:
            headers[name] = value

    elif auth_type == "cookie":
        value = auth_config.get("value", "")
        if value:
            headers["Cookie"] = value

    elif auth_type == "custom_headers":
        custom = auth_config.get("headers", {})
        if isinstance(custom, dict):
            headers.update(custom)

    elif auth_type == "credentials":
        # Basic auth from username:password
        username = auth_config.get("username", "")
        password = auth_config.get("password", "")
        if username:
            import base64

            cred = base64.b64encode(f"{username}:{password}".encode()).decode()
            headers["Authorization"] = f"Basic {cred}"

    return headers


def _auth_headers_to_cli_flags(auth_headers: dict[str, str]) -> list[str]:
    """Convert auth headers dict to CLI -H flags for katana/ffuf."""
    flags: list[str] = []
    for name, value in auth_headers.items():
        flags.extend(["-H", f"{name}: {value}"])
    return flags


# ---------------------------------------------------------------------------
# URL classification
# ---------------------------------------------------------------------------


def _classify_url(url: str, method: str = "GET", body: str = "") -> str:
    """Classify a URL into: api_endpoint, js_file, static_asset, form, page."""
    if _JS_EXTENSIONS.search(url):
        return "js_file"
    if _STATIC_EXTENSIONS.search(url):
        return "static_asset"
    if _API_PATTERNS.search(url):
        return "api_endpoint"
    # Check for form indicators in body content
    if body:
        body_lower = body.lower()
        if any(indicator in body_lower for indicator in _FORM_INDICATORS):
            return "form"
    if method and method.upper() in ("POST", "PUT", "PATCH", "DELETE"):
        return "api_endpoint"
    return "page"


def _extract_parameters_from_url(url: str) -> list[dict]:
    """Extract query parameters from a URL."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    return [
        {"name": name, "values": values, "source": "url", "url": url}
        for name, values in params.items()
    ]


# ---------------------------------------------------------------------------
# Katana crawl
# ---------------------------------------------------------------------------


def _run_katana(
    target_url: str,
    auth_headers: dict[str, str],
    max_depth: int = 3,
    crawl_scope: str = "host",
    timeout: int = DEFAULT_CRAWL_TIMEOUT,
) -> list[dict]:
    """
    Run katana crawler. Returns list of raw result dicts parsed from JSON output.

    Each result dict may contain:
      - request.endpoint, request.method, request.body
      - response.status_code, response.headers, response.body (partial)
      - timestamp
    """
    katana_bin = _find_katana()
    if not os.path.isfile(katana_bin):
        logger.warning("katana binary not found at %s", katana_bin)
        return []

    # Katana field-scope: fqdn=single host, rdn=root+subdomains, dn=domain keyword
    scope_flag = {"host": "-fs", "subdomain": "-fs", "all": "-fs"}
    scope_value = {
        "host": "fqdn",    # single host (www.example.com)
        "subdomain": "rdn",  # root domain + subdomains (*.example.com)
        "all": "dn",       # domain keyword (example)
    }

    cmd = [
        katana_bin,
        "-u", target_url,
        "-duc",        # disable update check (avoids blocking on startup)
        "-jc",         # JavaScript crawling
        "-ef", "png,jpg,jpeg,gif,svg,ico,css,woff,woff2,ttf,eot,otf,mp4,mp3,webm,webp,avif",
        "-d", str(max_depth),
        "-j",          # JSONL output (Katana v1.4+ uses -j/-jsonl, not -json)
        "-silent",
        "-nc",         # no color
        "-timeout", "10",
        "-retry", "2",
        "-rl", "50",   # rate limit (requests/sec)
        "-c", "10",    # concurrency
        "-ct", str(min(120, max(30, timeout // 2))),  # crawl duration limit (seconds)
    ]
    # Known files (robots, sitemap) - Katana v1.4+ requires depth >= 3 for -kf
    if max_depth >= 3:
        cmd = cmd[:4] + ["-kf", "all"] + cmd[4:]

    # Add scope filtering
    scope_key = crawl_scope if crawl_scope in scope_value else "host"
    cmd.extend([scope_flag[scope_key], scope_value[scope_key]])

    # Add auth headers
    for name, value in auth_headers.items():
        cmd.extend(["-H", f"{name}: {value}"])

    logger.info("Running katana: %s", " ".join(cmd[:8]) + " ...")
    results = []

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout,
            env={**os.environ, "HOME": os.environ.get("HOME", "/tmp"), "KATANA_UPDATE_CHECK": "false"},
        )
        stdout = proc.stdout.decode("utf-8", errors="ignore")
        stderr = proc.stderr.decode("utf-8", errors="ignore")

        if proc.returncode != 0 and not stdout.strip():
            logger.warning(
                "katana exited %d: %s", proc.returncode, stderr[:500]
            )
            return []

        for line in stdout.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                results.append(obj)
            except json.JSONDecodeError:
                # Some lines may be plain URLs (non-JSON fallback)
                if line.startswith("http"):
                    results.append({"request": {"endpoint": line, "method": "GET"}})

        logger.info("katana returned %d results", len(results))
    except subprocess.TimeoutExpired:
        logger.warning("katana timed out after %ds", timeout)
    except FileNotFoundError:
        logger.warning("katana not found at %s", katana_bin)
    except Exception as exc:
        logger.error("katana error: %s", exc)

    return results[:MAX_URLS_PER_CRAWL]


def _run_katana_docker(
    target_url: str,
    auth_headers: dict[str, str],
    max_depth: int = 3,
    crawl_scope: str = "host",
    timeout: int = DEFAULT_CRAWL_TIMEOUT,
) -> list[dict]:
    """
    Run katana via Docker when native binary hangs or fails.
    Uses projectdiscovery/katana image. Output: plain URLs, converted to katana-compatible dicts.
    """
    docker_bin = shutil.which("docker")
    if not docker_bin:
        logger.debug("docker not found, cannot use Katana Docker fallback")
        return []

    scope_value = {"host": "fqdn", "subdomain": "rdn", "all": "dn"}
    scope_key = crawl_scope if crawl_scope in scope_value else "host"
    scope = scope_value[scope_key]
    crawl_sec = min(120, max(30, timeout // 2))

    cmd = [
        docker_bin, "run", "--rm",
        "-e", "KATANA_UPDATE_CHECK=false",
        "projectdiscovery/katana:latest",
        "-u", target_url,
        "-duc", "-d", str(max_depth), "-fs", scope,
        "-ef", "png,jpg,jpeg,gif,svg,ico,css,woff,woff2,ttf,eot,otf,mp4,mp3,webm,webp,avif",
        "-silent", "-nc", "-timeout", "10", "-ct", str(crawl_sec),
    ]
    for name, value in auth_headers.items():
        cmd.extend(["-H", f"{name}: {value}"])

    logger.info("Running katana via Docker: %s", target_url)
    results: list[dict] = []
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout,
            env={**os.environ},
        )
        stdout = proc.stdout.decode("utf-8", errors="ignore")
        for line in stdout.strip().splitlines():
            line = line.strip()
            if line.startswith("http") and line not in {r.get("request", {}).get("endpoint") for r in results}:
                results.append({"request": {"endpoint": line, "method": "GET"}})
        logger.info("katana Docker returned %d results", len(results))
    except subprocess.TimeoutExpired:
        logger.warning("katana Docker timed out after %ds", timeout)
    except Exception as exc:
        logger.debug("katana Docker error: %s", exc)
    return results[:MAX_URLS_PER_CRAWL]


def _parse_katana_results(raw_results: list[dict]) -> dict:
    """
    Parse katana JSON results into structured crawl data.

    Returns {urls, api_endpoints, js_files, static_assets, forms, pages, parameters, raw_entries}.
    """
    urls: list[str] = []
    api_endpoints: list[dict] = []
    js_files: list[dict] = []
    static_assets: list[str] = []
    forms: list[dict] = []
    pages: list[dict] = []
    parameters: list[dict] = []
    seen_urls: set[str] = set()
    raw_entries: list[dict] = []

    for item in raw_results:
        # Extract endpoint URL (Katana JSONL: endpoint/url at root or in request)
        request_data = item.get("request") or {}
        if isinstance(request_data, str):
            endpoint = request_data
            method = "GET"
            req_body = ""
        elif isinstance(request_data, dict):
            endpoint = request_data.get("endpoint", "") or request_data.get("url", "")
            method = request_data.get("method", "GET") or "GET"
            req_body = request_data.get("body", "") or ""
        else:
            endpoint = item.get("endpoint", "") or item.get("url", "")
            method = item.get("method", "GET") or "GET"
            req_body = ""
        if not endpoint:
            endpoint = item.get("endpoint", "") or item.get("url", "")
        if not endpoint:
            continue

        # Deduplicate
        url_key = f"{method}:{endpoint}"
        if url_key in seen_urls:
            continue
        seen_urls.add(url_key)
        urls.append(endpoint)

        # Extract response data if present
        response_data = item.get("response", {})
        if isinstance(response_data, dict):
            status_code = response_data.get("status_code", 0)
            resp_headers = response_data.get("headers", {})
            resp_body = response_data.get("body", "")
        else:
            status_code = 0
            resp_headers = {}
            resp_body = ""

        # Build raw entry with full request/response context
        entry = {
            "url": endpoint,
            "method": method.upper(),
            "status_code": status_code,
            "source": item.get("source", ""),
            "tag": item.get("tag", ""),
        }
        if req_body:
            entry["request_body"] = req_body[:2000]
        if resp_headers:
            entry["response_headers"] = (
                resp_headers if isinstance(resp_headers, dict) else {}
            )
        raw_entries.append(entry)

        # Extract parameters from URL
        url_params = _extract_parameters_from_url(endpoint)
        parameters.extend(url_params)

        # Extract parameters from request body (form data)
        if req_body:
            for pair in req_body.split("&"):
                if "=" in pair:
                    pname = pair.split("=", 1)[0]
                    if pname:
                        parameters.append(
                            {
                                "name": pname,
                                "values": [pair.split("=", 1)[1] if "=" in pair else ""],
                                "source": "body",
                                "url": endpoint,
                                "method": method.upper(),
                            }
                        )

        # Classify
        category = _classify_url(endpoint, method, resp_body or req_body)

        if category == "js_file":
            js_files.append(
                {
                    "url": endpoint,
                    "status_code": status_code,
                    "source": item.get("source", ""),
                }
            )
        elif category == "static_asset":
            static_assets.append(endpoint)
        elif category == "api_endpoint":
            api_endpoints.append(
                {
                    "url": endpoint,
                    "method": method.upper(),
                    "status_code": status_code,
                    "parameters": [p["name"] for p in url_params],
                    "body_params": (
                        [
                            p.split("=", 1)[0]
                            for p in req_body.split("&")
                            if "=" in p
                        ]
                        if req_body
                        else []
                    ),
                }
            )
        elif category == "form":
            forms.append(
                {
                    "url": endpoint,
                    "method": method.upper(),
                    "parameters": [p["name"] for p in url_params],
                }
            )
        else:
            pages.append(
                {
                    "url": endpoint,
                    "method": method.upper(),
                    "status_code": status_code,
                }
            )

    # Deduplicate parameters by (name, url)
    seen_params: set[str] = set()
    unique_params: list[dict] = []
    for p in parameters:
        key = f"{p['name']}:{p.get('url', '')}"
        if key not in seen_params:
            seen_params.add(key)
            unique_params.append(p)

    return {
        "urls": urls,
        "api_endpoints": api_endpoints,
        "js_files": js_files,
        "static_assets": static_assets,
        "forms": forms,
        "pages": pages,
        "parameters": unique_params,
        "raw_entries": raw_entries,
    }


# ---------------------------------------------------------------------------
# spider_rs fallback (optional - pip install spider_rs)
# ---------------------------------------------------------------------------
def _run_spider_rs(target_url: str, max_urls: int = 500) -> list[dict]:
    """
    Use spider_rs when installed - high-performance Rust crawler.
    Returns list in katana-compatible format.
    """
    try:
        from spider_rs import Website

        website = Website(target_url)
        website.crawl()
        links = website.get_links() or []
    except ImportError:
        return []
    except Exception as e:
        logger.debug("spider_rs crawl failed: %s", e)
        return []

    return [
        {"request": {"endpoint": url, "method": "GET"}}
        for url in links[:max_urls]
        if url and isinstance(url, str) and url.startswith("http")
    ]


# ---------------------------------------------------------------------------
# httpx fallback crawl (when katana is not available)
# ---------------------------------------------------------------------------


def _httpx_fallback_crawl(
    target_url: str,
    auth_headers: dict[str, str],
    max_depth: int = 2,
    max_urls: int = 400,
) -> list[dict]:
    """
    Basic link-extraction crawl using httpx + regex.
    Used when katana is unavailable.
    """
    from html.parser import HTMLParser

    class LinkExtractor(HTMLParser):
        def __init__(self):
            super().__init__()
            self.links: list[str] = []
            self.forms: list[dict] = []
            self._current_form: dict | None = None

        def handle_starttag(self, tag, attrs):
            attrs_dict = dict(attrs)
            if tag == "a" and "href" in attrs_dict:
                self.links.append(attrs_dict["href"])
            elif tag == "link" and "href" in attrs_dict:
                self.links.append(attrs_dict["href"])
            elif tag == "script" and "src" in attrs_dict:
                self.links.append(attrs_dict["src"])
            elif tag == "img" and "src" in attrs_dict:
                self.links.append(attrs_dict["src"])
            elif tag == "iframe" and "src" in attrs_dict:
                self.links.append(attrs_dict["src"])
            elif tag == "form":
                self._current_form = {
                    "action": attrs_dict.get("action", ""),
                    "method": attrs_dict.get("method", "GET").upper(),
                    "inputs": [],
                }
            elif tag == "input" and self._current_form is not None:
                name = attrs_dict.get("name", "")
                if name:
                    self._current_form["inputs"].append(
                        {
                            "name": name,
                            "type": attrs_dict.get("type", "text"),
                            "value": attrs_dict.get("value", ""),
                        }
                    )

        def handle_endtag(self, tag):
            if tag == "form" and self._current_form is not None:
                self.forms.append(self._current_form)
                self._current_form = None

    parsed_target = urlparse(target_url)
    base_domain = parsed_target.netloc
    base_scheme = parsed_target.scheme

    visited: set[str] = set()
    queue: list[tuple[str, int]] = [(target_url, 0)]
    results: list[dict] = []
    request_headers = {**HEADERS, **auth_headers}

    while queue and len(results) < max_urls:
        url, depth = queue.pop(0)

        # Normalize
        if url in visited:
            continue
        visited.add(url)

        if depth > max_depth:
            continue

        try:
            with httpx.Client(
                timeout=TIMEOUT,
                headers=request_headers,
                verify=False,
                follow_redirects=True,
            ) as client:
                resp = client.get(url)

            results.append(
                {
                    "request": {"endpoint": url, "method": "GET"},
                    "response": {
                        "status_code": resp.status_code,
                        "headers": dict(resp.headers),
                        "body": resp.text[:2000] if resp.text else "",
                    },
                }
            )

            # Only parse HTML for links
            content_type = resp.headers.get("content-type", "")
            if "text/html" not in content_type:
                continue

            parser = LinkExtractor()
            try:
                parser.feed(resp.text or "")
            except Exception:
                pass

            # Process extracted links
            for link in parser.links:
                absolute = _resolve_link(link, url, base_scheme, base_domain)
                if absolute and absolute not in visited:
                    link_parsed = urlparse(absolute)
                    if link_parsed.netloc == base_domain:
                        queue.append((absolute, depth + 1))

            # Process forms
            for form in parser.forms:
                action = form.get("action", "")
                absolute_action = _resolve_link(
                    action, url, base_scheme, base_domain
                ) or url
                results.append(
                    {
                        "request": {
                            "endpoint": absolute_action,
                            "method": form.get("method", "GET"),
                            "body": "&".join(
                                f"{inp['name']}={inp.get('value', '')}"
                                for inp in form.get("inputs", [])
                                if inp.get("name")
                            ),
                        },
                        "tag": "form",
                    }
                )

            # Small delay to be polite
            time.sleep(0.3)

        except Exception as exc:
            logger.debug("httpx crawl error for %s: %s", url, exc)
            continue

    return results


def _resolve_link(
    href: str, current_url: str, base_scheme: str, base_domain: str
) -> str | None:
    """Resolve a relative or absolute link to a full URL."""
    if not href:
        return None
    href = href.strip()

    # Skip non-http links
    if href.startswith(("javascript:", "mailto:", "tel:", "data:", "#")):
        return None

    if href.startswith("//"):
        return f"{base_scheme}:{href}"
    elif href.startswith("/"):
        return f"{base_scheme}://{base_domain}{href}"
    elif href.startswith("http://") or href.startswith("https://"):
        return href
    else:
        # Relative URL
        return urljoin(current_url, href)


# ---------------------------------------------------------------------------
# Arjun parameter discovery
# ---------------------------------------------------------------------------


def _run_arjun(
    endpoints: list[str],
    auth_headers: dict[str, str],
    timeout: int = DEFAULT_ARJUN_TIMEOUT,
) -> list[dict]:
    """
    Run arjun on a list of endpoints to discover hidden parameters.

    Returns list of {url, parameters: [{name, type}]}.
    """
    arjun_bin = _find_arjun()
    if not os.path.isfile(arjun_bin):
        logger.warning("arjun not found at %s", arjun_bin)
        return []

    if not endpoints:
        return []

    # Cap endpoints to prevent excessive scanning
    endpoints = endpoints[:MAX_ARJUN_ENDPOINTS]
    results: list[dict] = []

    for endpoint in endpoints:
        fd, outpath = tempfile.mkstemp(suffix=".json", prefix="arjun_")
        os.close(fd)

        cmd = [
            arjun_bin,
            "-u", endpoint,
            "--stable",
            "-oJ", outpath,
            "-t", "5",  # threads
            "-q",       # quiet mode
        ]

        # Add auth headers
        for name, value in auth_headers.items():
            cmd.extend(["--headers", f"{name}: {value}"])

        try:
            logger.debug("Running arjun on %s", endpoint)
            proc = subprocess.run(
                cmd,
                capture_output=True,
                timeout=timeout,
                env={**os.environ, "HOME": os.environ.get("HOME", "/tmp")},
            )

            if os.path.exists(outpath) and os.path.getsize(outpath) > 0:
                try:
                    with open(outpath, "r", encoding="utf-8", errors="ignore") as f:
                        data = json.load(f)

                    # Arjun outputs {url: [params]} or [{url, params}]
                    if isinstance(data, dict):
                        for url, params in data.items():
                            if isinstance(params, list):
                                results.append(
                                    {
                                        "url": url,
                                        "parameters": [
                                            (
                                                {"name": p, "type": "query", "source": "arjun"}
                                                if isinstance(p, str)
                                                else {
                                                    "name": p.get("name", ""),
                                                    "type": p.get("type", "query"),
                                                    "source": "arjun",
                                                }
                                            )
                                            for p in params
                                        ],
                                    }
                                )
                    elif isinstance(data, list):
                        for item in data:
                            if isinstance(item, dict) and "url" in item:
                                params = item.get("params", item.get("parameters", []))
                                results.append(
                                    {
                                        "url": item["url"],
                                        "parameters": [
                                            (
                                                {"name": p, "type": "query", "source": "arjun"}
                                                if isinstance(p, str)
                                                else {
                                                    "name": p.get("name", ""),
                                                    "type": p.get("type", "query"),
                                                    "source": "arjun",
                                                }
                                            )
                                            for p in (params if isinstance(params, list) else [])
                                        ],
                                    }
                                )
                except (json.JSONDecodeError, KeyError) as exc:
                    logger.debug("arjun output parse error for %s: %s", endpoint, exc)

            elif proc.returncode != 0:
                stderr = (proc.stderr or b"").decode("utf-8", errors="ignore")
                logger.debug(
                    "arjun exited %d for %s: %s",
                    proc.returncode,
                    endpoint,
                    stderr[:200],
                )

        except subprocess.TimeoutExpired:
            logger.debug("arjun timed out for %s", endpoint)
        except FileNotFoundError:
            logger.warning("arjun not found at %s", arjun_bin)
            break  # No point trying more endpoints
        except Exception as exc:
            logger.debug("arjun error for %s: %s", endpoint, exc)
        finally:
            try:
                os.unlink(outpath)
            except OSError:
                pass

    return results


# ---------------------------------------------------------------------------
# Main crawl function
# ---------------------------------------------------------------------------


def run_crawl(
    target_url: str,
    auth_config: dict | None = None,
    max_depth: int = 3,
    crawl_scope: str = "host",
    progress_callback: Callable | None = None,
    crawl_id: str | None = None,
    timeout: int = DEFAULT_CRAWL_TIMEOUT,
    run_param_discovery: bool = True,
    use_playwright: bool = False,
) -> dict:
    """
    Run full crawl using katana (primary) with httpx fallback and arjun
    parameter discovery.

    Args:
        target_url: The URL to crawl.
        auth_config: Authentication configuration dict or None.
        max_depth: Maximum crawl depth (default 3).
        crawl_scope: Scope control - "host", "subdomain", or "all".
        progress_callback: Optional callable(phase, progress_pct, message).
        crawl_id: Optional ID for Redis progress tracking.
        timeout: Timeout in seconds for the katana process.
        run_param_discovery: Whether to run arjun for hidden parameters.
        use_playwright: If True, run Playwright on discovered pages for JS/SPA coverage.

    Returns:
        {
            urls: [str],
            api_endpoints: [{url, method, status_code, parameters, body_params}],
            parameters: [{name, values, source, url}],
            forms: [{url, method, parameters}],
            js_files: [{url, status_code, source}],
            pages: [{url, method, status_code}],
            static_assets: [str],
            stats: {
                total_urls, total_parameters, total_api_endpoints,
                total_js_files, total_forms, crawler_used, duration_seconds,
                arjun_parameters_found
            },
        }
    """
    if crawl_id is None:
        crawl_id = str(uuid.uuid4())

    auth_headers = _build_auth_headers(auth_config)
    start_time = time.time()

    def _update_progress(phase: str, pct: int, message: str) -> None:
        if progress_callback:
            try:
                progress_callback(phase, pct, message)
            except Exception:
                pass
        _crawl_progress_set(
            crawl_id,
            {
                "status": "running",
                "phase": phase,
                "progress_pct": pct,
                "message": message,
                "target_url": target_url,
                "crawl_id": crawl_id,
                "last_updated": time.time(),
                "elapsed_seconds": round(time.time() - start_time, 1),
            },
        )

    _update_progress("init", 0, "Starting crawl...")

    # -------------------------------------------------------------------
    # Phase 1: Primary crawl with katana
    # -------------------------------------------------------------------
    _update_progress("crawl", 5, "Running katana spider...")
    crawler_used = "katana"
    raw_results = _run_katana(
        target_url, auth_headers, max_depth, crawl_scope, timeout
    )

    # Fallback: Katana Docker (when native hangs), then spider_rs, then httpx
    if not raw_results:
        _update_progress("crawl", 8, "Trying Katana via Docker...")
        raw_results = _run_katana_docker(
            target_url, auth_headers, max_depth, crawl_scope, timeout
        )
        if raw_results:
            crawler_used = "katana+docker"
    if not raw_results:
        try:
            raw_results = _run_spider_rs(target_url, max_urls=500)
            if raw_results:
                crawler_used = "spider_rs"
                _update_progress("crawl", 10, f"Using spider_rs: found {len(raw_results)} links")
        except Exception as e:
            logger.debug("spider_rs fallback failed: %s", e)
    if not raw_results:
        _update_progress("crawl", 10, "Katana/spider_rs unavailable, falling back to httpx crawler...")
        crawler_used = "httpx"
        raw_results = _httpx_fallback_crawl(
            target_url, auth_headers, max_depth=min(max_depth, 2), max_urls=400
        )

    _update_progress("crawl", 50, f"Crawl complete. Processing {len(raw_results)} results...")

    # -------------------------------------------------------------------
    # Phase 2: Parse and classify
    # -------------------------------------------------------------------
    _update_progress("classify", 55, "Classifying discovered URLs...")
    parsed = _parse_katana_results(raw_results)

    # Optional: Playwright deepening pass for JS/SPA coverage
    if use_playwright:
        pages_for_playwright = [p["url"] for p in parsed.get("pages", []) if p.get("url")]
        # Always include target_url for SPA shells (minimal crawl may have 0 pages)
        if target_url and target_url not in pages_for_playwright:
            pages_for_playwright.insert(0, target_url)
        if pages_for_playwright:
            try:
                from .playwright_crawler import run_playwright_crawl

                def _pw_progress(msg: str) -> None:
                    _update_progress("playwright", 35, msg)

                pw_results = run_playwright_crawl(
                    target_url, auth_headers, pages_for_playwright,
                    max_pages=min(25, len(pages_for_playwright)),
                    progress_callback=_pw_progress,
                )
                if pw_results:
                    raw_results = raw_results + pw_results
                    parsed = _parse_katana_results(raw_results)
                    crawler_used = f"{crawler_used}+playwright"
                    _update_progress("playwright", 60, f"Playwright found {len(pw_results)} additional URLs")
            except Exception as e:
                logger.warning("Playwright deepening failed: %s", e)

    urls = parsed["urls"]

    api_endpoints = parsed["api_endpoints"]
    js_files = parsed["js_files"]
    static_assets = parsed["static_assets"]
    forms = parsed["forms"]
    pages = parsed["pages"]
    parameters = parsed["parameters"]

    _update_progress(
        "classify",
        65,
        f"Found {len(urls)} URLs, {len(api_endpoints)} API endpoints, "
        f"{len(js_files)} JS files, {len(forms)} forms",
    )

    # -------------------------------------------------------------------
    # Phase 2b: JS fetch, secrets, analysis (hidden URLs, deeplinks, SCA libs)
    # -------------------------------------------------------------------
    hidden_urls: list[str] = []
    js_libraries: list[dict] = []
    deeplinks: list[str] = []
    js_sca_result: dict | None = None
    retire_results: dict | None = None

    def _fetch_js(url: str) -> str:
        try:
            with httpx.Client(timeout=15.0, headers={**HEADERS, **auth_headers}, follow_redirects=True, verify=False) as client:
                r = client.get(url)
                if r.status_code == 200:
                    return r.text
        except Exception:
            pass
        return ""

    if js_files:
        retire_results = None
        _update_progress("secrets", 68, f"Scanning {len(js_files)} JS file(s) for secrets, URLs, libs...")
        try:
            from .secrets import scan_js_files
            from .js_analysis import analyze_js
            from .sca import scan_js_libraries, scan_js_with_retire

            js_files = scan_js_files(js_files, _fetch_js)

            parsed_target = urlparse(target_url)
            base_scheme = parsed_target.scheme
            base_netloc = parsed_target.netloc

            for entry in js_files:
                content = _fetch_js(entry.get("url", ""))
                if not content:
                    continue
                js_url = entry.get("url", "")
                analysis = analyze_js(content, js_url)
                entry["hidden_urls"] = analysis.get("urls", [])
                entry["deeplinks"] = analysis.get("deeplinks", [])
                entry["libraries"] = analysis.get("libraries", [])

                deeplinks.extend(analysis.get("deeplinks", []))
                js_libraries.extend(analysis.get("libraries", []))

                for u in analysis.get("urls", []):
                    raw_url = u.get("url", "")
                    if raw_url and raw_url.startswith("http") and raw_url not in urls:
                        hidden_urls.append(raw_url)

            # Merge hidden URLs into main url list (dedupe)
            seen_urls = set(urls)
            for u in hidden_urls:
                if u not in seen_urls and len(seen_urls) < MAX_URLS_PER_CRAWL:
                    seen_urls.add(u)
                    urls.append(u)

            # SCA on JS-identified libraries (dedupe by name+version)
            seen_libs: set[tuple[str, str]] = set()
            unique_libs: list[dict] = []
            for lib in js_libraries:
                k = (lib.get("name", ""), lib.get("version", ""))
                if k not in seen_libs:
                    seen_libs.add(k)
                    unique_libs.append(lib)
            if unique_libs:
                _update_progress("sca", 69, f"Running SCA on {len(unique_libs)} JS library(ies)...")
                try:
                    js_sca_result = scan_js_libraries(unique_libs)
                except Exception as sca_exc:
                    logger.debug("JS SCA failed: %s", sca_exc)
                    js_sca_result = None
            else:
                js_sca_result = None

            # Retire.js scan for JS library vulns + SBOM
            _update_progress("retire", 69, "Running Retire.js on JS files...")
            try:
                retire_results = scan_js_with_retire(js_files, _fetch_js)
                if retire_results and retire_results.get("total_vulns", 0) > 0:
                    by_url = retire_results.get("by_url", {})
                    for entry in js_files:
                        url = entry.get("url", "")
                        if url and url in by_url:
                            entry["retire_vulns"] = by_url[url]
            except Exception as retire_exc:
                logger.debug("Retire.js scan failed: %s", retire_exc)
                retire_results = None
        except Exception as exc:
            logger.warning("JS secrets/analysis failed: %s", exc)
    else:
        retire_results = None

    # -------------------------------------------------------------------
    # Phase 3: Parameter discovery with arjun
    # -------------------------------------------------------------------
    arjun_params_found = 0
    if run_param_discovery:
        # Select endpoints for parameter discovery: API endpoints + pages
        # Prefer endpoints that don't already have many known parameters
        discovery_targets: list[str] = []

        for ep in api_endpoints:
            if len(ep.get("parameters", [])) < 3:
                discovery_targets.append(ep["url"])
        for page in pages:
            if page.get("url") and len(discovery_targets) < MAX_ARJUN_ENDPOINTS:
                discovery_targets.append(page["url"])

        # Deduplicate while preserving order
        seen: set[str] = set()
        unique_targets: list[str] = []
        for t in discovery_targets:
            # Strip query string for arjun -- it discovers params on its own
            base = t.split("?")[0]
            if base not in seen:
                seen.add(base)
                unique_targets.append(base)

        if unique_targets:
            _update_progress(
                "params",
                70,
                f"Running arjun on {len(unique_targets)} endpoint(s)...",
            )
            arjun_results = _run_arjun(unique_targets, auth_headers)

            for ar in arjun_results:
                for param in ar.get("parameters", []):
                    param_name = param.get("name", "")
                    if param_name:
                        arjun_params_found += 1
                        parameters.append(
                            {
                                "name": param_name,
                                "values": [],
                                "source": "arjun",
                                "url": ar.get("url", ""),
                                "type": param.get("type", "query"),
                            }
                        )
            _update_progress(
                "params",
                90,
                f"Arjun discovered {arjun_params_found} hidden parameter(s)",
            )
        else:
            _update_progress("params", 90, "No endpoints suitable for parameter discovery")
    else:
        _update_progress("params", 90, "Parameter discovery skipped")

    # -------------------------------------------------------------------
    # Final: Deduplicate parameters across all sources
    # -------------------------------------------------------------------
    seen_params: set[str] = set()
    unique_parameters: list[dict] = []
    for p in parameters:
        key = f"{p.get('name', '')}:{p.get('url', '')}:{p.get('source', '')}"
        if key not in seen_params:
            seen_params.add(key)
            unique_parameters.append(p)

    duration = round(time.time() - start_time, 2)

    total_secrets = sum(j.get("secrets_count", 0) for j in js_files)
    result = {
        "urls": urls,
        "api_endpoints": api_endpoints,
        "parameters": unique_parameters,
        "forms": forms,
        "js_files": js_files,
        "pages": pages,
        "static_assets": static_assets,
        "deeplinks": list(dict.fromkeys(deeplinks)),  # deduped
        "js_sca": js_sca_result,
        "retire_results": retire_results,
        "stats": {
            "total_urls": len(urls),
            "total_parameters": len(unique_parameters),
            "total_api_endpoints": len(api_endpoints),
            "total_js_files": len(js_files),
            "total_forms": len(forms),
            "total_pages": len(pages),
            "total_static_assets": len(static_assets),
            "total_secrets_found": total_secrets,
            "total_hidden_urls": len(hidden_urls),
            "total_deeplinks": len(dict.fromkeys(deeplinks)),
            "crawler_used": crawler_used,
            "crawl_scope": crawl_scope,
            "max_depth": max_depth,
            "duration_seconds": duration,
            "arjun_parameters_found": arjun_params_found,
            "authenticated": bool(auth_headers),
        },
    }

    _update_progress("done", 100, "Crawl complete")
    progress_payload = {
        "status": "completed",
        "phase": "done",
        "progress_pct": 100,
        "target_url": target_url,
        "crawl_id": crawl_id,
        "last_updated": time.time(),
        "elapsed_seconds": duration,
        "stats": result["stats"],
        "urls": urls[:500],
        "api_endpoints": api_endpoints[:200],
        "js_files": js_files[:100],
        "deeplinks": result.get("deeplinks", []),
        "js_sca": result.get("js_sca"),
        "retire_results": result.get("retire_results"),
    }
    _crawl_progress_set(crawl_id, progress_payload)

    return result


# ---------------------------------------------------------------------------
# Recursive directory scanning
# ---------------------------------------------------------------------------


def run_recursive_directory_scan(
    target_url: str,
    base_path: str = "/",
    max_depth: int = 3,
    wordlist_key: str = "small",
    auth_config: dict | None = None,
    progress_callback: Callable | None = None,
    scan_id: str | None = None,
    timeout_per_level: int = DEFAULT_FFUF_TIMEOUT,
    max_results_per_level: int = 200,
) -> dict:
    """
    Recursively scan directories with ffuf. When a directory is found
    (status 301/302/200 with trailing-slash redirect or content), scan
    inside it up to max_depth.

    Args:
        target_url: The base URL to scan.
        base_path: Starting path (default "/").
        max_depth: Maximum recursion depth (default 3).
        wordlist_key: Wordlist key for ffuf ("small", "medium", etc.).
        auth_config: Authentication configuration dict or None.
        progress_callback: Optional callable(depth, path, found_count, message).
        scan_id: Optional ID for Redis progress tracking.
        timeout_per_level: Timeout per ffuf invocation in seconds.
        max_results_per_level: Max results per directory level.

    Returns:
        {
            directories: [{path, status, depth, children: [...]}],
            files: [{path, status, content_type}],
            tree: {nested dict representation},
            stats: {
                total_directories, total_files, max_depth_reached,
                levels_scanned, wordlist_used, duration_seconds
            },
        }
    """
    if scan_id is None:
        scan_id = str(uuid.uuid4())

    auth_headers = _build_auth_headers(auth_config)
    start_time = time.time()

    # Resolve wordlist
    resolved = get_wordlist_path(wordlist_key)
    if not resolved:
        return {
            "directories": [],
            "files": [],
            "tree": {},
            "stats": {
                "total_directories": 0,
                "total_files": 0,
                "max_depth_reached": 0,
                "levels_scanned": 0,
                "wordlist_used": "",
                "duration_seconds": 0,
                "error": "No wordlist available",
            },
        }

    wl_key, wl_path = resolved
    wordlist_path = str(wl_path)

    all_directories: list[dict] = []
    all_files: list[dict] = []
    scanned_paths: set[str] = set()
    max_depth_reached = 0

    def _update_scan_progress(depth: int, path: str, message: str) -> None:
        if progress_callback:
            try:
                progress_callback(
                    depth, path, len(all_directories) + len(all_files), message
                )
            except Exception:
                pass
        _crawl_progress_set(
            scan_id,
            {
                "status": "running",
                "type": "recursive_directory_scan",
                "current_depth": depth,
                "current_path": path,
                "directories_found": len(all_directories),
                "files_found": len(all_files),
                "message": message,
                "target_url": target_url,
                "scan_id": scan_id,
                "last_updated": time.time(),
                "elapsed_seconds": round(time.time() - start_time, 1),
            },
        )

    ffuf_bin = _find_ffuf()

    def _scan_directory(path: str, depth: int) -> list[dict]:
        """Scan a single directory with ffuf and return found entries."""
        nonlocal max_depth_reached

        normalized = path.rstrip("/") + "/"
        if normalized in scanned_paths:
            return []
        scanned_paths.add(normalized)

        if depth > max_depth:
            return []

        if depth > max_depth_reached:
            max_depth_reached = depth

        _update_scan_progress(
            depth, path, f"Scanning {path} (depth {depth}/{max_depth})..."
        )

        parsed = urlparse(target_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        fuzz_url = f"{base}{normalized}FUZZ"

        fd, outpath = tempfile.mkstemp(suffix=".json", prefix="ffuf_recursive_")
        os.close(fd)

        cmd = [
            ffuf_bin,
            "-u", fuzz_url,
            "-w", wordlist_path,
            "-mc", "200,201,204,301,302,307,401,403,405",
            "-fc", "404",
            "-t", "20",
            "-o", outpath,
            "-of", "json",
            "-timeout", "10",
            "-rate", "50",
            "-se",  # stop on spurious errors
        ]

        # Add auth headers
        cmd.extend(_auth_headers_to_cli_flags(auth_headers))

        entries: list[dict] = []

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                timeout=timeout_per_level,
                env={**os.environ},
            )

            if os.path.exists(outpath) and os.path.getsize(outpath) > 0:
                with open(outpath, "rb") as f:
                    data = json.loads(f.read().decode("utf-8", errors="ignore"))

                results = data.get("results", [])[:max_results_per_level]

                for r in results:
                    fuzz_value = str(r.get("input", {}).get("FUZZ", ""))
                    status = r.get("status", 0)
                    content_length = r.get("length", 0)
                    content_type = r.get("content-type", "")
                    redirect_location = r.get("redirectlocation", "")

                    entry_path = f"{normalized}{fuzz_value}".replace("//", "/")

                    # Determine if this is a directory
                    is_directory = (
                        status in (301, 302, 307)
                        and (
                            redirect_location.rstrip("/").endswith(fuzz_value)
                            or redirect_location.endswith(fuzz_value + "/")
                        )
                    ) or (
                        status == 200
                        and not _STATIC_EXTENSIONS.search(fuzz_value)
                        and not _INTERESTING_EXTENSIONS.search(fuzz_value)
                        and not "." in fuzz_value  # no extension likely = directory
                    )

                    entry = {
                        "path": entry_path,
                        "status": status,
                        "content_length": content_length,
                        "content_type": content_type,
                        "redirect_location": redirect_location,
                        "depth": depth,
                        "is_directory": is_directory,
                    }

                    entries.append(entry)

                    if is_directory:
                        all_directories.append(entry)
                    else:
                        all_files.append(entry)

            elif proc.returncode != 0:
                stderr = (proc.stderr or b"").decode("utf-8", errors="ignore")
                logger.debug(
                    "ffuf recursive exited %d for %s: %s",
                    proc.returncode,
                    path,
                    stderr[:200],
                )

        except subprocess.TimeoutExpired:
            logger.debug("ffuf recursive timed out for %s", path)
        except FileNotFoundError:
            logger.warning("ffuf not found at %s", ffuf_bin)
        except Exception as exc:
            logger.debug("ffuf recursive error for %s: %s", path, exc)
        finally:
            try:
                os.unlink(outpath)
            except OSError:
                pass

        # Recurse into discovered directories
        for entry in entries:
            if entry.get("is_directory") and depth < max_depth:
                child_entries = _scan_directory(entry["path"], depth + 1)
                entry["children"] = child_entries

        return entries

    # Start recursive scan
    _update_scan_progress(0, base_path, "Starting recursive directory scan...")
    tree_entries = _scan_directory(base_path, 0)

    duration = round(time.time() - start_time, 2)

    # Build flat tree representation
    def _build_tree(entries: list[dict]) -> dict:
        tree: dict = {}
        for e in entries:
            parts = [p for p in e["path"].strip("/").split("/") if p]
            node = tree
            for part in parts:
                if part not in node:
                    node[part] = {}
                node = node[part]
        return tree

    flat_list = [{"path": e["path"], "status": e.get("status", 200), "type": "dir" if e.get("is_directory") else "file"} for e in (all_directories + all_files)]
    result = {
        "directories": all_directories,
        "files": all_files,
        "flat": flat_list,
        "tree": _build_tree(all_directories + all_files),
        "stats": {
            "total_directories": len(all_directories),
            "total_files": len(all_files),
            "max_depth_reached": max_depth_reached,
            "levels_scanned": len(scanned_paths),
            "wordlist_used": wl_key,
            "duration_seconds": duration,
            "base_path": base_path,
            "target_url": target_url,
        },
    }

    _crawl_progress_set(
        scan_id,
        {
            "status": "completed",
            "type": "recursive_directory_scan",
            "directories_found": len(all_directories),
            "files_found": len(all_files),
            "target_url": target_url,
            "scan_id": scan_id,
            "last_updated": time.time(),
            "elapsed_seconds": duration,
            "stats": result["stats"],
        },
    )

    return result


# ---------------------------------------------------------------------------
# URL content fetcher
# ---------------------------------------------------------------------------


def fetch_url_content(
    url: str,
    auth_config: dict | None = None,
    timeout: float = 15.0,
    max_body_size: int = BODY_PREVIEW_LIMIT,
) -> dict:
    """
    Fetch URL content with full request/response data.

    Args:
        url: The URL to fetch.
        auth_config: Authentication configuration dict or None.
        timeout: Request timeout in seconds.
        max_body_size: Maximum body preview size in bytes.

    Returns:
        {
            url: str,
            status: int,
            headers: {str: str},
            body_preview: str,
            content_type: str,
            size: int,
            request_raw: str,
            response_raw: str,
            redirect_chain: [str],
            error: str | None,
        }
    """
    auth_headers = _build_auth_headers(auth_config)
    request_headers = {**HEADERS, **auth_headers}

    result = {
        "url": url,
        "status": 0,
        "headers": {},
        "body_preview": "",
        "content_type": "",
        "size": 0,
        "request_raw": "",
        "response_raw": "",
        "redirect_chain": [],
        "error": None,
    }

    try:
        parsed = urlparse(url)
        # Build raw request representation
        header_lines = "\r\n".join(
            f"{k}: {v}" for k, v in request_headers.items()
        )
        result["request_raw"] = (
            f"GET {parsed.path or '/'}"
            f"{'?' + parsed.query if parsed.query else ''} HTTP/1.1\r\n"
            f"Host: {parsed.netloc}\r\n"
            f"{header_lines}\r\n"
            f"\r\n"
        )

        with httpx.Client(
            timeout=httpx.Timeout(timeout, connect=min(timeout, 10.0)),
            headers=request_headers,
            verify=False,
            follow_redirects=True,
        ) as client:
            resp = client.get(url)

            # Track redirect chain
            redirect_chain: list[str] = []
            if hasattr(resp, "history") and resp.history:
                for r in resp.history:
                    redirect_chain.append(str(r.url))
            redirect_chain.append(str(resp.url))

            result["status"] = resp.status_code
            result["headers"] = dict(resp.headers)
            result["content_type"] = resp.headers.get("content-type", "")
            result["redirect_chain"] = redirect_chain

            # Body preview
            content_type = result["content_type"].lower()
            if any(
                t in content_type
                for t in ("text/", "json", "xml", "javascript", "html")
            ):
                body_text = resp.text or ""
                result["body_preview"] = body_text[:max_body_size]
                result["size"] = len(resp.content)
            else:
                result["body_preview"] = (
                    f"[Binary content: {result['content_type']}, "
                    f"{len(resp.content)} bytes]"
                )
                result["size"] = len(resp.content)

            # Build raw response representation
            resp_header_lines = "\r\n".join(
                f"{k}: {v}" for k, v in resp.headers.items()
            )
            body_for_raw = result["body_preview"][:2000]
            result["response_raw"] = (
                f"HTTP/1.1 {resp.status_code} {resp.reason_phrase}\r\n"
                f"{resp_header_lines}\r\n"
                f"\r\n"
                f"{body_for_raw}"
            )

    except httpx.TimeoutException:
        result["error"] = f"Request timed out after {timeout}s"
    except httpx.ConnectError as exc:
        result["error"] = f"Connection error: {exc}"
    except Exception as exc:
        result["error"] = f"Request failed: {exc}"

    return result
