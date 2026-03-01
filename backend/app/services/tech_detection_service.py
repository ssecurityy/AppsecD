"""Technology stack detection from website URL — headers, meta, script patterns."""
import re
import logging
from urllib.parse import urlparse
import httpx

logger = logging.getLogger(__name__)

TIMEOUT = httpx.Timeout(10.0, connect=5.0)
HEADERS = {"User-Agent": "AppSecD/1.0 (Technology Detection)"}

# Headers that reveal tech
HEADER_SIGNATURES = {
    "x-powered-by": "backend",
    "server": "server",
    "x-aspnet-version": "backend",
    "x-aspnetmvc-version": "backend",
    "x-drupal-cache": "cms",
    "x-generator": "cms",
    "x-varnish": "server",
    "via": "server",
}

# HTML patterns
HTML_PATTERNS = [
    (r"<meta[^>]+generator[^>]+content=[\"']([^\"']+)[\"']", "generator"),
    (r"wp-content|wp-includes|/wp-", "wordpress"),
    (r"drupal|sites/default", "drupal"),
    (r"_next/static|__NEXT_DATA__", "nextjs"),
    (r"react|react-dom|react\.", "react"),
    (r"vue\.js|vue\.runtime", "vue"),
    (r"angular|ng-version", "angular"),
    (r"jquery|jQuery", "jquery"),
    (r"bootstrap", "bootstrap"),
    (r"laravel", "laravel"),
    (r"django|csrftoken", "django"),
    (r"flask", "flask"),
    (r"express|__express", "express"),
    (r"rails", "rails"),
    (r"graphql|/graphql", "graphql"),
    (r"swagger|openapi", "openapi"),
]


def _try_urls(url: str) -> tuple[httpx.Response | None, str]:
    """Try URL, then fallbacks (https, www, http). Returns (response, final_url)."""
    parsed = urlparse(url)
    urls_to_try = [url]
    if not url.startswith("http"):
        base = f"https://{parsed.netloc or parsed.path}{parsed.path if parsed.netloc else ''}{parsed.query or ''}"
        urls_to_try = [base, base.replace("https://", "http://")]
    else:
        if "www." not in parsed.netloc:
            urls_to_try.append(url.replace(parsed.netloc, f"www.{parsed.netloc}", 1))
        if parsed.scheme == "https":
            urls_to_try.append(url.replace("https://", "http://"))
        elif parsed.scheme == "http":
            urls_to_try.append(url.replace("http://", "https://"))
    for u in urls_to_try:
        try:
            with httpx.Client(timeout=TIMEOUT, headers=HEADERS, verify=False, follow_redirects=True) as client:
                r = client.get(u)
                return r, u
        except Exception as e:
            logger.debug("Tech detection try %s: %s", u, e)
    return None, url


def detect_technology(url: str) -> dict:
    """
    Detect technology stack from URL. Returns stack_profile dict with
    frontend, backend, server, cms, and raw detections.
    """
    if not url or not url.strip():
        return {}
    url = url.strip()
    if not url.startswith("http"):
        url = f"https://{url}"

    resp, _ = _try_urls(url)
    if not resp:
        return {"_error": "Could not reach URL", "_detected": False}

    result: dict = {
        "frontend": [],
        "backend": [],
        "server": [],
        "cms": [],
        "api": [],
        "raw_headers": {},
        "_detected": True,
    }
    seen = set()

    # Headers
    for h, category in HEADER_SIGNATURES.items():
        v = resp.headers.get(h)
        if v:
            v = v.split("/")[0].strip()[:80]
            result["raw_headers"][h] = v
            key = f"{category}:{v.lower()}"
            if key not in seen:
                seen.add(key)
                if category == "backend" and v not in result["backend"]:
                    result["backend"].append(v)
                elif category == "server" and v not in result["server"]:
                    result["server"].append(v)
                elif category == "cms" and v not in result["cms"]:
                    result["cms"].append(v)

    # X-Powered-By often gives PHP, ASP.NET, Express
    powered = resp.headers.get("x-powered-by", "")
    if powered:
        for tech in ["PHP", "ASP.NET", "Express", "Next.js"]:
            if tech.lower() in powered.lower() and tech not in result["backend"]:
                result["backend"].append(tech)

    # HTML body
    try:
        body = resp.text[:50000].lower()
    except Exception:
        body = ""

    for pattern, tech in HTML_PATTERNS:
        if re.search(pattern, body, re.I):
            tech_title = tech.replace("_", " ").title()
            if tech_title not in seen:
                seen.add(tech_title)
                if tech in ("wordpress", "drupal"):
                    if tech_title not in result["cms"]:
                        result["cms"].append(tech_title)
                elif tech in ("nextjs", "react", "vue", "angular", "jquery", "bootstrap"):
                    if tech_title not in result["frontend"]:
                        result["frontend"].append(tech_title)
                elif tech in ("laravel", "django", "flask", "express", "rails"):
                    if tech_title not in result["backend"]:
                        result["backend"].append(tech_title)
                elif tech in ("graphql", "openapi"):
                    if tech_title not in result["api"]:
                        result["api"].append(tech_title)

    # Clean empty lists
    for k in list(result.keys()):
        if isinstance(result[k], list) and not result[k]:
            del result[k]
    return result
