"""World-class technology & WAF detection — Wappalyzer/BuiltWith + wafw00f style patterns.

Uses comprehensive fingerprinting: headers, meta, HTML, scripts, cookies.
No external fingerprint DB dependency; all patterns inline for 100% reliability.
"""
import re
import logging
from urllib.parse import urlparse
import httpx

logger = logging.getLogger(__name__)

TIMEOUT = httpx.Timeout(12.0, connect=6.0)
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}

# ─── WAF signatures (wafw00f-style): header/cookie/body patterns ───
WAF_SIGNATURES = [
    {"name": "Cloudflare", "headers": {"server": r"cloudflare", "cf-ray": r".+"}, "cookies": [r"__cfduid", r"__cf_bm"]},
    {"name": "AWS WAF", "headers": {"x-amz-cf-id": r".+", "x-amzn-requestid": r".+"}, "body": [r"Request blocked by AWS WAF", r"awswaf"]},
    {"name": "Akamai", "headers": {"x-akamai-request-id": r".+", "akamai-origin-hop": r".+"}, "cookies": [r"ak_bmsc"]},
    {"name": "F5 BIG-IP", "headers": {"x-wa-info": r".+"}, "cookies": [r"bigipserver", r"f5_cspm"], "body": [r"bigip|f5"]},
    {"name": "Sucuri", "headers": {"x-sucuri-id": r".+", "server": r"sucuri"}, "body": [r"sucuri", r"cloudproxy"]},
    {"name": "Imperva/Incapsula", "headers": {"x-cdn": r"incapsula", "x-iinfo": r".+"}, "cookies": [r"incap_ses", r"visid_incap"]},
    {"name": "ModSecurity", "headers": {"server": r"mod_security", "modsecurity": r".+"}},
    {"name": "Barracuda", "headers": {"server": r"barra"}, "body": [r"barracuda"]},
    {"name": "Radware", "headers": {"x-rdwr": r".+"}, "body": [r"radware"]},
    {"name": "Microsoft Azure WAF", "headers": {"x-azure-ref": r".+"}, "body": [r"azure"]},
]

# ─── Tech signatures (Wappalyzer/BuiltWith style) ───
# (pattern, category, tech_name)
HEADER_TECH = [
    (r"x-powered-by", "backend", None),  # value parsed separately
    (r"server", "server", None),
    (r"x-aspnetmvc-version", "backend", "ASP.NET MVC"),
    (r"x-aspnet-version", "backend", "ASP.NET"),
    (r"x-drupal-cache", "cms", "Drupal"),
    (r"x-generator", "cms", None),
    (r"x-varnish", "server", "Varnish"),
    (r"via", "server", None),
    (r"x-pingback", "cms", "WordPress"),
    (r"x-frame-options", "security", None),
]

# Meta generator + script/src patterns (pattern, category, tech_name)
HTML_TECH = [
    (r"wp-content|wp-includes|/wp-|wordpress", "cms", "WordPress"),
    (r"drupal|sites/default|drupal\.js", "cms", "Drupal"),
    (r"_next/static|__NEXT_DATA__|next\.js", "frontend", "Next.js"),
    (r"react-dom|react\.js|react\.production|createelement", "frontend", "React"),
    (r"vue\.js|vue\.runtime|__vue__|vue-router", "frontend", "Vue.js"),
    (r"angular|ng-version|ng-\w+", "frontend", "Angular"),
    (r"jquery|jQuery|\$\(|jquery\.min", "frontend", "jQuery"),
    (r"bootstrap|bootstrap\.min\.js", "frontend", "Bootstrap"),
    (r"ember|ember-data|ember\.js", "frontend", "Ember"),
    (r"svelte|svelte/ssr", "frontend", "Svelte"),
    (r"preact|preact/", "frontend", "Preact"),
    (r"tailwind|tailwindcss", "frontend", "Tailwind CSS"),
    (r"laravel|laravel_session|csrf_token", "backend", "Laravel"),
    (r"django|csrftoken|django\.middleware", "backend", "Django"),
    (r"flask|werkzeug", "backend", "Flask"),
    (r"express|__express|x-powered-by.*express", "backend", "Express"),
    (r"rails|rails-ujs|action_cable", "backend", "Rails"),
    (r"spring|springframework", "backend", "Spring"),
    (r"asp\.net|aspx|__viewstate", "backend", "ASP.NET"),
    (r"php|\.php\?|phpsessid", "backend", "PHP"),
    (r"graphql|/graphql|__schema", "api", "GraphQL"),
    (r"swagger|openapi|swagger-ui", "api", "Swagger"),
    (r"mongodb|mongo", "database", "MongoDB"),
    (r"google-analytics|ga\.js|gtag|googletagmanager", "analytics", "Google Analytics"),
    (r"gtm\.js|googletagmanager\.com", "analytics", "Google Tag Manager"),
    (r"hotjar|hj\.js", "analytics", "Hotjar"),
    (r"mixpanel", "analytics", "Mixpanel"),
    (r"segment\.io|analytics\.js", "analytics", "Segment"),
    (r"stripe\.com|stripe\.js", "payment", "Stripe"),
    (r"paypal\.com|paypalobjects", "payment", "PayPal"),
    (r"recaptcha|grecaptcha", "security", "reCAPTCHA"),
    (r"hcaptcha", "security", "hCaptcha"),
    (r"cloudflare|cf\.cloudflare", "cdn", "Cloudflare"),
    (r"jsdelivr|cdnjs", "cdn", None),
    (r"algolia|instantsearch", "search", "Algolia"),
    (r"elasticsearch|elastic\.co", "search", "Elasticsearch"),
    (r"datadog|dd\.rum", "monitoring", "Datadog"),
    (r"sentry\.io|sentry", "monitoring", "Sentry"),
]


def _try_urls(url: str) -> tuple[httpx.Response | None, str]:
    """Try URL, then fallbacks (https, http, www)."""
    parsed = urlparse(url)
    urls_to_try = [url]
    if not url.startswith("http"):
        base = f"https://{parsed.netloc or parsed.path}{parsed.path if parsed.netloc else ''}{parsed.query or ''}"
        urls_to_try = [base, base.replace("https://", "http://")]
    else:
        netloc = parsed.netloc or ""
        if "www." not in netloc and netloc:
            u2 = url.replace(netloc, f"www.{netloc}", 1)
            if u2 not in urls_to_try:
                urls_to_try.append(u2)
        if parsed.scheme == "https":
            u3 = url.replace("https://", "http://")
            if u3 not in urls_to_try:
                urls_to_try.append(u3)
        elif parsed.scheme == "http":
            u3 = url.replace("http://", "https://")
            if u3 not in urls_to_try:
                urls_to_try.append(u3)
    for u in urls_to_try:
        try:
            with httpx.Client(timeout=TIMEOUT, headers=HEADERS, verify=False, follow_redirects=True) as client:
                r = client.get(u)
                return r, u
        except Exception as e:
            logger.debug("Tech detection try %s: %s", u, e)
    return None, url


def _detect_waf(resp: httpx.Response) -> list[str]:
    """WAF fingerprinting (wafw00f-style)."""
    headers_lower = {k.lower(): v for k, v in resp.headers.items()}
    cookies_str = " ".join(resp.headers.get_list("set-cookie")).lower()
    body = (resp.text or "")[:10000].lower()
    detected = []

    for waf in WAF_SIGNATURES:
        name = waf["name"]
        matched = False
        if "headers" in waf:
            for hkey, hval in waf["headers"].items():
                v = headers_lower.get(hkey, "")
                if v and re.search(hval, v, re.I):
                    matched = True
                    break
        if not matched and "cookies" in waf:
            for pat in waf["cookies"]:
                if re.search(pat, cookies_str):
                    matched = True
                    break
        if not matched and "body" in waf:
            for pat in waf["body"]:
                if re.search(pat, body):
                    matched = True
                    break
        if matched:
            detected.append(name)

    return detected


def detect_technology(url: str) -> dict:
    """
    World-class technology detection. Returns stack_profile with
    frontend, backend, server, cms, api, waf, analytics, and raw detections.
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
        "waf": [],
        "database": [],
        "analytics": [],
        "cdn": [],
        "raw_headers": {},
        "_detected": True,
    }
    seen: set[str] = set()

    # 1. WAF detection (wafw00f-style)
    waf_detected = _detect_waf(resp)
    result["waf"] = waf_detected

    # 2. Headers
    headers_lower = {k.lower(): v for k, v in resp.headers.items()}
    for h, cat, tech_name in HEADER_TECH:
        v = headers_lower.get(h)
        if not v:
            continue
        v_clean = v.split("/")[0].strip()[:100]
        result["raw_headers"][h] = v_clean
        if cat == "server" and v_clean not in result["server"]:
            result["server"].append(v_clean)
        elif cat == "backend" and tech_name and tech_name not in result["backend"]:
            result["backend"].append(tech_name)
        elif cat == "backend" and not tech_name:
            for t in ["PHP", "ASP.NET", "Express", "Next.js", "Nginx", "Apache"]:
                if t.lower() in v_clean.lower() and t not in result["backend"]:
                    result["backend"].append(t)
                    break
        elif cat == "cms" and tech_name and tech_name not in result["cms"]:
            result["cms"].append(tech_name)

    powered = resp.headers.get("x-powered-by", "") or ""
    if powered:
        for t in ["PHP", "ASP.NET", "Express", "Next.js", "Nginx"]:
            if t.lower() in powered.lower() and t not in result["backend"]:
                result["backend"].append(t)
                break

    # 3. HTML body patterns (Wappalyzer-style)
    try:
        body = resp.text[:80000].lower()
    except Exception:
        body = ""

    for pattern, category, tech_name in HTML_TECH:
        if not re.search(pattern, body, re.I):
            continue
        name = tech_name or _pattern_to_name(pattern)
        if name and name.lower() not in seen:
            seen.add(name.lower())
            if category == "cms" and name not in result["cms"]:
                result["cms"].append(name)
            elif category == "frontend" and name not in result["frontend"]:
                result["frontend"].append(name)
            elif category == "backend" and name not in result["backend"]:
                result["backend"].append(name)
            elif category == "api" and name not in result["api"]:
                result["api"].append(name)
            elif category == "database" and name not in result["database"]:
                result["database"].append(name)
            elif category == "analytics" and name not in result["analytics"]:
                result["analytics"].append(name)
            elif category == "cdn" and name and name not in result["cdn"]:
                result["cdn"].append(name)
            elif category == "security" and "security" not in result:
                result["security"] = result.get("security", []) + [name]
            elif category == "payment" and "payment" not in result:
                result["payment"] = result.get("payment", []) + [name]
            elif category == "monitoring" and "monitoring" not in result:
                result["monitoring"] = result.get("monitoring", []) + [name]
            elif category == "search" and "search" not in result:
                result["search"] = result.get("search", []) + [name]

    # 4. Meta generator extraction
    gen_match = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', body, re.I)
    if not gen_match:
        gen_match = re.search(r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+name=["\']generator["\']', body, re.I)
    if gen_match:
        g = gen_match.group(1).strip()[:80]
        if g and g.lower() not in seen:
            seen.add(g.lower())
            if g not in result["cms"]:
                result["cms"].append(g)

    # Clean empty lists
    for k in list(result.keys()):
        if isinstance(result[k], list) and not result[k]:
            del result[k]
    return result


def _add_tech(result: dict, category: str, name: str, seen: set) -> None:
    if not name or name.lower() in seen:
        return
    seen.add(name.lower())
    arr = result.get(category, [])
    if isinstance(arr, list) and name not in arr:
        result.setdefault(category, []).append(name)


def _pattern_to_name(pattern: str) -> str:
    s = re.sub(r"[^\w\s]", " ", pattern).strip()
    return s.split()[0].title() if s else ""
