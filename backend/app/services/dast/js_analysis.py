"""JS file analysis: extract hidden URLs, deeplinks, library versions for SCA."""
import re
import logging
from typing import Any
from urllib.parse import urljoin, urlparse

logger = logging.getLogger(__name__)

# Patterns to extract URLs from JS
_URL_PATTERNS = [
    r'["\'](https?://[^"\']+)["\']',
    r'["\'](//[^"\']+)["\']',
    r'["\'](/[a-zA-Z0-9_\-/?.&=%]+)["\']',
    r'url\s*[=:]\s*["\']([^"\']+)["\']',
    r'fetch\s*\(\s*["\']([^"\']+)["\']',
    r'axios\.(?:get|post)\s*\(\s*["\']([^"\']+)["\']',
    r'\.get\s*\(\s*["\']([^"\']+)["\']',
    r'href\s*[=:]\s*["\']([^"\']+)["\']',
    r'src\s*[=:]\s*["\']([^"\']+)["\']',
    r'redirect\s*[=:]\s*["\']([^"\']+)["\']',
    r'location\s*=\s*["\']([^"\']+)["\']',
    r'window\.open\s*\(\s*["\']([^"\']+)["\']',
    r'`(https?://[^`]+)`',
    r'`(/[a-zA-Z0-9_\-/?.&=%]+)`',
]

# Deeplink / custom scheme patterns
_DEEPLINK_PATTERNS = [
    r'["\'](app://[^"\']+)["\']',
    r'["\'](intent://[^"\']+)["\']',
    r'["\'](myapp://[^"\']+)["\']',
    r'["\']([a-z][a-z0-9+.-]*://[^"\']+)["\']',  # custom schemes
    r'window\.location\s*=\s*["\']([a-z][a-z0-9+.-]*://[^"\']+)["\']',
]

# Library version patterns (common in JS bundles and comments)
_LIB_VERSION_PATTERNS = [
    r'["\']?(jquery|lodash|underscore|react|vue|angular|moment|dayjs|axios)["\']?\s*[:=]\s*["\']?([\d.]+(?:-\w+)?)["\']?',
    r'/\*\s*!\s*(?:jQuery\s+)?v?([\d.]+)\s*\|',
    r'jquery[.-]([\d.]+)\.min\.js',
    r'lodash\.([\d.]+)\.min\.js',
    r'@([a-zA-Z0-9/_-]+)@([\d.]+)',  # npm @scope/name@version
    r'([a-zA-Z0-9_-]+)\.min\.js\?v=([\d.]+)',
    r'version["\']?\s*[=:]\s*["\']([\d.]+)["\']',
]

# Known lib names to reduce noise
_KNOWN_LIBS = {
    "jquery", "lodash", "underscore", "react", "vue", "angular", "bootstrap",
    "moment", "dayjs", "axios", "fetch", "axios", "uuid", "validator",
    "chart", "d3", "socket", "express", "crypto", "buffer",
}


def extract_urls(content: str, base_url: str = "") -> list[dict[str, Any]]:
    """
    Extract hidden URLs from JS content.

    Returns list of {url, type: "absolute"|"relative"|"deeplink", source}.
    """
    urls: set[str] = set()
    result: list[dict[str, Any]] = []

    if not content:
        return result

    # Deeplinks
    for pat in _DEEPLINK_PATTERNS:
        for m in re.finditer(pat, content):
            u = m.group(1)
            if u and u not in urls:
                urls.add(u)
                result.append({"url": u, "type": "deeplink", "source": "regex"})

    # HTTP URLs
    for pat in _URL_PATTERNS:
        for m in re.finditer(pat, content):
            u = m.group(1)
            if not u or u in urls or len(u) > 500:
                continue
            u = u.split("\\")[0].strip()  # Escape cleanup
            if u.startswith("http"):
                urls.add(u)
                result.append({"url": u, "type": "absolute", "source": "regex"})
            elif u.startswith("/"):
                full = urljoin(base_url, u) if base_url else u
                urls.add(full)
                result.append({"url": full, "type": "relative", "source": "regex", "original": u})
            elif u.startswith("//"):
                full = f"https:{u}" if base_url else u
                urls.add(full)
                result.append({"url": full, "type": "absolute", "source": "regex"})

    return result


def extract_library_versions(content: str) -> list[dict[str, str]]:
    """
    Extract library name and version from JS content.
    Returns [{name, version}].
    """
    seen: set[tuple[str, str]] = set()
    result: list[dict[str, str]] = []

    if not content:
        return result

    for pat in _LIB_VERSION_PATTERNS:
        for m in re.finditer(pat, content, re.IGNORECASE):
            try:
                groups = m.groups()
                name = ""
                ver = ""
                if len(groups) >= 2:
                    name = (groups[0] or "").strip().lower()
                    ver = (groups[1] or "").strip()
                elif len(groups) == 1 and "jquery" in pat.lower():
                    ver = (groups[0] or "").strip()
                    name = "jquery"
                if not ver or not re.match(r"^[\d.]+", ver):
                    continue
                if not name:
                    name = "unknown"
                if name in ("http", "https", "version", "v") or len(name) < 2:
                    continue
                key = (name, ver)
                if key not in seen:
                    seen.add(key)
                    result.append({"name": name, "version": ver})
            except (IndexError, AttributeError):
                continue

    return result


def analyze_js(content: str, source_url: str = "") -> dict[str, Any]:
    """
    Full JS analysis: URLs, deeplinks, library versions.

    Returns {
        urls: [...],
        deeplinks: [...],
        libraries: [{name, version}],
    }
    """
    parsed = urlparse(source_url)
    base = f"{parsed.scheme}://{parsed.netloc}" if parsed.netloc else ""

    urls = extract_urls(content, base)
    deeplinks = [u["url"] for u in urls if u.get("type") == "deeplink"]
    libs = extract_library_versions(content)

    return {
        "urls": urls,
        "deeplinks": deeplinks,
        "libraries": libs,
    }
