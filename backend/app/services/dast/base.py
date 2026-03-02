"""DAST base: DastResult, ScanContext, HTTP helpers, constants."""
import time
import random
from pathlib import Path
from urllib.parse import urlparse

import httpx

# Project root: backend/app/services/dast/base.py -> parents[4] = navigator
DATA_ROOT = Path(__file__).resolve().parents[4] / "data"

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
]
BROWSER_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
}
HEADERS = {**BROWSER_HEADERS, "User-Agent": USER_AGENTS[0]}

TIMEOUT = httpx.Timeout(20.0, connect=10.0)
MIN_DELAY_BETWEEN_REQUESTS = 1.2
MAX_DELAY_BETWEEN_REQUESTS = 2.8
PROBE_DELAY = 2.0

_scan_ctx: "ScanContext | None" = None


def get_scan_ctx() -> "ScanContext | None":
    return _scan_ctx


def set_scan_ctx(ctx: "ScanContext | None") -> None:
    global _scan_ctx
    _scan_ctx = ctx


class DastResult:
    """Result of a single DAST check."""

    def __init__(
        self,
        check_id: str,
        title: str,
        status: str = "not_started",
        severity: str = "info",
        description: str = "",
        details: dict = None,
        evidence: str = "",
        remediation: str = "",
        cwe_id: str = "",
        owasp_ref: str = "",
        reproduction_steps: str = "",
        request_raw: str = "",
        response_raw: str = "",
    ):
        self.check_id = check_id
        self.title = title
        self.status = status
        self.severity = severity
        self.description = description
        self.details = details or {}
        self.evidence = evidence
        self.remediation = remediation
        self.cwe_id = cwe_id
        self.owasp_ref = owasp_ref
        self.reproduction_steps = reproduction_steps
        self.request_raw = request_raw
        self.response_raw = response_raw

    def to_dict(self) -> dict:
        return {
            "check_id": self.check_id,
            "title": self.title,
            "status": self.status,
            "severity": self.severity,
            "description": self.description,
            "details": self.details,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "cwe_id": self.cwe_id,
            "owasp_ref": self.owasp_ref,
            "reproduction_steps": self.reproduction_steps,
            "request_raw": self.request_raw,
            "response_raw": self.response_raw,
        }


class ScanContext:
    """WAF-aware scan context: resolved base URL, throttling, UA rotation."""

    def __init__(self, base_url: str | None):
        self.base_url = base_url
        self.ua_index = 0
        self.last_request = 0.0

    def _headers(self) -> dict:
        h = dict(BROWSER_HEADERS)
        h["User-Agent"] = USER_AGENTS[self.ua_index % len(USER_AGENTS)]
        self.ua_index += 1
        return h

    def throttle(self) -> None:
        elapsed = time.time() - self.last_request
        delay = random.uniform(MIN_DELAY_BETWEEN_REQUESTS, MAX_DELAY_BETWEEN_REQUESTS)
        if elapsed < delay:
            time.sleep(delay - elapsed)
        self.last_request = time.time()

    def _rewrite_url(self, url: str) -> str:
        if not self.base_url:
            return url
        p_url = urlparse(url)
        p_base = urlparse(self.base_url)
        if p_url.netloc and p_url.netloc.lower() == p_base.netloc.lower():
            return f"{p_base.scheme}://{p_base.netloc}{p_url.path or '/'}{p_url.query and '?' + p_url.query or ''}"
        return url

    def safe_get(self, url: str, **kwargs) -> httpx.Response | None:
        self.throttle()
        url = self._rewrite_url(url)
        urls_to_try = _url_variants(url)
        for _ in range(2):
            for u in urls_to_try:
                try:
                    h = self._headers()
                    h.update(kwargs.pop("headers", {}))
                    with httpx.Client(
                        timeout=TIMEOUT, headers=h, verify=False, follow_redirects=True
                    ) as client:
                        r = client.get(u, **kwargs)
                        if r.status_code == 429:
                            time.sleep(random.uniform(5, 10))
                            continue
                        return r
                except Exception:
                    pass
            time.sleep(PROBE_DELAY)
        return None

    def safe_request(self, method: str, url: str, **kwargs) -> httpx.Response | None:
        self.throttle()
        url = self._rewrite_url(url)
        urls_to_try = _url_variants(url)
        for _ in range(2):
            for u in urls_to_try:
                try:
                    h = self._headers()
                    h.update(kwargs.pop("headers", {}))
                    with httpx.Client(
                        timeout=TIMEOUT, headers=h, verify=False, follow_redirects=False
                    ) as client:
                        r = client.request(method, u, **kwargs)
                        if r.status_code == 429:
                            time.sleep(random.uniform(5, 10))
                            continue
                        return r
                except Exception:
                    pass
            time.sleep(PROBE_DELAY)
        return None


def _url_variants(url: str) -> list[str]:
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}{parsed.query and '?' + parsed.query or ''}"
    urls = [url]
    if parsed.scheme == "https":
        u2 = base.replace("https://", "http://")
        if u2 not in urls:
            urls.append(u2)
    elif parsed.scheme == "http":
        u2 = base.replace("http://", "https://")
        if u2 not in urls:
            urls.append(u2)
    netloc = parsed.netloc or ""
    if "www." not in netloc and netloc:
        for u in list(urls):
            u_www = u.replace(netloc, f"www.{netloc}", 1)
            if u_www not in urls:
                urls.append(u_www)
    return urls


def safe_get(url: str, **kwargs) -> httpx.Response | None:
    ctx = get_scan_ctx()
    if ctx:
        return ctx.safe_get(url, **kwargs)
    for u in _url_variants(url):
        try:
            h = {**BROWSER_HEADERS, "User-Agent": USER_AGENTS[0]}
            with httpx.Client(
                timeout=TIMEOUT, headers=h, verify=False, follow_redirects=True
            ) as client:
                return client.get(u, **kwargs)
        except Exception:
            pass
    return None


def safe_request(method: str, url: str, **kwargs) -> httpx.Response | None:
    ctx = get_scan_ctx()
    if ctx:
        return ctx.safe_request(method, url, **kwargs)
    for u in _url_variants(url):
        try:
            h = {**BROWSER_HEADERS, "User-Agent": USER_AGENTS[0]}
            with httpx.Client(
                timeout=TIMEOUT, headers=h, verify=False, follow_redirects=False
            ) as client:
                return client.request(method, u, **kwargs)
        except Exception:
            pass
    return None


def resolve_base_url(target_url: str) -> str | None:
    """Probe URL variants; return first reachable base URL."""
    variants = _url_variants(target_url)
    for _ in range(2):
        for ua in USER_AGENTS:
            for u in variants:
                try:
                    time.sleep(PROBE_DELAY)
                    with httpx.Client(
                        timeout=TIMEOUT,
                        headers={**BROWSER_HEADERS, "User-Agent": ua},
                        verify=False,
                        follow_redirects=True,
                    ) as client:
                        r = client.get(u)
                        if r.status_code < 500:
                            p = urlparse(str(r.url))
                            return f"{p.scheme}://{p.netloc}/"
                except Exception:
                    pass
    return None
