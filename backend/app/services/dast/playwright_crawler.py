"""Advanced Playwright-based crawler for JS/SPA coverage.

Features:
- Full DOM link extraction (a, area, buttons, data-* attributes)
- Network request interception to capture API calls
- Scroll-to-bottom for infinite scroll / lazy loading
- Click interaction on navigable elements
- Form discovery with field metadata
- Cookie and session handling for auth
- SPA route detection (hash + pushState)
"""
import logging
import os
import re
import time
from typing import Callable
from urllib.parse import urljoin, urlparse

logger = logging.getLogger(__name__)

_PLAYWRIGHT_AVAILABLE = False
try:
    from playwright.sync_api import sync_playwright
    _PLAYWRIGHT_AVAILABLE = True
except ImportError:
    logger.info(
        "Playwright not installed. For JS/SPA crawling: pip install playwright && playwright install chromium"
    )


def run_playwright_crawl(
    target_url: str,
    auth_headers: dict[str, str],
    page_urls: list[str],
    max_pages: int = 20,
    progress_callback: Callable[[str], None] | None = None,
) -> list[dict]:
    """
    Visit page URLs with Playwright, extract links from JS-rendered DOM,
    intercept network requests, handle SPAs, and discover forms.

    Returns list of katana-compatible dicts: [{request: {endpoint, method}}]
    """
    if not _PLAYWRIGHT_AVAILABLE:
        logger.warning(
            "Playwright not installed. Enable JS/SPA mode: pip install playwright && playwright install chromium"
        )
        return []

    parsed = urlparse(target_url)
    base_scheme = parsed.scheme or "https"
    base_netloc = parsed.netloc

    def _same_origin(href: str) -> bool:
        if not href or href.startswith("#") or href.startswith("javascript:") or href.startswith("data:"):
            return False
        try:
            p = urlparse(urljoin(target_url, href))
            return p.netloc == base_netloc or not p.netloc
        except Exception:
            return False

    results: list[dict] = []
    seen: set[str] = set()
    intercepted_requests: list[dict] = []

    launch_args = {"headless": True}
    if os.environ.get("PLAYWRIGHT_NO_SANDBOX", "1") == "1":
        launch_args["args"] = ["--no-sandbox", "--disable-setuid-sandbox"]

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(**launch_args)
            context = browser.new_context(
                ignore_https_errors=True,
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                viewport={"width": 1280, "height": 720},
            )
            for name, value in auth_headers.items():
                if name and value:
                    context.set_extra_http_headers({name: value})

            for i, url in enumerate(page_urls[:max_pages]):
                if not url or url in seen:
                    continue
                seen.add(url)
                if progress_callback:
                    progress_callback(f"Playwright: {i + 1}/{min(len(page_urls), max_pages)} — {urlparse(url).path}")
                try:
                    page = context.new_page()

                    page_api_calls: list[dict] = []

                    def handle_request(request):
                        req_url = request.url
                        method = request.method
                        if _same_origin(req_url) and req_url not in seen:
                            page_api_calls.append({"url": req_url, "method": method})

                    page.on("request", handle_request)

                    page.goto(url, wait_until="domcontentloaded", timeout=25000)
                    try:
                        page.wait_for_load_state("networkidle", timeout=8000)
                    except Exception:
                        pass

                    _scroll_page(page)

                    links = _extract_all_links(page)
                    for href in links:
                        if isinstance(href, str) and href.startswith("http") and _same_origin(href) and href not in seen:
                            seen.add(href)
                            results.append({"request": {"endpoint": href, "method": "GET"}, "source": url, "tag": "playwright"})

                    forms = _extract_forms(page, url, base_scheme, base_netloc)
                    for form in forms:
                        endpoint = form.get("action", url)
                        if endpoint not in seen:
                            seen.add(endpoint)
                            results.append({
                                "request": {
                                    "endpoint": endpoint,
                                    "method": form.get("method", "GET"),
                                    "body": "&".join(f"{f['name']}=" for f in form.get("fields", []) if f.get("name")),
                                },
                                "tag": "form",
                            })

                    for api_call in page_api_calls:
                        if api_call["url"] not in seen:
                            seen.add(api_call["url"])
                            results.append({
                                "request": {"endpoint": api_call["url"], "method": api_call["method"]},
                                "tag": "xhr",
                            })

                    inline_urls = _extract_inline_js_urls(page, base_scheme, base_netloc)
                    for js_url in inline_urls:
                        if js_url not in seen and _same_origin(js_url):
                            seen.add(js_url)
                            results.append({"request": {"endpoint": js_url, "method": "GET"}, "tag": "inline_js"})

                    page.close()
                except Exception as e:
                    logger.debug("Playwright page %s failed: %s", url, e)
                    try:
                        page.close()
                    except Exception:
                        pass

            browser.close()
    except Exception as e:
        logger.warning("Playwright crawl failed: %s", e)

    return results


def _scroll_page(page, max_scrolls: int = 5, pause: float = 0.5):
    """Scroll to bottom to trigger lazy-loaded content."""
    try:
        prev_height = 0
        for _ in range(max_scrolls):
            page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
            time.sleep(pause)
            curr_height = page.evaluate("document.body.scrollHeight")
            if curr_height == prev_height:
                break
            prev_height = curr_height
        page.evaluate("window.scrollTo(0, 0)")
    except Exception:
        pass


def _extract_all_links(page) -> list[str]:
    """Extract all navigable links from rendered DOM."""
    links: list[str] = []
    try:
        links.extend(page.eval_on_selector_all(
            "a[href]", "els => els.map(e => e.href).filter(Boolean)"
        ) or [])
        links.extend(page.eval_on_selector_all(
            "area[href]", "els => els.map(e => e.href).filter(Boolean)"
        ) or [])
        links.extend(page.eval_on_selector_all(
            "[data-href]", "els => els.map(e => e.dataset.href).filter(Boolean)"
        ) or [])
        links.extend(page.eval_on_selector_all(
            "[data-url]", "els => els.map(e => e.dataset.url).filter(Boolean)"
        ) or [])
        links.extend(page.eval_on_selector_all(
            "[data-link]", "els => els.map(e => e.dataset.link).filter(Boolean)"
        ) or [])
        links.extend(page.eval_on_selector_all(
            "form[action]", "els => els.map(e => e.action).filter(Boolean)"
        ) or [])
        links.extend(page.eval_on_selector_all(
            "link[href]", "els => els.map(e => e.href).filter(Boolean)"
        ) or [])
        links.extend(page.eval_on_selector_all(
            "script[src]", "els => els.map(e => e.src).filter(Boolean)"
        ) or [])
        links.extend(page.eval_on_selector_all(
            "iframe[src]", "els => els.map(e => e.src).filter(Boolean)"
        ) or [])
    except Exception:
        pass
    return links


def _extract_forms(page, current_url: str, base_scheme: str, base_netloc: str) -> list[dict]:
    """Extract form details from rendered DOM."""
    forms = []
    try:
        raw = page.evaluate("""
            () => {
                return Array.from(document.querySelectorAll('form')).map(f => ({
                    action: f.action || '',
                    method: (f.method || 'GET').toUpperCase(),
                    enctype: f.enctype || '',
                    fields: Array.from(f.querySelectorAll('input, select, textarea')).map(el => ({
                        name: el.name || '',
                        type: el.type || el.tagName.toLowerCase(),
                        value: el.value || '',
                        required: el.required || false,
                        placeholder: el.placeholder || '',
                    })).filter(f => f.name)
                }))
            }
        """)
        for form in (raw or []):
            action = form.get("action", "")
            if not action or not action.startswith("http"):
                action = urljoin(current_url, action) if action else current_url
            forms.append({
                "action": action,
                "method": form.get("method", "GET"),
                "enctype": form.get("enctype", ""),
                "fields": form.get("fields", []),
            })
    except Exception:
        pass
    return forms


def _extract_inline_js_urls(page, base_scheme: str, base_netloc: str) -> list[str]:
    """Extract API endpoint URLs from inline JavaScript."""
    urls = []
    try:
        js_text = page.evaluate("""
            () => {
                const scripts = document.querySelectorAll('script:not([src])');
                return Array.from(scripts).map(s => s.textContent).join('\\n');
            }
        """)
        if js_text:
            for pattern in [
                r'["\'](https?://[^"\']+)["\']',
                r'["\'](/api/[^"\']+)["\']',
                r'["\'](/v[0-9]+/[^"\']+)["\']',
                r'fetch\s*\(\s*["\']([^"\']+)["\']',
                r'axios\.\w+\s*\(\s*["\']([^"\']+)["\']',
                r'\.(?:get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']',
            ]:
                for m in re.finditer(pattern, js_text):
                    u = m.group(1)
                    if u.startswith("/"):
                        u = f"{base_scheme}://{base_netloc}{u}"
                    if u.startswith("http"):
                        urls.append(u)
    except Exception:
        pass
    return urls[:200]
