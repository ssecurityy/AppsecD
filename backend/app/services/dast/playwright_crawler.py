"""Optional Playwright-based crawler for JS/SPA coverage."""
import logging
import os
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
    Visit page URLs with Playwright, extract links from JS-rendered DOM.

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

    def _extract_links(page) -> list[str]:
        """Extract all navigable links (a, area, link rel=alternate, etc)."""
        links = []
        try:
            # Primary: <a href>
            a_hrefs = page.eval_on_selector_all(
                "a[href]",
                "els => els.map(e => e.href).filter(Boolean)",
            )
            links.extend(a_hrefs or [])
            # Forms with action
            form_actions = page.eval_on_selector_all(
                "form[action]",
                "els => els.map(e => e.action).filter(Boolean)",
            )
            links.extend(form_actions or [])
        except Exception:
            pass
        return links

    results: list[dict] = []
    seen: set[str] = set()
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
                    progress_callback(f"Playwright: {i + 1}/{min(len(page_urls), max_pages)}")
                try:
                    page = context.new_page()
                    # Prefer domcontentloaded for faster; fallback to load
                    page.goto(url, wait_until="domcontentloaded", timeout=20000)
                    # Brief wait for SPA routing/hydration
                    page.wait_for_load_state("networkidle", timeout=5000)

                    for href in _extract_links(page):
                        if not isinstance(href, str):
                            continue
                        if href.startswith("http") and _same_origin(href) and href not in seen:
                            seen.add(href)
                            results.append({"request": {"endpoint": href, "method": "GET"}})

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
