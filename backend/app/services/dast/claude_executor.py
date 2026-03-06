"""Claude DAST Tool Executor — bridges Claude tool calls to actual DAST operations.

Routes tool_use calls to: existing DAST checks, HTTP requests, crawling
(via claude_crawler), injection testing (via claude_tester), finding creation,
and test case management.
"""
import json
import logging
import re
import time
from urllib.parse import urlparse, urlencode, urljoin

import httpx

from .base import (
    DastResult, ScanContext, safe_get, safe_request,
    BROWSER_HEADERS, USER_AGENTS, TIMEOUT,
)
from .runner import ALL_CHECKS

logger = logging.getLogger(__name__)

# Content-type shorthand mapping
CONTENT_TYPE_MAP = {
    "json": "application/json",
    "form": "application/x-www-form-urlencoded",
    "xml": "application/xml",
    "text": "text/plain",
}


class ClaudeToolExecutor:
    """Executes Claude tool calls against actual DAST operations."""

    def __init__(
        self,
        target_url: str,
        scan_context: ScanContext | None = None,
        project_id: str = "",
        scan_id: str = "",
        scope_domains: list[str] | None = None,
        scope_domain: str = "",
    ):
        self.target_url = target_url
        self.ctx = scan_context or ScanContext(target_url)
        self.project_id = project_id
        self.scan_id = scan_id
        # Accept both scope_domain (str) and scope_domains (list)
        if scope_domains:
            self.scope_domains = scope_domains
        elif scope_domain:
            self.scope_domains = [urlparse(scope_domain).hostname or scope_domain]
        else:
            self.scope_domains = [urlparse(target_url).hostname or ""]

        # Accumulated results
        self.findings: list[dict] = []
        self.crawl_results: list[dict] = []
        self.new_test_cases: list[dict] = []
        self._check_map = {name: fn for name, fn in ALL_CHECKS}

    def execute(self, tool_name: str, tool_input: dict) -> dict:
        """Route tool call to appropriate handler. Returns result dict."""
        handlers = {
            "browse_url": self._browse_url,
            "crawl_sitemap": self._crawl_sitemap,
            "discover_endpoints": self._discover_endpoints,
            "enumerate_subdomains": self._enumerate_subdomains,
            "analyze_javascript": self._analyze_javascript,
            "discover_api_schema": self._discover_api_schema,
            "interact_form": self._interact_form,
            "http_request": self._http_request,
            "run_dast_check": self._run_dast_check,
            "test_injection": self._test_injection,
            "test_authentication": self._test_authentication,
            "test_race_condition": self._test_race_condition,
            "test_websocket": self._test_websocket,
            "test_graphql": self._test_graphql,
            "test_llm_chatbot": self._test_llm_chatbot,
            "create_finding": self._create_finding,
            "save_crawl_result": self._save_crawl_result,
            "save_test_case": self._save_test_case,
            "get_project_context": self._get_project_context,
            "offer_pentest_option": self._offer_pentest_option,
            "update_progress": self._update_progress,
        }
        handler = handlers.get(tool_name)
        if not handler:
            return {"error": f"Unknown tool: {tool_name}"}
        try:
            return handler(tool_input)
        except Exception as e:
            logger.warning("Tool %s execution error: %s", tool_name, e)
            return {"error": str(e)[:500], "tool": tool_name}

    # ── SCOPE & SAFETY ────────────────────────────────────────────

    def _check_scope(self, url: str) -> bool:
        """Verify URL is within scan scope."""
        from app.core.ssrf import is_ssrf_blocked_url
        if is_ssrf_blocked_url(url):
            return False
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()
        for domain in self.scope_domains:
            if hostname == domain or hostname.endswith(f".{domain}"):
                return True
        return False

    def _format_request(self, method: str, url: str, headers: dict, body: str = "") -> str:
        """Format HTTP request as raw string for evidence."""
        parsed = urlparse(url)
        path = parsed.path or "/"
        if parsed.query:
            path += f"?{parsed.query}"
        lines = [f"{method} {path} HTTP/1.1", f"Host: {parsed.netloc}"]
        for k, v in headers.items():
            if k.lower() not in ("host",):
                lines.append(f"{k}: {v}")
        if body:
            lines.append("")
            lines.append(body[:2000])
        return "\n".join(lines)

    def _format_response(self, resp: httpx.Response) -> str:
        """Format HTTP response as raw string for evidence."""
        lines = [f"HTTP/1.1 {resp.status_code} {resp.reason_phrase or ''}"]
        for k, v in resp.headers.items():
            lines.append(f"{k}: {v}")
        lines.append("")
        body = resp.text[:3000] if resp.text else ""
        lines.append(body)
        return "\n".join(lines)

    # ── CRAWLING & DISCOVERY TOOLS (delegated to claude_crawler) ──

    def _browse_url(self, inp: dict) -> dict:
        """Browse URL with headless browser — delegates to claude_crawler."""
        url = inp["url"]
        if not self._check_scope(url):
            return {"error": f"URL out of scope: {url}"}
        self.ctx.throttle()
        from .claude_crawler import browse_url
        scope = self.scope_domains[0] if self.scope_domains else ""
        return browse_url(url, actions=inp.get("actions", []), scope_domain=scope)

    def _crawl_sitemap(self, inp: dict) -> dict:
        """Parse sitemap.xml and robots.txt — delegates to claude_crawler."""
        target = inp.get("target_url", self.target_url)
        if not self._check_scope(target):
            return {"error": f"URL out of scope: {target}"}
        self.ctx.throttle()
        from .claude_crawler import crawl_sitemap
        return crawl_sitemap(target)

    def _discover_endpoints(self, inp: dict) -> dict:
        """Discover hidden paths — delegates to claude_crawler."""
        base_url = inp.get("base_url", self.target_url)
        if not self._check_scope(base_url):
            return {"error": f"URL out of scope: {base_url}"}
        self.ctx.throttle()
        from .claude_crawler import discover_endpoints
        return discover_endpoints(
            base_url=base_url,
            wordlist_type=inp.get("wordlist_type", "common"),
            custom_words=inp.get("custom_words", []),
            max_paths=min(inp.get("max_paths", 200), 500),
        )

    def _enumerate_subdomains(self, inp: dict) -> dict:
        """Enumerate subdomains — delegates to claude_crawler."""
        from .claude_crawler import enumerate_subdomains
        domain = inp.get("domain", "")
        if not domain:
            return {"error": "domain parameter is required"}
        return enumerate_subdomains(
            domain=domain,
            methods=inp.get("methods"),
        )

    def _analyze_javascript(self, inp: dict) -> dict:
        """Analyze JavaScript — delegates to claude_crawler."""
        js_url = inp.get("js_url", "")
        if js_url and not self._check_scope(js_url):
            return {"error": f"URL out of scope: {js_url}"}
        self.ctx.throttle()
        from .claude_crawler import analyze_javascript
        return analyze_javascript(
            js_url=js_url,
            js_content=inp.get("js_content", ""),
        )

    def _discover_api_schema(self, inp: dict) -> dict:
        """Discover API schemas — delegates to claude_crawler."""
        base_url = inp.get("base_url", self.target_url)
        if not self._check_scope(base_url):
            return {"error": f"URL out of scope: {base_url}"}
        self.ctx.throttle()
        from .claude_crawler import discover_api_schema
        return discover_api_schema(
            base_url=base_url,
            api_type=inp.get("api_type", "rest"),
        )

    def _interact_form(self, inp: dict) -> dict:
        """Fill and submit a form — delegates to claude_crawler."""
        form_url = inp.get("form_url", self.target_url)
        action = inp.get("form_action", form_url)
        if action and not action.startswith("http"):
            action = urljoin(form_url, action)
        if not self._check_scope(action):
            return {"error": f"Form action URL out of scope: {action}"}
        self.ctx.throttle()
        from .claude_crawler import interact_form
        return interact_form(
            form_url=form_url,
            form_action=action,
            fields=inp.get("fields", []),
            method=inp.get("form_method", "POST"),
            submit=inp.get("submit", True),
        )

    # ── HTTP REQUEST TOOL (executor-specific, uses ScanContext) ───

    def _http_request(self, inp: dict) -> dict:
        """Execute custom HTTP request."""
        url = inp["url"]
        method = inp.get("method", "GET").upper()

        if not url.startswith("http"):
            url = urljoin(self.target_url, url)

        if not self._check_scope(url):
            return {"error": f"URL out of scope: {url}"}

        headers = dict(BROWSER_HEADERS)
        headers.update(inp.get("auth_headers", {}))
        headers.update(inp.get("headers", {}))

        ct = inp.get("content_type")
        if ct and ct in CONTENT_TYPE_MAP:
            headers["Content-Type"] = CONTENT_TYPE_MAP[ct]

        body = inp.get("raw_body") or inp.get("body")
        timeout = min(inp.get("timeout_seconds", 15), 30)
        follow = inp.get("follow_redirects", False)
        concurrent = min(inp.get("concurrent_count", 1), 50)

        if concurrent > 1:
            return self._concurrent_request(method, url, headers, body, concurrent, timeout)

        self.ctx.throttle()
        try:
            with httpx.Client(
                timeout=httpx.Timeout(float(timeout)),
                headers=headers,
                verify=False,
                follow_redirects=follow,
            ) as client:
                start = time.time()
                kwargs = {}
                if body and method in ("POST", "PUT", "PATCH", "DELETE"):
                    kwargs["content"] = body
                resp = client.request(method, url, **kwargs)
                timing = round((time.time() - start) * 1000, 1)

                return {
                    "status_code": resp.status_code,
                    "headers": dict(resp.headers),
                    "body": (resp.text or "")[:5000],
                    "timing_ms": timing,
                    "redirect_chain": [str(r.url) for r in resp.history] if resp.history else [],
                    "cookies": dict(resp.cookies),
                    "request_raw": self._format_request(method, url, headers, body or ""),
                    "response_raw": self._format_response(resp),
                }
        except httpx.TimeoutException:
            return {"error": "Request timed out", "timing_ms": timeout * 1000}
        except Exception as e:
            return {"error": str(e)[:300]}

    def _concurrent_request(self, method: str, url: str, headers: dict, body: str | None, count: int, timeout: float) -> dict:
        """Send concurrent requests for race condition testing."""
        import concurrent.futures

        results = []
        start = time.time()

        def make_request(i):
            try:
                with httpx.Client(timeout=httpx.Timeout(float(timeout)), verify=False) as c:
                    req_start = time.time()
                    kwargs = {}
                    if body and method in ("POST", "PUT", "PATCH", "DELETE"):
                        kwargs["content"] = body
                    r = c.request(method, url, headers=headers, **kwargs)
                    return {
                        "index": i,
                        "status_code": r.status_code,
                        "body_preview": (r.text or "")[:500],
                        "timing_ms": round((time.time() - req_start) * 1000, 1),
                    }
            except Exception as e:
                return {"index": i, "error": str(e)[:200]}

        with concurrent.futures.ThreadPoolExecutor(max_workers=count) as executor:
            futures = [executor.submit(make_request, i) for i in range(count)]
            for f in concurrent.futures.as_completed(futures):
                results.append(f.result())

        total_time = round((time.time() - start) * 1000, 1)
        results.sort(key=lambda r: r.get("index", 0))

        status_codes = [r.get("status_code") for r in results if "status_code" in r]
        bodies = [r.get("body_preview", "") for r in results if "body_preview" in r]
        inconsistent = len(set(status_codes)) > 1 or len(set(bodies)) > 1

        return {
            "concurrent_count": count,
            "total_time_ms": total_time,
            "results": results,
            "inconsistencies_detected": inconsistent,
            "unique_status_codes": list(set(status_codes)),
            "timing_spread_ms": max(r.get("timing_ms", 0) for r in results) - min(r.get("timing_ms", 0) for r in results) if results else 0,
        }

    def _run_dast_check(self, inp: dict) -> dict:
        """Run an existing DAST check by name."""
        check_name = inp["check_name"]
        url = inp.get("target_url", self.target_url)
        if not url.startswith("http"):
            url = self.target_url

        fn = self._check_map.get(check_name)
        if not fn:
            return {"error": f"Check '{check_name}' not found. Available: {', '.join(self._check_map.keys())}"}

        try:
            result = fn(url)
            return result.to_dict()
        except Exception as e:
            return {"error": f"Check '{check_name}' failed: {str(e)[:300]}"}

    # ── TESTING TOOLS (delegated to claude_tester) ────────────────

    def _test_injection(self, inp: dict) -> dict:
        """Test parameter for injection — delegates to claude_tester."""
        url = inp.get("url", self.target_url)
        if not url.startswith("http"):
            url = urljoin(self.target_url, url)
        if not self._check_scope(url):
            return {"error": f"URL out of scope: {url}"}
        self.ctx.throttle()
        from .claude_tester import test_injection
        parameter = inp.get("parameter", "")
        if not parameter:
            return {"error": "parameter name is required"}
        return test_injection(
            url=url,
            parameter=parameter,
            injection_type=inp.get("injection_type", "xss"),
            payload_level=inp.get("payload_level", "basic"),
            custom_payloads=inp.get("custom_payloads"),
            method=inp.get("base_method", "GET"),
        )

    def _test_authentication(self, inp: dict) -> dict:
        """Test authentication security — delegates to claude_tester."""
        login_url = inp.get("login_url", self.target_url)
        if not login_url.startswith("http"):
            login_url = urljoin(self.target_url, login_url)
        if not self._check_scope(login_url):
            return {"error": f"URL out of scope: {login_url}"}
        self.ctx.throttle()
        from .claude_tester import test_authentication
        return test_authentication(
            login_url=login_url,
            username_field=inp.get("username_field", "username"),
            password_field=inp.get("password_field", "password"),
            test_type=inp.get("test_type", "default_creds"),
            context=inp.get("app_context"),
        )

    def _test_race_condition(self, inp: dict) -> dict:
        """Test for race conditions — delegates to claude_tester."""
        requests_config = inp.get("requests", [])
        # If simple single-URL form, build config from inp
        if not requests_config and inp.get("url"):
            url = inp["url"]
            if not url.startswith("http"):
                url = urljoin(self.target_url, url)
            if not self._check_scope(url):
                return {"error": f"URL out of scope: {url}"}
            count = min(inp.get("concurrent_count", 20), 50)
            requests_config = [{
                "method": inp.get("method", "POST"),
                "url": url,
                "headers": {**BROWSER_HEADERS, **(inp.get("headers", {}))},
                "body": inp.get("body"),
            }] * count

        from .claude_tester import test_race_condition
        return test_race_condition(
            requests_config=requests_config,
            timing_method=inp.get("timing_method", "concurrent"),
            repeat_count=inp.get("repeat_rounds", inp.get("repeat_count", 1)),
        )

    def _test_websocket(self, inp: dict) -> dict:
        """Test WebSocket endpoint — delegates to claude_tester."""
        from .claude_tester import test_websocket
        ws_url = inp.get("ws_url", "")
        if not ws_url:
            return {"error": "ws_url parameter is required"}
        return test_websocket(
            ws_url=ws_url,
            initial_messages=inp.get("initial_messages"),
            test_messages=inp.get("test_messages"),
            auth_headers=inp.get("auth_headers"),
        )

    def _test_graphql(self, inp: dict) -> dict:
        """Test GraphQL endpoint — delegates to claude_tester."""
        gql_url = inp.get("graphql_url", "")
        if not gql_url.startswith("http"):
            gql_url = urljoin(self.target_url, gql_url)
        if not self._check_scope(gql_url):
            return {"error": f"URL out of scope: {gql_url}"}
        self.ctx.throttle()
        from .claude_tester import test_graphql
        return test_graphql(
            graphql_url=gql_url,
            test_type=inp.get("test_type", "introspection"),
        )

    def _test_llm_chatbot(self, inp: dict) -> dict:
        """Test LLM/AI chatbot — delegates to claude_tester."""
        chatbot_url = inp.get("chatbot_url", "")
        if not chatbot_url.startswith("http"):
            chatbot_url = urljoin(self.target_url, chatbot_url)
        if not self._check_scope(chatbot_url):
            return {"error": f"URL out of scope: {chatbot_url}"}
        self.ctx.throttle()
        from .claude_tester import test_llm_chatbot
        return test_llm_chatbot(
            chatbot_url=chatbot_url,
            chatbot_type=inp.get("chatbot_type", "api"),
            test_type=inp.get("test_type", "prompt_injection"),
        )

    # ── REPORTING TOOLS ───────────────────────────────────────────

    def _create_finding(self, inp: dict) -> dict:
        """Record a confirmed security finding."""
        finding = {
            "check_id": f"CLAUDE-{len(self.findings)+1:03d}",
            "title": inp["title"],
            "status": "failed",
            "severity": inp.get("severity", "medium"),
            "description": inp.get("description", ""),
            "evidence": inp.get("evidence", ""),
            "reproduction_steps": inp.get("reproduction_steps", ""),
            "impact": inp.get("impact", ""),
            "remediation": inp.get("remediation", ""),
            "cwe_id": inp.get("cwe_id", ""),
            "owasp_ref": inp.get("owasp_ref", ""),
            "request_raw": inp.get("request_raw", ""),
            "response_raw": inp.get("response_raw", "")[:5000],
            "affected_url": inp.get("affected_url", ""),
            "affected_parameter": inp.get("affected_parameter", ""),
            "cvss_score": inp.get("cvss_score", ""),
        }
        self.findings.append(finding)
        return {"status": "recorded", "finding_index": len(self.findings), "finding": finding}

    def _save_crawl_result(self, inp: dict) -> dict:
        """Save a crawled page/endpoint."""
        self.crawl_results.append(inp)
        return {"status": "saved", "total_crawled": len(self.crawl_results)}

    def _save_test_case(self, inp: dict) -> dict:
        """Queue a new test case for creation."""
        self.new_test_cases.append(inp)
        return {"status": "queued", "total_test_cases": len(self.new_test_cases)}

    def _get_project_context(self, inp: dict) -> dict:
        """Return project context (stub — populated by agent from DB)."""
        return {
            "target_url": self.target_url,
            "scope_domains": self.scope_domains,
            "total_findings": len(self.findings),
            "total_crawled": len(self.crawl_results),
        }

    def _offer_pentest_option(self, inp: dict) -> dict:
        """Present penetration options to user."""
        return {"status": "options_presented", "finding_title": inp["finding_title"], "options_count": len(inp.get("options", []))}

    def _update_progress(self, inp: dict) -> dict:
        """Update progress — handled by agent, this is a no-op."""
        return {"status": "updated", "phase": inp.get("phase", "")}
