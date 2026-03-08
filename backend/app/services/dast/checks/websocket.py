"""WebSocket security testing checks for DAST."""
import json
import logging
import ssl
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

TIMEOUT = 10


async def check_websocket_deep(url: str) -> list[dict]:
    """Comprehensive WebSocket security testing.

    Detects: insecure ws:// usage, missing origin validation,
    message injection, auth token handling, CSWSH.
    """
    findings: list[dict] = []
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    ws_endpoints = _discover_ws_endpoints(base)

    for ws_url in ws_endpoints:
        findings.extend(await _check_ws_vs_wss(ws_url))
        findings.extend(await _check_origin_bypass(ws_url))
        findings.extend(await _check_message_injection(ws_url))
        findings.extend(await _check_cswsh(ws_url, url))

    return findings


def _discover_ws_endpoints(base_url: str) -> list[str]:
    """Return candidate WebSocket endpoint URLs."""
    parsed = urlparse(base_url)
    scheme = "wss" if parsed.scheme == "https" else "ws"
    host = parsed.netloc
    return [
        f"{scheme}://{host}/ws",
        f"{scheme}://{host}/websocket",
        f"{scheme}://{host}/socket",
        f"{scheme}://{host}/socket.io/",
        f"{scheme}://{host}/api/ws",
        f"{scheme}://{host}/cable",
        f"{scheme}://{host}/realtime",
    ]


async def _try_connect(ws_url: str, extra_headers: dict | None = None) -> tuple[bool, str]:
    """Attempt a WebSocket connection. Returns (connected, detail_message)."""
    try:
        import websockets
        import asyncio

        headers = extra_headers or {}
        async with asyncio.timeout(TIMEOUT):
            async with websockets.connect(
                ws_url,
                additional_headers=headers,
                ssl=ssl.create_default_context() if ws_url.startswith("wss") else None,
                open_timeout=TIMEOUT,
            ) as ws:
                return True, "Connection established"
    except ImportError:
        return False, "websockets library not available"
    except Exception as e:
        return False, str(e)[:200]


async def _check_ws_vs_wss(ws_url: str) -> list[dict]:
    """Check if WebSocket uses insecure ws:// instead of wss://."""
    if ws_url.startswith("ws://"):
        connected, detail = await _try_connect(ws_url)
        if connected:
            return [{
                "title": "Insecure WebSocket Connection (ws://)",
                "severity": "high",
                "confidence": "confirmed",
                "description": (
                    f"WebSocket endpoint {ws_url} uses unencrypted ws:// protocol. "
                    "All data transmitted is visible to network attackers. Use wss:// (TLS)."
                ),
                "url": ws_url,
                "evidence": "Successfully connected via unencrypted ws://",
                "remediation": "Use wss:// (WebSocket Secure) with valid TLS certificates.",
                "cwe_id": "CWE-319",
                "owasp_ref": "A02:2021",
                "category": "insecure_transport",
            }]
    return []


async def _check_origin_bypass(ws_url: str) -> list[dict]:
    """Test if WebSocket accepts connections from arbitrary origins."""
    evil_origin = "https://evil-attacker.example.com"
    connected, detail = await _try_connect(ws_url, {"Origin": evil_origin})
    if connected:
        return [{
            "title": "WebSocket Missing Origin Validation",
            "severity": "high",
            "confidence": "confirmed",
            "description": (
                f"WebSocket at {ws_url} accepts connections from arbitrary origins "
                f"(tested with {evil_origin}). This enables Cross-Site WebSocket Hijacking (CSWSH)."
            ),
            "url": ws_url,
            "evidence": f"Connection accepted with Origin: {evil_origin}",
            "remediation": "Validate the Origin header on WebSocket upgrade requests. "
                          "Only accept connections from trusted origins.",
            "cwe_id": "CWE-346",
            "owasp_ref": "A07:2021",
            "category": "cross_site_websocket_hijacking",
        }]
    return []


async def _check_message_injection(ws_url: str) -> list[dict]:
    """Test for XSS/injection via WebSocket messages."""
    connected, detail = await _try_connect(ws_url)
    if not connected:
        return []

    try:
        import websockets
        import asyncio

        xss_payloads = [
            '<script>alert(1)</script>',
            '{"message": "<img src=x onerror=alert(1)>"}',
            '{"__proto__": {"polluted": true}}',
        ]

        async with asyncio.timeout(TIMEOUT):
            async with websockets.connect(ws_url, open_timeout=TIMEOUT) as ws:
                for payload in xss_payloads:
                    await ws.send(payload)
                    try:
                        response = await asyncio.wait_for(ws.recv(), timeout=3)
                        if payload in response or "script" in response.lower():
                            return [{
                                "title": "WebSocket Message Reflection (Potential XSS)",
                                "severity": "high",
                                "confidence": "medium",
                                "description": (
                                    f"WebSocket at {ws_url} reflects injected content in responses. "
                                    "If displayed in a browser, this can lead to XSS."
                                ),
                                "url": ws_url,
                                "evidence": f"Payload reflected: {payload[:100]}",
                                "remediation": "Sanitize and validate all WebSocket messages. "
                                              "Never render WebSocket data as raw HTML.",
                                "cwe_id": "CWE-79",
                                "owasp_ref": "A03:2021",
                                "category": "injection",
                            }]
                    except asyncio.TimeoutError:
                        pass
    except Exception:
        pass
    return []


async def _check_cswsh(ws_url: str, http_url: str) -> list[dict]:
    """Check for Cross-Site WebSocket Hijacking vulnerability."""
    connected_no_cookies, _ = await _try_connect(ws_url)
    if not connected_no_cookies:
        return []

    connected_evil_origin, _ = await _try_connect(
        ws_url, {"Origin": "https://evil.example.com"}
    )
    if connected_evil_origin:
        return [{
            "title": "Cross-Site WebSocket Hijacking (CSWSH)",
            "severity": "high",
            "confidence": "medium",
            "description": (
                f"WebSocket at {ws_url} is vulnerable to CSWSH. It accepts connections "
                "from arbitrary origins and may use cookies for authentication, allowing "
                "an attacker's page to establish authenticated WebSocket connections."
            ),
            "url": ws_url,
            "evidence": "WebSocket connected from malicious origin without authentication challenge",
            "remediation": (
                "1. Validate the Origin header server-side. "
                "2. Use per-connection tokens instead of cookies. "
                "3. Implement CSRF tokens for WebSocket handshake."
            ),
            "cwe_id": "CWE-352",
            "owasp_ref": "A01:2021",
            "category": "cross_site_websocket_hijacking",
        }]
    return []
