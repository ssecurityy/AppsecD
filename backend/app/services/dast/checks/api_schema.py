"""OpenAPI/Swagger schema-aware security testing for DAST."""
import json
import logging
import re
from urllib.parse import urljoin

import httpx

logger = logging.getLogger(__name__)

TIMEOUT = 15

SCHEMA_PATHS = [
    "/openapi.json", "/swagger.json", "/api-docs",
    "/v1/openapi.json", "/v2/swagger.json", "/v3/openapi.json",
    "/api/openapi.json", "/api/swagger.json", "/docs/openapi.json",
    "/.well-known/openapi.json",
]


async def check_api_schema(url: str, session: httpx.AsyncClient | None = None) -> list[dict]:
    """OpenAPI/Swagger spec-aware security testing.

    1. Discover and fetch API schema
    2. Validate schema security definitions
    3. Generate test cases from schema
    """
    findings: list[dict] = []

    schema, schema_url = await _discover_schema(url, session)
    if not schema:
        return findings

    findings.extend(_check_schema_exposure(schema_url))
    findings.extend(_check_security_definitions(schema, url))
    findings.extend(_check_sensitive_endpoints(schema, url))
    findings.extend(await _test_parameter_fuzzing(schema, url, session))

    return findings


async def _discover_schema(
    base_url: str, session: httpx.AsyncClient | None = None,
) -> tuple[dict | None, str]:
    """Try to discover and fetch an OpenAPI/Swagger schema."""
    base = base_url.rstrip("/")

    for path in SCHEMA_PATHS:
        url = f"{base}{path}"
        try:
            if session:
                resp = await session.get(url, timeout=TIMEOUT)
            else:
                async with httpx.AsyncClient(timeout=TIMEOUT, verify=False) as client:
                    resp = await client.get(url)

            if resp.status_code == 200:
                ct = resp.headers.get("content-type", "")
                if "json" in ct or "yaml" in ct or resp.text.strip().startswith("{"):
                    try:
                        schema = resp.json()
                        if _is_openapi_schema(schema):
                            logger.info("OpenAPI schema discovered at %s", url)
                            return schema, url
                    except (json.JSONDecodeError, ValueError):
                        pass
        except Exception:
            continue

    return None, ""


def _is_openapi_schema(data: dict) -> bool:
    """Check if a JSON dict looks like an OpenAPI/Swagger schema."""
    return bool(
        data.get("openapi") or data.get("swagger") or data.get("paths")
    )


def _check_schema_exposure(schema_url: str) -> list[dict]:
    """Flag that the API schema is publicly accessible."""
    if not schema_url:
        return []
    return [{
        "title": "API Schema Publicly Accessible",
        "severity": "low",
        "confidence": "confirmed",
        "description": (
            f"The OpenAPI/Swagger schema is publicly accessible at {schema_url}. "
            "This provides attackers with a complete map of API endpoints, parameters, "
            "and data models."
        ),
        "url": schema_url,
        "evidence": "OpenAPI schema fetched without authentication",
        "remediation": "Restrict API schema access to authenticated users or internal networks. "
                      "Consider removing it from production entirely.",
        "cwe_id": "CWE-200",
        "owasp_ref": "API8:2023",
        "category": "information_disclosure",
    }]


def _check_security_definitions(schema: dict, base_url: str) -> list[dict]:
    """Analyze security definitions in the schema."""
    findings: list[dict] = []

    security = schema.get("security", [])
    security_defs = (
        schema.get("securityDefinitions", {}) or
        schema.get("components", {}).get("securitySchemes", {})
    )
    paths = schema.get("paths", {})

    if not security and not security_defs:
        findings.append({
            "title": "API Schema Has No Security Definitions",
            "severity": "high",
            "confidence": "confirmed",
            "description": (
                "The OpenAPI schema does not define any security schemes. "
                "This means endpoints may lack authentication."
            ),
            "url": base_url,
            "evidence": "No 'security' or 'securityDefinitions' in schema",
            "remediation": "Define security schemes (Bearer, OAuth2, API key) in the schema "
                          "and apply them to all endpoints.",
            "cwe_id": "CWE-306",
            "owasp_ref": "API2:2023",
            "category": "authentication",
        })

    unprotected = []
    for path, methods in paths.items():
        for method_name in ("get", "post", "put", "patch", "delete"):
            method_def = methods.get(method_name, {})
            if not isinstance(method_def, dict):
                continue
            endpoint_security = method_def.get("security")
            if endpoint_security == [] or (not security and endpoint_security is None):
                unprotected.append(f"{method_name.upper()} {path}")

    if unprotected:
        findings.append({
            "title": f"{len(unprotected)} API Endpoints Without Authentication",
            "severity": "medium",
            "confidence": "medium",
            "description": (
                f"The following endpoints have no security requirements defined: "
                f"{', '.join(unprotected[:10])}"
                + (f" (and {len(unprotected) - 10} more)" if len(unprotected) > 10 else "")
            ),
            "url": base_url,
            "evidence": f"{len(unprotected)} endpoints with empty or no security",
            "remediation": "Apply security schemes to all endpoints except public ones. "
                          "Use 'security: []' only intentionally for public endpoints.",
            "cwe_id": "CWE-306",
            "owasp_ref": "API2:2023",
            "category": "authentication",
        })

    for scheme_name, scheme_def in security_defs.items():
        if isinstance(scheme_def, dict):
            if scheme_def.get("type") == "apiKey" and scheme_def.get("in") == "query":
                findings.append({
                    "title": f"API Key Passed in Query String ({scheme_name})",
                    "severity": "medium",
                    "confidence": "confirmed",
                    "description": (
                        f"Security scheme '{scheme_name}' passes API key via query string. "
                        "Query parameters are logged in server access logs, browser history, "
                        "and proxy logs."
                    ),
                    "url": base_url,
                    "evidence": f"apiKey scheme '{scheme_name}' with in: query",
                    "remediation": "Pass API keys in the Authorization header instead of "
                                  "query parameters.",
                    "cwe_id": "CWE-598",
                    "owasp_ref": "API2:2023",
                    "category": "authentication",
                })

    return findings


def _check_sensitive_endpoints(schema: dict, base_url: str) -> list[dict]:
    """Detect potentially sensitive endpoints in the schema."""
    findings: list[dict] = []
    paths = schema.get("paths", {})

    sensitive_patterns = [
        (r"/admin", "Admin endpoint"),
        (r"/debug", "Debug endpoint"),
        (r"/internal", "Internal endpoint"),
        (r"/health", "Health check"),
        (r"/metrics", "Metrics endpoint"),
        (r"/graphql", "GraphQL endpoint"),
        (r"/test", "Test endpoint"),
    ]

    for path in paths:
        for pattern, label in sensitive_patterns:
            if re.search(pattern, path, re.IGNORECASE):
                findings.append({
                    "title": f"Potentially Sensitive Endpoint Exposed: {path}",
                    "severity": "info",
                    "confidence": "low",
                    "description": (
                        f"{label} '{path}' is defined in the API schema. "
                        "Verify this endpoint is intentionally public and properly secured."
                    ),
                    "url": urljoin(base_url, path),
                    "evidence": f"Endpoint matches sensitive pattern: {pattern}",
                    "remediation": f"Verify {label.lower()} access is restricted to authorized users.",
                    "cwe_id": "CWE-200",
                    "owasp_ref": "API8:2023",
                    "category": "information_disclosure",
                })
                break

    return findings


async def _test_parameter_fuzzing(
    schema: dict, base_url: str, session: httpx.AsyncClient | None,
) -> list[dict]:
    """Test required parameter omission on a few endpoints."""
    findings: list[dict] = []
    paths = schema.get("paths", {})
    tested = 0

    for path, methods in paths.items():
        if tested >= 5:
            break
        for method_name in ("post", "put", "patch"):
            method_def = methods.get(method_name, {})
            if not isinstance(method_def, dict):
                continue

            parameters = method_def.get("parameters", [])
            required_params = [
                p for p in parameters
                if isinstance(p, dict) and p.get("required") and p.get("in") == "query"
            ]

            if not required_params:
                continue

            full_url = urljoin(base_url, path)
            try:
                if session:
                    resp = await session.request(method_name.upper(), full_url, timeout=TIMEOUT)
                else:
                    async with httpx.AsyncClient(timeout=TIMEOUT, verify=False) as client:
                        resp = await client.request(method_name.upper(), full_url)

                if resp.status_code < 400:
                    findings.append({
                        "title": f"Required Parameter Bypass: {method_name.upper()} {path}",
                        "severity": "medium",
                        "confidence": "medium",
                        "description": (
                            f"Endpoint {method_name.upper()} {path} responds with "
                            f"status {resp.status_code} when required parameters are omitted."
                        ),
                        "url": full_url,
                        "evidence": f"Status {resp.status_code} without required params",
                        "remediation": "Validate all required parameters server-side and "
                                      "return 400 when they are missing.",
                        "cwe_id": "CWE-20",
                        "owasp_ref": "API3:2023",
                        "category": "input_validation",
                    })
            except Exception:
                pass

            tested += 1

    return findings
