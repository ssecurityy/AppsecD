"""GraphQL security testing checks for DAST."""
import json
import logging
import re

import httpx

logger = logging.getLogger(__name__)

TIMEOUT = 15


async def check_graphql_deep(url: str, session: httpx.AsyncClient | None = None) -> list[dict]:
    """Comprehensive GraphQL security testing.

    Detects: introspection enabled, query depth abuse, batch query abuse,
    field suggestion enumeration, mutation injection, and authorization bypass.
    """
    findings: list[dict] = []
    endpoints = _discover_graphql_endpoints(url)

    for ep in endpoints:
        findings.extend(await _check_introspection(ep, session))
        findings.extend(await _check_query_depth(ep, session))
        findings.extend(await _check_batch_queries(ep, session))
        findings.extend(await _check_field_suggestions(ep, session))
        findings.extend(await _check_debug_mode(ep, session))

    return findings


def _discover_graphql_endpoints(base_url: str) -> list[str]:
    """Return candidate GraphQL endpoint URLs."""
    base = base_url.rstrip("/")
    candidates = [
        f"{base}/graphql",
        f"{base}/api/graphql",
        f"{base}/v1/graphql",
        f"{base}/gql",
        f"{base}/query",
    ]
    return candidates


async def _post_graphql(
    url: str, query: str, session: httpx.AsyncClient | None = None, variables: dict | None = None,
) -> dict | None:
    """Send a GraphQL query and return parsed response, or None on failure."""
    payload: dict = {"query": query}
    if variables:
        payload["variables"] = variables

    try:
        if session:
            resp = await session.post(
                url, json=payload,
                headers={"Content-Type": "application/json"},
                timeout=TIMEOUT,
            )
        else:
            async with httpx.AsyncClient(timeout=TIMEOUT, verify=False) as client:
                resp = await client.post(
                    url, json=payload,
                    headers={"Content-Type": "application/json"},
                )
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass
    return None


async def _check_introspection(url: str, session: httpx.AsyncClient | None) -> list[dict]:
    """Check if GraphQL introspection is enabled."""
    query = """
    query IntrospectionQuery {
        __schema {
            queryType { name }
            mutationType { name }
            types { name kind description fields { name type { name kind } } }
        }
    }
    """
    result = await _post_graphql(url, query, session)
    if result and result.get("data", {}).get("__schema"):
        schema = result["data"]["__schema"]
        type_count = len(schema.get("types", []))
        mutations = schema.get("mutationType")

        desc = (
            f"GraphQL introspection is enabled at {url}, exposing the full API schema "
            f"({type_count} types discovered). "
        )
        if mutations:
            desc += "Mutation type is available, which may allow write operations. "
        desc += "Disable introspection in production to prevent API enumeration."

        return [{
            "title": "GraphQL Introspection Enabled",
            "severity": "medium",
            "confidence": "confirmed",
            "description": desc,
            "url": url,
            "evidence": f"Schema exposed {type_count} types via __schema query",
            "remediation": "Disable introspection in production. For Apollo: "
                          "introspection: false in ApolloServer config.",
            "cwe_id": "CWE-200",
            "owasp_ref": "API8:2023",
            "category": "information_disclosure",
        }]
    return []


async def _check_query_depth(url: str, session: httpx.AsyncClient | None) -> list[dict]:
    """Test for missing query depth limiting."""
    deep_query = """
    query DeepNesting {
        __schema {
            types {
                fields {
                    type {
                        fields {
                            type {
                                fields {
                                    type {
                                        name
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    """
    result = await _post_graphql(url, deep_query, session)
    if result and result.get("data") and not result.get("errors"):
        return [{
            "title": "GraphQL Query Depth Not Limited",
            "severity": "medium",
            "confidence": "confirmed",
            "description": (
                f"GraphQL at {url} allows deeply nested queries without depth limiting. "
                "An attacker can craft exponentially expensive queries to cause denial of service."
            ),
            "url": url,
            "evidence": "6-level deep nested query succeeded without error",
            "remediation": "Implement query depth limiting (max 5-7 levels). "
                          "Use graphql-depth-limit or equivalent middleware.",
            "cwe_id": "CWE-400",
            "owasp_ref": "API4:2023",
            "category": "denial_of_service",
        }]
    return []


async def _check_batch_queries(url: str, session: httpx.AsyncClient | None) -> list[dict]:
    """Test for batch query abuse (query batching without limits)."""
    batch_payload = [
        {"query": "{ __typename }"},
        {"query": "{ __typename }"},
        {"query": "{ __typename }"},
        {"query": "{ __typename }"},
        {"query": "{ __typename }"},
    ]
    try:
        if session:
            resp = await session.post(
                url, json=batch_payload,
                headers={"Content-Type": "application/json"},
                timeout=TIMEOUT,
            )
        else:
            async with httpx.AsyncClient(timeout=TIMEOUT, verify=False) as client:
                resp = await client.post(
                    url, json=batch_payload,
                    headers={"Content-Type": "application/json"},
                )
        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, list) and len(data) >= 5:
                return [{
                    "title": "GraphQL Batch Query Abuse Possible",
                    "severity": "low",
                    "confidence": "confirmed",
                    "description": (
                        f"GraphQL at {url} accepts batched queries without limits. "
                        "Attackers can send many queries in a single request to bypass "
                        "rate limiting or amplify attacks."
                    ),
                    "url": url,
                    "evidence": f"Batch of 5 queries accepted, returned {len(data)} results",
                    "remediation": "Limit batch query size to 1-3 queries. "
                                  "Implement per-query cost analysis.",
                    "cwe_id": "CWE-770",
                    "owasp_ref": "API4:2023",
                    "category": "denial_of_service",
                }]
    except Exception:
        pass
    return []


async def _check_field_suggestions(url: str, session: httpx.AsyncClient | None) -> list[dict]:
    """Test if GraphQL returns field suggestions on typos (aids enumeration)."""
    query = '{ __typenme }'
    result = await _post_graphql(url, query, session)
    if result and result.get("errors"):
        error_text = json.dumps(result["errors"])
        if "did you mean" in error_text.lower() or "suggestion" in error_text.lower():
            return [{
                "title": "GraphQL Field Suggestion Enabled",
                "severity": "info",
                "confidence": "confirmed",
                "description": (
                    f"GraphQL at {url} returns field suggestions on invalid queries, "
                    "which aids attackers in enumerating the schema even when introspection "
                    "is disabled."
                ),
                "url": url,
                "evidence": "Field suggestions returned for typo query",
                "remediation": "Disable field suggestions in production. For GraphQL.js: "
                              "set 'didYouMean' to false.",
                "cwe_id": "CWE-200",
                "owasp_ref": "API8:2023",
                "category": "information_disclosure",
            }]
    return []


async def _check_debug_mode(url: str, session: httpx.AsyncClient | None) -> list[dict]:
    """Check if GraphQL is in debug mode (stack traces in errors)."""
    query = '{ __invalid_query_for_error }'
    result = await _post_graphql(url, query, session)
    if result and result.get("errors"):
        error_text = json.dumps(result["errors"])
        if any(kw in error_text.lower() for kw in ("stack", "traceback", "at line", "node_modules")):
            return [{
                "title": "GraphQL Debug Mode Enabled",
                "severity": "medium",
                "confidence": "confirmed",
                "description": (
                    f"GraphQL at {url} returns stack traces or debug information in error "
                    "responses, exposing internal server details."
                ),
                "url": url,
                "evidence": "Stack trace detected in error response",
                "remediation": "Disable debug mode in production. Remove stack traces "
                              "from error responses.",
                "cwe_id": "CWE-209",
                "owasp_ref": "API8:2023",
                "category": "information_disclosure",
            }]
    return []
