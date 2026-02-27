"""Stack-aware payload filtering — prioritize payloads matching project stack."""
from typing import Any


# Keywords that indicate payload is for specific tech
STACK_PAYLOAD_MAP = {
    "postgresql": ["pg_sleep", "pg_sleep(", "postgres", "::", "cast("],
    "mysql": ["sleep(", "benchmark(", "mysql", "concat("],
    "mssql": ["waitfor", "mssql", "char("],
    "mongodb": ["$gt", "$where", "mongodb", "nosql"],
    "graphql": ["graphql", "__schema", "introspection"],
    "jwt": ["jwt", "eyJ", "alg", "none"],
    "xml": ["xxe", "<!entity", "<?xml"],
    "php": ["php", "phpinfo", "<?php"],
}


def filter_payloads_for_stack(payloads: list, stack: dict) -> list:
    """
    Filter and reorder payloads to prioritize those matching the project stack.
    Returns payloads with stack-relevant ones first.
    """
    if not payloads:
        return payloads

    stack_str = _stack_to_search_string(stack)
    relevant = []
    other = []
    for p in payloads:
        p_str = str(p).lower()
        if _matches_stack(p_str, stack_str):
            relevant.append(p)
        else:
            other.append(p)
    return relevant + other if relevant else payloads


def _stack_to_search_string(stack: dict) -> str:
    parts = []
    for k, v in (stack or {}).items():
        if isinstance(v, list):
            parts.extend(str(x).lower() for x in v)
        else:
            parts.append(str(v).lower())
    return " ".join(parts)


def _matches_stack(payload_str: str, stack_str: str) -> bool:
    """Check if payload is relevant to stack."""
    payload_lower = payload_str.lower()
    if "postgresql" in stack_str or "postgres" in stack_str:
        if any(kw in payload_lower for kw in STACK_PAYLOAD_MAP["postgresql"]):
            return True
    if "mysql" in stack_str:
        if any(kw in payload_lower for kw in STACK_PAYLOAD_MAP["mysql"]):
            return True
    if "mssql" in stack_str or "sql server" in stack_str:
        if any(kw in payload_lower for kw in STACK_PAYLOAD_MAP["mssql"]):
            return True
    if "mongodb" in stack_str or "mongo" in stack_str:
        if any(kw in payload_lower for kw in STACK_PAYLOAD_MAP["mongodb"]):
            return True
    if "graphql" in stack_str:
        if any(kw in payload_lower for kw in STACK_PAYLOAD_MAP["graphql"]):
            return True
    if "jwt" in stack_str:
        if any(kw in payload_lower for kw in STACK_PAYLOAD_MAP["jwt"]):
            return True
    if "xml" in stack_str or "soap" in stack_str:
        if any(kw in payload_lower for kw in STACK_PAYLOAD_MAP["xml"]):
            return True
    if "php" in stack_str:
        if any(kw in payload_lower for kw in STACK_PAYLOAD_MAP["php"]):
            return True
    return False
