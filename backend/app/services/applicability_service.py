"""Applicability scoring: Technology Match + Feature Match + Risk Weight."""
from typing import Any


def compute_applicability_score(test_case: dict, stack: dict) -> tuple[int, str]:
    """
    Returns (score 0-100, tier: "applicable"|"optional"|"na").
    Score = Technology Match (0-40) + Feature Match (0-40) + Risk Weight (0-20)
    """
    tech_score = _technology_match(test_case, stack)
    feature_score = _feature_match(test_case, stack)
    risk_score = _risk_weight(test_case)
    total = min(100, tech_score + feature_score + risk_score)

    if total >= 70:
        tier = "applicable"
    elif total >= 40:
        tier = "optional"
    else:
        tier = "na"
    return total, tier


def _technology_match(tc: dict, stack: dict) -> int:
    """0-40: How well stack matches test case tech requirements."""
    conditions = tc.get("applicability_conditions") or {}
    if not conditions:
        return 40  # No conditions = full score

    requires_any = conditions.get("requires_any", [])
    if requires_any:
        for req in requires_any:
            key, val = (req.split(":", 1) if ":" in req else (req, "yes"))
            stack_val = str(stack.get(key, "")).lower()
            if isinstance(stack_val, list):
                stack_val = ",".join(str(x).lower() for x in stack_val)
            if val.lower() in stack_val or stack_val == "yes" or stack_val == "true":
                return 40
        return 0

    excludes_if = conditions.get("excludes_if", [])
    for exc in excludes_if:
        key, val = (exc.split(":", 1) if ":" in exc else (exc, "no"))
        stack_val = str(stack.get(key, "")).lower()
        if isinstance(stack_val, list):
            stack_val = ",".join(str(x).lower() for x in stack_val)
        if val.lower() in stack_val or stack_val == "no" or stack_val == "none":
            return 0
    return 40


def _feature_match(tc: dict, stack: dict) -> int:
    """0-40: Feature flags alignment."""
    tags = tc.get("tags") or []
    title_desc = (tc.get("title") or "") + " " + (tc.get("description") or "")
    combined = " ".join(tags).lower() + " " + title_desc.lower()

    score = 20  # Base
    # Boost for matching features
    if "graphql" in combined and _stack_has(stack, "api_type", "graphql"):
        score += 10
    if "jwt" in combined and _stack_has(stack, "auth_type", "jwt"):
        score += 10
    if "sql" in combined and _stack_has(stack, "database", "postgresql", "mysql", "mssql"):
        score += 10
    if "file" in combined and _stack_has(stack, "features:file_upload", "yes"):
        score += 10
    if "otp" in combined or "mfa" in combined and _stack_has(stack, "auth_type", "mfa", "otp"):
        score += 10
    return min(40, score)


def _stack_has(stack: dict, key: str, *values: str) -> bool:
    raw = stack.get(key)
    if raw is None:
        return False
    if isinstance(raw, list):
        v = ",".join(str(x).lower() for x in raw)
    else:
        v = str(raw).lower()
    return any(val.lower() in v for val in values)


def _risk_weight(tc: dict) -> int:
    """0-20: Severity-based risk weight."""
    sev = (tc.get("severity") or "medium").lower()
    weights = {"critical": 20, "high": 15, "medium": 10, "low": 5, "info": 2}
    return weights.get(sev, 10)
