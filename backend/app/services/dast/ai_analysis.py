"""DAST AI Analysis — LLM-powered scan interpretation, crawl analysis, summaries."""
import json
import logging
from typing import Optional

logger = logging.getLogger(__name__)


def _call_gemini(api_key: str, model: str, prompt: str, temperature: float = 0.3) -> str | None:
    try:
        import google.generativeai as genai
        genai.configure(api_key=api_key)
        m = genai.GenerativeModel(model)
        r = m.generate_content(prompt)
        return (r.text or "").strip()
    except Exception as e:
        logger.warning("Gemini call failed (%s): %s", model, e)
    return None


def _call_llm(provider: str, model: str, api_key: str, prompt: str, temperature: float = 0.3) -> str | None:
    if provider == "google":
        return _call_gemini(api_key, model, prompt, temperature)
    try:
        if provider == "openai":
            from openai import OpenAI
            client = OpenAI(api_key=api_key)
            r = client.chat.completions.create(
                model=model,
                messages=[{"role": "user", "content": prompt}],
                temperature=temperature,
                max_tokens=4096,
            )
            return (r.choices[0].message.content or "").strip()
        elif provider == "anthropic":
            from anthropic import Anthropic
            client = Anthropic(api_key=api_key)
            r = client.messages.create(
                model=model, max_tokens=4096,
                messages=[{"role": "user", "content": prompt}],
            )
            return (r.content[0].text if r.content else "").strip()
    except Exception as e:
        logger.warning("LLM call failed (%s/%s): %s", provider, model, e)
    return None


def _parse_json(text: str) -> dict | list | None:
    if not text:
        return None
    text = text.strip()
    if text.startswith("```"):
        parts = text.split("```")
        if len(parts) >= 2:
            text = parts[1]
            if text.startswith("json"):
                text = text[4:]
    try:
        return json.loads(text.strip())
    except json.JSONDecodeError:
        return None


def summarize_scan(
    results: list[dict],
    target_url: str,
    *,
    provider: str = "google",
    model: str = "gemini-2.5-flash",
    api_key: str = "",
) -> dict:
    """Generate AI summary of DAST scan results."""
    if not api_key:
        return _rule_based_scan_summary(results, target_url)

    passed = sum(1 for r in results if r.get("status") == "passed")
    failed = sum(1 for r in results if r.get("status") == "failed")
    errors = sum(1 for r in results if r.get("status") == "error")

    failed_checks = [
        {"title": r.get("title", ""), "severity": r.get("severity", ""), "description": r.get("description", "")[:200]}
        for r in results if r.get("status") == "failed"
    ][:15]

    prompt = f"""You are an expert security analyst. Summarize this DAST scan result concisely.

Target: {target_url}
Total checks: {len(results)} | Passed: {passed} | Failed: {failed} | Errors: {errors}

Failed checks:
{json.dumps(failed_checks, indent=2)}

Provide a JSON response:
{{"summary": "2-3 sentence executive summary of security posture", "risk_level": "critical|high|medium|low|info", "top_issues": ["issue1", "issue2", "issue3"], "recommendations": ["rec1", "rec2", "rec3"]}}"""

    raw = _call_llm(provider, model, api_key, prompt)
    parsed = _parse_json(raw)
    if parsed and isinstance(parsed, dict):
        return parsed

    return _rule_based_scan_summary(results, target_url)


def _rule_based_scan_summary(results: list[dict], target_url: str) -> dict:
    passed = sum(1 for r in results if r.get("status") == "passed")
    failed = sum(1 for r in results if r.get("status") == "failed")
    critical = [r for r in results if r.get("status") == "failed" and r.get("severity") in ("critical", "high")]
    risk = "critical" if any(r.get("severity") == "critical" for r in critical) else \
           "high" if critical else "medium" if failed else "low"
    summary = f"Scan of {target_url} completed: {passed} passed, {failed} failed out of {len(results)} checks."
    if critical:
        summary += f" Found {len(critical)} critical/high severity issue(s) requiring immediate attention."
    return {
        "summary": summary,
        "risk_level": risk,
        "top_issues": [r.get("title", "") for r in results if r.get("status") == "failed"][:5],
        "recommendations": ["Address critical/high findings first", "Re-scan after remediation"],
    }


def analyze_crawl_output(
    urls: list[str],
    api_endpoints: list[dict],
    parameters: list[dict],
    forms: list[dict],
    js_files: list[dict],
    target_url: str,
    *,
    provider: str = "google",
    model: str = "gemini-2.5-flash",
    api_key: str = "",
) -> dict:
    """AI analysis of crawl output — identify attack surface and suggested tests."""
    if not api_key:
        return _rule_based_crawl_analysis(urls, api_endpoints, parameters, forms, js_files, target_url)

    endpoints_summary = json.dumps(api_endpoints[:20], indent=1) if api_endpoints else "None"
    params_summary = json.dumps(parameters[:20], indent=1) if parameters else "None"
    forms_summary = json.dumps(forms[:10], indent=1) if forms else "None"

    prompt = f"""You are an expert penetration tester analyzing crawl results from a web application.

Target: {target_url}
Total URLs discovered: {len(urls)}
API endpoints: {len(api_endpoints)}
Parameters: {len(parameters)}
Forms: {len(forms)}
JS files: {len(js_files)}

API Endpoints (sample):
{endpoints_summary}

Parameters (sample):
{params_summary}

Forms (sample):
{forms_summary}

Analyze the attack surface. Respond in JSON:
{{"attack_surface_score": "critical|high|medium|low", "summary": "2-3 sentence attack surface analysis", "high_value_targets": [{{"url": "endpoint url", "reason": "why this is interesting", "suggested_tests": ["test1", "test2"]}}], "parameter_risks": [{{"name": "param name", "risk": "what could go wrong", "test_type": "sqli|xss|idor|ssrf|lfi"}}], "recommended_checks": ["check_id1", "check_id2"], "missing_coverage": ["area not covered by current crawl"]}}"""

    raw = _call_llm(provider, model, api_key, prompt)
    parsed = _parse_json(raw)
    if parsed and isinstance(parsed, dict):
        return parsed

    return _rule_based_crawl_analysis(urls, api_endpoints, parameters, forms, js_files, target_url)


def _rule_based_crawl_analysis(urls, api_endpoints, parameters, forms, js_files, target_url) -> dict:
    high_value = []
    for ep in api_endpoints[:5]:
        high_value.append({
            "url": ep.get("url", ""), "reason": "API endpoint discovered",
            "suggested_tests": ["sqli_error", "cors", "rate_limiting"]
        })
    param_risks = []
    for p in parameters[:5]:
        name = p.get("name", "").lower()
        risk_type = "xss"
        if any(k in name for k in ["id", "user", "account"]):
            risk_type = "idor"
        elif any(k in name for k in ["url", "redirect", "next", "return"]):
            risk_type = "ssrf"
        elif any(k in name for k in ["query", "search", "q", "filter"]):
            risk_type = "sqli"
        param_risks.append({"name": p.get("name", ""), "risk": f"Potential {risk_type} vector", "test_type": risk_type})

    return {
        "attack_surface_score": "high" if len(api_endpoints) > 5 else "medium" if api_endpoints else "low",
        "summary": f"Discovered {len(urls)} URLs with {len(api_endpoints)} API endpoints and {len(parameters)} parameters.",
        "high_value_targets": high_value,
        "parameter_risks": param_risks,
        "recommended_checks": ["cors", "sqli_error", "xss_basic", "security_headers", "ssl_tls"],
        "missing_coverage": [],
    }


def categorize_paths(
    paths: list[dict],
    target_url: str,
    *,
    provider: str = "google",
    model: str = "gemini-2.5-flash",
    api_key: str = "",
) -> dict:
    """AI categorization of discovered directory paths."""
    if not api_key or not paths:
        return _rule_based_categorize(paths)

    paths_str = "\n".join(f"{p.get('path', '')} (HTTP {p.get('status', '?')})" for p in paths[:50])
    prompt = f"""You are a security expert. Categorize these discovered web paths by risk level and type.

Target: {target_url}
Discovered paths:
{paths_str}

Respond in JSON:
{{"categories": {{"admin": ["paths"], "api": ["paths"], "backup": ["paths"], "config": ["paths"], "sensitive": ["paths"], "static": ["paths"], "other": ["paths"]}}, "high_risk_paths": [{{"path": "/path", "reason": "why risky", "severity": "critical|high|medium|low"}}], "summary": "brief categorization summary"}}"""

    raw = _call_llm(provider, model, api_key, prompt)
    parsed = _parse_json(raw)
    if parsed and isinstance(parsed, dict):
        return parsed

    return _rule_based_categorize(paths)


def _rule_based_categorize(paths: list[dict]) -> dict:
    categories = {"admin": [], "api": [], "backup": [], "config": [], "sensitive": [], "static": [], "other": []}
    high_risk = []
    for p in paths:
        path = (p.get("path", "") or "").lower()
        if any(k in path for k in ["admin", "panel", "dashboard", "manage"]):
            categories["admin"].append(p.get("path", ""))
            high_risk.append({"path": p.get("path", ""), "reason": "Admin panel", "severity": "high"})
        elif any(k in path for k in ["api", "v1", "v2", "graphql", "rest"]):
            categories["api"].append(p.get("path", ""))
        elif any(k in path for k in [".bak", ".old", "backup", ".sql", ".dump"]):
            categories["backup"].append(p.get("path", ""))
            high_risk.append({"path": p.get("path", ""), "reason": "Backup file", "severity": "critical"})
        elif any(k in path for k in [".env", ".git", "config", ".htaccess", "web.config"]):
            categories["config"].append(p.get("path", ""))
            high_risk.append({"path": p.get("path", ""), "reason": "Config exposure", "severity": "critical"})
        elif any(k in path for k in ["css", "js", "img", "font", "static", "assets"]):
            categories["static"].append(p.get("path", ""))
        else:
            categories["other"].append(p.get("path", ""))
    return {"categories": categories, "high_risk_paths": high_risk, "summary": f"Categorized {len(paths)} paths."}


def suggest_checks(
    target_url: str,
    stack_profile: dict | None = None,
    crawl_stats: dict | None = None,
    *,
    provider: str = "google",
    model: str = "gemini-2.5-flash",
    api_key: str = "",
) -> dict:
    """AI-powered check suggestion based on target and discovered context."""
    if not api_key:
        return _rule_based_suggest_checks(stack_profile, crawl_stats)

    stack_str = json.dumps(stack_profile or {})
    crawl_str = json.dumps(crawl_stats or {})

    prompt = f"""You are a DAST expert. Suggest which security checks to prioritize for this target.

Target URL: {target_url}
Tech Stack: {stack_str}
Crawl Stats: {crawl_str}

Available check categories: headers, ssl, cookies, recon, injection, http, misc
Available checks: security_headers, ssl_tls, cookie_security, cors, open_redirect, xss_basic, sqli_error, 
info_disclosure, directory_listing, robots_txt, sitemap_xml, http_methods, rate_limiting, backup_files,
host_header_injection, crlf_injection, api_docs_exposure, tech_fingerprint, sensitive_data

Respond in JSON:
{{"priority_checks": ["check_id1", "check_id2", ...], "reasoning": "why these checks first", "estimated_risk_areas": ["area1", "area2"], "skip_checks": ["check_id"], "skip_reason": "why skip"}}"""

    raw = _call_llm(provider, model, api_key, prompt)
    parsed = _parse_json(raw)
    if parsed and isinstance(parsed, dict):
        return parsed

    return _rule_based_suggest_checks(stack_profile, crawl_stats)


def _rule_based_suggest_checks(stack_profile: dict | None, crawl_stats: dict | None) -> dict:
    priority = [
        "security_headers", "ssl_tls", "cors", "cookie_security",
        "info_disclosure", "sqli_error", "xss_basic", "directory_listing",
        "robots_txt", "rate_limiting", "backup_files",
    ]
    return {
        "priority_checks": priority,
        "reasoning": "Standard priority: transport security, headers, injection, recon",
        "estimated_risk_areas": ["headers", "injection", "recon"],
        "skip_checks": [],
        "skip_reason": "",
    }


def interpret_scan_result(
    check_result: dict,
    target_url: str,
    *,
    provider: str = "google",
    model: str = "gemini-2.5-flash",
    api_key: str = "",
) -> dict:
    """AI interpretation of a single DAST check result."""
    if not api_key:
        return check_result

    prompt = f"""You are a security expert. Interpret this DAST check result and provide enhanced analysis.

Target: {target_url}
Check: {check_result.get('title', '')}
Status: {check_result.get('status', '')}
Description: {check_result.get('description', '')}
Evidence: {check_result.get('evidence', '')[:500]}
Severity: {check_result.get('severity', '')}

Provide enhanced interpretation in JSON:
{{"interpretation": "detailed explanation of what this means", "business_impact": "potential business impact", "exploitation_difficulty": "easy|medium|hard", "false_positive_likelihood": "low|medium|high", "remediation_steps": ["step1", "step2"], "references": ["url1"]}}"""

    raw = _call_llm(provider, model, api_key, prompt)
    parsed = _parse_json(raw)
    if parsed and isinstance(parsed, dict):
        return {**check_result, "ai_analysis": parsed}

    return check_result
