"""LLM-enhanced AI services — advanced security analysis features."""
import json
import logging
from typing import Optional

logger = logging.getLogger(__name__)


def _call_llm(provider: str, model: str, api_key: str, prompt: str, temperature: float = 0.3) -> str | None:
    """Universal LLM caller. Returns raw text response or None."""
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
                model=model,
                max_tokens=4096,
                messages=[{"role": "user", "content": prompt}],
            )
            return (r.content[0].text if r.content else "").strip()
        elif provider == "google":
            import google.generativeai as genai
            genai.configure(api_key=api_key)
            m = genai.GenerativeModel(model)
            r = m.generate_content(prompt)
            return (r.text or "").strip()
    except Exception as e:
        logger.warning("LLM call failed (%s/%s): %s", provider, model, e)
    return None


def _parse_json(text: str) -> dict | list | None:
    """Parse JSON from LLM response, handling markdown fences."""
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


# ─── 1. Vulnerable Endpoint Analysis ───

def analyze_endpoint(
    endpoint: str, method: str, parameters: str, request_sample: str,
    response_sample: str, framework: str,
    *, provider: str = "", model: str = "", api_key: str = "",
) -> dict:
    """Analyze an endpoint for potential vulnerabilities."""
    if api_key and model:
        prompt = f"""You are an expert penetration tester. Analyze this endpoint for security vulnerabilities.

Endpoint: {method} {endpoint}
Parameters: {parameters}
Framework: {framework}

Request Sample:
{request_sample[:2000]}

Response Sample:
{response_sample[:2000]}

Identify:
1. Likely vulnerability types (SQLi, XSS, IDOR, SSRF, etc.)
2. Risk priority (critical/high/medium/low)
3. Specific attack vectors for each vulnerability
4. Suggested test payloads
5. Recommended test cases

Respond in JSON only:
{{"vulnerabilities": [{{"type": "vulnerability type", "priority": "critical|high|medium|low", "description": "why this endpoint may be vulnerable", "attack_vectors": ["vector1", "vector2"], "payloads": ["payload1", "payload2"], "test_steps": ["step1", "step2"]}}], "overall_risk": "critical|high|medium|low", "summary": "brief analysis summary"}}"""
        result = _call_llm(provider, model, api_key, prompt)
        parsed = _parse_json(result)
        if parsed:
            return parsed

    # Rule-based fallback
    vulns = []
    params_lower = (parameters or "").lower()
    endpoint_lower = (endpoint or "").lower()
    if any(p in params_lower for p in ["id", "user_id", "account", "order"]):
        vulns.append({"type": "IDOR", "priority": "high", "description": "ID-based parameters may allow unauthorized access", "attack_vectors": ["Enumerate IDs", "Access other users' resources"], "payloads": ["Change ID to another user's ID"], "test_steps": ["1. Note your ID", "2. Change to another user's ID", "3. Check if data is returned"]})
    if any(p in params_lower for p in ["search", "query", "q", "name", "input", "comment"]):
        vulns.append({"type": "XSS", "priority": "medium", "description": "User input parameters may reflect in response", "attack_vectors": ["Reflected XSS", "Stored XSS"], "payloads": ["<script>alert(1)</script>", "\" onmouseover=alert(1)"], "test_steps": ["1. Inject XSS payload", "2. Check if reflected in response"]})
    if any(p in params_lower for p in ["query", "filter", "sort", "where", "order_by"]):
        vulns.append({"type": "SQL Injection", "priority": "critical", "description": "Query-like parameters may be injectable", "attack_vectors": ["Union-based", "Boolean-based blind"], "payloads": ["' OR 1=1--", "' UNION SELECT NULL--"], "test_steps": ["1. Inject SQL payload", "2. Observe error/different response"]})
    if any(p in params_lower for p in ["url", "redirect", "next", "return", "callback"]):
        vulns.append({"type": "SSRF/Open Redirect", "priority": "high", "description": "URL parameters may allow server-side requests or redirects", "attack_vectors": ["SSRF to internal services", "Open redirect for phishing"], "payloads": ["http://169.254.169.254/latest/meta-data/", "//evil.com"], "test_steps": ["1. Inject internal/external URL", "2. Check if server fetches it"]})
    if not vulns:
        vulns.append({"type": "General", "priority": "medium", "description": "Standard security testing recommended", "attack_vectors": ["Authentication bypass", "Authorization flaws"], "payloads": [], "test_steps": ["1. Test authentication", "2. Test authorization"]})
    return {"vulnerabilities": vulns, "overall_risk": vulns[0]["priority"] if vulns else "medium", "summary": f"Analysis of {method} {endpoint}: {len(vulns)} potential vulnerability type(s) identified."}


# ─── 2. Similar Test Generation ───

def generate_similar_tests(
    existing_test: dict, target_context: str,
    *, provider: str = "", model: str = "", api_key: str = "",
) -> list[dict]:
    """Generate similar test cases from an existing one."""
    if api_key and model:
        prompt = f"""You are an expert security tester. Given this existing test case, generate 3 similar test cases adapted for: {target_context}

Existing Test Case:
Title: {existing_test.get('title', '')}
Description: {existing_test.get('description', '')}
Phase: {existing_test.get('phase', '')}
OWASP: {existing_test.get('owasp_ref', '')}
CWE: {existing_test.get('cwe_id', '')}
How to Test: {existing_test.get('how_to_test', '')[:500]}
Payloads: {json.dumps(existing_test.get('payloads', [])[:5])}

Generate 3 new test cases in the EXACT same format. Each should be distinct and adapted for the new context.

Respond in JSON only:
{{"test_cases": [{{"title": "...", "description": "...", "phase": "{existing_test.get('phase', 'post_auth')}", "owasp_ref": "...", "cwe_id": "...", "severity": "critical|high|medium|low|info", "where_to_test": "...", "what_to_test": "...", "how_to_test": "step by step", "payloads": ["p1", "p2"], "tool_commands": [{{"tool": "...", "command": "...", "description": "..."}}], "pass_indicators": "...", "fail_indicators": "...", "remediation": "...", "tags": ["tag1"]}}]}}"""
        result = _call_llm(provider, model, api_key, prompt, temperature=0.5)
        parsed = _parse_json(result)
        if parsed and "test_cases" in parsed:
            return parsed["test_cases"]
    return []


# ─── 3. Missing Test Suggestion ───

def suggest_missing_tests(
    project_stack: dict, existing_phases: list[str], tested_count: int, total_count: int,
    *, provider: str = "", model: str = "", api_key: str = "",
) -> dict:
    """Suggest tests that are missing from the current scope."""
    if api_key and model:
        prompt = f"""You are an expert security tester. Analyze this project's testing coverage and suggest missing test areas.

Project Stack: {json.dumps(project_stack)}
Tested Phases: {', '.join(existing_phases)}
Coverage: {tested_count}/{total_count} test cases executed

Identify:
1. Missing test categories based on the stack
2. Specific tests that should be added
3. Priority for each suggestion

Respond in JSON only:
{{"missing_areas": [{{"category": "area name", "priority": "high|medium|low", "reason": "why this is missing", "suggested_tests": [{{"title": "...", "description": "...", "severity": "...", "phase": "..."}}]}}], "coverage_assessment": "brief assessment", "recommendations": ["rec1", "rec2"]}}"""
        result = _call_llm(provider, model, api_key, prompt)
        parsed = _parse_json(result)
        if parsed:
            return parsed
    return {"missing_areas": [], "coverage_assessment": f"Coverage: {tested_count}/{total_count}", "recommendations": ["Complete all test phases", "Focus on high-severity test cases first"]}


# ─── 4. Framework-Specific Tests ───

def generate_framework_tests(
    framework: str, version: str, features: list[str],
    *, provider: str = "", model: str = "", api_key: str = "",
) -> list[dict]:
    """Generate framework-specific security tests."""
    if api_key and model:
        prompt = f"""You are a security expert specializing in {framework}. Generate 5 security test cases specific to:

Framework: {framework} {version}
Features used: {', '.join(features) if features else 'general'}

Generate tests that target known vulnerability patterns in {framework}. Include latest CVEs if applicable.

Respond in JSON only:
{{"test_cases": [{{"title": "...", "description": "...", "phase": "...", "owasp_ref": "...", "cwe_id": "...", "severity": "...", "where_to_test": "...", "what_to_test": "...", "how_to_test": "...", "payloads": [], "tool_commands": [], "pass_indicators": "...", "fail_indicators": "...", "remediation": "...", "tags": ["{framework.lower()}"]}}]}}"""
        result = _call_llm(provider, model, api_key, prompt, temperature=0.5)
        parsed = _parse_json(result)
        if parsed and "test_cases" in parsed:
            return parsed["test_cases"]
    return []


# ─── 5. Remediation Enrichment ───

def enrich_remediation(
    finding_title: str, finding_description: str, current_remediation: str,
    app_framework: str, app_language: str,
    *, provider: str = "", model: str = "", api_key: str = "",
) -> dict:
    """Enrich remediation with app-specific, actionable guidance."""
    if api_key and model:
        prompt = f"""You are a senior application security engineer. Enrich this remediation with specific, actionable code-level guidance.

Finding: {finding_title}
Description: {finding_description}
Current Remediation: {current_remediation}
Application Framework: {app_framework}
Language: {app_language}

Provide:
1. Framework-specific fix (code example)
2. Configuration changes needed
3. Library/package recommendations
4. Testing verification steps

Respond in JSON only:
{{"enriched_remediation": "detailed remediation text with code examples", "code_example": "actual code fix", "config_changes": ["change1"], "packages": ["package1"], "verification_steps": ["step1"], "references": [{{"title": "...", "url": "..."}}]}}"""
        result = _call_llm(provider, model, api_key, prompt)
        parsed = _parse_json(result)
        if parsed:
            return parsed
    return {"enriched_remediation": current_remediation, "code_example": "", "config_changes": [], "packages": [], "verification_steps": [], "references": []}


# ─── 6. Finding Deduplication ───

def deduplicate_findings(
    findings: list[dict],
    *, provider: str = "", model: str = "", api_key: str = "",
) -> dict:
    """Analyze findings for duplicates and suggest merges."""
    if api_key and model and len(findings) >= 2:
        findings_text = "\n".join([
            f"[{i}] {f.get('title', '')} | {f.get('severity', '')} | {f.get('cwe_id', '')} | {f.get('affected_url', '')} | {(f.get('description', '') or '')[:100]}"
            for i, f in enumerate(findings)
        ])
        prompt = f"""You are a security analyst. Review these findings and identify duplicates or very similar ones that should be merged.

Findings:
{findings_text}

For each group of similar findings, explain why they should be merged and which one to keep as primary.

Respond in JSON only:
{{"duplicate_groups": [{{"primary_index": 0, "duplicate_indices": [1, 3], "reason": "why these are duplicates", "suggested_merged_title": "better title"}}], "unique_count": 5, "duplicate_count": 2, "summary": "brief deduplication summary"}}"""
        result = _call_llm(provider, model, api_key, prompt)
        parsed = _parse_json(result)
        if parsed:
            return parsed
    return {"duplicate_groups": [], "unique_count": len(findings), "duplicate_count": 0, "summary": "No duplicates detected (rule-based)."}


# ─── 7. Natural Language Query ───

def query_findings_nl(
    query: str, available_severities: list[str], available_statuses: list[str],
    available_cwes: list[str],
    *, provider: str = "", model: str = "", api_key: str = "",
) -> dict:
    """Convert natural language to structured finding filters."""
    if api_key and model:
        prompt = f"""Convert this natural language query into structured filters for a security findings database.

Query: "{query}"

Available filter values:
- Severities: {', '.join(available_severities)}
- Statuses: {', '.join(available_statuses)}
- CWE IDs: {', '.join(available_cwes[:20])}

Respond in JSON only:
{{"filters": {{"severity": ["list of matching severities or empty"], "status": ["list of matching statuses or empty"], "cwe_id": ["list of matching CWEs or empty"], "search_text": "keyword search text if applicable", "date_from": "YYYY-MM-DD or null", "date_to": "YYYY-MM-DD or null"}}, "interpretation": "what the query means in plain English"}}"""
        result = _call_llm(provider, model, api_key, prompt)
        parsed = _parse_json(result)
        if parsed:
            return parsed
    # Rule-based: simple keyword matching
    query_lower = query.lower()
    filters = {"severity": [], "status": [], "cwe_id": [], "search_text": "", "date_from": None, "date_to": None}
    for sev in available_severities:
        if sev.lower() in query_lower:
            filters["severity"].append(sev)
    for status in available_statuses:
        if status.lower() in query_lower:
            filters["status"].append(status)
    keywords = ["sqli", "xss", "csrf", "idor", "ssrf", "rce", "lfi", "xxe", "injection", "redirect"]
    for kw in keywords:
        if kw in query_lower:
            filters["search_text"] = kw
            break
    return {"filters": filters, "interpretation": f"Keyword search for: {query}"}


# ─── 8. Vulnerability Trends ───

def analyze_vulnerability_trends(
    projects_data: list[dict],
    *, provider: str = "", model: str = "", api_key: str = "",
) -> dict:
    """Analyze vulnerability trends across projects."""
    if api_key and model and projects_data:
        projects_text = "\n".join([
            f"Project: {p.get('name', '')} | Findings: {p.get('finding_count', 0)} | Critical: {p.get('critical', 0)} | High: {p.get('high', 0)} | Top CWEs: {', '.join(p.get('top_cwes', []))}"
            for p in projects_data
        ])
        prompt = f"""You are a security analytics expert. Analyze vulnerability trends across these projects.

Projects:
{projects_text}

Identify:
1. Common vulnerability patterns
2. Trending vulnerability types
3. Risk hotspots
4. Strategic recommendations

Respond in JSON only:
{{"patterns": [{{"pattern": "...", "frequency": "X projects", "severity": "...", "recommendation": "..."}}], "trending_vulns": [{{"type": "...", "trend": "increasing|stable|decreasing", "affected_projects": 3}}], "risk_hotspots": ["..."], "strategic_recommendations": ["..."], "summary": "executive summary of trends"}}"""
        result = _call_llm(provider, model, api_key, prompt)
        parsed = _parse_json(result)
        if parsed:
            return parsed
    return {"patterns": [], "trending_vulns": [], "risk_hotspots": [], "strategic_recommendations": ["Conduct regular assessments", "Prioritize critical/high findings"], "summary": "Insufficient data for trend analysis."}


# ─── 9. Payload from CVE ───

def generate_cve_payloads(
    cve_id: str, cve_description: str, affected_product: str,
    *, provider: str = "", model: str = "", api_key: str = "",
) -> dict:
    """Generate proof-of-concept payloads from a CVE."""
    if api_key and model:
        prompt = f"""You are a security researcher. Generate proof-of-concept test payloads for this CVE.

CVE: {cve_id}
Description: {cve_description[:1000]}
Affected Product: {affected_product}

Generate test payloads that can verify if a system is vulnerable. Include:
1. Direct exploitation payloads
2. Detection/verification payloads
3. curl commands for testing

IMPORTANT: These are for authorized security testing only.

Respond in JSON only:
{{"payloads": [{{"payload": "...", "type": "exploit|detection|verification", "description": "what this tests", "command": "full curl/http command if applicable"}}], "test_steps": ["step1"], "indicators_of_vulnerability": ["indicator1"], "mitigation": "how to fix"}}"""
        result = _call_llm(provider, model, api_key, prompt, temperature=0.4)
        parsed = _parse_json(result)
        if parsed:
            return parsed
    return {"payloads": [], "test_steps": [f"Search for {cve_id} PoC on exploit-db/GitHub"], "indicators_of_vulnerability": [], "mitigation": f"Apply vendor patch for {cve_id}"}


# ─── 10. Tool Command Generation ───

def generate_tool_commands(
    test_title: str, test_description: str, target_url: str,
    parameters: str, vuln_type: str,
    *, provider: str = "", model: str = "", api_key: str = "",
) -> dict:
    """Generate ready-to-run tool commands for a test case."""
    if api_key and model:
        prompt = f"""You are an expert penetration tester. Generate ready-to-run tool commands for this security test.

Test: {test_title}
Description: {test_description[:500]}
Target URL: {target_url}
Parameters: {parameters}
Vulnerability Type: {vuln_type}

Generate commands for common tools. Use the actual target URL and parameters.

Respond in JSON only:
{{"commands": [{{"tool": "tool name", "command": "full ready-to-run command", "description": "what this does", "expected_output": "what to look for"}}], "manual_steps": ["step1"], "notes": "important considerations"}}"""
        result = _call_llm(provider, model, api_key, prompt)
        parsed = _parse_json(result)
        if parsed:
            return parsed
    # Rule-based: common tool commands
    commands = []
    vuln_lower = (vuln_type or "").lower()
    if "sql" in vuln_lower:
        commands.append({"tool": "sqlmap", "command": f"sqlmap -u '{target_url}' --batch --level=3 --risk=2", "description": "Automated SQL injection testing", "expected_output": "Parameter X is vulnerable"})
    if "xss" in vuln_lower:
        commands.append({"tool": "dalfox", "command": f"dalfox url '{target_url}' --blind", "description": "XSS scanning", "expected_output": "Vulnerable parameter found"})
    commands.append({"tool": "curl", "command": f"curl -v '{target_url}'", "description": "Manual request inspection", "expected_output": "Check response headers and body"})
    commands.append({"tool": "ffuf", "command": f"ffuf -u '{target_url}/FUZZ' -w /opt/navigator/data/SecLists/Discovery/Web-Content/common.txt", "description": "Directory fuzzing", "expected_output": "Hidden paths/files"})
    return {"commands": commands, "manual_steps": ["Review tool output", "Verify findings manually"], "notes": "Always get authorization before testing."}


# ─── 11. Burp Import LLM Enhancement ───

def enhance_burp_findings(
    findings: list[dict],
    *, provider: str = "", model: str = "", api_key: str = "",
) -> list[dict]:
    """Enhance Burp-imported findings with LLM for better severity/CWE mapping."""
    if not api_key or not model or not findings:
        return findings

    findings_text = "\n".join([
        f"[{i}] Title: {f.get('title', '')} | Severity: {f.get('severity', '')} | URL: {f.get('affected_url', '')} | Desc: {(f.get('description', '') or '')[:150]}"
        for i, f in enumerate(findings[:20])
    ])
    prompt = f"""You are an expert security analyst. Review these Burp Suite imported findings and improve their classification.

Findings:
{findings_text}

For each finding, provide improved: severity, CWE ID, OWASP category, and a better title if the original is generic.

Respond in JSON only:
{{"enhanced": [{{"index": 0, "title": "improved title or same", "severity": "critical|high|medium|low|info", "cwe_id": "CWE-XXX", "owasp_category": "A0X:2021"}}]}}"""
    result = _call_llm(provider, model, api_key, prompt)
    parsed = _parse_json(result)
    if parsed and "enhanced" in parsed:
        for enhancement in parsed["enhanced"]:
            idx = enhancement.get("index", -1)
            if 0 <= idx < len(findings):
                if enhancement.get("title"):
                    findings[idx]["title"] = enhancement["title"]
                if enhancement.get("severity"):
                    findings[idx]["severity"] = enhancement["severity"]
                if enhancement.get("cwe_id"):
                    findings[idx]["cwe_id"] = enhancement.get("cwe_id", "")
                if enhancement.get("owasp_category"):
                    findings[idx]["owasp_category"] = enhancement.get("owasp_category", "")
    return findings


# ─── 12. AI Result Interpretation ───

def interpret_tool_results(
    tool_name: str, raw_output: str, test_context: str,
    *, provider: str = "", model: str = "", api_key: str = "",
) -> dict:
    """Interpret tool output and suggest pass/fail + finding."""
    if api_key and model:
        prompt = f"""You are a senior penetration tester. Interpret this security tool output and determine the result.

Tool: {tool_name}
Test Context: {test_context}

Raw Output:
{raw_output[:3000]}

Determine:
1. Is the target vulnerable? (pass = not vulnerable, fail = vulnerable)
2. If vulnerable, provide finding details
3. Confidence level

Respond in JSON only:
{{"verdict": "pass|fail|inconclusive", "confidence": "high|medium|low", "finding": {{"title": "finding title if fail", "severity": "critical|high|medium|low|info", "description": "detailed description", "cwe_id": "CWE-XXX", "impact": "...", "recommendation": "...", "evidence": "relevant evidence from output"}}, "explanation": "why this verdict"}}"""
        result = _call_llm(provider, model, api_key, prompt)
        parsed = _parse_json(result)
        if parsed:
            return parsed
    return {"verdict": "inconclusive", "confidence": "low", "finding": None, "explanation": "No LLM configured. Manual review required."}


# ─── 13. Full Report Summarization ───

def summarize_full_report(
    project: dict, findings: list[dict], phases: list[dict],
    *, provider: str = "", model: str = "", api_key: str = "",
) -> dict:
    """Generate a comprehensive report narrative (beyond exec summary)."""
    if api_key and model:
        findings_text = "\n".join([
            f"- [{f.get('severity', '')}] {f.get('title', '')}: {(f.get('description', '') or '')[:80]}"
            for f in findings[:30]
        ])
        phases_text = "\n".join([
            f"- {p.get('phase', '')}: {p.get('tested', 0)}/{p.get('total', 0)} tested, {p.get('failed', 0)} failed"
            for p in phases
        ])
        prompt = f"""You are a senior security consultant at a Big 4 firm. Write a professional, comprehensive security assessment narrative for this report.

Application: {project.get('application_name', '')}
URL: {project.get('application_url', '')}
Testing Type: {project.get('testing_type', '')}
Environment: {project.get('environment', '')}
Total Findings: {len(findings)}

Findings:
{findings_text}

Phase Coverage:
{phases_text}

Write a 3-section narrative:
1. Executive Summary (3-4 sentences for C-level)
2. Technical Summary (detailed analysis of findings, patterns, risk areas)
3. Strategic Recommendations (prioritized action items)

Respond in JSON only:
{{"executive_summary": "...", "technical_summary": "...", "strategic_recommendations": ["rec1", "rec2", "rec3"], "risk_rating": "Critical|High|Medium|Low", "key_statistics": {{"total_findings": 0, "critical_high": 0, "coverage_pct": 0}}}}"""
        result = _call_llm(provider, model, api_key, prompt)
        parsed = _parse_json(result)
        if parsed:
            return parsed
    # Fallback
    critical_high = sum(1 for f in findings if (f.get("severity") or "").lower() in ("critical", "high"))
    return {
        "executive_summary": f"Security assessment of {project.get('application_name', 'the application')} identified {len(findings)} finding(s). {f'{critical_high} are Critical/High severity.' if critical_high else 'No critical issues found.'}",
        "technical_summary": "Detailed technical analysis requires LLM configuration.",
        "strategic_recommendations": ["Address Critical/High findings within 30 days", "Implement secure coding practices", "Schedule regular security assessments"],
        "risk_rating": "High" if critical_high else "Medium",
        "key_statistics": {"total_findings": len(findings), "critical_high": critical_high, "coverage_pct": 0},
    }
