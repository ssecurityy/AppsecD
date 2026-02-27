"""AI Assist — rule-based or LLM suggestions for CWE, CVSS, impact, remediation on FAIL."""
from typing import Any
from app.core.config import get_settings


# Pattern -> (CWE, CVSS base, severity, impact template, remediation template)
VULN_PATTERNS = [
    (["sql injection", "sqli", "sql injection"], ("CWE-89", "9.8", "critical",
     "Attacker can read, modify, or delete database data. May lead to full database compromise.",
     "Use parameterized queries/prepared statements. Never concatenate user input into SQL. Apply principle of least privilege to DB user.")),
    (["xss", "cross-site scripting"], ("CWE-79", "6.1", "medium",
     "Attacker can execute JavaScript in victim's browser. Session hijacking, credential theft, or defacement possible.",
     "Encode all user-controlled output. Use Content-Security-Policy. Prefer text over innerHTML. Sanitize with DOMPurify or similar.")),
    (["csrf", "cross-site request forgery"], ("CWE-352", "6.5", "medium",
     "Attacker can trick authenticated users into performing unwanted actions.",
     "Implement CSRF tokens. Use SameSite cookie attribute. Validate Origin/Referer headers.")),
    (["idor", "insecure direct object reference", "direct object reference"], ("CWE-639", "7.5", "high",
     "Attacker can access other users' data by manipulating IDs.",
     "Implement proper authorization checks. Use UUIDs instead of sequential IDs. Verify resource ownership server-side.")),
    (["xxe", "xml external entity"], ("CWE-611", "8.6", "high",
     "Attacker can read local files, perform SSRF, or cause DoS via XML parsing.",
     "Disable external entities in XML parser. Use safe parsers. Validate and sanitize XML input.")),
    (["ssrf", "server-side request forgery"], ("CWE-918", "8.6", "high",
     "Attacker can make the server request internal resources, cloud metadata, or arbitrary URLs.",
     "Validate and whitelist URLs. Block internal IP ranges. Disable redirect following.")),
    (["lfi", "local file inclusion", "path traversal"], ("CWE-22", "7.5", "high",
     "Attacker can read arbitrary files from the server.",
     "Avoid user-controlled file paths. Use allowlists. Validate and sanitize path inputs.")),
    (["rce", "remote code execution", "command injection"], ("CWE-78", "9.8", "critical",
     "Attacker can execute arbitrary commands on the server.",
     "Never pass user input to shell/exec. Use safe APIs. Apply principle of least privilege.")),
    (["auth bypass", "authentication bypass"], ("CWE-287", "9.8", "critical",
     "Attacker can access protected resources without valid credentials.",
     "Enforce authentication on all protected endpoints. Validate session server-side. Implement proper session invalidation.")),
    (["jwt", "token"], ("CWE-347", "7.4", "high",
     "JWT vulnerabilities may allow token forgery or privilege escalation.",
     "Validate JWT signature. Use strong algorithms (RS256). Verify expiration and issuer. Never use alg:none.")),
    (["ssti", "server-side template injection"], ("CWE-1336", "9.8", "critical",
     "Attacker can execute arbitrary code via template engine.",
     "Never pass user input to template engines. Use sandboxed templates. Sanitize all template variables.")),
    (["open redirect"], ("CWE-601", "6.1", "medium",
     "Attacker can redirect users to malicious sites for phishing.",
     "Validate redirect URLs against allowlist. Use relative URLs. Avoid user-controlled redirect parameters.")),
]


def _suggest_rule_based(title: str, description: str, severity: str = "medium") -> dict:
    """Rule-based suggestion (no API key required)."""
    combined = (title or "") + " " + (description or "")
    combined_lower = combined.lower()
    for keywords, (cwe, cvss, sev, impact, remediation) in VULN_PATTERNS:
        if any(kw in combined_lower for kw in keywords):
            return {
                "cwe_id": cwe,
                "cvss_score": cvss,
                "severity": sev,
                "impact": impact,
                "recommendation": remediation,
            }
    return {
        "cwe_id": "CWE-Unknown",
        "cvss_score": "5.0",
        "severity": severity,
        "impact": "Review the vulnerability and assess business impact.",
        "recommendation": "Implement secure coding practices. Follow OWASP guidelines. Conduct security review.",
    }


def _suggest_llm(
    title: str,
    description: str,
    severity: str = "medium",
    *,
    model: str | None = None,
    api_key: str | None = None,
) -> dict | None:
    """LLM-based suggestion when API key is set. Returns None on failure."""
    try:
        from openai import OpenAI
        s = get_settings()
        key = api_key if api_key is not None else s.openai_api_key
        if not key:
            return None
        client = OpenAI(api_key=key)
        prompt = f"""Given this security finding, suggest CWE ID, CVSS score, severity, impact, and remediation.
Title: {title}
Description: {description}
Current severity: {severity}

Respond in JSON only, no markdown:
{{"cwe_id": "CWE-XXX", "cvss_score": "X.X", "severity": "critical|high|medium|low|info", "impact": "...", "recommendation": "..."}}"""
        r = client.chat.completions.create(
            model=model or "gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.3,
        )
        import json
        text = (r.choices[0].message.content or "").strip()
        if text.startswith("```"):
            text = text.split("```")[1]
            if text.startswith("json"):
                text = text[4:]
        data = json.loads(text)
        return {
            "cwe_id": data.get("cwe_id", "CWE-Unknown"),
            "cvss_score": str(data.get("cvss_score", "5.0")),
            "severity": data.get("severity", severity),
            "impact": data.get("impact", ""),
            "recommendation": data.get("recommendation", ""),
        }
    except Exception:
        return None


def suggest_finding(
    title: str,
    description: str,
    severity: str = "medium",
    *,
    model: str | None = None,
    api_key: str | None = None,
) -> dict:
    """
    Suggest CWE, CVSS, impact, remediation. Uses LLM when api_key (or env) is set, else rule-based.
    """
    result = _suggest_llm(title, description, severity, model=model, api_key=api_key)
    if result:
        return result
    return _suggest_rule_based(title, description, severity)
