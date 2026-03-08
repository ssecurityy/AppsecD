"""AI-powered analysis for SAST findings — false positive reduction and remediation."""
import json
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# Batch size for AI analysis (keep token usage reasonable)
BATCH_SIZE = 10
MAX_CODE_CONTEXT = 1500  # chars per finding

# Local copy of model pricing — avoids fragile cross-module import from DAST
MODEL_PRICING = {
    "claude-haiku-4-5-20251001": {"input": 1.0, "output": 5.0},
    "claude-sonnet-4-6": {"input": 3.0, "output": 15.0},
    "claude-opus-4-6": {"input": 15.0, "output": 75.0},
    "claude-3-5-haiku-20241022": {"input": 1.0, "output": 5.0},
    "claude-3-5-sonnet-20241022": {"input": 3.0, "output": 15.0},
}


async def analyze_findings_with_ai(
    findings: list[dict],
    api_key: str,
    model: str = "claude-haiku-4-5-20251001",
    organization_id: str | None = None,
) -> list[dict]:
    """Analyze SAST findings using Claude AI.

    For each finding, determines:
    - Is it a true positive or false positive?
    - Developer-friendly explanation
    - Specific remediation with fixed code

    Returns findings with ai_analysis field populated.
    """
    if not api_key or not findings:
        return findings

    try:
        from anthropic import Anthropic
        client = Anthropic(api_key=api_key)
    except Exception as e:
        logger.error("Failed to create Anthropic client: %s", e)
        return findings

    analyzed = []
    total_cost = 0.0

    # Process in batches
    for i in range(0, len(findings), BATCH_SIZE):
        batch = findings[i:i + BATCH_SIZE]
        try:
            batch_result, cost = await _analyze_batch(client, batch, model)
            analyzed.extend(batch_result)
            total_cost += cost
        except Exception as e:
            logger.warning("AI analysis batch failed: %s", e)
            # Return unanalyzed findings for this batch
            for f in batch:
                f["ai_analysis"] = {"error": str(e)[:200]}
            analyzed.extend(batch)

    logger.info("AI analysis complete: %d findings, cost: $%.4f", len(analyzed), total_cost)
    return analyzed


async def _analyze_batch(client, findings: list[dict], model: str) -> tuple[list[dict], float]:
    """Analyze a batch of findings."""
    import asyncio

    # Build prompt
    findings_text = ""
    for idx, f in enumerate(findings):
        snippet = (f.get("code_snippet") or "")[:MAX_CODE_CONTEXT]
        findings_text += f"""
--- Finding {idx + 1} ---
Rule: {f.get('rule_id', 'unknown')}
Severity: {f.get('severity', 'unknown')}
File: {f.get('file_path', 'unknown')}
Line: {f.get('line_start', '?')}
Message: {f.get('message', '')[:300]}
Code:
```
{snippet}
```
"""

    system_prompt = """You are an expert application security engineer reviewing SAST (Static Analysis) findings.
For each finding, analyze the code context and determine:
1. Whether it's a TRUE POSITIVE (real vulnerability) or FALSE POSITIVE (safe code flagged incorrectly)
2. A clear, developer-friendly explanation of the issue (or why it's a false positive)
3. Specific remediation steps with fixed code (if true positive)

Respond with a JSON array. Each element must have:
{
  "index": <finding number starting from 1>,
  "is_false_positive": <boolean>,
  "confidence": <"high"|"medium"|"low">,
  "explanation": "<2-3 sentence explanation for developers>",
  "remediation": "<specific fix description>",
  "fixed_code": "<corrected code snippet or null if false positive>"
}

Be conservative: only mark as false positive if you are confident the code is safe.
Focus on actionable, specific advice — no generic boilerplate."""

    try:
        response = await asyncio.to_thread(
            client.messages.create,
            model=model,
            max_tokens=4096,
            system=system_prompt,
            messages=[{"role": "user", "content": f"Analyze these {len(findings)} findings:\n{findings_text}"}],
        )

        # Parse response
        text = response.content[0].text if response.content else ""

        # Extract JSON from response — try raw text first, then code blocks
        json_text = text
        analyses = None

        # Try parsing raw text directly first
        try:
            analyses = json.loads(json_text)
        except json.JSONDecodeError:
            pass

        # Fallback: extract from markdown code blocks
        if analyses is None:
            if "```json" in text:
                json_text = text.split("```json")[1].split("```")[0]
            elif "```" in text:
                json_text = text.split("```")[1].split("```")[0]
            analyses = json.loads(json_text)

        # Calculate cost
        usage = response.usage
        pricing = MODEL_PRICING.get(model, MODEL_PRICING.get("claude-haiku-4-5-20251001", {}))
        cost = (
            usage.input_tokens * pricing.get("input", 1.0) / 1_000_000
            + usage.output_tokens * pricing.get("output", 5.0) / 1_000_000
        )

        # Map analyses back to findings
        analysis_map = {a["index"]: a for a in analyses if isinstance(a, dict)}

        for idx, f in enumerate(findings):
            ai = analysis_map.get(idx + 1, {})
            f["ai_analysis"] = {
                "is_false_positive": ai.get("is_false_positive", False),
                "confidence": ai.get("confidence", "low"),
                "explanation": ai.get("explanation", ""),
                "remediation": ai.get("remediation", ""),
                "fixed_code": ai.get("fixed_code"),
            }
            if ai.get("is_false_positive"):
                f["fix_suggestion"] = "AI flagged as likely false positive: " + ai.get("explanation", "")
            elif ai.get("remediation"):
                f["fix_suggestion"] = ai["remediation"]
            if ai.get("fixed_code"):
                f["fixed_code"] = ai["fixed_code"]

        return findings, cost

    except json.JSONDecodeError:
        logger.warning("Failed to parse AI response as JSON")
        for f in findings:
            f["ai_analysis"] = {"error": "Failed to parse AI response"}
        return findings, 0.0
    except Exception as e:
        logger.warning("AI analysis failed: %s", e)
        raise


async def explain_finding(
    finding: dict,
    api_key: str,
    model: str = "claude-sonnet-4-6",
) -> dict:
    """Get a detailed AI explanation for a single finding.

    Returns: {explanation, remediation, fixed_code, attack_scenario, references}
    """
    import asyncio

    try:
        from anthropic import Anthropic
        client = Anthropic(api_key=api_key)
    except Exception as e:
        return {"error": str(e)}

    snippet = (finding.get("code_snippet") or "")[:2000]
    prompt = f"""Analyze this security vulnerability in detail:

Rule: {finding.get('rule_id', 'unknown')}
Severity: {finding.get('severity', 'unknown')}
CWE: {finding.get('cwe_id', 'unknown')}
File: {finding.get('file_path', 'unknown')}:{finding.get('line_start', '?')}
Message: {finding.get('message', '')}

Code:
```
{snippet}
```

Provide:
1. **What's the vulnerability?** Clear explanation for developers
2. **Attack scenario**: How an attacker would exploit this
3. **Impact**: What damage could result
4. **Fix**: Specific remediation with corrected code
5. **Prevention**: How to prevent this class of vulnerability

Respond in JSON: {{explanation, attack_scenario, impact, remediation, fixed_code, prevention}}"""

    try:
        response = await asyncio.to_thread(
            client.messages.create,
            model=model,
            max_tokens=2048,
            messages=[{"role": "user", "content": prompt}],
        )
        text = response.content[0].text if response.content else "{}"
        if "```json" in text:
            text = text.split("```json")[1].split("```")[0]
        elif "```" in text:
            text = text.split("```")[1].split("```")[0]
        return json.loads(text)
    except Exception as e:
        return {"error": str(e)[:200]}
