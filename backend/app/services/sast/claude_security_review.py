"""Claude Code Security Review integration — AI-powered semantic security analysis.

Provides three review modes:
  - scan:  Full repository security audit
  - pr:    PR diff review for security regressions
  - audit: Deep comprehensive audit with narrative report
"""
import asyncio
import json
import logging
import os
import re
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# ── Prompt templates ──────────────────────────────────────────────────

SECURITY_AUDIT_PROMPT = """You are an expert application security engineer performing a security code review.
You specialize in finding REAL, EXPLOITABLE vulnerabilities — not theoretical issues.

## Vulnerability Categories With Concrete Examples

### 1. SQL Injection (CWE-89)
VULNERABLE:
```python
query = f"SELECT * FROM users WHERE name = '{user_input}'"
cursor.execute(query)
```
```javascript
const q = `SELECT * FROM orders WHERE id = ${req.params.id}`;
db.query(q);
```
```java
String sql = "SELECT * FROM users WHERE id = " + request.getParameter("id");
stmt.executeQuery(sql);
```
```go
db.Query("SELECT * FROM users WHERE name = '" + name + "'")
```

### 2. Cross-Site Scripting / XSS (CWE-79)
VULNERABLE:
```python
return f"<div>{user_input}</div>"
```
```javascript
element.innerHTML = userInput;
res.send(`<p>${req.query.msg}</p>`);
```
```java
out.println("<div>" + request.getParameter("name") + "</div>");
```

### 3. Command Injection (CWE-78)
VULNERABLE:
```python
os.system(f"ping {host}")
subprocess.call(f"ls {user_dir}", shell=True)
```
```javascript
exec(`git clone ${repoUrl}`);
child_process.execSync('rm -rf ' + userPath);
```
```go
exec.Command("sh", "-c", "echo " + userInput).Run()
```

### 4. Path Traversal (CWE-22)
VULNERABLE:
```python
open(os.path.join("/uploads", filename))  # filename = "../../etc/passwd"
```
```javascript
fs.readFile(path.join(baseDir, req.params.file));
```
```java
new File(uploadDir, request.getParameter("filename"));
```

### 5. SSRF (CWE-918)
VULNERABLE:
```python
requests.get(user_provided_url)
urllib.request.urlopen(url_from_input)
```
```javascript
fetch(req.body.webhook_url);
axios.get(userUrl);
```

### 6. Insecure Deserialization (CWE-502)
VULNERABLE:
```python
pickle.loads(user_data)
yaml.load(data)  # without Loader=SafeLoader
```
```java
ObjectInputStream ois = new ObjectInputStream(untrustedStream);
ois.readObject();
```

### 7. Hardcoded Secrets (CWE-798)
VULNERABLE:
```python
API_KEY = "sk-live-abc123..."
db_password = "admin123"
```

### 8. Missing Auth / Broken Access Control (CWE-862, CWE-863)
VULNERABLE:
```python
@app.route("/admin/delete_user/<id>")
def delete_user(id):  # No auth check!
    db.delete_user(id)
```

## Anti-False-Positive Rules — Do NOT Flag These:

1. **Parameterized queries** — These are SAFE, never flag them:
   - `cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))`
   - `db.query(User).filter(User.id == user_id)` (ORM usage)
   - `db.execute(select(User).where(User.id == uid))`  (SQLAlchemy Core)
   - Prepared statements with `?` or `$1` placeholders

2. **Sanitized / escaped output** — SAFE:
   - Template engines with auto-escaping (Jinja2 default, React JSX, Go html/template)
   - `html.escape()`, `markupsafe.escape()`, `DOMPurify.sanitize()`
   - Content-Security-Policy headers in place

3. **Test fixtures and test files** — SAFE:
   - Files in `tests/`, `test_*.py`, `*_test.go`, `*.test.js`, `*.spec.ts`
   - Hardcoded values in test fixtures are NOT real secrets

4. **Dead code / commented code** — Do not flag commented-out vulnerable code

5. **Internal-only endpoints with auth middleware applied at router level** — Check for middleware before flagging missing auth

6. **subprocess with shell=False and list args** — SAFE:
   - `subprocess.run(["ls", "-la", path])` is NOT command injection

7. **Path operations with explicit validation** — SAFE:
   - Code that checks `os.path.realpath()` or rejects `..` before file access

## Confidence Calibration

Only report findings you are >80% confident about. Rate your confidence honestly:
- 0.95+: Definite vulnerability with clear exploit path
- 0.85-0.94: Very likely vulnerability, minor uncertainty about context
- 0.80-0.84: Probable vulnerability, needs verification of surrounding context
- Below 0.80: Do NOT report — too speculative

## Language-Specific Guidance

**Python**: Watch for f-string SQL, `eval()`, `pickle.loads()`, `yaml.load()` without SafeLoader,
`subprocess` with `shell=True`, `os.system()`, Jinja2 `|safe` filter, Flask `send_file()` without path validation.

**JavaScript/TypeScript**: Watch for `innerHTML`, `eval()`, `Function()`, `child_process.exec()` with string concat,
`dangerouslySetInnerHTML`, missing CSRF tokens, `document.write()`, prototype pollution via `Object.assign()` with user input.

**Java**: Watch for `Runtime.exec()` with string concat, `ObjectInputStream.readObject()`, JNDI injection,
`Statement.executeQuery()` with string concat (vs PreparedStatement), XXE in DocumentBuilderFactory without disabling external entities.

**Go**: Watch for `fmt.Sprintf` in SQL queries, `os/exec.Command("sh", "-c", userInput)`,
`html/template` vs `text/template` misuse, missing input validation on HTTP handlers.

## Required Output Format

Respond with a JSON array. Each finding MUST have these fields:
```json
[{
    "file": "relative/path/to/file.ext",
    "line": 42,
    "end_line": 45,
    "severity": "CRITICAL|HIGH|MEDIUM|LOW",
    "category": "Input Validation|Auth|Cryptography|Code Execution|Data Exposure|Business Logic",
    "title": "Concise title (max 80 chars)",
    "description": "Detailed explanation of WHY this is vulnerable and WHAT the impact is.",
    "exploit_scenario": "Step-by-step: 1) Attacker sends X, 2) Application does Y, 3) Result is Z",
    "confidence": 0.92,
    "cwe_id": "CWE-NNN",
    "remediation": "Specific fix instructions with code context",
    "fixed_code": "The corrected code snippet"
}]
```

Optional fields (include when applicable):
- `"end_line"`: Last line of the vulnerable code block
- `"data_flow"`: For injection flaws, describe source -> sink path

If no vulnerabilities found, return an empty array: []
"""

PR_REVIEW_PROMPT = """You are an expert application security engineer reviewing a pull request diff for security regressions.

Focus ONLY on security issues introduced or worsened by this change.
Do NOT flag pre-existing issues unless the change makes them worse.

For each security regression found, respond with a JSON array:
[{
    "file": "path/to/file.py",
    "line": 42,
    "severity": "HIGH",
    "category": "Input Validation",
    "title": "SQL Injection introduced in user query",
    "description": "The new code interpolates user input directly into SQL...",
    "exploit_scenario": "An attacker could...",
    "confidence": 0.9,
    "cwe_id": "CWE-89",
    "remediation": "Use parameterized queries...",
    "fixed_code": "cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))"
}]

Only report findings with confidence >= 0.7. If no security regressions, return: []
"""

AUDIT_PROMPT = """You are an expert application security engineer performing a comprehensive security audit.

Perform a thorough security analysis covering ALL of the following areas:

1. **Input Validation** — injection flaws (SQL, command, XXE, SSTI, LDAP, XPath), path traversal, SSRF, open redirect
2. **Authentication & Authorization** — auth bypass, privilege escalation, session management, missing access controls, IDOR
3. **Cryptography** — weak algorithms, hardcoded secrets, weak randomness, missing encryption, insecure key management
4. **Code Execution** — deserialization, eval injection, prototype pollution, unsafe reflection, dynamic code loading
5. **Data Exposure** — sensitive data in logs, PII mishandling, API key leakage, verbose error messages
6. **Business Logic** — race conditions, TOCTOU, workflow bypass, numeric overflow, missing validation

For each vulnerability found, include it in the JSON array:
[{
    "file": "path/to/file.py",
    "line": 42,
    "severity": "CRITICAL|HIGH|MEDIUM|LOW",
    "category": "category name",
    "title": "Short title",
    "description": "Detailed description...",
    "exploit_scenario": "How an attacker would exploit this...",
    "confidence": 0.95,
    "cwe_id": "CWE-NNN",
    "remediation": "How to fix...",
    "fixed_code": "corrected code snippet"
}]

After the JSON array, provide a narrative AUDIT SUMMARY section (separated by `---AUDIT_SUMMARY---`) covering:
- Overall security posture assessment
- Key risk areas
- Positive security practices observed
- Strategic recommendations

Only report findings with confidence >= 0.7.
"""

TRIAGE_PROMPT = """You are a security triage specialist. Perform a QUICK scan of the following code.
Focus ONLY on CRITICAL and HIGH severity vulnerabilities that are clearly exploitable.

Look for:
- Direct SQL string concatenation/interpolation with user input
- Command injection via os.system/subprocess with shell=True and user input
- Hardcoded production secrets/API keys (not test fixtures)
- Missing authentication on sensitive endpoints
- Unsafe deserialization of untrusted data
- Direct use of eval/exec with user input
- SSRF with unvalidated URLs from user input

Do NOT report: medium/low issues, theoretical risks, best-practice suggestions, or issues in test files.

Respond with a JSON array of findings. Each MUST have:
```json
[{
    "file": "path/to/file.ext",
    "line": 42,
    "severity": "CRITICAL|HIGH",
    "category": "category name",
    "title": "Short title",
    "confidence": 0.9,
    "cwe_id": "CWE-NNN",
    "description": "Brief description of the vulnerability"
}]
```

If nothing CRITICAL or HIGH found, return: []
Be fast and decisive — this is a triage pass, not a deep audit.
"""

VERIFICATION_PROMPT = """You are a false-positive analyst. Your job is to VERIFY or REJECT security findings.

For each finding below, determine if it is a TRUE POSITIVE or FALSE POSITIVE by checking:

1. **Is the input actually user-controlled?** Trace the data flow from source to sink.
   - If the value comes from a config file, environment variable, or hardcoded constant, it may be safe.
2. **Are there mitigations in place?** Check for:
   - Input validation/sanitization before the vulnerable call
   - Parameterized queries / ORM usage
   - Auth middleware applied at router/app level
   - Output encoding/escaping
3. **Is this in test/dead code?** Files in tests/, test fixtures, commented-out code = false positive.
4. **Is the severity accurate?** Downgrade if the impact is limited (e.g., requires admin access already).

For each finding, respond with:
```json
[{
    "original_index": 0,
    "verdict": "true_positive|false_positive|downgrade",
    "adjusted_severity": "CRITICAL|HIGH|MEDIUM|LOW",
    "adjusted_confidence": 0.92,
    "reasoning": "Why this is/isn't a real vulnerability",
    "mitigations_found": ["list", "of", "mitigations"]
}]
```

Be rigorous. A 30% false positive rate is unacceptable — reject anything you are not confident about.
"""

# ── Model pricing (per million tokens) ────────────────────────────────

MODEL_PRICING = {
    "claude-sonnet-4-6-20250514": {"input": 3.0, "output": 15.0},
    "claude-sonnet-4-6": {"input": 3.0, "output": 15.0},
    "claude-haiku-4-5-20251001": {"input": 1.0, "output": 5.0},
    "claude-3-5-haiku-20241022": {"input": 1.0, "output": 5.0},
    "claude-3-5-sonnet-20241022": {"input": 3.0, "output": 15.0},
    "claude-opus-4-6-20250514": {"input": 15.0, "output": 75.0},
    "claude-opus-4-6": {"input": 15.0, "output": 75.0},
}

# ── Security-relevant path keywords for file prioritization ──────────

SECURITY_KEYWORDS = [
    "auth", "login", "crypto", "api", "route", "middleware", "config",
    "secret", "password", "token", "session", "admin", "payment",
    "permission", "rbac", "acl", "sanitize", "validate", "upload",
    "oauth", "jwt", "key", "credential", "encrypt", "decrypt",
    "certificate", "ssl", "tls", "webhook", "cors",
]

# File batch sizes
BATCH_SIZE_SCAN = 8
BATCH_SIZE_AUDIT = 5
MAX_FILES_SCAN = 50
MAX_FILE_SIZE = 50_000  # chars per file


def _security_relevance_score(file_path: str) -> int:
    """Score a file path by security relevance (higher = more relevant)."""
    lower = file_path.lower()
    score = 0
    for kw in SECURITY_KEYWORDS:
        if kw in lower:
            score += 1
    return score


def _prioritize_files(file_paths: list[str], max_files: int = MAX_FILES_SCAN) -> list[str]:
    """Sort files by security relevance and return top N."""
    scored = [(path, _security_relevance_score(path)) for path in file_paths]
    scored.sort(key=lambda x: (-x[1], x[0]))
    return [path for path, _ in scored[:max_files]]


def _parse_claude_json(text: str) -> list[dict]:
    """Parse JSON response from Claude with fallback handling.

    Handles:
    - Raw JSON arrays
    - JSON wrapped in markdown code fences
    - JSON embedded in surrounding text
    """
    if not text or not text.strip():
        return []

    # Try raw text first
    try:
        result = json.loads(text.strip())
        if isinstance(result, list):
            return result
        return []
    except json.JSONDecodeError:
        pass

    # Try extracting from markdown code blocks
    json_text = None
    if "```json" in text:
        parts = text.split("```json")
        if len(parts) > 1:
            json_text = parts[1].split("```")[0]
    elif "```" in text:
        parts = text.split("```")
        if len(parts) > 2:
            json_text = parts[1].split("```")[0]

    if json_text:
        try:
            result = json.loads(json_text.strip())
            if isinstance(result, list):
                return result
        except json.JSONDecodeError:
            pass

    # Last resort: find first [ ... ] block
    bracket_match = re.search(r"\[[\s\S]*\]", text)
    if bracket_match:
        try:
            result = json.loads(bracket_match.group())
            if isinstance(result, list):
                return result
        except json.JSONDecodeError:
            pass

    logger.warning("Failed to parse Claude response as JSON array")
    return []


def _calculate_cost(usage, model: str) -> float:
    """Calculate USD cost from token usage and model pricing."""
    pricing = MODEL_PRICING.get(model, {"input": 3.0, "output": 15.0})
    input_cost = getattr(usage, "input_tokens", 0) * pricing["input"] / 1_000_000
    output_cost = getattr(usage, "output_tokens", 0) * pricing["output"] / 1_000_000
    return input_cost + output_cost


def _normalize_severity(severity: str) -> str:
    """Normalize severity to lowercase standard values."""
    s = severity.strip().lower()
    if s in ("critical", "high", "medium", "low", "info"):
        return s
    mapping = {
        "crit": "critical",
        "error": "high",
        "warning": "medium",
        "warn": "medium",
        "note": "low",
        "informational": "info",
    }
    return mapping.get(s, "medium")


def _finding_to_sast_dict(finding: dict, mode: str) -> dict:
    """Convert a Claude finding to SastFinding-compatible dict."""
    return {
        "rule_id": f"claude_review.{finding.get('category', 'general').lower().replace(' ', '_')}",
        "rule_source": "claude_review",
        "severity": _normalize_severity(finding.get("severity", "medium")),
        "confidence": str(
            "high" if finding.get("confidence", 0) >= 0.9
            else "medium" if finding.get("confidence", 0) >= 0.75
            else "low"
        ),
        "title": finding.get("title", "Security Issue"),
        "description": finding.get("description", ""),
        "message": finding.get("exploit_scenario", ""),
        "file_path": finding.get("file", "unknown"),
        "line_start": finding.get("line", 0),
        "line_end": finding.get("line", 0),
        "code_snippet": finding.get("fixed_code", ""),
        "fix_suggestion": finding.get("remediation", ""),
        "fixed_code": finding.get("fixed_code"),
        "cwe_id": finding.get("cwe_id"),
        "owasp_category": _cwe_to_owasp(finding.get("cwe_id", "")),
        "ai_analysis": {
            "is_false_positive": False,
            "confidence": finding.get("confidence", 0.7),
            "explanation": finding.get("description", ""),
            "remediation": finding.get("remediation", ""),
            "exploit_scenario": finding.get("exploit_scenario", ""),
            "category": finding.get("category", ""),
            "review_mode": mode,
        },
    }


def _cwe_to_owasp(cwe_id: str) -> str:
    """Map common CWE IDs to OWASP Top 10 2021 categories."""
    if not cwe_id:
        return ""
    cwe_owasp_map = {
        "CWE-79": "A03:2021-Injection",
        "CWE-89": "A03:2021-Injection",
        "CWE-78": "A03:2021-Injection",
        "CWE-77": "A03:2021-Injection",
        "CWE-90": "A03:2021-Injection",
        "CWE-611": "A03:2021-Injection",
        "CWE-917": "A03:2021-Injection",
        "CWE-22": "A01:2021-Broken Access Control",
        "CWE-918": "A10:2021-SSRF",
        "CWE-287": "A07:2021-Identification and Authentication Failures",
        "CWE-862": "A01:2021-Broken Access Control",
        "CWE-863": "A01:2021-Broken Access Control",
        "CWE-639": "A01:2021-Broken Access Control",
        "CWE-327": "A02:2021-Cryptographic Failures",
        "CWE-328": "A02:2021-Cryptographic Failures",
        "CWE-330": "A02:2021-Cryptographic Failures",
        "CWE-798": "A07:2021-Identification and Authentication Failures",
        "CWE-502": "A08:2021-Software and Data Integrity Failures",
        "CWE-94": "A03:2021-Injection",
        "CWE-1321": "A08:2021-Software and Data Integrity Failures",
        "CWE-200": "A01:2021-Broken Access Control",
        "CWE-532": "A09:2021-Security Logging and Monitoring Failures",
    }
    return cwe_owasp_map.get(cwe_id, "")


class ClaudeSecurityReviewer:
    """Claude-powered semantic security analysis for code repositories."""

    def __init__(
        self,
        api_key: str,
        model: str = "claude-sonnet-4-6-20250514",
        organization_id: str = "",
        custom_instructions: str = "",
    ):
        self.api_key = api_key
        self.model = model
        self.organization_id = organization_id
        self.custom_instructions = custom_instructions
        self.total_cost = 0.0
        self._client = None
        self._all_project_files: list[tuple[str, int]] = []  # (path, relevance_score)

    def _get_client(self):
        """Lazily create Anthropic client."""
        if self._client is None:
            from anthropic import Anthropic
            self._client = Anthropic(api_key=self.api_key)
        return self._client

    async def _call_claude(
        self,
        system_prompt: str,
        user_content: str,
        max_tokens: int = 8192,
    ) -> tuple[str, float]:
        """Send a message to Claude and return (response_text, cost_usd)."""
        client = self._get_client()

        # Inject custom instructions into system prompt if provided
        effective_prompt = system_prompt
        if self.custom_instructions:
            effective_prompt += (
                f"\n\n## Organization-Specific Instructions\n\n"
                f"{self.custom_instructions}\n"
            )

        response = await asyncio.to_thread(
            client.messages.create,
            model=self.model,
            max_tokens=max_tokens,
            system=effective_prompt,
            messages=[{"role": "user", "content": user_content}],
        )

        text = response.content[0].text if response.content else ""
        cost = _calculate_cost(response.usage, self.model)
        self.total_cost += cost
        return text, cost

    def _build_cross_file_preamble(self) -> str:
        """Build a preamble listing all project files with security relevance scores.

        Gives Claude architectural awareness of the broader codebase even when
        analyzing a small batch.
        """
        if not self._all_project_files:
            return ""

        lines = ["## Project Architecture Context\n"]
        lines.append(
            "The following is a map of ALL files in this project with their "
            "security relevance scores (higher = more security-sensitive). "
            "Use this to understand cross-file relationships, such as whether "
            "an auth middleware is defined elsewhere, or whether a utility "
            "function sanitizes inputs before they reach a sink.\n"
        )

        # Group by directory for readability
        dirs: dict[str, list[tuple[str, int]]] = {}
        for fpath, score in self._all_project_files:
            d = os.path.dirname(fpath) or "."
            dirs.setdefault(d, []).append((os.path.basename(fpath), score))

        # Sort dirs by max score descending (most security-relevant first)
        sorted_dirs = sorted(dirs.items(), key=lambda kv: -max(s for _, s in kv[1]))

        for dir_path, files in sorted_dirs[:30]:  # Limit to top 30 dirs
            lines.append(f"  {dir_path}/")
            # Sort files within dir by score desc
            for fname, score in sorted(files, key=lambda x: -x[1])[:15]:
                marker = " *" if score >= 2 else ""
                lines.append(f"    {fname} [relevance={score}]{marker}")

        lines.append("")
        lines.append(
            "Files marked with * are highly security-relevant. "
            "When you see a function call to code in another file, "
            "consider what that file likely does based on its name and path.\n"
        )
        return "\n".join(lines)

    # ── Mode 1: Repository Scan ───────────────────────────────────────

    async def review_codebase(
        self,
        source_path: str,
        languages: list[str],
        scan_config: dict | None = None,
        existing_findings: list[dict] | None = None,
    ) -> list[dict]:
        """Scan mode: review key files from a repository for security issues.

        Reads up to MAX_FILES_SCAN files (prioritized by security relevance),
        sends them in batches to Claude with three-phase analysis, and returns
        SastFinding-compatible dicts.

        Args:
            existing_findings: Optional list of findings from other scanners
                (e.g. Semgrep) to dedup against.
        """
        config = scan_config or {}
        exclude_patterns = config.get("exclude_patterns", [])

        # Collect all scannable files
        from .code_extractor import list_scannable_files
        all_files = list_scannable_files(source_path)

        # Filter by language if specified
        lang_filter = config.get("languages") or languages
        if lang_filter:
            from .code_extractor import LANGUAGE_EXTENSIONS
            allowed_exts = {
                ext for ext, lang in LANGUAGE_EXTENSIONS.items()
                if lang in lang_filter
            }
            all_files = [
                f for f in all_files
                if os.path.splitext(f)[1].lower() in allowed_exts
            ]

        # Apply exclude patterns
        for pattern in exclude_patterns:
            all_files = [f for f in all_files if pattern not in f]

        # Build cross-file context: score ALL files for architectural awareness
        self._all_project_files = [
            (fpath, _security_relevance_score(fpath)) for fpath in all_files
        ]

        # Prioritize by security relevance
        prioritized = _prioritize_files(all_files, MAX_FILES_SCAN)
        logger.info(
            "Claude review: %d/%d files selected for review (from %s)",
            len(prioritized), len(all_files), source_path,
        )

        if not prioritized:
            return []

        # Read file contents
        file_contents = self._read_files(source_path, prioritized)
        if not file_contents:
            return []

        # Process in batches — real three-phase analysis
        all_findings = []
        batches = [
            file_contents[i:i + BATCH_SIZE_SCAN]
            for i in range(0, len(file_contents), BATCH_SIZE_SCAN)
        ]

        for batch_idx, batch in enumerate(batches):
            try:
                findings = await self._analyze_batch(batch, "scan", batch_idx, len(batches))
                all_findings.extend(findings)
            except Exception as e:
                logger.warning("Batch %d/%d failed: %s", batch_idx + 1, len(batches), e)

        # Dedup against existing findings from other scanners
        if existing_findings:
            pre_dedup = len(all_findings)
            all_findings = self._dedup_against_existing(all_findings, existing_findings)
            logger.info(
                "Claude dedup: %d -> %d findings (removed %d duplicates of Semgrep/other findings)",
                pre_dedup, len(all_findings), pre_dedup - len(all_findings),
            )

        return all_findings

    # ── Mode 2: PR Diff Review ────────────────────────────────────────

    async def review_pr_diff(
        self,
        diff_text: str,
        repo_context: str = "",
        scan_config: dict | None = None,
    ) -> list[dict]:
        """PR mode: analyze a unified diff for security regressions.

        Returns findings with line numbers relative to the diff.
        """
        if not diff_text or not diff_text.strip():
            return []

        # Truncate very large diffs
        max_diff_chars = 100_000
        if len(diff_text) > max_diff_chars:
            diff_text = diff_text[:max_diff_chars] + "\n... (diff truncated)"
            logger.warning("Diff truncated to %d characters", max_diff_chars)

        context_section = ""
        if repo_context:
            context_section = f"\n\nRepository context:\n{repo_context}\n"

        user_content = f"""Review this pull request diff for security regressions:
{context_section}
```diff
{diff_text}
```
"""

        try:
            response_text, cost = await self._call_claude(
                PR_REVIEW_PROMPT,
                user_content,
                max_tokens=4096,
            )
            raw_findings = _parse_claude_json(response_text)
            findings = [
                _finding_to_sast_dict(f, "pr")
                for f in raw_findings
                if f.get("confidence", 0) >= 0.7
            ]
            logger.info(
                "PR review: %d findings, cost $%.4f",
                len(findings), cost,
            )
            return findings

        except Exception as e:
            logger.error("PR review failed: %s", e)
            return []

    # ── Mode 3: Deep Audit ────────────────────────────────────────────

    async def review_audit(
        self,
        source_path: str,
        languages: list[str],
        scan_config: dict | None = None,
        existing_findings: list[dict] | None = None,
    ) -> tuple[list[dict], str]:
        """Audit mode: deep comprehensive security audit with narrative report.

        Returns (findings, audit_summary_text).
        """
        config = scan_config or {}
        exclude_patterns = config.get("exclude_patterns", [])

        from .code_extractor import list_scannable_files
        all_files = list_scannable_files(source_path)

        # Apply exclude patterns
        for pattern in exclude_patterns:
            all_files = [f for f in all_files if pattern not in f]

        # Build cross-file context
        self._all_project_files = [
            (fpath, _security_relevance_score(fpath)) for fpath in all_files
        ]

        # For audit mode, take more files but in smaller batches
        prioritized = _prioritize_files(all_files, MAX_FILES_SCAN)
        file_contents = self._read_files(source_path, prioritized)

        if not file_contents:
            return [], "No files found to audit."

        # Process in smaller batches for deeper analysis
        all_findings = []
        audit_summaries = []
        batches = [
            file_contents[i:i + BATCH_SIZE_AUDIT]
            for i in range(0, len(file_contents), BATCH_SIZE_AUDIT)
        ]

        for batch_idx, batch in enumerate(batches):
            try:
                findings, summary = await self._analyze_batch_audit(
                    batch, batch_idx, len(batches),
                )
                all_findings.extend(findings)
                if summary:
                    audit_summaries.append(summary)
            except Exception as e:
                logger.warning("Audit batch %d/%d failed: %s", batch_idx + 1, len(batches), e)

        # Dedup against existing findings
        if existing_findings:
            pre_dedup = len(all_findings)
            all_findings = self._dedup_against_existing(all_findings, existing_findings)
            logger.info(
                "Audit dedup: %d -> %d findings (removed %d duplicates)",
                pre_dedup, len(all_findings), pre_dedup - len(all_findings),
            )

        # Combine audit summaries
        combined_summary = "\n\n".join(audit_summaries) if audit_summaries else "Audit completed."
        return all_findings, combined_summary

    # ── Internal helpers ──────────────────────────────────────────────

    def _read_files(
        self,
        source_path: str,
        relative_paths: list[str],
    ) -> list[tuple[str, str]]:
        """Read file contents. Returns list of (relative_path, content) tuples."""
        results = []
        for rel_path in relative_paths:
            abs_path = os.path.join(source_path, rel_path)
            try:
                with open(abs_path, "r", encoding="utf-8", errors="replace") as fh:
                    content = fh.read(MAX_FILE_SIZE)
                if content.strip():
                    results.append((rel_path, content))
            except (OSError, UnicodeDecodeError) as e:
                logger.debug("Skipping unreadable file %s: %s", rel_path, e)
        return results

    async def _analyze_batch(
        self,
        file_batch: list[tuple[str, str]],
        mode: str,
        batch_idx: int,
        total_batches: int,
    ) -> list[dict]:
        """Real three-phase analysis for a batch of files.

        Phase 1 (Triage): Quick scan for obvious high/critical severity issues.
        Phase 2 (Deep Analysis): For files with Phase 1 hits, re-analyze with
            full context and cross-file references.
        Phase 3 (Verification): Verify each finding is not a false positive
            by checking for mitigations.
        """
        # Build file content block
        files_text = ""
        for rel_path, content in file_batch:
            files_text += f"\n--- File: {rel_path} ---\n{content}\n"

        # Build cross-file context preamble
        preamble = self._build_cross_file_preamble()

        # ── Phase 1: Triage — quick scan for critical/high issues ──
        triage_content = (
            f"Batch {batch_idx + 1}/{total_batches}. "
            f"Quick triage scan of these {len(file_batch)} files:\n"
        )
        if preamble:
            triage_content += f"\n{preamble}\n"
        triage_content += files_text

        try:
            triage_text, triage_cost = await self._call_claude(
                TRIAGE_PROMPT,
                triage_content,
                max_tokens=4096,
            )
            triage_findings = _parse_claude_json(triage_text)
            logger.info(
                "Batch %d/%d Phase 1 (Triage): %d potential issues, cost $%.4f",
                batch_idx + 1, total_batches, len(triage_findings), triage_cost,
            )
        except Exception as e:
            logger.warning("Batch %d/%d Phase 1 failed: %s", batch_idx + 1, total_batches, e)
            triage_findings = []

        # ── Phase 2: Deep Analysis — full scan with context ──
        # Always run Phase 2 (the thorough prompt catches medium-severity
        # issues that triage intentionally skips)
        deep_content = (
            f"Batch {batch_idx + 1}/{total_batches}. "
            f"Analyze these {len(file_batch)} files for security vulnerabilities.\n"
        )
        if preamble:
            deep_content += f"\n{preamble}\n"
        # If Phase 1 found hits, tell Phase 2 about them for additional context
        if triage_findings:
            triage_summary = "\n".join(
                f"  - {f.get('file', '?')}:{f.get('line', '?')} — {f.get('title', 'unknown')} ({f.get('severity', '?')})"
                for f in triage_findings
            )
            deep_content += (
                f"\nPhase 1 triage flagged these potential issues. Include them in your "
                f"analysis and look for additional vulnerabilities beyond these:\n{triage_summary}\n"
            )
        deep_content += files_text

        try:
            deep_text, deep_cost = await self._call_claude(
                SECURITY_AUDIT_PROMPT,
                deep_content,
                max_tokens=8192,
            )
            deep_findings = _parse_claude_json(deep_text)
            logger.info(
                "Batch %d/%d Phase 2 (Deep): %d findings, cost $%.4f",
                batch_idx + 1, total_batches, len(deep_findings), deep_cost,
            )
        except Exception as e:
            logger.error("Batch %d/%d Phase 2 failed: %s", batch_idx + 1, total_batches, e)
            deep_findings = []

        # Merge Phase 1 + Phase 2 findings, dedup by file+line
        merged = self._merge_phase_findings(triage_findings, deep_findings)

        if not merged:
            logger.info("Batch %d/%d: no findings after merge", batch_idx + 1, total_batches)
            return []

        # ── Phase 3: Verification — false positive check ──
        verification_content = self._build_verification_content(merged, files_text)

        try:
            verify_text, verify_cost = await self._call_claude(
                VERIFICATION_PROMPT,
                verification_content,
                max_tokens=4096,
            )
            verdicts = _parse_claude_json(verify_text)
            logger.info(
                "Batch %d/%d Phase 3 (Verify): %d verdicts, cost $%.4f",
                batch_idx + 1, total_batches, len(verdicts), verify_cost,
            )
            # Apply verdicts
            verified = self._apply_verification_verdicts(merged, verdicts)
        except Exception as e:
            logger.warning(
                "Batch %d/%d Phase 3 failed (keeping Phase 2 findings): %s",
                batch_idx + 1, total_batches, e,
            )
            # If verification fails, keep all findings with confidence >= 0.8
            verified = [f for f in merged if f.get("confidence", 0) >= 0.8]

        # Convert to SAST dicts
        findings = [
            _finding_to_sast_dict(f, mode)
            for f in verified
            if f.get("confidence", 0) >= 0.8
        ]

        logger.info(
            "Batch %d/%d: %d verified findings (from %d merged candidates)",
            batch_idx + 1, total_batches, len(findings), len(merged),
        )
        return findings

    def _merge_phase_findings(
        self,
        triage_findings: list[dict],
        deep_findings: list[dict],
    ) -> list[dict]:
        """Merge findings from Phase 1 (triage) and Phase 2 (deep), deduplicating
        by file + line proximity (within 3 lines).

        Phase 2 (deep) findings take priority since they have more detail.
        """
        if not triage_findings:
            return deep_findings
        if not deep_findings:
            # Promote triage findings — they only have partial fields
            return triage_findings

        merged = list(deep_findings)  # Deep findings are the primary set
        deep_locations = {
            (f.get("file", ""), f.get("line", 0))
            for f in deep_findings
        }

        for tf in triage_findings:
            tf_file = tf.get("file", "")
            tf_line = tf.get("line", 0)

            # Check if any deep finding covers the same location (within 3 lines)
            already_covered = any(
                df == tf_file and abs(dl - tf_line) <= 3
                for df, dl in deep_locations
            )
            if not already_covered:
                merged.append(tf)

        return merged

    def _build_verification_content(
        self,
        findings: list[dict],
        files_text: str,
    ) -> str:
        """Build user content for the verification (Phase 3) prompt."""
        findings_desc = []
        for idx, f in enumerate(findings):
            findings_desc.append(
                f"Finding #{idx}:\n"
                f"  File: {f.get('file', 'unknown')}\n"
                f"  Line: {f.get('line', '?')}\n"
                f"  Severity: {f.get('severity', '?')}\n"
                f"  Title: {f.get('title', '?')}\n"
                f"  CWE: {f.get('cwe_id', 'N/A')}\n"
                f"  Description: {f.get('description', 'N/A')}\n"
                f"  Confidence: {f.get('confidence', '?')}\n"
            )

        return (
            f"Verify these {len(findings)} security findings. "
            f"For each, check the source code to determine if it is a "
            f"true positive or false positive.\n\n"
            f"FINDINGS TO VERIFY:\n"
            + "\n".join(findings_desc)
            + f"\n\nSOURCE CODE:\n{files_text}"
        )

    def _apply_verification_verdicts(
        self,
        findings: list[dict],
        verdicts: list[dict],
    ) -> list[dict]:
        """Apply Phase 3 verification verdicts to findings.

        Removes false positives and adjusts severity/confidence based on verdicts.
        """
        if not verdicts:
            return findings

        # Build verdict lookup by original_index
        verdict_map: dict[int, dict] = {}
        for v in verdicts:
            idx = v.get("original_index")
            if idx is not None and isinstance(idx, int):
                verdict_map[idx] = v

        verified = []
        for idx, finding in enumerate(findings):
            verdict = verdict_map.get(idx)
            if verdict is None:
                # No verdict for this finding — keep it if confidence is high
                if finding.get("confidence", 0) >= 0.8:
                    verified.append(finding)
                continue

            v_type = verdict.get("verdict", "").lower()
            if v_type == "false_positive":
                logger.debug(
                    "Verification rejected finding: %s in %s (reason: %s)",
                    finding.get("title"), finding.get("file"),
                    verdict.get("reasoning", "no reason"),
                )
                continue

            # True positive or downgrade — update the finding
            if v_type == "downgrade":
                adjusted_sev = verdict.get("adjusted_severity")
                if adjusted_sev:
                    finding["severity"] = adjusted_sev
            adjusted_conf = verdict.get("adjusted_confidence")
            if adjusted_conf is not None and isinstance(adjusted_conf, (int, float)):
                finding["confidence"] = adjusted_conf

            # Add verification metadata
            finding["verification"] = {
                "verdict": v_type,
                "reasoning": verdict.get("reasoning", ""),
                "mitigations_found": verdict.get("mitigations_found", []),
            }
            verified.append(finding)

        return verified

    def _dedup_against_existing(
        self,
        claude_findings: list[dict],
        existing_findings: list[dict],
    ) -> list[dict]:
        """Deduplicate Claude findings against existing Semgrep/other scanner findings.

        Compares by file_path + line range (within 5 lines) + similar category/CWE.
        If a match is found, skip the Claude finding (the other scanner already caught it).

        Args:
            claude_findings: Findings from Claude review (SastFinding-compatible dicts).
            existing_findings: Findings from other scanners (Semgrep, secret scanner, etc.).

        Returns:
            Only genuinely new findings that other scanners did not catch.
        """
        if not existing_findings:
            return claude_findings

        # Build lookup index of existing findings: (file_path, line_bucket) -> list[finding]
        existing_index: dict[str, list[dict]] = {}
        for ef in existing_findings:
            fp = ef.get("file_path", "")
            if fp:
                existing_index.setdefault(fp, []).append(ef)

        # CWE category groups for fuzzy matching
        cwe_category_map = {
            "CWE-89": "injection", "CWE-78": "injection", "CWE-77": "injection",
            "CWE-79": "xss", "CWE-80": "xss",
            "CWE-22": "path_traversal", "CWE-23": "path_traversal",
            "CWE-918": "ssrf",
            "CWE-502": "deserialization",
            "CWE-798": "hardcoded_secret", "CWE-259": "hardcoded_secret",
            "CWE-327": "crypto", "CWE-328": "crypto", "CWE-330": "crypto",
            "CWE-862": "access_control", "CWE-863": "access_control",
            "CWE-287": "auth", "CWE-306": "auth",
        }

        def _get_category_group(finding: dict) -> str:
            cwe = finding.get("cwe_id", "")
            if cwe in cwe_category_map:
                return cwe_category_map[cwe]
            # Fall back to rule_id or category field
            rule = finding.get("rule_id", "").lower()
            cat = finding.get("category", "").lower() if isinstance(finding.get("category"), str) else ""
            for keyword in ("injection", "xss", "traversal", "ssrf", "crypto", "auth", "secret"):
                if keyword in rule or keyword in cat:
                    return keyword
            return "other"

        deduped = []
        for cf in claude_findings:
            cf_file = cf.get("file_path", "")
            cf_line = cf.get("line_start", 0)
            cf_group = _get_category_group(cf)

            # Check if any existing finding overlaps
            is_duplicate = False
            for ef in existing_index.get(cf_file, []):
                ef_line_start = ef.get("line_start", 0)
                ef_line_end = ef.get("line_end", ef_line_start)
                ef_group = _get_category_group(ef)

                # Same file, within 5 lines, similar category
                line_close = (
                    abs(cf_line - ef_line_start) <= 5
                    or abs(cf_line - ef_line_end) <= 5
                )
                category_match = (cf_group == ef_group) or cf_group == "other" or ef_group == "other"

                if line_close and category_match:
                    is_duplicate = True
                    logger.debug(
                        "Dedup: Claude finding '%s' at %s:%d matches existing '%s' at line %d",
                        cf.get("title"), cf_file, cf_line,
                        ef.get("title"), ef_line_start,
                    )
                    break

            if not is_duplicate:
                deduped.append(cf)

        return deduped

    async def _analyze_batch_audit(
        self,
        file_batch: list[tuple[str, str]],
        batch_idx: int,
        total_batches: int,
    ) -> tuple[list[dict], str]:
        """Deep audit analysis for a batch of files.

        Returns (findings, audit_summary).
        """
        files_text = ""
        for rel_path, content in file_batch:
            files_text += f"\n--- File: {rel_path} ---\n{content}\n"

        preamble = self._build_cross_file_preamble()

        user_content = (
            f"Audit batch {batch_idx + 1}/{total_batches}. "
            f"Perform a deep security audit of these {len(file_batch)} files:\n"
        )
        if preamble:
            user_content += f"\n{preamble}\n"
        user_content += files_text

        try:
            response_text, cost = await self._call_claude(
                AUDIT_PROMPT,
                user_content,
                max_tokens=8192,
            )

            # Split response into findings JSON and audit summary
            audit_summary = ""
            json_part = response_text
            if "---AUDIT_SUMMARY---" in response_text:
                parts = response_text.split("---AUDIT_SUMMARY---", 1)
                json_part = parts[0]
                audit_summary = parts[1].strip()

            raw_findings = _parse_claude_json(json_part)
            findings = [
                _finding_to_sast_dict(f, "audit")
                for f in raw_findings
                if f.get("confidence", 0) >= 0.7
            ]

            logger.info(
                "Audit batch %d/%d: %d findings, cost $%.4f",
                batch_idx + 1, total_batches, len(findings), cost,
            )
            return findings, audit_summary

        except Exception as e:
            logger.error("Audit batch %d/%d failed: %s", batch_idx + 1, total_batches, e)
            return [], ""


# ── Main entry point ──────────────────────────────────────────────────

async def run_claude_review(
    source_path: str,
    mode: str,  # "scan", "pr", "audit"
    languages: list[str],
    api_key: str,
    model: str = "claude-sonnet-4-6-20250514",
    organization_id: str = "",
    diff_text: str = "",
    scan_config: dict | None = None,
    custom_instructions: str = "",
    existing_findings: list[dict] | None = None,
) -> dict:
    """Run Claude security review.

    Args:
        source_path: Path to source code directory (for scan/audit modes).
        mode: Review mode — "scan", "pr", or "audit".
        languages: Detected languages in the repository.
        api_key: Anthropic API key.
        model: Claude model to use.
        organization_id: Organization UUID string.
        diff_text: Unified diff text (required for PR mode).
        scan_config: Optional scan configuration overrides.
        custom_instructions: Org-specific instructions appended to prompts
            (e.g. "Pay special attention to our internal auth middleware"
            or "Ignore findings in the /vendor/ directory").
        existing_findings: Findings from other scanners (Semgrep, etc.) to
            deduplicate against. Claude findings that overlap with existing
            findings (same file, similar line, similar category) are removed.

    Returns:
        {
            "findings": [...],        # SastFinding-compatible dicts
            "cost_usd": float,
            "model_used": str,
            "files_reviewed": int,
            "audit_summary": str | None,  # only for audit mode
        }
    """
    if not api_key:
        logger.error("Claude review requires an API key")
        return {
            "findings": [],
            "cost_usd": 0.0,
            "model_used": model,
            "files_reviewed": 0,
            "audit_summary": None,
        }

    reviewer = ClaudeSecurityReviewer(
        api_key=api_key,
        model=model,
        organization_id=organization_id,
        custom_instructions=custom_instructions,
    )

    findings = []
    audit_summary = None
    files_reviewed = 0

    try:
        if mode == "scan":
            findings = await reviewer.review_codebase(
                source_path, languages, scan_config,
                existing_findings=existing_findings,
            )
            # Count unique files in findings
            files_reviewed = len({f["file_path"] for f in findings}) if findings else 0
            # If no findings, count files that were actually reviewed
            if not files_reviewed:
                from .code_extractor import list_scannable_files
                all_files = list_scannable_files(source_path)
                files_reviewed = min(len(all_files), MAX_FILES_SCAN)

        elif mode == "pr":
            if not diff_text:
                logger.warning("PR review mode requires diff_text")
                return {
                    "findings": [],
                    "cost_usd": 0.0,
                    "model_used": model,
                    "files_reviewed": 0,
                    "audit_summary": None,
                }
            findings = await reviewer.review_pr_diff(diff_text, "", scan_config)
            files_reviewed = len({f["file_path"] for f in findings})

        elif mode == "audit":
            findings, audit_summary = await reviewer.review_audit(
                source_path, languages, scan_config,
                existing_findings=existing_findings,
            )
            files_reviewed = len({f["file_path"] for f in findings}) if findings else 0
            if not files_reviewed:
                from .code_extractor import list_scannable_files
                all_files = list_scannable_files(source_path)
                files_reviewed = min(len(all_files), MAX_FILES_SCAN)

        else:
            logger.error("Unknown review mode: %s", mode)

    except Exception as e:
        logger.exception("Claude review failed (mode=%s): %s", mode, e)

    result = {
        "findings": findings,
        "cost_usd": round(reviewer.total_cost, 6),
        "model_used": model,
        "files_reviewed": files_reviewed,
        "audit_summary": audit_summary,
    }

    logger.info(
        "Claude review complete: mode=%s, findings=%d, cost=$%.4f, files=%d",
        mode, len(findings), reviewer.total_cost, files_reviewed,
    )

    return result
