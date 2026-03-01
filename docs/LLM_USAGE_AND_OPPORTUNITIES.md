# LLM Usage & Opportunities — AppSecD

**Last updated:** 2026-03-01

This document maps where LLMs are used in the application, and where they could add value with documented benefits.

---

## Current LLM Usage

### 1. Finding Suggestions (CWE, CVSS, Impact, Remediation)

**Location:**  

- Backend: `ai_assist_service.py` → `suggest_finding()`  
- API: `POST /ai-assist/suggest`  
- Frontend: Project page → "Suggest" button when creating/editing a finding

**Flow:**

1. User enters finding title/description (optionally from failed test).
2. Clicks "Suggest" → calls `/ai-assist/suggest` with title, description, severity.
3. If LLM configured: LLM returns CWE, CVSS, severity, impact, remediation (JSON).
4. Fallback: Rule-based matching on keywords (sqli, xss, idor, etc.).

**Providers:** OpenAI, Anthropic, Google (configurable in Admin Settings).

**Benefit:** Faster, more accurate classification and remediation guidance.

---

### 2. Auto-Suggest from Failed Test

**Location:**  

- Backend: `findings.py` → `POST /findings/auto-suggest`  
- Uses same `suggest_finding()` as above

**Flow:**

1. When a test case fails, API can suggest a finding with pre-filled data.
2. Combines test title, description, and tester notes.
3. LLM or rule-based suggestion populates CWE, CVSS, impact, remediation.

**Benefit:** Reduces manual data entry and speeds up finding creation.

---

### 3. Payload Crafting / Enhancement

**Location:**  

- Backend: `ai_assist.py` → `POST /ai-assist/craft-payload`  
- Frontend: Project page → "AI Enhance" button next to payload list per test case

**Flow:**

1. User clicks "AI Enhance" on a test case with payloads.
2. Sends test title, description, existing payloads, target URL, context (e.g. OWASP ID).
3. LLM generates 5 enhanced/obfuscated payloads with WAF bypass techniques, encodings, etc.
4. Fallback: Returns original payloads if no LLM configured.

**Benefit:** Context-aware payloads and WAF bypass variants without manual research.

---

### 4. Report Executive Summary

**Location:**  

- Backend: `reports.py` → `POST /projects/{id}/report/summarize`  
- Frontend: `summarizeReport()` in api.ts — **not currently used in the report UI**

**Flow:**

1. API takes project + findings.
2. If LLM configured: generates 3–4 sentence executive summary.
3. Fallback: Static template with counts.

**Benefit:** Professional, project-specific executive summaries for stakeholders.  
**Gap:** Endpoint exists but report page shows static summary; UI does not call `summarizeReport()`.

---

### 5. LLM Configuration & Test

**Location:**  

- Admin Settings → AI/LLM tab  
- API: `PUT /admin/settings/llm`, `POST /admin/settings/llm/test`

**Features:**

- Per-org provider/model selection (OpenAI, Anthropic, Google).
- Encrypted API keys in DB.
- Test connection to verify key and model.

---

## Summary: Where LLM Is Used Today


| Use Case               | Backend | Frontend | Fallback        |
| ---------------------- | ------- | -------- | --------------- |
| Finding suggestions    | ✅       | ✅        | Rule-based      |
| Auto-suggest from fail | ✅       | ✅        | Rule-based      |
| Payload crafting       | ✅       | ✅        | Original list   |
| Report summary         | ✅       | ❌        | Static template |


---

## Potential LLM Use Cases (With Benefits)

### High Impact, Medium Effort


| Opportunity                     | Description                                                          | Benefit                                                       |
| ------------------------------- | -------------------------------------------------------------------- | ------------------------------------------------------------- |
| Wire report summary to UI       | Add "Generate Summary" button and display LLM summary in report page | Makes existing backend feature usable; better exec summaries. |
| Natural language findings query | "Show me all SQLi findings" → LLM maps to filters                    | Power users can query without learning filters.               |
| Remediation text enrichment     | LLM augments rule-based remediation with app context                 | More actionable, context-specific guidance.                   |


### Medium Impact, Medium Effort


| Opportunity                        | Description                                                          | Benefit                                       |
| ---------------------------------- | -------------------------------------------------------------------- | --------------------------------------------- |
| AI result interpretation           | Parse tool output (nuclei, ZAP, etc.) → suggest pass/fail or finding | Automates triage of ambiguous scanner output. |
| Report summarization (full report) | LLM summary of full report, not just exec summary                    | One-paragraph summary for stakeholders.       |
| Chat-style security assistant      | "How do I test for IDOR?" → step-by-step guidance                    | Training and knowledge sharing.               |


### High Impact, Higher Effort


| Opportunity                    | Description                                        | Benefit                                         |
| ------------------------------ | -------------------------------------------------- | ----------------------------------------------- |
| Auto-findings from tool output | Parse nuclei/ZAP/Burp JSON → LLM suggests findings | Less manual import; smarter mapping.            |
| Vulnerability trend analysis   | LLM identifies patterns across projects            | Strategic insights (e.g. "XSS in 60% of apps"). |
| Finding deduplication          | LLM compares findings → suggest merge/similar      | Cleaner, less noisy findings.                   |


### Low Effort, Quick Wins


| Opportunity                         | Description                                                        | Benefit                         |
| ----------------------------------- | ------------------------------------------------------------------ | ------------------------------- |
| Wire summarizeReport to report page | Call `summarizeReport` and show result in exec summary section     | No new backend; better reports. |
| LLM for Burp import mapping         | When importing Burp XML, use LLM to improve severity/title mapping | Smarter imports.                |


---

## LLM Test Case Generation & Security Assistant (Proposed)

### Vision

User describes functionality (endpoint, request/response, framework, etc.) → LLM generates full test cases in the **same format** as our OWASP WSTG library. Saved in an **extra/custom field** (project-scoped or org library). LLM uses **public resources**, **internal data** (test cases, payloads), and **latest CVE** for frameworks to produce actionable test guidance.

---

### Data LLM Can Use

| Source | Description |
|--------|-------------|
| **Internal — OWASP WSTG (126 tests)** | Full structure: title, description, owasp_ref, cwe_id, phase, how_to_test, payloads, tool_commands, pass/fail indicators |
| **Internal — Payload library** | PAT, SecLists, FuzzDB, Nuclei, XSS, SQLi, NoSQL, Intruder, BLNS |
| **Internal — Project/org data** | stack_profile, existing findings, test results |
| **Public — CVE/NVD** | Latest CVEs for frameworks (Spring, Laravel, Django, React, etc.) |
| **Public — OWASP, PortSwigger, CWE** | Cheat sheets, academy, reference |

---

### 1. Generate Test Cases from User Description

**User provides:**
- Functionality description (e.g. "File upload that converts PDF to image")
- Request/response sample (headers, body, status) — optional
- Endpoint URL, method, parameters
- Framework/stack — optional (or from project)
- What to test hint (e.g. "focus on path traversal") — optional

**LLM outputs:** Full test case(s) in **identical format** to `TestCase` model.

**Save target:** Extra/custom test cases (project-scoped `project_custom_tests` or org library). Same schema → works with existing UI, results, reports.

**Benefit:** Describe any functionality → get test plan. No blank-slate planning.

---

### 2. "How to Test X?" Assistant

**User asks:** e.g. "How do I test for IDOR?", "What's the latest CVE for Spring Boot 3.2?", "Which endpoints are likely vulnerable to SQLi?"

**LLM receives:**
- Question
- **Injected context:** Relevant test cases from our library, payloads from PAT/SecLists, latest CVE for mentioned frameworks
- Project stack, target URL, auth type

**LLM returns:** Step-by-step guidance + optional generated test case(s) in our format.

**Benefit:** On-demand expertise using our data + public intel (including latest CVE).

---

### 3. Vulnerable Endpoint Analysis

**Input:** Endpoint, method, params, request/response sample, framework.

**Output:** Likely vuln types (SQLi, XSS, IDOR, etc.), priority, suggested tests, payloads to try.

**Benefit:** Quick triage; focus on highest-risk endpoints.

---

### 4. Similar / Extra Test Case Generation

**Input:** Existing test (or finding) + "Generate similar for [related functionality]".

**Output:** New test cases in same format, adapted for related context.

**Benefit:** Extend coverage without manual copy-paste.

---

### Extra Field & Save Format

- **Extra field:** Project-scoped custom tests (e.g. `project_custom_tests` or org-level extra library).
- **Same format:** `TestCase` schema (title, phase, payloads, tool_commands, pass/fail indicators, etc.) so it integrates with current flow.
- **Validation:** Parse LLM JSON, validate against schema, then save.

---

## All LLM Possibilities (What Is Possible)

### Test Case & Methodology

| Feature | Status | Description |
|---------|--------|-------------|
| Generate test cases from description | Proposed | User describes functionality + request/response → LLM outputs full test cases |
| Save in extra field, same format | Proposed | Project/org custom tests; identical schema to WSTG |
| "How to test X?" assistant | Proposed | Uses our payloads, WSTG, latest CVE |
| Latest CVE for framework | Proposed | When user asks → inject CVE context; generate test to verify |
| Vulnerable endpoint analysis | Proposed | Request/response → suggested tests and payloads |
| Similar test generation | Proposed | From existing test → variants for related functionality |
| Missing test suggestion | Proposed | Compare scope vs library → "Add tests for X" |
| Framework-specific expansion | Proposed | e.g. GraphQL → generate tests from public + our data |

### Findings & Remediation

| Feature | Status | Description |
|---------|--------|-------------|
| Finding suggestions | Done | CWE, CVSS, impact, remediation |
| Auto-suggest from failed test | Done | Pre-filled from test failure |
| Remediation enrichment | Proposed | App-specific remediation |
| Finding deduplication | Proposed | LLM suggests merge |
| Auto-findings from tool output | Proposed | Parse nuclei/ZAP/Burp → LLM suggests |

### Payloads & Tools

| Feature | Status | Description |
|---------|--------|-------------|
| Payload crafting | Done | WAF bypass, obfuscation |
| Payload from CVE | Proposed | CVE → PoC payloads |
| Tool command generation | Proposed | "Run SQLMap here" → full command with our paths |

### Reports & Queries

| Feature | Status | Description |
|---------|--------|-------------|
| Report summary | Backend done | Wire to UI |
| Natural language query | Proposed | "SQLi findings last 30 days" → filters |
| Vulnerability trends | Proposed | Patterns across projects |
| Chat-style assistant | Proposed | General security Q&A |

### Integrations

| Feature | Status | Description |
|---------|--------|-------------|
| Burp import + LLM mapping | Proposed | Improve severity/title on import |
| AI result interpretation | Proposed | Tool output → pass/fail or finding |

---

## Test Case Schema (LLM Output Format)

```json
{
  "title": "Test SQL Injection in Login",
  "description": "Verify parameterized queries.",
  "phase": "post_auth",
  "owasp_ref": "WSTG-INPV-05",
  "cwe_id": "CWE-89",
  "severity": "critical",
  "where_to_test": "Login form",
  "what_to_test": "SQLi via username",
  "how_to_test": "1. Enter payloads...",
  "payloads": ["admin'--", "' OR '1'='1"],
  "tool_commands": [{"tool": "sqlmap", "command": "...", "description": "..."}],
  "pass_indicators": "...",
  "fail_indicators": "...",
  "remediation": "...",
  "references": [{"url": "...", "title": "..."}],
  "tags": ["sqli", "auth"],
  "applicability_conditions": {}
}
```

---

## Architecture Notes

- **Config:** Per-org LLM config via `org_settings_service.get_llm_config(db, org_id)`.
- **Providers:** OpenAI, Anthropic, Google.
- **Fallback:** All features degrade when no API key (rule-based or static).
- **Pattern:** `get_llm_config` → `_call_*` with provider/model/key → parse JSON.
- **Context injection:** Pass top-K relevant test cases + payload samples + CVE for mentioned frameworks to stay within token limits.

