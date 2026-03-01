# LLM Usage & Opportunities — AppSecD

**Last updated:** 2026-03-01

This document maps where LLMs are used, with verified implementation status.

**Status legend:** **Done** = Implemented (backend + frontend); **Pending** = Partially implemented; **Not implemented** = Not built.

| Done | Pending | Not implemented |
|------|---------|-----------------|
| 10   | 2       | 18              |

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
- Frontend: Report page → "AI Summary" button, `handleSummarize()` → `summarizeReport()`

**Flow:**

1. User clicks "AI Summary" on report page.
2. API takes project + findings, LLM generates 3–4 sentence executive summary.
3. Fallback: Static template with counts when no LLM configured.
4. Summary displayed in report UI.

**Benefit:** Professional, project-specific executive summaries for stakeholders.

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

| Use Case               | Status  | Backend | Frontend | Fallback        |
| ---------------------- | ------- | ------- | -------- | --------------- |
| Finding suggestions    | Done    | ✅      | ✅       | Rule-based      |
| Auto-suggest from fail | Done    | ✅      | ✅       | Rule-based      |
| Payload crafting       | Done    | ✅      | ✅       | Original list   |
| Report summary         | Done    | ✅      | ✅       | Static template |
| LLM config & test      | Done    | ✅      | ✅       | —               |


---

## Potential LLM Use Cases (With Benefits)

### High Impact, Medium Effort


| Opportunity                     | Status | Description                                                          |
| ------------------------------- | ------ | -------------------------------------------------------------------- |
| Wire report summary to UI       | Done   | "AI Summary" button on report page; calls summarizeReport            |
| Natural language findings query | Not implemented | "Show me all SQLi findings" → LLM maps to filters            |
| Remediation text enrichment     | Not implemented | LLM augments rule-based remediation with app context         |


### Medium Impact, Medium Effort


| Opportunity                        | Status | Description                                                          |
| ---------------------------------- | ------ | -------------------------------------------------------------------- |
| AI result interpretation           | Not implemented | Parse tool output (nuclei, ZAP, etc.) → suggest pass/fail or finding |
| Report summarization (full report) | Not implemented | LLM summary of full report, not just exec summary                    |
| Chat-style security assistant      | Done   | Security Intel assistant — "How do I test for X?" with context        |


### High Impact, Higher Effort


| Opportunity                    | Status | Description                                        |
| ------------------------------ | ------ | -------------------------------------------------- |
| Auto-findings from tool output | Not implemented | Parse nuclei/ZAP/Burp JSON → LLM suggests findings |
| Vulnerability trend analysis   | Not implemented | LLM identifies patterns across projects            |
| Finding deduplication          | Not implemented | LLM compares findings → suggest merge/similar      |


### Low Effort, Quick Wins


| Opportunity                         | Status | Description                                                        |
| ----------------------------------- | ------ | ------------------------------------------------------------------ |
| Wire summarizeReport to report page | Done   | Report page has "AI Summary" button; calls summarizeReport          |
| LLM for Burp import mapping         | Not implemented | When importing Burp XML, use LLM to improve severity/title mapping |


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

## All LLM Possibilities — Status (Done | Pending | Not implemented)

### Test Case & Methodology

| Feature | Status | Description |
|---------|--------|-------------|
| Generate test cases (app_type, tech_stack, focus_areas) | Done | `POST /security-intel/generate-test-cases` — LLM generates test cases; Security Intel UI |
| Save test cases to project | Done | `POST /security-intel/save-test-cases` — saves to project, ai-generated category |
| "How to test X?" chat assistant | Done | `POST /security-intel/assistant` — chat with test cases, CVEs, project context; can suggest test cases |
| Add suggested test cases from assistant | Done | `POST /security-intel/assistant/add-test-cases` — add assistant-suggested tests to project |
| CVE context in assistant | Done | Injects relevant CVEs from StoredCVE into assistant context |
| Generate from endpoint + request/response | Pending | Current flow uses app_type/focus_areas; not full "describe endpoint + req/res" |
| Latest CVE for framework (live NVD) | Pending | Uses stored CVEs; not real-time CVE lookup per question |
| Vulnerable endpoint analysis | Not implemented | Request/response → suggested tests and payloads |
| Similar test generation | Not implemented | From existing test → variants for related functionality |
| Missing test suggestion | Not implemented | Compare scope vs library → "Add tests for X" |
| Framework-specific expansion | Not implemented | e.g. GraphQL → generate tests from public + our data |

### Findings & Remediation

| Feature | Status | Description |
|---------|--------|-------------|
| Finding suggestions | Done | CWE, CVSS, impact, remediation — `/ai-assist/suggest` |
| Auto-suggest from failed test | Done | `/findings/auto-suggest` — pre-filled from test failure |
| Remediation enrichment | Not implemented | App-specific remediation |
| Finding deduplication | Not implemented | LLM suggests merge |
| Auto-findings from tool output | Not implemented | Parse nuclei/ZAP/Burp → LLM suggests |

### Payloads & Tools

| Feature | Status | Description |
|---------|--------|-------------|
| Payload crafting | Done | WAF bypass, obfuscation — `/ai-assist/craft-payload` |
| Payload from CVE | Not implemented | CVE → PoC payloads |
| Tool command generation | Not implemented | "Run SQLMap here" → full command with our paths |

### Reports & Queries

| Feature | Status | Description |
|---------|--------|-------------|
| Report summary | Done | Backend + frontend; "AI Summary" button on report page |
| Natural language query | Not implemented | "SQLi findings last 30 days" → filters |
| Vulnerability trends | Not implemented | Patterns across projects |
| Chat-style assistant | Done | Security Intel assistant — `/security-intel/assistant` |

### Integrations

| Feature | Status | Description |
|---------|--------|-------------|
| Burp import + LLM mapping | Not implemented | Improve severity/title on import |
| AI result interpretation | Not implemented | Tool output → pass/fail or finding |

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

