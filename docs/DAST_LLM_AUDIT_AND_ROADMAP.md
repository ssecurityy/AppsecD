# DAST & LLM Independent Audit — AppSecD Navigator

**Document Version:** 1.0  
**Date:** 2026-03-02  
**Purpose:** Independent review of all LLM usage, DAST functionality, gaps, and opportunities. Covers test phases, test cases, and recommended enhancements.

---

## Executive Summary

| Area | Current State | Opportunity |
|------|---------------|-------------|
| **LLM Usage** | 10 features across findings, payloads, reports, Security Intel, Burp import | **Zero LLM integration in DAST** — crawl, discovery, scan interpretation untouched |
| **DAST Checks** | 41 automated checks (headers, SSL, cookies, recon, injection, misc) | Extend with Nuclei, SQLMap, JS analysis, SCA; add LLM-driven interpretation |
| **Test Phases** | recon, pre_auth, auth, post_auth, business, api, client, transport, infra, tools | LLM can suggest phase-specific tests and prioritize by stack |
| **Test Cases** | ~180 (53 seed + 126 OWASP WSTG + LLM-generated) | LLM can generate DAST-focused tests from crawl output |

**Key Finding:** DAST and LLM are **completely decoupled**. The DAST module has no LLM calls; all LLM features live in ai_assist, Security Intel, reports, and findings. Significant value can be unlocked by integrating LLM into DAST workflows.

---

## Part 1 — Current LLM Usage (Full Audit)

### 1.1 Implemented LLM Features

| # | Feature | API / Location | DAST-Related? |
|---|---------|----------------|---------------|
| 1 | **Finding suggestions** (CWE, CVSS, impact, remediation) | `POST /ai-assist/suggest` | No — generic finding creation |
| 2 | **Auto-suggest from failed test** | `POST /findings/auto-suggest` | Partial — used when DAST fails a check and creates finding |
| 3 | **Payload crafting / AI Enhance** | `POST /ai-assist/craft-payload` | Yes — can enhance payloads for injection tests, but not wired into DAST UI |
| 4 | **Report executive summary** | `POST /projects/{id}/report/summarize` | Partial — reports include DAST findings |
| 5 | **LLM config & test** | `PUT /admin/settings/llm`, `POST /admin/settings/llm/test` | — |
| 6 | **Test case generation** (app_type, tech_stack) | `POST /security-intel/generate-test-cases` | Yes — can generate DAST-relevant tests, not in DAST flow |
| 7 | **Security assistant** (chat) | `POST /security-intel/assistant` | Yes — "How do I test X?" with CVE context |
| 8 | **Add suggested tests from assistant** | `POST /security-intel/assistant/add-test-cases` | Yes — test cases for DAST phases |
| 9 | **Burp import LLM enhancement** | `POST /findings/import/burp` (optional) | Yes — improves Burp findings; Burp is DAST-related |
| 10 | **Vulnerable endpoint analysis** | `POST /ai-assist/analyze-endpoint` (llm_enhanced_service) | **Yes** — ideal for DAST crawl output; not exposed in DAST UI |

### 1.2 LLM-Enhanced Service Endpoints (Backend Ready, Not Always in UI)

| Endpoint / Function | Purpose | DAST Relevance |
|---------------------|---------|----------------|
| `analyze_endpoint` | Endpoint + req/res → vuln types, payloads, tests | **High** — feed crawl API endpoints |
| `generate_similar_tests` | From existing test → similar for new context | **High** — adapt tests for discovered endpoints |
| `suggest_missing_tests` | Compare scope vs library → missing coverage | **High** — DAST coverage gaps |
| `generate_framework_tests` | Stack-specific tests (React, Django, etc.) | **High** — project stack_profile |
| `enrich_remediation` | Better remediation text | Medium |
| `deduplicate_findings` | Merge similar findings | Medium |
| `query_findings_nl` | Natural language findings query | Low |
| `analyze_vulnerability_trends` | Patterns across projects | Low |
| `generate_cve_payloads` | CVE → PoC payloads | **High** — nuclei/CVE-style tests |
| `generate_tool_commands` | Test → ready-to-run CLI commands | **High** — DAST tool orchestration |
| `interpret_tool_results` | Tool output → pass/fail + finding | **Critical** — DAST result interpretation |
| `summarize_full_report` | Full report narrative | Medium |
| `enhance_burp_findings` | Burp import → better mapping | **High** |

### 1.3 Where LLM Is NOT Used (Gap)

| Component | Current Behavior | LLM Opportunity |
|-----------|------------------|-----------------|
| **DAST API** | No LLM calls | Interpret scan results, suggest findings, prioritize checks |
| **Crawler output** | Raw URLs, params, forms, API endpoints | LLM analyzes each endpoint → suggested tests, payloads |
| **ffuf / dir discovery** | Raw paths | LLM categorizes (admin, backup, api, sensitive) |
| **Nuclei output** | Parse JSON only | LLM summarizes, deduplicates, maps to findings |
| **XSS/SQLi checks** | Rule-based only | LLM crafts context-aware payloads from form/param names |
| **Scan result presentation** | Raw pass/fail | LLM generates human-readable summary per check |
| **Check selection** | User picks all or subset | LLM suggests checks based on stack_profile, discovered tech |

---

## Part 2 — Current DAST Functionality

### 2.1 DAST Architecture

```
Frontend (dast/page.tsx)
    │
    ├─ Run scan (selected checks)
    ├─ Run crawl (Katana + Arjun + optional Playwright)
    ├─ ffuf directory discovery
    ├─ Recursive dir scan
    └─ View results, crawl output, directory tree
           │
           ▼
Backend (dast.py)
    ├─ POST /dast/scan
    ├─ POST /dast/crawl
    ├─ POST /dast/ffuf, /dast/ffuf-exhaustive
    ├─ POST /dast/recursive-dir-scan
    ├─ GET /dast/project/{id}/latest, /history
    └─ Background: run_dast_scan → runner → checks/*
```

### 2.2 DAST Checks (41 Modules)

| Category | Checks | Check IDs (examples) |
|----------|--------|----------------------|
| **Headers** | 12 | security_headers, cache_control, sri, version_headers, coop_coep, xss_protection_header, csp_reporting, expect_ct, permissions_policy, content_type_sniffing, clickjacking, corp, clear_site_data |
| **SSL/TLS** | 4 | ssl_tls, http_redirect_https, hsts_preload, hsts_subdomains |
| **Cookies** | 2 | cookie_security, cookie_prefix |
| **Recon** | 8 | info_disclosure, tech_fingerprint, sitemap_xml, robots_txt, directory_listing, backup_files, api_docs_exposure, security_txt, dotenv_git |
| **Injection** | 6 | cors, open_redirect, host_header_injection, crlf_injection, xss_basic, sqli_error |
| **HTTP** | 4 | http_methods, rate_limiting, sensitive_data, form_autocomplete, debug_response |
| **Misc** | 15+ | weak_referrer, cache_age, upgrade_insecure, redirect_chain, timing_allow_origin, alt_svc, content_disposition, pragma_no_cache, server_timing, via_header, x_forwarded_disclosure, allow_dangerous, trace_xst, padding_oracle |

### 2.3 DAST Services

| Service | Purpose | Tools Used |
|---------|---------|------------|
| **crawler.py** | Katana crawl + Arjun param discovery + optional Playwright | katana, arjun, playwright |
| **discovery.py** | ffuf directory discovery | ffuf |
| **playwright_crawler.py** | JS-rendered page crawling | Playwright |
| **runner.py** | Orchestrates checks, progress | — |
| **checks/** | Individual check implementations | curl, nuclei (some), subprocess |
| **js_analysis.py** | JS file analysis | — |
| **sca.py** | Software composition analysis | — |
| **secrets.py** | Secret detection | — |

### 2.4 Test Phases (Mapping)

| Phase | Description | DAST Checks Mapped |
|-------|-------------|--------------------|
| **recon** | Reconnaissance | robots_txt, sitemap, dir listing, tech_fingerprint, security_txt, backup, dotenv_git, version_headers, debug, via, xff |
| **pre_auth** | Pre-authentication | security_headers, cors, open_redirect, host_header, crlf, http_methods, rate_limiting, form_autocomplete, cache, coop, referrer, clickjacking, trace, etc. |
| **auth** | Authentication | cookie_security, rate_limiting |
| **post_auth** | Post-authentication | xss_basic, sqli_error, sensitive_data |
| **api** | API testing | cors, sqli, api_docs |
| **client** | Client-side | sri, xss_protection, csp, clickjacking, pii |
| **transport** | Transport security | ssl_tls, http_redirect_https, hsts |
| **infra** | Infrastructure | Various header/info checks |
| **tools** | Tool-specific | — |

---

## Part 3 — LLM Opportunities in DAST (Prioritized)

### 3.1 Critical (High Impact, Clear Path)

| Opportunity | Description | Implementation |
|-------------|-------------|----------------|
| **1. Crawl Output → Endpoint Analysis** | After crawl, send each API endpoint/form to `analyze_endpoint`. Show "Suggested tests" and "Likely vulns" per endpoint. | New API `POST /dast/analyze-crawl`; frontend tab "AI Analysis" in Crawl section |
| **2. DAST Result Interpretation** | When a check fails, call `interpret_tool_results` with raw output. LLM suggests pass/fail + finding details. | Integrate into `_run_scan_background` after each failed check |
| **3. AI Payload Enhancement in DAST** | For XSS/SQLi checks, call `craft-payload` with discovered param names and form context. Use LLM payloads in injection tests. | Wire `POST /ai-assist/craft-payload` into DAST injection checks; add "AI Enhance" in DAST UI for selected params |
| **4. Check Selection Assistant** | User provides stack (e.g. React + Django API). LLM suggests which DAST checks to run first. | New API `POST /dast/suggest-checks`; "AI Suggest" button next to check selector |
| **5. DAST Finding → Auto-Suggest** | When DAST creates a finding (failed check), call `suggest_finding` to enrich CWE, CVSS, remediation. | Already partially done via auto-suggest from failed test; ensure DAST flow triggers it |

### 3.2 High (Strong Value)

| Opportunity | Description | Implementation |
|-------------|-------------|----------------|
| **6. Scan Summary** | After scan completes, LLM generates 2–3 sentence summary: "Found X failures (Y critical). Key issues: ..." | New API `POST /dast/summarize-scan`; show in DAST results header |
| **7. Discovered Paths Categorization** | ffuf/recursive dir output → LLM categorizes paths (admin, backup, api, config, sensitive). | New API `POST /dast/categorize-paths`; show in Directory tree |
| **8. Nuclei Integration + LLM** | When Nuclei (or similar) runs, parse JSON → LLM summarizes findings, maps to our findings, suggests remediation. | Integrate nuclei runner; pipe output to `interpret_tool_results` |
| **9. Tool Command Generation** | For each DAST check, "Generate commands" → LLM produces ready-to-run curl/ffuf/sqlmap commands for manual verification. | Use `generate_tool_commands`; "Copy as curl" / "Run manually" in DAST UI |
| **10. Missing Test Suggestion** | Compare crawl output (endpoints, params) vs existing test cases → "You haven't tested X, Y, Z." | Use `suggest_missing_tests`; new tab "Coverage Gaps" |

### 3.3 Medium (Nice to Have)

| Opportunity | Description |
|-------------|-------------|
| **11. Framework-Specific Tests** | Project stack_profile (React, Spring, etc.) → LLM generates additional DAST checks. |
| **12. Similar Test Generation** | From a DAST check result → "Generate similar tests for this endpoint." |
| **13. Natural Language Query** | "Show me all XSS-related DAST failures" → LLM maps to filters. |
| **14. Crawl Diff Analysis** | Compare two crawls (e.g. before/after deploy) → LLM summarizes new/removed endpoints. |

---

## Part 4 — Test Cases & Coverage

### 4.1 Current Test Case Sources

| Source | Count | Format | DAST Automation |
|--------|-------|--------|-----------------|
| seed_db.py | ~53 | tool_commands, pass/fail indicators | Mapped to DAST checks |
| OWASP WSTG import | ~126 | Parsed markdown | Partially mapped |
| LLM-generated (Security Intel) | Variable | Same TestCase schema | Not yet in DAST |
| DAST checks | 41 | Hardcoded in checks/* | Fully automated |

### 4.2 DAST Check → TestCase Mapping

The DAST API maps each check to a `module_id` (e.g. WSTG-CONF-07) for syncing to `ProjectTestResult`. See `DAST_CHECK_TO_MODULE` in `dast.py` — covers 61 mappings.

### 4.3 Additional Test Cases to Implement (DAST Automation Matrix)

| Phase | Test Case | Tool | Confidence | Status |
|-------|-----------|------|------------|--------|
| **Recon** | Nuclei CVE scanning | nuclei | 90% | Nuclei used in some checks; expand |
| **Recon** | RetireJS / vulnerable JS libs | retire | 90% | js_analysis.py exists; integrate |
| **Recon** | Subdomain enumeration | subfinder/amass | 85% | Not implemented |
| **Pre-Auth** | Username enumeration | ffuf | 85% | Not implemented |
| **Pre-Auth** | Brute force / lockout | hydra/ffuf | 90% | Not implemented |
| **Auth** | Session fixation | curl | 85% | Not implemented |
| **Auth** | JWT attacks | jwt_tool | 92% | Not implemented |
| **Auth** | MFA bypass | Manual/Burp | 85% | Manual only |
| **Post-Auth** | IDOR | ffuf + auth | 88% | Not implemented |
| **Post-Auth** | SQLi (deep) | sqlmap | 92% | sqli_error exists; expand with sqlmap |
| **Post-Auth** | XSS (reflected/stored) | dalfox/xsstrike | 88% | xss_basic exists; expand |
| **Post-Auth** | SSRF | curl | 90% | Not implemented |
| **Post-Auth** | SSTI | tplmap | 90% | Not implemented |
| **Post-Auth** | LFI/Path traversal | ffuf/curl | 92% | Not implemented |
| **Post-Auth** | Command injection | commix | 90% | Not implemented |
| **Post-Auth** | XXE | curl + payload | 90% | Not implemented |
| **API** | GraphQL introspection | graphql-cop | 85% | Not implemented |
| **API** | Parameter mining | arjun | 90% | Arjun in crawler; use for tests |
| **Client** | CSP bypass | Manual | 70% | csp_reporting exists |
| **Transport** | TLS cipher enumeration | testssl.sh | 95% | ssl_tls exists; testssl optional |
| **Infra** | SCA (deps) | pip-audit, retire | 90% | sca.py exists; integrate |

### 4.4 Suggested New DAST Checks (Rule-Based + LLM Assist)

| Check ID | Name | Description | LLM Use |
|----------|------|-------------|---------|
| DAST-NUCL-01 | Nuclei CVE Scan | Run nuclei with CVE templates | Interpret results |
| DAST-SQLM-01 | SQLMap Deep Scan | sqlmap on discovered params | Interpret output |
| DAST-XSS-02 | XSS Full Scan | dalfox on discovered inputs | Craft payloads |
| DAST-JWT-01 | JWT Security | jwt_tool on Authorization tokens | — |
| DAST-IDOR-01 | IDOR Basic | Enumerate IDs with auth | — |
| DAST-SSRF-01 | SSRF Probe | Internal URL in params | Craft payloads |
| DAST-SCA-01 | SCA Scan | pip-audit, retire on assets | Summarize findings |
| DAST-SECR-01 | Secrets Scan | TruffleHog / custom on JS/source | — |

---

## Part 5 — Test Phases Deep Dive

### 5.1 Phase Coverage Summary

| Phase | Automated Now | Can Automate | LLM Can Help |
|-------|---------------|--------------|--------------|
| **recon** | 8 checks | +Nuclei, RetireJS, subdomain | Categorize, prioritize |
| **pre_auth** | 15+ checks | +Username enum, brute | Suggest checks by stack |
| **auth** | 2 checks | +Session fix, JWT, MFA | — |
| **post_auth** | 3 checks | +IDOR, SQLi deep, XSS, SSRF, SSTI, LFI, RCE, XXE | Payload crafting, interpretation |
| **api** | Partial | +GraphQL, param mining | Endpoint analysis |
| **client** | 5 checks | +CSP bypass | — |
| **transport** | 4 checks | +testssl deep | — |
| **infra** | 6 checks | +SCA | Summarize |
| **business** | 0 | Workflow, payment — mostly manual | Suggest test scenarios |
| **tools** | 0 | — | — |

### 5.2 Phase-Specific Test Case Ideas (LLM-Generated)

LLM can generate project-specific test cases when given:

- **recon:** Discovered tech stack, headers, JS files
- **pre_auth:** Login form structure, CAPTCHA presence
- **auth:** Auth type (JWT, session, OAuth)
- **post_auth:** Discovered API endpoints, parameter names
- **api:** OpenAPI/Swagger if found
- **client:** CSP, SRI, X-Frame-Options from headers

Example prompt: *"Project uses React SPA + Django REST. Crawl found /api/users, /api/orders/{id}. Generate 5 high-priority DAST test cases."*

---

## Part 6 — Implementation Roadmap

### Phase 1 — Quick Wins (1–2 weeks)

1. **Wire `analyze_endpoint` to crawl output** — New tab "AI Analysis" in Crawl section; call for each API endpoint.
2. **Add "AI Suggest Checks"** — Button that calls `suggest_missing_tests` + stack → suggests which checks to run.
3. **DAST result → Auto-suggest finding** — Ensure DAST-created findings trigger `suggest_finding` for enrichment.

### Phase 2 — Core Integration (2–4 weeks)

4. **`interpret_tool_results` for failed checks** — After each failed DAST check, optionally call LLM to refine finding.
5. **AI payload enhancement in DAST** — For XSS/SQLi, add "AI Enhance" next to param list; use craft-payload.
6. **Scan summary** — After scan, call LLM to generate 2–3 sentence summary.

### Phase 3 — Advanced (4–6 weeks)

7. **Discovered paths categorization** — LLM categorizes ffuf/recursive output.
8. **Nuclei runner + LLM interpretation** — Integrate nuclei; parse JSON; LLM summarizes.
9. **Tool command generation** — "Generate curl/ffuf commands" per check.
10. **Coverage gaps** — Compare crawl vs tests; suggest missing tests.

### Phase 4 — New Checks & Tools (6–8 weeks)

11. **SQLMap integration** — For discovered params, run sqlmap; interpret with LLM.
12. **dalfox / XSS scanner** — For discovered inputs.
13. **JWT check** — jwt_tool when Authorization header found.
14. **SCA integration** — pip-audit, retire; LLM summarize.
15. **IDOR/SSRF probes** — Basic automation with auth.

---

## Part 7 — Additional Test Cases (Comprehensive List)

### 7.1 OWASP Top 10 (2021) Coverage

| A0X | Category | DAST Check(s) | Gaps |
|-----|----------|---------------|------|
| A01 | Broken Access Control | rate_limiting, (IDOR not auto) | IDOR, BOLA |
| A02 | Cryptographic Failures | ssl_tls, cookie_security | Weak ciphers |
| A03 | Injection | sqli_error, xss_basic, crlf | SQLMap, XXE, LDAP, NoSQL |
| A04 | Insecure Design | — | Business logic (manual) |
| A05 | Security Misconfiguration | headers, directory_listing, debug | — |
| A06 | Vulnerable Components | — | SCA, RetireJS |
| A07 | Auth Failures | cookie, rate_limit | Session fix, JWT |
| A08 | Software/Data Integrity | sri | — |
| A09 | Logging Failures | — | Manual |
| A10 | SSRF | — | SSRF probe |

### 7.2 CWE Coverage (Examples)

| CWE | Name | DAST Check |
|-----|------|------------|
| CWE-79 | XSS | xss_basic |
| CWE-89 | SQLi | sqli_error |
| CWE-78 | OS Command Injection | — |
| CWE-918 | SSRF | — |
| CWE-22 | Path Traversal | — |
| CWE-352 | CSRF | — |
| CWE-287 | Improper Auth | cookie, rate |
| CWE-863 | Incorrect Authorization | — |
| CWE-200 | Info Disclosure | info_disclosure, sensitive_data |
| CWE-327 | Weak Crypto | ssl_tls |

### 7.3 API-Specific Test Cases

| Test | Description | Status |
|------|-------------|--------|
| BOLA/IDOR | Change resource ID with same token | Not implemented |
| Mass assignment | Add `isAdmin` in request body | Not implemented |
| Rate limiting | Excessive requests | rate_limiting exists |
| GraphQL introspection | Expose schema | Not implemented |
| API versioning | Old versions exposed | Not implemented |
| Pagination | Large offset/limit | Not implemented |
| OpenAPI exposure | /swagger, /openapi.json | api_docs_exposure |

### 7.4 Client-Side Test Cases

| Test | Description | Status |
|------|-------------|--------|
| Clickjacking | X-Frame-Options | clickjacking |
| CSP | Content-Security-Policy | csp_reporting |
| SRI | Subresource Integrity | sri |
| Autocomplete | Sensitive fields | form_autocomplete |
| PII in DOM | Sensitive data in response | sensitive_data |
| XSS in stored | Stored XSS | xss_basic (basic) |

---

## Part 8 — Summary & Recommendations

### 8.1 Audit Summary

- **LLM:** 10 features live; 13 more in `llm_enhanced_service` (partially wired). **None** are used inside DAST flows.
- **DAST:** 41 checks, crawl (Katana + Arjun + Playwright), ffuf, recursive dir. Solid foundation.
- **Gap:** No LLM in DAST. Crawl output, scan results, and path discovery are not analyzed by LLM.

### 8.2 Top 5 Recommendations

1. **Integrate `analyze_endpoint` into Crawl UI** — Immediate value; backend exists.
2. **Use `interpret_tool_results` for failed DAST checks** — Better findings, less manual work.
3. **Wire payload crafting into DAST** — AI Enhance for XSS/SQLi params.
4. **Add check suggestion** — LLM suggests which checks to run based on stack + crawl.
5. **Add scan summary** — LLM generates human-readable scan summary.

### 8.3 Test Case Expansion

- **Short term:** Map more DAST checks to test cases; ensure all 41 sync to ProjectTestResult.
- **Medium term:** Add Nuclei, SQLMap, dalfox runners; interpret with LLM.
- **Long term:** IDOR, SSRF, JWT, SCA, GraphQL checks.

---

## Appendix A — File Reference

| File | Purpose |
|------|---------|
| `backend/app/api/dast.py` | DAST API; no LLM |
| `backend/app/api/ai_assist.py` | Payload crafting, suggest; LLM |
| `backend/app/api/security_intel.py` | Test gen, assistant; LLM |
| `backend/app/api/findings.py` | Burp import, auto-suggest; LLM |
| `backend/app/api/reports.py` | Report summarize; LLM |
| `backend/app/services/llm_enhanced_service.py` | 13 LLM functions |
| `backend/app/services/dast/crawler.py` | Katana, Arjun, Playwright |
| `backend/app/services/dast/checks/*` | 41 check implementations |
| `frontend/src/app/projects/[id]/dast/page.tsx` | DAST UI; no LLM calls |

---

## Appendix B — API Quick Reference

### Existing LLM APIs Usable by DAST

| API | Method | Use in DAST |
|-----|--------|-------------|
| `/ai-assist/suggest` | POST | Enrich DAST findings |
| `/ai-assist/craft-payload` | POST | XSS/SQLi payloads for discovered params |
| `/ai-assist/analyze-endpoint` | POST | Per-crawl endpoint analysis |
| `/ai-assist/suggest-missing-tests` | POST | Coverage gaps |
| `/ai-assist/interpret-tool-results` | POST | Failed check interpretation |
| `/security-intel/generate-test-cases` | POST | DAST-focused test cases |
| `/security-intel/assistant` | POST | "How to test X?" in DAST context |

### New APIs to Add

| API | Purpose |
|-----|---------|
| `POST /dast/analyze-crawl` | Analyze crawl output with LLM |
| `POST /dast/suggest-checks` | Suggest checks by stack + crawl |
| `POST /dast/summarize-scan` | Generate scan summary |
| `POST /dast/categorize-paths` | Categorize discovered paths |
| `POST /dast/coverage-gaps` | Compare crawl vs test coverage |

---

*End of document.*
