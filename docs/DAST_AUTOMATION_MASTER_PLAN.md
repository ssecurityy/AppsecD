# DAST Automation Master Plan — AppSecD/Navigator

**Document Version:** 1.0  
**Date:** 2026-03-01  
**Author:** Expert Analysis (Architecture, Security, DevOps, DAST)  
**Purpose:** Comprehensive plan for automating test cases with high true-positive rate, proper request/response capture, spider/endpoint discovery, and production-ready integration. Considers Accunetix, Burp Suite, industry DAST, and internal application scenarios.

---

## Executive Summary

Navigator is a **guided manual VAPT platform** with gamification. It currently has **no crawler/spider** and **no automated scan execution**. All test case results are manual. This plan outlines how to evolve Navigator into a **hybrid platform** that supports both manual testing (current) and automated DAST runs—with proper pass/fail determination, request/response storage, and "Automate" buttons per test case.

**Key Deliverables:**
- Test case automation matrix with confidence levels (100% true positive vs. possible false positives)
- Tools/CLI installation requirements per test type
- Spider/endpoint discovery architecture (including **Burp Suite crawler & API**)
- **Burp Suite integration** — crawler, scan API, test case mapping (~15–20 tests)
- Internal application support (VPN, proxy, agent-based)
- Dedicated scanner server option (reduce load on main app)
- Full request/response capture on pass and fail

---

## 1. Application Understanding

### 1.1 Current Architecture

| Component | Technology | Purpose |
|-----------|------------|---------|
| Frontend | Next.js 14, Tailwind | Project/test UI, findings, reports |
| Backend | FastAPI (Python) | REST API, auth, test cases, findings |
| Database | PostgreSQL 16 | Projects, test cases, results, findings |
| Cache | Redis | Session, Celery broker, project list cache |
| Async | Celery + Redis | Report generation (DOCX/PDF) only |

### 1.2 Test Case Model (TestCase)

| Field | Purpose |
|-------|---------|
| `tool_commands` | JSONB array of `{tool, command, description}` — CLI commands to run |
| `pass_indicators` | Text — what indicates secure (e.g., "No sensitive version disclosed") |
| `fail_indicators` | Text — what indicates vulnerability (e.g., "Exact framework version exposed") |
| `payloads` | JSONB — payloads for injection tests |
| `phase` | recon, pre_auth, auth, post_auth, business, api, client, transport, infra, tools |

**Variable substitution:** Commands use literal `TARGET` (e.g., `https://TARGET/robots.txt`). Navigator has `Project.application_url` but **no variable substitution** yet.

### 1.3 Project Test Result (ProjectTestResult)

| Field | Purpose |
|-------|---------|
| `status` | not_started, in_progress, passed, failed, na, blocked |
| `request_captured` | Text — raw HTTP request (for evidence) |
| `response_captured` | Text — raw HTTP response |
| `evidence` | JSONB — [{filename, url, description}] |
| `tool_used`, `payload_used` | For audit trail |

**Finding model** has `request`, `response` — same purpose for findings.

### 1.4 Test Case Sources

| Source | Count | Format |
|--------|-------|--------|
| seed_db.py | ~53 curated | Python dict with tool_commands, pass/fail indicators |
| OWASP WSTG import | ~126 | Parsed from markdown; may lack tool_commands |
| LLM-generated | Variable | Security Intel API → project-scoped custom tests |

### 1.5 Existing Tool Integration

| Tool | Status | Notes |
|------|--------|-------|
| Burp Suite | ✅ Import only | POST /findings/import/burp — XML upload → findings with request/response. **Plan:** Burp crawler + REST API for automated crawl/scan (Section 6). |
| Nuclei | ❌ None | CLI mentioned in tool_commands; no runner |
| ZAP, ffuf, SQLMap, etc. | ❌ None | CLI commands documented only |

---

## 2. Test Case Automation Matrix

For each test type we assess: **Automation Confidence**, **True Positive Rate**, **Tools Required**, **Request/Response Capture**.

### 2.1 Confidence Levels

| Level | Meaning | Use Case |
|-------|---------|----------|
| **95–100%** | Deterministic; tool output clearly indicates pass/fail. No manual verification needed. | Auto-pass/fail, auto-create finding on fail |
| **80–94%** | High confidence; rare edge cases may cause FP. | Auto-suggest pass/fail; human review recommended |
| **60–79%** | Moderate; context-dependent. | Automation aids; human must confirm |
| **&lt;60%** | Low; subjective or requires manual interpretation. | Manual only; automation provides hints only |

### 2.2 Full Automation Matrix (Seed + WSTG Test Cases)

#### 2.2.1 Recon Phase

| Test Case | Automation Confidence | True Positive | Tools (CLI) | Request/Response Save | Notes |
|-----------|----------------------|---------------|-------------|------------------------|------|
| Technology Fingerprinting (WhatWeb/curl) | **95%** | High | whatweb, curl | Yes (stdout = evidence) | Parse headers; regex match version disclosure |
| robots.txt & sitemap.xml | **98%** | High | curl | Yes | 200 + content = pass/fail by regex on sensitive paths |
| Directory & File Discovery (ffuf/gobuster) | **95%** | High | ffuf, gobuster | Yes (JSON output) | Parse discovered paths; 200/301/302/403 counts |
| .git Exposure | **98%** | High | curl | Yes | 200 on /.git/HEAD = fail |
| Nuclei Automated Scanning | **90%** | High (Nuclei JSON) | nuclei | Yes (JSON + req/resp in template) | Nuclei JSON has request/response; parse findings |
| RetireJS / JS Vuln Scan | **90%** | High | retire (npm) | Yes (JSON) | Parse JSON for vulnerable libs |
| SSL/TLS Configuration | **95%** | High | testssl.sh | Yes | Parse TLS versions, ciphers; deterministic |

#### 2.2.2 Pre-Auth Phase

| Test Case | Automation Confidence | True Positive | Tools (CLI) | Request/Response Save | Notes |
|-----------|----------------------|---------------|-------------|------------------------|------|
| Login Page Source Inspection | **70%** | Moderate | curl + grep | Yes | Hardcoded secrets detection; grep for keywords |
| Username Enumeration | **85%** | High | ffuf, Burp (manual) | Yes | Different response length/code = fail; ffuf -fr filter |
| Brute Force / Lockout | **90%** | High | hydra, ffuf | Yes | No lockout = many 200; parse rate/response |
| SQL Injection on Login | **92%** | High | sqlmap | Yes (SQLMap output) | SQLMap confirms vuln; parse for "injectable" |
| Forgot Password Security | **60%** | Moderate | curl, Burp | Partial | Token replay, expiry — mostly manual |
| Autocomplete on Sensitive Fields | **95%** | High | curl + grep | Yes | Missing autocomplete=off = fail |
| CAPTCHA Bypass | **90%** | High | curl | Yes | Submit without captcha; 200 = fail |
| CSRF on Login | **75%** | Moderate | curl | Yes | No token in form = fail; SameSite check |

#### 2.2.3 Auth Phase

| Test Case | Automation Confidence | True Positive | Tools (CLI) | Request/Response Save | Notes |
|-----------|----------------------|---------------|-------------|------------------------|------|
| Session Token Security | **65%** | Moderate | Burp Sequencer, script | Partial | Entropy analysis; requires token collection |
| Session Fixation | **85%** | High | curl | Yes | Same cookie pre/post login = fail |
| Session Timeout/Logout | **80%** | High | curl | Yes | Replay token after logout; 200 = fail |
| JWT Token Attack Suite | **92%** | High | jwt_tool | Yes | jwt_tool returns success/fail per attack |
| OAuth/SSO Testing | **70%** | Moderate | curl | Partial | State param, redirect_uri — context-dependent |
| MFA Testing | **85%** | High | Burp Intruder, script | Yes | OTP brute force, bypass — parse responses |

#### 2.2.4 Post-Auth Phase

| Test Case | Automation Confidence | True Positive | Tools (CLI) | Request/Response Save | Notes |
|-----------|----------------------|---------------|-------------|------------------------|------|
| IDOR | **88%** | High | ffuf, Autorize | Yes | Different user data returned = fail; needs auth |
| Vertical Privilege Escalation | **90%** | High | curl, ffuf | Yes | 200 on /admin with user token = fail |
| Mass Assignment | **85%** | High | curl | Yes | isAdmin in response = fail |
| SQL Injection (Post-Auth) | **92%** | High | sqlmap | Yes | Same as pre-auth; add auth header |
| XSS (Reflected/Stored) | **88%** | High | xsstrike, dalfox | Yes | Tool confirms XSS; parse output |
| SSRF | **90%** | High | curl, custom script | Yes | 169.254.169.254 in response = fail |
| SSTI | **90%** | High | tplmap | Yes | 49 in response for {{7*7}} = fail |
| LFI/Path Traversal | **92%** | High | ffuf, curl | Yes | /etc/passwd in response = fail |
| Command Injection | **90%** | High | commix | Yes | Tool confirms RCE; parse output |
| File Upload | **85%** | High | curl | Yes | Webshell 200 + executable = fail |
| XXE | **90%** | High | curl + payload | Yes | /etc/passwd or OOB callback = fail |

#### 2.2.5 Business Logic, API, Client, Transport, Infra

| Phase | Representative Tests | Avg Confidence | Notes |
|-------|---------------------|----------------|-------|
| Business | Workflow circumvention, Payment, Race condition | 75% | Many require multi-step; automation partial |
| API | BOLA, Rate limiting, GraphQL | 85% | curl/ffuf with auth; deterministic |
| Client | Clickjacking, CSP, CORS | 95% | curl -I; header parsing |
| Transport | SSL (see Recon) | 95% | testssl.sh |
| Infra | Security headers, TRACE, Sensitive files | 95% | curl -I, ffuf |

---

## 3. Tools & CLI Installation Matrix

Required tools for **full automation coverage** (per test case or phase):

| Tool | Install Method | Purpose | Required For |
|------|----------------|---------|--------------|
| **curl** | apt install curl | HTTP requests, header checks | Most tests |
| **nuclei** | go install / binary | Template-based CVE/config scanning | Recon, Infra |
| **ffuf** | go install | Fuzzing, directory/file discovery | Recon, Pre-Auth, Post-Auth |
| **gobuster** | go install | Directory/file discovery | Recon |
| **feroxbuster** | cargo install / binary | Recursive directory search | Recon |
| **whatweb** | apt / gem | Technology fingerprinting | Recon |
| **testssl.sh** | git clone | SSL/TLS assessment | Transport |
| **retire** | npm install -g retire | JS library vulnerabilities | Recon |
| **sqlmap** | pip install sqlmap | SQL injection | Pre-Auth, Post-Auth |
| **nikto** | apt / cpan | Web server scan | Infra |
| **nmap** | apt install nmap | Port scan, ssl-enum-ciphers | Recon, Infra |
| **hydra** | apt install hydra | Brute force | Pre-Auth |
| **jwt_tool** | pip install jwt-tool | JWT attacks | Auth |
| **xsstrike** | git clone | XSS discovery | Post-Auth |
| **dalfox** | go install | XSS scanning | Post-Auth |
| **commix** | pip install commix | Command injection | Post-Auth |
| **tplmap** | git clone | SSTI | Post-Auth |
| **arjun** | pip install arjun | Parameter mining | API |
| **graphql-cop** | pip install | GraphQL audit | API |
| **git-dumper** | pip install git-dumper | .git extraction | Recon |
| **Burp Suite Pro** | Manual (PortSwigger) | Crawler + scanner; REST API | Spider, ~15–20 test cases |
| **burpa** | pip install burpa | CLI wrapper for Burp API | Burp scan automation |

### 3.1 Single-Line Install Script (Scanner Server)

```bash
# Ubuntu/Debian - Navigator DAST Scanner Dependencies
apt-get update && apt-get install -y curl nmap hydra nikto
pip install sqlmap jwt-tool commix arjun
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/ffuf/ffuf/v2@latest
go install -v github.com/OJ/gobuster/v3@latest
go install github.com/epi052/feroxbuster@latest
npm install -g retire
# Optional: whatweb, testssl.sh (manual install)
```

---

## 4. Spider & Endpoint Discovery

### 4.1 Current State

- **No crawler/spider** in Navigator.
- Target URL = `Project.application_url` (single base URL).
- No automatic discovery of endpoints, forms, or parameters.

### 4.2 Spider Architecture Options

| Approach | Description | Confidence | Effort |
|----------|-------------|------------|--------|
| **1. Nuclei Discovery** | Nuclei has discovery templates; can enumerate URLs. | 85% | Low |
| **2. OWASP ZAP Spider** | ZAP API/headless spider; returns sitemap. | 90% | Medium |
| **3. Custom Crawler (Crawlee/Playwright)** | Headless browser + link extraction. | 85% | Medium |
| **4. ffuf/gobuster on base URL** | Directory/file discovery; no form parsing. | 80% | Low |
| **5. Burp Suite Sitemap Export** | Manual: export sitemap from Burp → import. | 95% | Low (user-driven) |
| **6. Burp Suite Crawler + REST API** | Automated: Burp Professional + API crawls app; returns sitemap. | **95%** | Medium (requires license) |
| **7. OpenAPI/Swagger** | If API has /openapi.json or /swagger — parse. | 98% | Low |

### 4.3 Recommended Spider Flow

1. **Phase 0 — Discovery (before test execution)**
   - Run Nuclei discovery templates on `{{TARGET}}`.
   - Run ffuf with `/opt/navigator/data/SecLists/Discovery/Web-Content/` for directories.
   - If `stack_profile` indicates API: try `/api/`, `/swagger`, `/openapi.json`.
   - Store discovered URLs in `project_discovered_urls` (new table or JSONB in Project).

2. **Variable Substitution**
   - `{{TARGET}}` → `Project.application_url`
   - `{{URL}}` → same or specific discovered URL
   - `{{TOKEN}}` / `{{AUTH_HEADER}}` → from login flow capture (future)
   - `{{COOKIE}}` → session cookie (future)

3. **Confidence: 85%** — Spider will find static links and common paths; SPA and heavy JS may need ZAP/Playwright.

---

## 5. Request/Response Capture (DAST-Style)

### 5.1 Pass Scenario

- Tool exits 0, output matches `pass_indicators` (or regex).
- **Save:**
  - `ProjectTestResult.status` = `passed`
  - `ProjectTestResult.request_captured` = last request (if tool provides it)
  - `ProjectTestResult.response_captured` = last response
  - `ProjectTestResult.tool_used` = tool name
  - `ProjectTestResult.evidence` = [{url: "stdout", description: "Tool output"}]
- **UI:** Show green "Passed" automatically.

### 5.2 Fail Scenario

- Tool exits non-zero, or output matches `fail_indicators`.
- **Save:**
  - `ProjectTestResult.status` = `failed`
  - `ProjectTestResult.request_captured` = vulnerable request (critical)
  - `ProjectTestResult.response_captured` = vulnerable response
  - `ProjectTestResult.tool_used`, `payload_used`
  - `ProjectTestResult.evidence` = full tool output + optional file refs
- **Optional:** Auto-create `Finding` with pre-filled title, description, request, response.
- **UI:** Show red "Failed" + "Create Finding" button (or auto-create).

### 5.3 Tools That Provide Request/Response

| Tool | Output Format | Request/Response in Output |
|------|---------------|---------------------------|
| Nuclei | JSON | Yes (embedded in template or match) |
| Burp XML | XML | Yes (base64 in issue) |
| ZAP | JSON/XML | Yes |
| SQLMap | Text/JSON | Yes (injection request) |
| curl | Manual capture | stdout/stderr; we capture via wrapper |
| ffuf | JSON | URL + status; no full req/resp — need to re-curl |
| jwt_tool | Text | Request in output |
| dalfox, xsstrike | Text/JSON | PoC URL; can re-curl for req/resp |

**Strategy:** For tools without native req/resp, run a follow-up `curl` to the detected URL with same params and capture.

---

## 6. Burp Suite Crawler & API Integration

### 6.1 Feasibility Summary

| Capability | Feasible? | Confidence | Requirements |
|------------|-----------|------------|--------------|
| **Burp Crawler as Spider** | ✅ Yes | **95%** | Burp Professional + REST API or burp-rest-api extension |
| **Burp Scan for Test Cases** | ✅ Yes | **92%** | Same; scan covers many OWASP checks |
| **Automated Crawl → Import** | ✅ Yes | **90%** | Existing Burp XML import; extend for sitemap/scan results |
| **Authenticated Scans** | ✅ Yes | **88%** | burpa `--app-user`/`--app-pass` or Burp login macro |

**Conclusion:** Burp Suite can be used as a **primary or complementary** spider and scanner. Navigator already has Burp XML import for findings; extending to use Burp's crawler and scan API adds enterprise-grade coverage for organizations that have Burp Professional.

### 6.2 Burp REST API Options

| Option | Description | Use Case |
|--------|-------------|----------|
| **Native Burp REST API** | Built into Burp Professional. Enable: User Options → Misc → REST API. Binds to configurable port (default 127.0.0.1). Requires API key. | Start scans, query scan status, retrieve results |
| **burp-rest-api (VMware)** | Third-party JAR extension. Runs Burp in headless mode with REST API on port 8090. Requires Burp Pro JAR. | Headless automation; CI/CD; no GUI |
| **burpa** (Python) | CLI/Python wrapper. Uses **both** native API + burp-rest-api. `burpa scan <url>` triggers full crawl + audit. | Simplest integration; single command |

### 6.3 Burp Crawler Capabilities

- **Crawl:** Burp Spider crawls the application, discovers links, forms, parameters, and JavaScript-rendered content (via built-in browser engine).
- **Sitemap:** After crawl, Burp maintains a sitemap of all discovered URLs, parameters, and request/response pairs.
- **Export:** Sitemap and scan results can be exported as XML (Navigator already parses Burp XML for findings).
- **Auth:** Login macros and form-based auth allow crawling authenticated areas.

### 6.4 Test Cases Mapped to Burp Scanner

Burp Scanner automatically checks for many vulnerabilities that align with Navigator test cases:

| Navigator Test Case (Phase) | Burp Scanner Coverage | Mapping Confidence |
|-----------------------------|------------------------|--------------------|
| Technology Fingerprinting | Partial (Server header, etc.) | 70% |
| robots.txt / sitemap | ✅ Robots.txt file finding | **95%** |
| Directory/File Discovery | ✅ Backup file, sensitive files | **90%** |
| SSL/TLS Configuration | ✅ TLS findings, HSTS, cert | **95%** |
| Security Headers | ✅ Missing headers, HSTS, CSP | **95%** |
| Autocomplete on Sensitive Fields | ✅ Form field checks | **85%** |
| SQL Injection | ✅ SQL injection checks | **95%** |
| XSS (Reflected/Stored) | ✅ XSS checks | **92%** |
| Clickjacking (X-Frame-Options) | ✅ Header checks | **95%** |
| CORS Misconfiguration | ✅ CORS findings | **90%** |
| CSRF | ✅ CSRF token checks | **85%** |
| Session Cookie Flags | ✅ HttpOnly, Secure, SameSite | **95%** |
| TRACE method (XST) | ✅ HTTP method checks | **95%** |
| Sensitive Data in Response | ✅ Information disclosure | **90%** |
| IDOR / Access Control | Partial (logic-based) | 70% |
| JWT / OAuth | Limited | 50% |

**~15–20 test cases** have **high-confidence** Burp coverage. Use Burp for these; use CLI tools (nuclei, sqlmap, jwt_tool, etc.) for the rest.

### 6.5 Integration Architecture

```
[Navigator Backend]                    [Burp Suite Professional]
       |                                        |
       |  POST scan request (target, auth)      |
       |--------------------------------------->|  REST API (port 1337)
       |                                        |  or burp-rest-api (8090)
       |                                        |
       |  Burp: Crawl + Audit (spider+scanner)  |
       |<---------------------------------------|
       |  Poll scan status / Get report         |
       |                                        |
       |  Burp exports XML (findings + req/resp)|
       |<---------------------------------------|
       |                                        |
       v
[POST /findings/import/burp]  -->  Create Finding + ProjectTestResult
       |
       v
[Map Burp finding type → Navigator TestCase]
(e.g., "SQL injection" → MOD-36-PRE, MOD-27)
```

### 6.6 Implementation Options

| Approach | Effort | Automation Level | Notes |
|----------|--------|------------------|-------|
| **A. burpa CLI wrapper** | Low | High | Call `burpa scan <target>` from Celery task; parse HTML/XML report; import via existing Burp import |
| **B. Direct Burp REST API** | Medium | High | Use native API to start scan, poll status, fetch issues; map to test results |
| **C. burp-rest-api extension** | Medium | High | Run Burp headless on scanner server; same as B but no GUI required |
| **D. Manual Burp + Import** | Done | Low | User runs Burp, exports XML, uploads to Navigator (current flow) |

### 6.7 Tools & Installation for Burp Integration

| Component | Install | Notes |
|-----------|---------|-------|
| **Burp Suite Professional** | Manual download from PortSwigger | License required |
| **burpa** | `pip install burpa` | Easiest; uses Burp API |
| **burp-rest-api** | Download JAR from [vmware/burp-rest-api](https://github.com/vmware/burp-rest-api) | For headless; run with Burp JAR |
| **Java 21** | `apt install openjdk-21-jre` | Required for Burp + extension |

### 6.8 Burp-Specific "Automate" Flow

1. **User clicks "Run with Burp"** on a phase (e.g., Recon, Client) or on specific test cases that support Burp.
2. **Backend** checks if Burp is configured (URL, API key in project/org settings).
3. **Celery task** calls `burpa scan <application_url>` or native Burp API to start crawl+audit.
4. **Task polls** until scan completes (crawling → auditing → succeeded).
5. **Task fetches** Burp report (HTML/XML).
6. **Parser** extracts issues; for each issue:
   - Match to Navigator `TestCase` by vulnerability type (e.g., "SQL injection" → MOD-27).
   - Create/update `ProjectTestResult` (status = failed, request/response from Burp XML).
   - Create `Finding` via existing import logic.
7. **WebSocket** broadcasts progress; UI shows "Passed" or "Failed" per mapped test case.

### 6.9 Limitations & Considerations

| Limitation | Mitigation |
|------------|------------|
| **Burp Professional license** | Use for orgs that already have it; offer Nuclei/CLI path for others |
| **Single Burp instance** | Queue scans; or run multiple Burp instances on different ports |
| **Headless mode** | ARM64 Burp lacks built-in browser; use x86 for crawler |
| **Scan duration** | Full crawl+audit can take 30+ min; run async, show progress |
| **Internal apps** | Burp must reach target; use agent or VPN (same as Section 7) |

### 6.10 Additions to Phase Plan

| Phase | Burp-Specific Tasks | Confidence |
|-------|---------------------|------------|
| **Phase 2** | Burp XML import enhancement: map issue types to TestCase IDs; auto-update ProjectTestResult | 90% |
| **Phase 2** | burpa CLI runner: Celery task to run `burpa scan` and ingest report | 90% |
| **Phase 3** | Burp as spider: use Burp sitemap/crawl output as `project_discovered_urls` for other tools | 85% |
| **Phase 4** | "Run with Burp" button per phase; org-level Burp API config (URL, key) | 95% |

---

## 7. Internal Application Support

> **Detailed guide:** See [DAST_VPN_INTERNAL_TARGETS.md](./DAST_VPN_INTERNAL_TARGETS.md) for the full solution (SaaS + VPN targets, agent architecture, alternatives).

### 6.1 Challenge

- Internal apps (e.g., `http://internal-app.local:8080`) are not reachable from Navigator's cloud/server.

### 6.2 Solutions

| Approach | Description | Use Case |
|----------|-------------|----------|
| **1. VPN** | Navigator server joins client VPN; can reach internal URLs. | Enterprise with VPN for scanners |
| **2. Agent/Scan Runner** | Lightweight agent on client network runs scans, reports back to Navigator API. | Internal apps; no VPN |
| **3. Proxy Forward** | Client runs local proxy; forwards requests to internal app. | Dev/test environments |
| **4. Docker on Client** | Client runs Navigator scanner container; container has network access to internal app. | On-prem deploy |
| **5. Burp/ZAP in Client** | User runs Burp/ZAP locally; imports XML to Navigator. | Already supported (Burp import) |

### 6.3 Recommended: Agent-Based Scanner

- **Architecture:** Navigator backend sends scan job (project_id, test_case_ids, target_url, auth_config) to a **Scanner Agent**.
- Agent runs on client network (VM, Docker, or bare metal).
- Agent executes tools locally, parses output, posts results to Navigator API (`POST /api/v1/scan-results`).
- Navigator stores `ProjectTestResult` + `Finding` as if run locally.
- **Confidence: 90%** — Same automation logic; only execution location differs.

### 6.4 Internal URL Configuration

- `Project.application_url` can be internal (e.g., `http://10.0.1.50:3000`).
- Add `Project.scan_origin`: `server` | `agent` — indicates where scan runs.
- For `agent`: Navigator does not execute tools; only queues and receives results.

---

## 8. Industry DAST Comparison (Accunetix, Burp, etc.)

| Capability | Accunetix | Burp Suite | Navigator (Plan) |
|------------|-----------|------------|------------------|
| Crawler/Spider | DeepScan (JS-aware) | Built-in spider | Nuclei + ffuf + optional ZAP |
| Auth handling | Login macro, forms | Manual login | Login flow capture (Phase 2) |
| Scan speed | Fast (optimized) | Slower | Depends on tools (parallel) |
| False positive reduction | AcuSensor (IAST) | Manual verification | pass_indicators/fail_indicators + regex |
| Request/response storage | Yes | Yes | Yes (ProjectTestResult, Finding) |
| API testing | Yes | Yes | Yes (curl, ffuf with auth) |
| Scheduled scans | Yes | No (Pro has scan) | Planned (Celery + cron) |
| CI/CD integration | Yes | Limited | Webhook trigger planned |

**Navigator's Edge (2026):**
- **Unified manual + automated** — Same test case library for both.
- **Gamification + workflow** — Testers still drive methodology; automation fills gaps.
- **LLM assist** — Payload crafting, severity suggestion, test case generation.
- **Open toolchain** — Nuclei, ffuf, sqlmap, etc. — no vendor lock-in.
- **Extensible** — Add new tools via `tool_commands` + parser.

---

## 9. Dedicated Scanner Server

### 8.1 Why Separate Server

- Tool execution (nuclei, ffuf, sqlmap) is **CPU and I/O intensive**.
- Reduces load on main Navigator API/DB.
- Allows different network placement (e.g., scanner in DMZ, API in private).

### 8.2 Architecture

```
[Navigator API]  ----(Celery/RQ)---->  [Scanner Server]
       |                                      |
       |                              - nuclei, ffuf, sqlmap, etc.
       |                              - Docker optional (sandbox)
       |                              - Posts results to API
       v
[PostgreSQL]  <----(HTTP/API)-------  [Scanner Worker]
```

### 8.3 Scanner Server Setup

- **OS:** Ubuntu 22.04 LTS
- **Resources:** 4 vCPU, 8 GB RAM (scans can spike)
- **Network:** Reachable from Navigator (Redis/Celery broker) and from scanner to target URLs
- **Tools:** Install all CLIs from Section 3
- **Celery worker:** Same broker as Navigator; executes `run_single_test`, `run_phase_tests` tasks
- **Data:** Shared Redis + PostgreSQL connection (or API callback)

### 8.4 Load Distribution

| Workload | Main Server | Scanner Server |
|----------|-------------|----------------|
| API, auth, UI | ✅ | ❌ |
| Report generation (Celery) | Optional | Optional |
| Test execution (nuclei, ffuf, etc.) | ❌ | ✅ |
| DB writes (results) | ✅ | Via API or shared DB |

---

## 10. "Automate" Button UX

### 9.1 Per-Test-Case Button

- **Location:** Next to "Mark Passed" / "Mark Failed" on each test case card.
- **Label:** "▶ Automate" or "Run Test"
- **Action:**
  1. Call `POST /api/v1/testcases/run/{result_id}` (or `/{test_case_id}`).
  2. Backend enqueues Celery task with `result_id`, `project_id`, `test_case_id`, `application_url`.
  3. WebSocket broadcasts: `{"type": "test_started", "result_id": "..."}`.
  4. Worker runs tool, parses output, updates `ProjectTestResult`.
  5. WebSocket: `{"type": "test_completed", "result_id": "...", "status": "passed"|"failed", "request_captured": "...", "response_captured": "..."}`.
  6. UI updates card: green Pass / red Fail; shows request/response in expandable section.

### 9.2 Per-Phase Button

- **"Run All [Phase] Tests"** — Batch execution for phase (e.g., all recon).
- Progress bar; WebSocket stream for each completion.
- Applicability filtering: skip tests where `applicability_conditions` don't match `stack_profile`.

### 9.3 Pass/Fail Display

- **Passed:** Green badge, "Passed (automated)" + timestamp. Collapsible request/response.
- **Failed:** Red badge, "Failed (automated)" + "Create Finding" button. Request/response pre-filled in finding form.

---

## 11. Implementation Phases

### Phase 1 — Foundation (4–6 weeks)

| Task | Effort | Confidence |
|------|--------|------------|
| Variable substitution (`{{TARGET}}` → `application_url`) in tool_commands | Low | 100% |
| Single test execution API + Celery task | Medium | 95% |
| Output parsing: regex on pass_indicators/fail_indicators | Medium | 85% |
| Request/response capture (for tools that provide it; else stdout) | Low | 90% |
| "Run Test" button + WebSocket progress | Medium | 95% |

### Phase 2 — Tool Runners (4–6 weeks)

| Task | Effort | Confidence |
|------|--------|------------|
| Nuclei runner + JSON parsing → findings | High | 90% |
| curl/ffuf wrapper with req/resp capture | Medium | 95% |
| SQLMap output parser | Medium | 90% |
| Burp XML import (existing) — ensure request/response in Finding | Low | 100% |
| **Burp API/burpa integration** — run Burp scan, map findings to test cases | Medium | 90% |
| Auto-finding from failed test (optional) | Medium | 85% |

### Phase 3 — Spider & Discovery (3–4 weeks)

| Task | Effort | Confidence |
|------|--------|------------|
| Nuclei + ffuf discovery run before tests | Medium | 85% |
| **Burp crawler as spider** — use Burp sitemap for `project_discovered_urls` (if Burp configured) | Medium | 95% |
| Store discovered URLs in project | Low | 95% |
| `{{URL}}` from discovered list (or random for fuzzing) | Low | 90% |

### Phase 4 — Batch & Schedule (3–4 weeks)

| Task | Effort | Confidence |
|------|--------|------------|
| Run phase / run all tests | Medium | 95% |
| **"Run with Burp"** button per phase (where Burp coverage applies) | Low | 95% |
| Scheduled scans (Celery beat) | Low | 95% |
| Webhook trigger for CI/CD | Low | 95% |
| Dedicated scanner server deployment (incl. Burp if licensed) | Medium | 90% |

### Phase 5 — Internal & Agent (4–6 weeks)

| Task | Effort | Confidence |
|------|--------|------------|
| Scanner Agent (lightweight runner, reports to API) | High | 85% |
| Login flow capture for auth tests | High | 75% |
| VPN / proxy configuration for internal targets | Medium | 80% |

---

## 12. Summary Tables

### 11.1 Test Cases Automatable with High Confidence (95%+)

| Phase | Count (approx) | Examples |
|-------|----------------|----------|
| Recon | 7 | Technology fingerprinting, robots.txt, directory discovery, .git, Nuclei, RetireJS, SSL |
| Pre-Auth | 3 | Autocomplete, CAPTCHA, SQLi (sqlmap) |
| Auth | 2 | Session fixation, JWT (jwt_tool) |
| Post-Auth | 10+ | IDOR, SQLi, XSS, SSRF, SSTI, LFI, RCE, File upload, XXE |
| Client/Infra | 5+ | CSP, CORS, Headers, TRACE, Sensitive files |

**Total high-confidence automatable: ~30–35** of ~53 seed + 126 WSTG (subset overlap).

**With Burp Suite Professional:** Add **~15–20 test cases** via Burp crawler + scanner (Section 6). Overlap with CLI-based tests; use Burp where available for higher coverage (headers, SQLi, XSS, TLS, etc.).

### 11.2 Tools Installation Quick Reference

```
curl, nmap, nikto, hydra     → apt install
sqlmap, jwt_tool, commix, arjun → pip install
nuclei, ffuf, gobuster       → go install
retire                      → npm install -g
feroxbuster                 → cargo / binary
testssl.sh                  → git clone
whatweb                     → apt / gem
burpa                       → pip install burpa
Burp Suite Professional     → Manual (PortSwigger); enable REST API
```

### 11.3 Request/Response Save Rules

| Outcome | status | request_captured | response_captured | evidence |
|---------|--------|------------------|-------------------|----------|
| Pass | passed | If available | If available | Tool stdout |
| Fail | failed | **Always** (critical) | **Always** | Full output + req/resp |
| Error (timeout, tool crash) | blocked | Last attempt | Last attempt | Error message |

---

## 13. Conclusion

Navigator can evolve into a **hybrid manual + automated DAST platform** with:

1. **~30–35 test cases** automatable with **95%+ confidence** via CLI tools; **+15–20 via Burp Suite** (crawler + scanner) where licensed.
2. **Request/response** saved on both pass and fail, DAST-style.
3. **Spider** via Nuclei + ffuf (85%) or **Burp crawler** (95% when Burp Pro available).
4. **Burp integration** — REST API/burpa for automated crawl+scan; existing XML import extended with test case mapping.
5. **Internal apps** supported via Agent or VPN.
6. **Dedicated scanner server** for load isolation.
7. **"Automate" button** per test and per phase with WebSocket progress (incl. "Run with Burp" where applicable).

Implementation should follow Phase 1 → 2 → 3 → 4 → 5, with each phase delivering working automation for a subset of tests.

---

## Appendix A: Per-Test-Case Tool & CLI Reference

| Test Case (module_id) | Primary Tool | CLI Command Snippet | Output Parse |
|----------------------|--------------|---------------------|--------------|
| MOD-RECON-01 | whatweb | `whatweb https://TARGET -a 3` | grep version/Server |
| MOD-RECON-02 | curl | `curl https://TARGET/robots.txt` | grep Disallow |
| MOD-RECON-03 | ffuf | `ffuf -w ... -u https://TARGET/FUZZ -o json` | Parse JSON status |
| MOD-RECON-04 | curl | `curl -s https://TARGET/.git/HEAD` | 200 + ref: = fail |
| MOD-RECON-05 | nuclei | `nuclei -u https://TARGET -json` | Parse JSON findings |
| MOD-RECON-06 | retire | `retire --url https://TARGET --outputformat json` | Parse JSON vulns |
| MOD-RECON-07 | testssl.sh | `testssl.sh https://TARGET` | Parse TLS/cipher output |
| MOD-36-PRE | sqlmap | `sqlmap -u 'https://TARGET/login' --data=...` | "injectable" in output |
| MOD-21 | ffuf/curl | IDOR with auth header | Compare response |
| MOD-23-VERTICAL | curl | `curl -H "Authorization: Bearer X" https://TARGET/admin` | 200 = fail |

---

## Appendix B: False Positive Mitigation

| Strategy | Implementation |
|----------|----------------|
| **Strict regex** | Use `fail_indicators` as regex only when unambiguous (e.g., "ref: refs/heads" for .git) |
| **Multi-signal** | Require 2+ signals (e.g., status 200 + content match) before marking fail |
| **Tool-native** | Prefer tools with built-in confirmation (Nuclei, SQLMap) over custom parsing |
| **Human review** | All automated "failed" results show "Create Finding" — human can mark FP |
| **Finding status** | Add `fp` (false positive) status to Finding; exclude from reports |
| **Retest** | Recheck workflow already exists; apply to automated findings |

---

## Appendix C: Variable Substitution Spec

| Placeholder | Source | Example |
|-------------|--------|---------|
| `{{TARGET}}` | Project.application_url | https://example.com |
| `{{URL}}` | Discovered URL or TARGET | https://example.com/api/users |
| `{{TOKEN}}` | Login flow capture (future) | eyJhbGc... |
| `{{AUTH_HEADER}}` | Authorization header | Bearer eyJhbGc... |
| `{{COOKIE}}` | Session cookie | session=abc123 |
| `{{WORDLIST}}` | Navigator payload API | /api/v1/payloads/download/{id} |

---

## Appendix D: Database Schema Additions (Proposed)

```sql
-- Discovered URLs per project (spider output)
CREATE TABLE project_discovered_urls (
  id UUID PRIMARY KEY,
  project_id UUID REFERENCES projects(id),
  url TEXT NOT NULL,
  method VARCHAR(10),
  discovered_at TIMESTAMPTZ DEFAULT now()
);

-- Scan execution metadata (for history)
ALTER TABLE project_test_results ADD COLUMN execution_mode VARCHAR(20); -- 'manual' | 'automated'
ALTER TABLE project_test_results ADD COLUMN execution_started_at TIMESTAMPTZ;
ALTER TABLE project_test_results ADD COLUMN execution_completed_at TIMESTAMPTZ;
ALTER TABLE project_test_results ADD COLUMN tool_exit_code INTEGER;
ALTER TABLE project_test_results ADD COLUMN tool_stdout TEXT;
ALTER TABLE project_test_results ADD COLUMN tool_stderr TEXT;
```

---

## Appendix E: Burp Issue Type → Navigator Test Case Mapping

| Burp Finding (example names) | Navigator module_id / Phase |
|-----------------------------|-----------------------------|
| SQL injection | MOD-36-PRE, MOD-27 (pre_auth, post_auth) |
| Cross-site scripting (XSS) | MOD-28 (post_auth) |
| Robots.txt file | MOD-RECON-02 (recon) |
| Backup file | MOD-RECON-03 (recon) |
| Cookie without HttpOnly flag | MOD-01, client phase |
| Strict transport security not enforced | MOD-RECON-07 (transport) |
| TLS cookie without secure flag | MOD-01, auth |
| Cacheable HTTPS response | client/transport |
| Missing Content-Security-Policy | Client phase (CSP test) |
| Missing X-Frame-Options | Client phase (clickjacking) |
| CORS misconfiguration | Client phase (CORS test) |
| CSRF token | pre_auth, post_auth (CSRF tests) |
| Sensitive data in response | Various (information disclosure) |
