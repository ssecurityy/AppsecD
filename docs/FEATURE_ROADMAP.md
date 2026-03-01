# VAPT Navigator — Feature Roadmap & Advisor

**Last updated:** 2026-03-01

This document outlines implemented features, planned enhancements, and future ideas. Status reflects actual codebase verification. Acts as a comprehensive master plan for achieving a world-class VAPT platform.

**Status legend:** ✅ Done | ⚠️ Partial | ❌ Not

---

## 1. Report & Presentation


| Feature                           | Status | Effort | Priority |
| --------------------------------- | ------ | ------ | -------- |
| **Charts in HTML report**         | ✅ Done | —      | —        |
| **Table of contents**             | ✅ Done | —      | —        |
| **Live report view**              | ✅ Done | —      | —        |
| **Evidence/screenshot embedding** | ✅ Done | —      | —        |
| **Signed report hash (SHA-256)**  | ✅ Done | —      | —        |
| **Custom report templates**       | ❌ Not  | High   | Low      |
| **Report scheduling**             | ❌ Not  | Medium | Medium   |
| **Executive dashboard PDF**       | ❌ Not  | Medium | Medium   |
| **Comparison reports**            | ❌ Not  | High   | Low      |


**Notes:**

- Evidence upload (images, PDF, etc.) and embedding in HTML/DOCX/PDF reports is implemented.
- SHA-256 hash in HTML report footer (report_service.py).

---

## 2. Testing & Engagement


| Feature                                  | Status | Effort | Priority |
| ---------------------------------------- | ------ | ------ | -------- |
| **Screenshot/evidence embedding**        | ✅ Done | —      | —        |
| **Gamification badges**                  | ✅ Done | —      | —        |
| **OWASP WSTG test cases**                | ✅ Done | —      | —        |
| **Payloads in DB (PAT, SecLists, etc.)** | ✅ Done | —      | —        |
| **Payload sources UI**                   | ✅ Done | —      | —        |
| **Skill tree**                           | ❌ Not  | High   | Medium   |
| **Organization leaderboard**             | ❌ Not  | Medium | Medium   |
| **Burp XML import**                      | ✅ Done | —      | —        |
| **CI/CD webhook**                        | ❌ Not  | Medium | High     |
| **Time tracking**                        | ❌ Not  | Low    | Medium   |
| **Test case templates**                  | ❌ Not  | Medium | Low      |


**Notes:**

- 126 OWASP WSTG test cases imported; payloads from PAT, SecLists, FuzzDB, Nuclei, etc. in PostgreSQL.
- Time tracking was marked Partial previously; no dedicated backend found — treat as Not.

---

## 3. AI & Intelligence


| Feature                                            | Status | Effort | Priority |
| -------------------------------------------------- | ------ | ------ | -------- |
| **AI Assist (rule-based)**                         | ✅ Done | —      | —        |
| **AI Assist (LLM mode)**                           | ✅ Done | —      | —        |
| **Severity recommendation**                        | ✅ Done | —      | —        |
| **Multi-provider LLM (OpenAI, Anthropic, Google)** | ✅ Done | —      | —        |
| **Admin/org LLM config**                           | ✅ Done | —      | —        |
| **Auto-findings from results**                     | ❌ Not  | High   | Medium   |
| **Natural language queries**                       | ❌ Not  | High   | Low      |
| **Report summarization**                           | ❌ Not  | Medium | Medium   |
| **Vulnerability trend analysis**                   | ❌ Not  | High   | Low      |


**Notes:**

- AI Assist: rule-based (no API key) + LLM (OpenAI/Anthropic/Google) with model selection in Admin Settings.
- Org-scoped LLM config for multi-tenant; encrypted API keys in DB.

---

## 4. Integrations


| Feature                      | Status | Effort | Priority |
| ---------------------------- | ------ | ------ | -------- |
| **JIRA**                     | ✅ Done | —      | —        |
| **JIRA per-org config**      | ✅ Done | —      | —        |
| **Slack notifications**      | ✅ Done | —      | —        |
| **Microsoft Teams**          | ❌ Not  | Medium | Medium   |
| **SMTP/Email notifications** | ✅ Done | —      | —        |
| **DefectDojo**               | ❌ Not  | High   | Medium   |
| **Generic webhook (outgoing)** | ✅ Done | —      | —        |
| **GitHub Issues**            | ❌ Not  | Medium | Medium   |
| **ServiceNow**               | ❌ Not  | High   | Low      |
| **Nuclei results import**    | ❌ Not  | High   | Medium   |
| **OWASP ZAP import**         | ❌ Not  | Medium | Medium   |


**Notes:**

- JIRA: env vars + per-org settings; create issues from findings.
- Slack, SMTP, generic webhook on critical/high findings (notification_service); configurable per-org in Admin Settings. Teams not implemented.

---

## 5. Vulnerability Management


| Feature                    | Status | Effort | Priority |
| -------------------------- | ------ | ------ | -------- |
| **Remediation tracking**   | ✅ Done | —      | —        |
| **Recheck workflow**       | ✅ Done | —      | —        |
| **Vulnerabilities page**   | ✅ Done | —      | —        |
| **Recheck status/history** | ✅ Done | —      | —        |
| **Compliance mapping**     | ✅ Done | —      | —        |


**Notes:**

- Full recheck lifecycle: pending, resolved, not_fixed, partially_fixed, exception, deferred, retest_needed.
- `/projects/[id]/vulnerabilities` — dedicated vulnerability management UI.

---

## 6. UI/UX & Psychology


| Feature                        | Status     | Effort | Priority |
| ------------------------------ | ---------- | ------ | -------- |
| **Dark theme**                 | ✅ Done     | —      | —        |
| **Progress visualization**     | ✅ Done     | —      | —        |
| **Professional design**        | ⚠️ Partial | Medium | High     |
| **Animations (Framer Motion)** | ⚠️ Partial | Low    | Medium   |
| **Tester engagement cues**     | ⚠️ Partial | Medium | High     |
| **Reduced cognitive load**     | ❌ Not      | Medium | Medium   |
| **Micro-interactions**         | ❌ Not      | Low    | Medium   |


---

## 7. Security & Compliance


| Feature               | Status     | Effort | Priority |
| --------------------- | ---------- | ------ | -------- |
| **MFA**               | ✅ Done     | —      | —        |
| **Audit logs**        | ✅ Done     | —      | —        |
| **Rate limiting**     | ✅ Done     | —      | —        |
| **RBAC**              | ⚠️ Partial | Medium | Medium   |
| **SSO (SAML/OIDC)**   | ❌ Not      | High   | Medium   |
| **Report encryption** | ❌ Not      | Medium | Low      |
| **Data retention**    | ❌ Not      | Medium | Low      |


**Notes:**

- MFA: full flow (setup, verify, login step, admin enable/disable). Login enforces MFA when enabled.

---

## 8. Performance & Scale


| Feature            | Status     | Effort | Priority |
| ------------------ | ---------- | ------ | -------- |
| **WebSocket**      | ✅ Done     | —      | —        |
| **Celery async**   | ✅ Done     | —      | —        |
| **Redis (broker)** | ✅ Done     | —      | —        |
| **Redis caching**  | ✅ Done     | —      | —        |
| **Pagination**     | ✅ Done     | —      | —        |
| **Health endpoints** | ✅ Done   | —      | —        |
| **Lazy loading**   | ⚠️ Partial | Low    | Medium   |
| **CDN for assets** | ❌ Not      | Low    | Low      |


**Notes:**

- Redis: Celery broker + project list caching (60s TTL, cache_service); cache invalidation on project changes.
- Health: `/health` (liveness), `/health/ready` (DB + Redis).

---

## 9. Organizations & Multi-Tenancy


| Feature                      | Status | Effort | Priority |
| ---------------------------- | ------ | ------ | -------- |
| **Organizations**            | ✅ Done | —      | —        |
| **Org-scoped settings**      | ✅ Done | —      | —        |
| **Super admin org settings** | ✅ Done | —      | —        |
| **Super admin role**         | ✅ Done | —      | —        |


---

## 10. Quick Wins (Low Effort, High Impact)


| Item                              | Status |
| --------------------------------- | ------ |
| Live report link                  | ✅ Done |
| Charts in HTML report             | ✅ Done |
| Table of contents in report       | ✅ Done |
| MFA login UI enforcement          | ✅ Done |
| Organization leaderboard          | ❌ Not  |
| Slack webhook on critical finding | ✅ Done |
| SMTP/email on critical finding    | ✅ Done |
| Report SHA-256 hash in footer     | ✅ Done |


---

## 11. Test Case Automation (Master Plan)

*Goal: Fully automate execution of all test cases — run tools, parse output, record pass/fail, optionally create findings.*

### 11.1 Core Execution Engine

| Feature | Description | Effort | Priority |
|---------|-------------|--------|----------|
| **Variable substitution** | Replace `{{TARGET}}`, `{{URL}}`, `{{TOKEN}}`, `{{AUTH_HEADER}}`, `{{COOKIE}}` in tool_commands from project context | Medium | Critical |
| **Single test execution** | Run one test case: execute tool_commands, capture stdout/stderr, store output | Medium | Critical |
| **Batch execution** | Run all tests in a phase, or all tests in project | Medium | Critical |
| **Parallel execution** | Run multiple tests concurrently (configurable concurrency limit) | Medium | High |
| **Celery task queue** | Async execution via Celery; long-running scans don't block API | Low | Critical |
| **Execution sandbox** | Docker container or isolated env for tool execution (security) | High | High |
| **Execution history** | Store last run timestamp, duration, exit code per test | Low | High |

### 11.2 Tool Integration & Parsing

| Feature | Description | Effort | Priority |
|---------|-------------|--------|----------|
| **Nuclei runner** | Execute `nuclei -u {{TARGET}}`, parse JSON output, auto-create findings | High | Critical |
| **OWASP ZAP runner** | Run ZAP via API/headless, import scan results as findings | High | Critical |
| **Burp XML import** | Import Burp Suite XML export → findings | Medium | Critical |
| **ffuf/gobuster runner** | Execute fuzzing, parse output for discovered paths, record as pass/fail | Medium | High |
| **SQLMap runner** | Run SQLMap on target params, parse for SQLi confirmation | Medium | High |
| **Nikto runner** | Run Nikto, parse output for vulnerabilities | Low | Medium |
| **Nmap runner** | Port scan, store open ports as recon data | Low | Medium |
| **curl/script runner** | Execute curl, Python, Bash from tool_commands; regex match pass/fail | Medium | Critical |
| **Output parsing rules** | Use `pass_indicators`/`fail_indicators` or regex to determine result | Medium | Critical |
| **Structured output parsing** | Parse JSON/XML from tools (nuclei, ZAP) into structured findings | High | Critical |

### 11.3 Wordlist & Payload Integration

| Feature | Description | Effort | Priority |
|---------|-------------|--------|----------|
| **Dynamic wordlist URLs** | Replace hardcoded paths with Navigator API: `/payloads/download/{id}` | Low | High |
| **Payload injection** | Inject payloads from DB into tool commands (e.g., ffuf -w from Navigator) | Medium | High |
| **Wordlist streaming** | Stream large wordlists from DB for tools that read from stdin | Medium | Medium |

### 11.4 Scheduling & Triggers

| Feature | Description | Effort | Priority |
|---------|-------------|--------|----------|
| **Scheduled scans** | Cron-like: daily, weekly, monthly full or phase-specific runs | Medium | High |
| **Phase-gated execution** | Run phase B only when phase A is complete (e.g., post-auth after auth) | Medium | High |
| **Webhook trigger** | Incoming webhook to start scan (e.g., from CI/CD) | Low | High |
| **Manual trigger** | "Run all" / "Run phase" button with progress via WebSocket | Medium | Critical |

### 11.5 Result Processing & AI

| Feature | Description | Effort | Priority |
|---------|-------------|--------|----------|
| **Auto-finding from failed test** | When test fails → suggest/create finding with pre-filled title, description, evidence | High | Critical |
| **Evidence extraction** | Auto-attach tool output, screenshots, or parsed data as evidence | Medium | High |
| **AI result interpretation** | LLM parses ambiguous tool output → suggest pass/fail or finding | High | Medium |
| **Deduplication** | Merge duplicate findings from same tool run | Medium | Medium |

### 11.6 Test Dependencies & Chaining

| Feature | Description | Effort | Priority |
|---------|-------------|--------|----------|
| **Login flow capture** | Record login request/response; extract session cookie/token for subsequent tests | High | High |
| **Test dependencies** | Define "Test B requires Test A pass" (e.g., auth before IDOR) | Medium | Medium |
| **Context propagation** | Pass auth token, cookies, headers from one test to next in chain | Medium | High |

---

## 12. Discovery & Recon Automation

| Feature | Description | Effort | Priority |
|---------|-------------|--------|----------|
| **Subdomain enumeration** | Integrate subfinder, amass, or similar; store subdomains per project | High | High |
| **Technology fingerprinting** | Run WhatWeb/Wappalyzer, store results in project metadata | Medium | Medium |
| **Endpoint discovery** | Crawl + fuzz; store discovered URLs for test case targeting | High | High |
| **Screenshot capture** | Headless browser screenshot of key pages for report | Medium | Medium |
| **SSL/TLS assessment** | Run sslyze or testssl.sh, store results | Low | Medium |

---

## 13. Notifications & Alerting

| Feature | Status | Description | Effort | Priority |
|---------|--------|-------------|--------|----------|
| **SMTP/Email** | ✅ Done | Critical finding alert (configurable per-org) | — | — |
| **Slack webhook** | ✅ Done | Webhook on critical finding | — | — |
| **Microsoft Teams** | ❌ Not | Incoming webhook for Teams channels | Low | Medium |
| **PagerDuty** | ❌ Not | Critical severity → PagerDuty incident | Medium | Medium |
| **Webhook (generic)** | ✅ Done | Configurable outgoing webhook with JSON payload on finding created | — | — |
| **In-app notifications** | ❌ Not | Bell icon, unread count, mark as read | Medium | Medium |

---

## 14. Integrations (Extended)

| Feature | Description | Effort | Priority |
|---------|-------------|--------|----------|
| **DefectDojo** | Push findings for compliance/DevSecOps | High | Medium |
| **GitHub Issues** | Create issue from finding | Medium | Medium |
| **GitLab Issues** | Create issue from finding | Medium | Medium |
| **Linear** | Create Linear issue from finding | Medium | Low |
| **ServiceNow** | Create ServiceNow ticket | High | Low |
| **JIRA automation** | Auto-transition on remediation status | Medium | Medium |

---

## 15. API & Extensibility

| Feature | Status | Description | Effort | Priority |
|---------|--------|-------------|--------|----------|
| **REST API (full)** | ⚠️ Partial | CRUD projects, findings, test results, reports; API key auth | High | Critical |
| **API versioning** | ✅ Done | `/api/v1/` for backward compatibility | — | — |
| **Webhooks (outgoing)** | ✅ Done | Generic webhook on finding created (notification_service) | — | — |
| **Plugin system** | ❌ Not | Load custom Python modules for tool runners, parsers | High | Low |
| **Custom fields** | ❌ Not | Org-defined custom fields on findings/projects | Medium | Medium |

---

## 16. Analytics & Metrics

| Feature | Description | Effort | Priority |
|---------|-------------|--------|----------|
| **Executive dashboard** | KPIs: findings by severity, MTTR, trend over time | High | High |
| **Vulnerability trends** | Chart: findings over time, by category, by project | Medium | High |
| **Tester metrics** | Findings per tester, coverage %, streak | Medium | Medium |
| **Benchmarking** | Compare project metrics to org average | Medium | Low |
| **Export to CSV/Excel** | Export findings, test results for external analysis | Low | Medium |

---

## 17. Collaboration & Workflow

| Feature | Description | Effort | Priority |
|---------|-------------|--------|----------|
| **Comments on findings** | Threaded comments, @mentions | Medium | High |
| **Assignment workflow** | Assign finding to dev; notify on assignment | Low | High |
| **Approval workflow** | Finding requires approval before "accepted" | Medium | Low |
| **Shared notes** | Project-level or finding-level notes | Low | Medium |
| **Activity feed** | Recent changes across project | Medium | Medium |

---

## 18. DevOps & CI/CD

| Feature | Description | Effort | Priority |
|---------|-------------|--------|----------|
| **CI/CD webhook** | Trigger scan on pipeline event | Medium | High |
| **Quality gates** | Fail build if critical findings > threshold | High | High |
| **Pipeline status** | Report scan status to GitLab/GitHub Actions | Medium | Medium |
| **SAST integration** | Import Semgrep, CodeQL, Bandit results | High | Medium |
| **Dependency scanning** | Import Snyk, Dependabot, Trivy results | High | Medium |
| **Container scanning** | Import Trivy, Grype image scan results | High | Low |

---

## 19. UX Enhancements

| Feature | Status | Description | Effort | Priority |
|---------|--------|-------------|--------|----------|
| **Keyboard shortcuts** | ❌ Not | Power-user shortcuts (e.g., j/k navigation) | Low | Medium |
| **Bulk actions** | ❌ Not | Bulk update status, bulk assign, bulk export | Medium | High |
| **Advanced filters** | ⚠️ Partial | Backend: severity, recheck_status, status, date; frontend: severity/recheck in API, client filters in vulnerabilities page | — | — |
| **Saved views** | ❌ Not | Save filter presets (e.g., "My critical findings") | Medium | Medium |
| **Dark/light theme toggle** | ✅ Done | User preference (theme in layout) | — | — |
| **Reduced motion** | ❌ Not | Accessibility: respect prefers-reduced-motion | Low | Low |

---

## 20. Security & Compliance (Extended)

| Feature | Description | Effort | Priority |
|---------|-------------|--------|----------|
| **SSO (SAML/OIDC)** | Enterprise single sign-on | High | Medium |
| **Report encryption** | Encrypt sensitive reports at rest | Medium | Low |
| **Data retention** | Auto-archive/delete old projects per policy | Medium | Low |
| **RBAC refinement** | Per-phase, per-finding-type permissions | Medium | Medium |
| **Audit log export** | Export audit logs for compliance | Low | Medium |
| **IP allowlist** | Restrict admin access by IP | Low | Low |

---

## 21. Future Roadmap (Proposed Additions)

| Feature | Status | Description | Effort | Priority |
|---------|--------|-------------|--------|----------|
| **SMTP notifications** | ✅ Done | Email alerts on critical findings | — | — |
| **Slack webhook** | ✅ Done | Webhook on critical finding | — | — |
| **Microsoft Teams** | ❌ Not | Incoming webhook for Teams channels | Low | Medium |
| **Burp XML import** | ✅ Done | Import findings from Burp Suite XML export | — | — |
| **CI/CD webhook** | ❌ Not | Outgoing webhook on project completion; API key for automated runs | Medium | High |
| **Nuclei integration** | ❌ Not | Run Nuclei, import results as findings | High | Critical |
| **ZAP integration** | ❌ Not | Import OWASP ZAP scan results | Medium | High |
| **DefectDojo sync** | ❌ Not | Push findings to DefectDojo for compliance | High | Medium |
| **GitHub Issues** | ❌ Not | Create GitHub issue from finding | Medium | Medium |
| **Signed report hash** | ✅ Done | SHA-256 in report footer for integrity | — | — |
| **Report scheduling** | ❌ Not | Weekly/monthly digest | Medium | Medium |
| **Redis caching** | ✅ Done | Cache project list (60s TTL) | — | — |
| **Custom test case library** | Org-specific test cases | Medium | Medium |
| **API-first** | Full REST API for CI/CD, third-party tools | High | Critical |

---

## 22. Long-Term Vision

- **Platform as a service** — Multi-tenant SaaS with org isolation (partially done).
- **API-first** — Full REST API for CI/CD and third-party tools.
- **Mobile companion** — Lightweight mobile app for testers on the go.
- **Compliance automation** — Auto-map findings to compliance frameworks (mapping done; automation partial).
- **Fully automated testing** — One-click run all tests; tools execute, parse, create findings; human reviews and approves.

---

## 23. Implementation Priority (Phased Plan)

### Phase 1 — Test Automation Foundation (Critical)
1. Variable substitution (`{{TARGET}}`, etc.) in tool_commands
2. Single test execution (run one test, capture output)
3. Celery task for async execution
4. Output parsing (pass_indicators/fail_indicators or regex)
5. "Run test" / "Run phase" UI with WebSocket progress

### Phase 2 — Tool Runners
1. Nuclei runner + JSON parsing → findings
2. Burp XML import
3. ZAP import
4. curl/script runner with variable substitution

### Phase 3 — Automation Completeness
1. Batch execution (all tests, all phase)
2. Auto-finding from failed test
3. Dynamic wordlist URLs (Download from Navigator)
4. Scheduled scans
5. Webhook trigger

### Phase 4 — Notifications & Integrations
1. SMTP, Slack, Teams webhooks
2. CI/CD webhook
3. REST API (full)
4. DefectDojo, GitHub Issues

### Phase 5 — Polish
1. Redis caching, pagination
2. Analytics dashboard
3. Comments, bulk actions
4. SSO, RBAC refinement

---

## 24. Additional Automation & Edge Cases

| Feature | Description | Effort | Priority |
|---------|-------------|--------|----------|
| **Applicability filtering** | Skip tests that don't apply (e.g., no GraphQL → skip GraphQL tests) | Medium | High |
| **Test timeout** | Per-test timeout to avoid hung processes | Low | High |
| **Retry logic** | Retry flaky tests (e.g., network timeout) | Low | Medium |
| **Resource limits** | CPU/memory limits per test (e.g., via cgroups) | Medium | Medium |
| **Scope/allowlist** | Only scan allowed URLs; block dangerous targets | Medium | High |
| **Rate limiting (scan)** | Throttle requests to avoid DoS on target | Low | High |
| **Evidence auto-attach** | Attach tool output file (e.g., nuclei JSON) to test result | Low | High |
| **Copy command to clipboard** | One-click copy tool_commands for manual run | Low | Low |
| **Custom tool runners** | User-defined scripts to run + parse custom tools | High | Low |

---

## 24b. Methodology & Compliance

| Feature | Description | Effort | Priority |
|---------|-------------|--------|----------|
| **Custom methodology** | Org-defined phases/modules beyond OWASP WSTG | High | Low |
| **PTES / NIST / SANS** | Import test cases from other frameworks | Medium | Medium |
| **Compliance report** | Map findings to NIST 800-53, SOC2, ISO 27001 controls | Medium | High |
| **Scope validation** | Mark URLs in-scope vs out-of-scope; validate scan targets | Medium | High |
| **Finding templates** | Pre-defined templates for common vuln types | Low | Medium |
| **False positive workflow** | Mark as FP with justification; exclude from report | Low | High |
| **Severity override** | Override AI severity with justification + audit | Low | Medium |

---

## 24c. Data & Lifecycle

| Feature | Description | Effort | Priority |
|---------|-------------|--------|----------|
| **Project clone** | Duplicate project with findings, test results | Low | Medium |
| **Project archive** | Archive completed projects; read-only access | Low | Medium |
| **Export project** | Full export (JSON/ZIP) for backup or migration | Medium | Medium |
| **Import project** | Import from export file | Medium | Low |
| **Bulk delete** | Delete old projects per retention policy | Low | Low |
| **Report branding** | Org logo, colors, custom footer in reports | Medium | Low |

---

## 25. Summary

**Implemented (✅):**

- Reports: Charts, TOC, live view, evidence embedding, **signed report hash (SHA-256)**.
- Testing: WSTG test cases, payloads in DB, payload sources UI, **Burp XML import**.
- AI: Rule-based + LLM (multi-provider), severity recommendation.
- Integrations: JIRA (env + per-org), **Slack**, **SMTP**, **generic webhook** on critical findings.
- Vulnerability Management: Remediation, recheck workflow, vulnerabilities page.
- Security: MFA (full login flow), audit logs, rate limiting.
- Infra: WebSocket, Celery, Redis broker, **Redis caching** (project list).
- Org: Organizations, super admin, org-scoped settings.
- API: **Versioning** (`/api/v1/`), webhook on finding created.

**Priority next steps (Test Automation):**

1. Variable substitution + single test execution.
2. Celery task + output parsing (pass/fail).
3. Nuclei + Burp + ZAP import.
4. Auto-finding from failed test.
5. Batch run + WebSocket progress.

**Priority next steps (Platform):**

1. REST API (full) with API key auth.
2. Microsoft Teams webhook.
3. Report scheduling.

---

## 26. Master Checklist (All Possible Features)

*Quick reference — every feature that can be implemented.*

| # | Category | Feature |
|---|----------|---------|
| 1 | Report | Charts, TOC, live view, evidence embedding |
| 2 | Report | Signed hash, scheduling, executive PDF, comparison, custom templates |
| 3 | Testing | WSTG test cases, payloads DB, payload sources UI |
| 4 | Testing | Skill tree, leaderboard, time tracking, test case templates |
| 5 | **Automation** | Variable substitution, single/batch execution, Celery queue |
| 6 | **Automation** | Nuclei, ZAP, Burp, ffuf, SQLMap, Nikto, Nmap runners |
| 7 | **Automation** | Output parsing, auto-finding, scheduled scans, webhook trigger |
| 8 | **Automation** | Dynamic wordlists, login flow capture, test dependencies |
| 9 | **Automation** | Timeout, retry, scope/allowlist, applicability filter |
| 10 | Discovery | Subdomain enum, tech fingerprinting, endpoint discovery |
| 11 | AI | Rule-based + LLM, severity recommendation, multi-provider |
| 12 | AI | Report summarization, auto-findings, trend analysis, NL queries |
| 13 | Integrations | JIRA, Slack, Teams, SMTP, DefectDojo, GitHub, ServiceNow |
| 14 | Integrations | Burp/ZAP/Nuclei import, PagerDuty, generic webhook |
| 15 | Vuln Mgmt | Remediation, recheck, vulnerabilities page, compliance mapping |
| 16 | Notifications | SMTP, Slack, Teams, PagerDuty, in-app |
| 17 | API | Full REST API, versioning, webhooks, plugin system |
| 18 | Analytics | Executive dashboard, trends, tester metrics, export |
| 19 | Collaboration | Comments, assignment, approval workflow, activity feed |
| 20 | DevOps | CI/CD webhook, quality gates, SAST, dependency/container scan |
| 21 | UX | Keyboard shortcuts, bulk actions, filters, saved views |
| 22 | Security | MFA, audit, rate limit, SSO, RBAC, encryption, retention |
| 23 | Performance | Redis cache, pagination, lazy load, CDN |
| 24 | Org | Multi-tenant, org settings, super admin |
| 25 | Methodology | Custom methodology, compliance report, scope validation |
| 26 | Data | Clone, archive, export/import, branding |

