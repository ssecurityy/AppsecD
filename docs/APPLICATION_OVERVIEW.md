# VAPT Navigator (AppSecD) — Application Overview & Benefits

**Document Version:** 1.0  
**Date:** 2026-03-02  
**Purpose:** Comprehensive summary of what the application does, all features, and benefits over traditional manual application security testing.

---

## 1. What This Application Does

**VAPT Navigator** (also branded as **AppSecD**) is an **intelligent web application security testing platform** that combines **guided manual penetration testing** with **automated DAST (Dynamic Application Security Testing)**. It is designed for security teams, pentesters, and developers who need to:

- Run structured security assessments aligned with OWASP WSTG methodology
- Track test results, findings, and remediation in one place
- Generate professional reports for stakeholders
- Use AI/LLM to accelerate finding classification, payload crafting, and test case generation
- Automate many security checks via integrated DAST scanning
- Manage vulnerabilities through a full lifecycle (discovery → fix → recheck)

Unlike traditional approaches (spreadsheets, standalone tools, ad-hoc workflows), Navigator provides a **unified, gamified, trackable platform** that guides testers through phases while capturing evidence, linking findings to tests, and producing audit-ready reports.

---

## 2. Feature Summary

### 2.1 Core Workflow

| Feature | Description |
|---------|-------------|
| **Projects** | Create VAPT engagements with app name, URL, scope, target dates, tech stack |
| **Test Case Library** | 180+ test cases (OWASP WSTG, seed tests, LLM-generated) organized by phase |
| **Phase-Based Testing** | 10 phases: recon, pre_auth, auth, post_auth, business, api, client, transport, infra, tools |
| **Test Results** | Mark each test as Passed / Failed / N/A / Blocked; attach evidence, payloads, notes |
| **Findings** | Create vulnerabilities from failed tests; link to evidence; track severity, CWE, OWASP |
| **Evidence** | Upload screenshots, files; embed in reports |
| **Progress Tracking** | Visual progress bar, phase completion, tested/passed/failed counts per phase |

### 2.2 AI & LLM Features

| Feature | Description | Fallback |
|---------|-------------|----------|
| **Finding Suggestions** | AI suggests CWE, CVSS, impact, remediation from title/description | Rule-based keyword matching |
| **Auto-Suggest from Failed Test** | When test fails, one-click pre-filled finding with AI classification | Rule-based |
| **Payload Crafting** | AI generates enhanced, obfuscated payloads (WAF bypass, encodings) | Original payloads |
| **Report Executive Summary** | LLM generates 3–4 sentence project-specific exec summary | Static template |
| **Test Case Generation** | LLM creates test cases from app type, tech stack, focus areas | — |
| **Security Assistant** | Chat-style "How do I test for X?" with CVE context, test library | — |
| **LLM Config** | Per-org provider (OpenAI, Anthropic, Google), model, encrypted API key | — |
| **Advanced AI (Backend Ready)** | Endpoint analysis, similar tests, missing tests, tool commands, result interpretation | — |

### 2.3 Vulnerability Management

| Feature | Description |
|---------|-------------|
| **Vulnerabilities Page** | Dedicated `/projects/[id]/vulnerabilities` for all findings in one view |
| **Status Workflow** | Open → Confirmed → In Progress → Fixed |
| **Recheck Lifecycle** | pending, resolved, not_fixed, partially_fixed, exception, deferred, retest_needed |
| **Recheck Tracking** | Recheck date, notes, assignee; status history |
| **Compliance Mapping** | OWASP Top 10, CWE, MITRE ATT&CK, ISO 27001, NIST 800-53 in reports |
| **JIRA Integration** | Create JIRA issues from findings; bulk create; per-org JIRA config |
| **Burp Import** | Import Burp Suite XML; optional LLM enhancement for severity/CWE mapping |

### 2.4 Automatic Report Generation

| Feature | Description |
|---------|-------------|
| **Formats** | HTML, DOCX (Word), PDF, JSON, CSV |
| **Live Report View** | Interactive page with charts, exec summary, findings table; refresh on demand |
| **Charts** | Severity doughnut, OWASP bar, CWE mapping, phase coverage |
| **Table of Contents** | Clickable navigation in HTML/DOCX |
| **Evidence Embedding** | Screenshots and files embedded in HTML/DOCX/PDF |
| **Signed Hash** | SHA-256 hash in HTML report footer for integrity |
| **AI Summary** | One-click LLM executive summary on report page |
| **Async Generation** | Queue DOCX/PDF in background (Celery); poll for download when ready |
| **Organization Branding** | Logo, company name in reports when configured |

### 2.5 DAST (Automated Security Scanning)

| Feature | Description |
|---------|-------------|
| **41 Automated Checks** | Security headers, SSL/TLS, cookies, CORS, recon (robots, sitemap, dir listing), injection (XSS, SQLi), HTTP methods, rate limiting, sensitive data, and more |
| **Crawler** | Katana crawl + Arjun parameter discovery + optional Playwright for JS/SPA |
| **Directory Discovery** | ffuf scans; recursive dir scan with persistence |
| **Scan Progress** | Real-time progress; history; latest results per project |
| **Auto-Findings** | Failed checks → auto-create findings with request/response evidence |
| **Test Sync** | DAST results map to ProjectTestResult; auto-mark test cases passed/failed |
| **Auth Support** | Bearer token, header, cookie for authenticated scans |

### 2.6 Integrations & Notifications

| Feature | Description |
|---------|-------------|
| **JIRA** | Create issues from findings; per-org JIRA URL, project, API token |
| **Slack** | Webhook on critical/high findings; configurable per org |
| **SMTP/Email** | Email alerts on critical/high findings |
| **Generic Webhook** | Outgoing webhook for custom integrations |
| **Burp Suite** | XML import for findings with request/response |

### 2.7 Payloads & Wordlists

| Feature | Description |
|---------|-------------|
| **PayloadsAllTheThings** | Full PAT in PostgreSQL; categories, preview, copy |
| **SecLists** | Discovery, Fuzzing, Passwords, etc.; download, preview |
| **FuzzDB, XSS, SQLi, Nuclei, Intruder, BLNS** | All in DB; no filesystem dependency |
| **Payload Sources UI** | Browse by source; applicable payloads per test |
| **Payload Intelligence** | Stack-aware payload suggestions based on project tech |

### 2.8 Gamification & Engagement

| Feature | Description |
|---------|-------------|
| **XP Points** | Earn XP for findings, phase completion |
| **Achievement Badges** | First finding, phase complete, streak, etc. |
| **Phase Completion** | +100 XP when all tests in a phase are completed |
| **Streak & Daily Bonus** | Consecutive-day engagement rewards |
| **Progress Visualization** | Phase overlay on project; completion percentage |

### 2.9 Security Intelligence

| Feature | Description |
|---------|-------------|
| **CVE Feed** | Multi-source CVE sync (NVD, GitHub, etc.); search by CVE ID |
| **CVE in Assistant** | Relevant CVEs injected into Security Assistant context |
| **Test Case Generation** | LLM generates tests from app type, stack, focus |
| **Security Assistant** | Chat with test library, CVEs, project context; add suggested tests |
| **Dashboard** | Security Intel overview; CVE counts, recent activity |

### 2.10 Administration & Multi-Tenancy

| Feature | Description |
|---------|-------------|
| **Organizations** | Multi-tenant; org-scoped projects, users, settings |
| **Roles** | super_admin, admin, lead, tester, viewer; project-level membership |
| **Audit Logs** | Admin actions; user management; settings changes |
| **MFA** | TOTP-based; admin can enable per user |
| **Admin Settings** | LLM (provider, model, API key), JIRA, notifications (Slack, SMTP, webhook) |
| **User Management** | Create, edit, assign to orgs; password reset |

### 2.11 Security & Performance

| Feature | Description |
|---------|-------------|
| **JWT Auth** | Login, refresh; secure cookies |
| **Rate Limiting** | SlowAPI on auth and sensitive endpoints |
| **Redis Caching** | Project list cache; Celery broker for async tasks |
| **WebSocket** | Real-time project updates |
| **Health Endpoints** | `/health`, `/health/ready` for liveness/readiness |

---

## 3. Benefits Over Traditional Manual AppSec

### 3.1 Traditional Manual AppSec Pain Points

| Pain Point | Description |
|------------|-------------|
| **No structure** | Ad-hoc checklists; easy to miss tests; no phase discipline |
| **Scattered evidence** | Screenshots in folders; no link between test and finding |
| **Manual report writing** | Hours spent on Word/PDF; inconsistent format; copy-paste errors |
| **Slow finding write-up** | Manual CWE/CVSS lookup; generic remediation text |
| **No visibility** | Spreadsheets; no real-time progress; managers don’t see status |
| **Tool sprawl** | Burp, ZAP, Nuclei, ffuf—results live in separate tools |
| **No remediation tracking** | Fixes unclear; no recheck workflow |
| **Knowledge silos** | Junior testers lack guidance; no "how to test X" assistant |

### 3.2 How Navigator Addresses These

| Benefit | How Navigator Helps |
|---------|---------------------|
| **Structured methodology** | OWASP WSTG phases; 180+ curated test cases; guided flow |
| **Centralized evidence** | Evidence linked to test results and findings; embedded in reports |
| **Automatic reports** | HTML, DOCX, PDF, JSON, CSV; charts, TOC, SHA-256; one-click download |
| **AI-accelerated findings** | CWE, CVSS, remediation suggested by AI; auto-suggest from failed tests |
| **Real-time progress** | Progress bar, phase completion, tested/passed/failed; WebSocket updates |
| **Unified tooling** | DAST built-in; Burp import; payloads in DB; Security Intel for context |
| **Full remediation workflow** | Recheck status, notes, dates; vulnerabilities page for tracking |
| **On-demand expertise** | Security Assistant answers "How do I test X?" with library + CVE context |
| **Gamification** | XP, badges, streaks; encourages consistent engagement |
| **Multi-tenant** | Orgs, projects, roles; suitable for MSSPs and enterprises |

### 3.3 Quantitative Benefits (Typical)

| Metric | Traditional | With Navigator |
|--------|-------------|----------------|
| Report generation | 2–4 hours | &lt; 1 minute (download) |
| Finding classification | 5–10 min per finding | ~30 sec (AI suggest) |
| Payload research | 15–30 min per test | Seconds (AI Enhance) |
| Progress visibility | Weekly status meetings | Real-time dashboard |
| Test coverage consistency | Varies by tester | Standardized library |
| Recheck tracking | Email/Excel | Dedicated workflow |

---

## 4. Application Architecture (Brief)

```
┌─────────────────────────────────────────────────────────────────────────┐
│  FRONTEND (Next.js 14)                                                   │
│  Dashboard │ Projects │ Test Cases │ Findings │ Report │ DAST │ Admin   │
└─────────────────────────────────────────────────────────────────────────┘
                                      │ REST API + WebSocket
                                      ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  BACKEND (FastAPI)                                                       │
│  Auth │ Projects │ Test Cases │ Findings │ Reports │ AI Assist │ DAST   │
│  Security Intel │ JIRA │ Notifications │ Payloads │ Organizations       │
└─────────────────────────────────────────────────────────────────────────┘
                    │                              │
                    ▼                              ▼
         ┌──────────────────┐           ┌──────────────────┐
         │   PostgreSQL     │           │      Redis       │
         │   (Port 5433)    │           │ Celery + Cache   │
         └──────────────────┘           └──────────────────┘
```

- **Frontend:** Next.js 14, Tailwind, Zustand (auth)
- **Backend:** FastAPI, SQLAlchemy async, Celery
- **Data:** PostgreSQL 16, Redis, file storage for evidence
- **Ports:** Frontend 3000, Backend 5001

---

## 5. Key User Journeys

### 5.1 Create Project & Run Tests

1. Create project (app name, URL, scope, stack)
2. Assign testers; project gets test case library
3. Testers work through phases; mark Pass/Fail; upload evidence
4. Failed test → Create Finding (AI suggest for CWE/remediation)
5. Generate report (HTML/DOCX/PDF) or view Live Report

### 5.2 Run DAST Scan

1. Open project → DAST tab
2. Optionally run crawl first (Katana + Arjun)
3. Select checks or run all; start scan
4. View results; failed checks auto-create findings
5. DAST results sync to ProjectTestResult (test cases marked)

### 5.3 Manage Vulnerabilities

1. Go to Vulnerabilities page
2. View all findings; filter by status, severity
3. Update status (Open → In Progress → Fixed)
4. Trigger recheck; record result (resolved, not_fixed, etc.)
5. Create JIRA issue; notify via Slack/email on critical/high

### 5.4 Get AI Help

1. **Finding:** Click "AI Suggest" → CWE, CVSS, remediation populated
2. **Payloads:** Click "AI Enhance" on test case → 5 enhanced payloads
3. **Report:** Click "AI Summary" on report page → exec summary generated
4. **Security Intel:** Ask "How do I test for IDOR?" → step-by-step + test cases
5. **Test cases:** Generate tests from app type, stack, focus areas → add to project

---

## 6. Summary

**VAPT Navigator** is a **unified AppSec platform** that:

- **Guides** testers through OWASP-aligned phases with 180+ test cases  
- **Automates** 41+ DAST checks, crawling, and directory discovery  
- **Accelerates** findings with AI (CWE, CVSS, payloads, reports)  
- **Manages** vulnerabilities from discovery to recheck  
- **Produces** professional reports in HTML, DOCX, PDF, JSON, CSV  
- **Integrates** with JIRA, Slack, SMTP, webhooks, Burp Suite  
- **Scales** with organizations, roles, and multi-tenancy  

It reduces manual effort, improves consistency, and provides visibility that traditional spreadsheets and standalone tools cannot match.

---

*End of document.*
