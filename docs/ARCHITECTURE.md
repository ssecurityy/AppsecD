# VAPT Navigator — System Architecture

**Last updated:** 2026-02-27

This document describes how the Navigator platform works end-to-end: frontend, backend, database, Redis, and data flow.

---

## 1. High-Level Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              FRONTEND (Next.js)                              │
│  Dashboard │ Projects │ Project Detail │ Test Cases │ Findings │ Live Report │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      │ REST API + WebSocket
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           BACKEND (FastAPI)                                  │
│  Auth │ Projects │ Test Cases │ Findings │ Evidence │ Reports │ AI Assist   │
│  Badges │ Audit │ MFA │ WebSocket │ Organizations │ Payloads               │
└─────────────────────────────────────────────────────────────────────────────┘
                    │                              │
                    ▼                              ▼
         ┌──────────────────┐           ┌──────────────────┐
         │   PostgreSQL     │           │      Redis        │
         │   (Navigator DB) │           │ Celery broker +   │
         │   Port: 5433     │           │ result backend    │
         └──────────────────┘           │ Port: 6379/1     │
                                        └──────────────────┘
```

---

## 2. Backend (FastAPI)

### 2.1 Entry Point

- **File:** `backend/app/main.py`
- **CORS:** Configured via `allowed_origins` (default: localhost:3000)
- **Rate limiting:** SlowAPI (in-memory by default)
- **Routes:** All under `/api/v1` via `api_router`

### 2.2 API Routes

| Router | Prefix | Purpose |
|--------|--------|---------|
| `auth` | `/auth` | Login, register, JWT, refresh |
| `projects` | `/projects` | CRUD projects, onboarding |
| `testcases` | `/test-cases` | Test case library, project test cases, results |
| `findings` | `/findings` | Create/update findings, remediation, JIRA |
| `payloads` | `/payloads` | SecLists, PayloadsAllTheThings |
| `reports` | `/projects/{id}/report` | Download HTML/PDF/DOCX/JSON/CSV, live data |
| `evidence` | `/projects/{id}/evidence` | Upload evidence files |
| `badges` | `/badges` | XP, badges, streak |
| `ai_assist` | `/ai-assist` | CWE/CVSS/remediation suggestions |
| `audit` | `/audit` | Admin audit logs |
| `mfa` | `/mfa` | MFA setup/verify |
| `websocket` | `/ws` | Real-time updates |
| `organizations` | `/organizations` | Multi-tenant orgs |
| `settings` | `/settings` | Admin API key status |

### 2.3 Services

| Service | Purpose |
|---------|---------|
| `report_service` | Build report data, generate HTML/DOCX/PDF |
| `ai_assist_service` | Rule-based + optional LLM (OpenAI) suggestions |
| `compliance_mapping` | OWASP, CWE, MITRE ATT&CK, ISO 27001, NIST 800-53 |
| `applicability_service` | Stack-aware test case applicability |
| `payload_intelligence` | Stack-aware payload suggestions |
| `badge_service` | XP, badges, phase completion |
| `audit_service` | Audit log writes |
| `jira_service` | JIRA issue creation |

---

## 3. Database (PostgreSQL)

**Connection:** `postgresql+asyncpg://...` (async SQLAlchemy)  
**Default DB:** `navigator` on port `5433`

### 3.1 Core Tables

| Table | Purpose |
|-------|---------|
| `users` | Auth, roles (admin/lead/tester/viewer), XP, badges, MFA |
| `organizations` | Multi-tenant orgs |
| `projects` | VAPT projects: app name, URL, scope, lead, testers, status |
| `project_members` | Project ↔ user membership, roles |
| `categories` | Test case categories |
| `test_cases` | Master test case library (OWASP, CWE, phase, payloads) |
| `project_test_results` | Per-project test case results (status, evidence, payload) |
| `findings` | Security findings linked to project + optional test_result |
| `phase_completions` | User phase completion (XP, badges) |
| `audit_logs` | Admin audit trail |

### 3.2 Key Relationships

```
Organization ──┬── User (organization_id)
              └── Project (organization_id)

Project ──┬── ProjectMember (project_id, user_id)
          ├── ProjectTestResult (project_id, test_case_id)
          ├── Finding (project_id, test_result_id?)
          └── Evidence files (stored under uploads/{project_id}/)

TestCase ── Category (category_id)
ProjectTestResult ── TestCase
Finding ── ProjectTestResult (optional, for evidence linkage)
```

### 3.3 What We Store

- **Projects:** Application metadata, scope, dates, stack profile, applicable categories, counts (total/tested/passed/failed/na)
- **Test results:** Status (not_started, passed, failed, na, blocked), evidence `[{filename, url}]`, payload, notes
- **Findings:** Title, severity, OWASP, CWE, CVSS, status, remediation, evidence URLs, compliance mapping
- **Evidence:** Files stored in `uploads_path/{project_id}/`, URLs in `ProjectTestResult.evidence` and `Finding.evidence_urls`

---

## 4. Redis

**URL:** `redis://127.0.0.1:6379/1` (configurable via `REDIS_URL`)

### 4.1 Usage

| Component | Purpose |
|-----------|---------|
| **Celery broker** | Task queue for async report generation (DOCX, PDF) |
| **Celery backend** | Store task results |

### 4.2 Celery Tasks

- **`generate_report_async`** — Generates DOCX/PDF in background; called when user requests async report download.

### 4.3 Rate Limiting

- SlowAPI uses in-memory storage by default (not Redis). For multi-instance deployments, configure Redis-backed storage.

---

## 5. Frontend (Next.js)

### 5.1 Structure

```
frontend/src/
├── app/                    # App Router pages
│   ├── page.tsx            # Landing
│   ├── dashboard/          # Dashboard
│   ├── projects/           # Projects list, [id] detail, new, [id]/report
│   ├── payloads/           # Payload browser
│   ├── seclists/           # SecLists browser
│   ├── login/
│   └── admin/              # Users, audit, settings
├── components/             # Navbar, shared UI
└── lib/                    # api.ts, store.ts (Zustand auth)
```

### 5.2 Key Pages

| Route | Purpose |
|-------|---------|
| `/` | Landing |
| `/dashboard` | User dashboard |
| `/projects` | Project list |
| `/projects/new` | Full onboarding wizard |
| `/projects/[id]` | Project detail: test cases, findings, report dropdown |
| `/projects/[id]/report` | **Live report view** — charts, exec summary, findings |
| `/admin/users` | User management |
| `/admin/audit` | Audit logs |
| `/admin/settings` | API key status, JIRA/AI config |

### 5.3 State & API

- **Auth:** Zustand store (`useAuthStore`), JWT in cookies/localStorage
- **API client:** `lib/api.ts` — `api.getProjects()`, `api.getReportData(id)`, etc.
- **Charts:** Recharts (live report page)

---

## 6. Data Flow Examples

### 6.1 Report Generation

1. User clicks "Download HTML" on project page.
2. Frontend calls `GET /api/v1/projects/{id}/report?format=html`.
3. Backend loads project, findings, phases; builds report data via `report_service.build_report_data`.
4. `report_service.generate_html` produces HTML with Chart.js (severity doughnut, OWASP bar), table of contents, executive summary.
5. Response: HTML file download.

### 6.2 Live Report View

1. User clicks "Live Report" on project page → navigates to `/projects/[id]/report`.
2. Frontend calls `GET /api/v1/projects/{id}/report/data`.
3. Backend returns JSON: project, findings (with evidence from test results), phases, risk_score, severity_distribution, owasp_mapping, cwe_mapping.
4. Frontend renders Recharts (pie, bar), executive summary, findings table, refresh/download actions.

### 6.3 Finding + Evidence

1. Tester runs test case, uploads evidence via `/projects/{id}/evidence`.
2. Evidence stored in `uploads/{project_id}/`, URL saved in `ProjectTestResult.evidence`.
3. Tester creates finding, links to test result (`test_result_id`).
4. Report joins finding → test result → evidence for screenshots in HTML/DOCX/PDF.

### 6.4 AI Assist

1. User clicks "AI Suggest" on finding form.
2. Frontend calls `POST /api/v1/ai-assist` with title/description.
3. If `OPENAI_API_KEY` set: LLM suggests CWE, CVSS, remediation.
4. Else: rule-based keyword matching.
5. Response populates form fields.

---

## 7. File Storage

| Path | Purpose |
|------|---------|
| `uploads_path/{project_id}/` | Evidence files (images, etc.) |
| `payloads_path` | PayloadsAllTheThings repo |
| `seclists_path` | SecLists repo |

---

## 8. Security

- **Auth:** JWT, optional MFA for admin
- **Roles:** admin, lead, tester, viewer — project-level permissions via `ProjectMember`
- **Rate limiting:** SlowAPI on auth and sensitive endpoints
- **Audit:** Admin actions logged to `audit_logs`

---

## 9. Ports (Navigator Only)

| Service | Port |
|---------|------|
| Frontend (Next.js) | 3000 |
| Backend (FastAPI) | 5001 |
| PostgreSQL (Navigator) | 5433 |
| Redis | 6379 |

*Do not modify ports used by other applications (e.g., dedsec-training, CyberSentinal, PM2 5000).*
