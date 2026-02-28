# VAPT Navigator — Implementation Status vs Plan

**Last updated:** 2026-02-27

This document audits what is implemented vs. the Feature Gap Plan, with frontend mapping, API key requirements, and admin configuration instructions.

---

## Summary: Implemented vs. Not Implemented

| Tier | Feature | Status | Backend | Frontend | API Key Required |
|------|---------|--------|---------|----------|------------------|
| 1 | Report Generation | ✅ Done | `reports.py`, `report_service.py` | Report dropdown on project page | No |
| 2 | Full Report Formats | ✅ Done | HTML, DOCX, PDF, JSON, CSV | Same | No |
| 3 | Executive Report | ✅ Done | Risk score, OWASP/CWE in report | In report | No |
| 4 | Evidence Storage | ✅ Done | `evidence.py` | Upload in test case cards | No |
| 5 | Complete Onboarding | ✅ Done | `projects.py`, migration 004 | `projects/new/page.tsx` | No |
| 6 | Achievement Badges | ✅ Done | `badge_service.py`, `badges.py` | Navbar, toast | No |
| 7 | Phase Completion | ✅ Done | `test_cases.py`, `phase_completion.py` | Toast on phase complete | No |
| 8 | Celebration UI | ✅ Done | — | Phase complete toast | No |
| 9 | Progress Bar | ✅ Done | — | Project page | No |
| 10 | Streak & Daily Bonus | ✅ Done | `findings.py`, `auth.py`, migration 006 | — | No |
| 11 | Skill Tree | ❌ Not | — | — | No |
| 12 | AI Assist | ⚠️ Partial | `ai_assist_service.py` (rule-based) | `projects/[id]/page.tsx` "AI Suggest" | **Yes** — for LLM mode |
| 13 | Applicability Scoring | ✅ Done | `applicability_service.py` | Project test cases | No |
| 14 | Payload Intelligence | ✅ Done | `payload_intelligence.py` | Project test cases | No |
| 15 | Severity Recommendation | ⚠️ Partial | In rule-based AI | Same as AI Assist | **Yes** — for LLM mode |
| 16 | Compliance Mapping | ✅ Done | `compliance_mapping.py` | In report | No |
| 17 | Organizations | ✅ Done | `organizations.py`, migration 009 | — | No |
| 18 | Audit Logs | ✅ Done | `audit.py`, `audit_service.py` | `/admin/audit` | No |
| 19 | MFA | ✅ Done | `mfa.py`, migration 008 | — | No |
| 20 | Rate Limiting | ✅ Done | `limiter.py` | — | No |
| 21 | WebSocket | ✅ Done | `websocket.py` | — | No |
| 22 | Celery | ✅ Done | `celery_app.py`, `tasks.py` | — | No |
| 23 | JIRA | ✅ Done | `jira_service.py` | JIRA button in Findings panel | **Yes** — env vars |
| 24 | Remediation Tracking | ✅ Done | `findings.py` | Status dropdown in Findings panel | No |
| 25 | CI/CD Integration | ❌ Not | — | — | No |
| 26–30 | Future (Burp, Screenshot, etc.) | ❌ Not | — | — | No |

---

## API Key & Configuration Requirements

### 1. AI Assist (LLM Mode)

**Current:** Rule-based mode works without any API key. Keyword matching → CWE, CVSS, impact, remediation.

**Optional LLM mode:** Admin can configure model and API key from `/admin/settings` (stored encrypted in DB). Falls back to `OPENAI_API_KEY` in `.env` if not set in Admin Settings. Falls back to rule-based if no key available.

| Where to Add | File | Variable |
|--------------|------|----------|
| **Admin UI** | `/admin/settings` | Select model, set/replace API key (recommended) |
| **Environment** | `backend/.env` | `OPENAI_API_KEY=sk-...` (fallback) |

**No API key:** Rule-based mode (always works).  
**With API key (Admin or env):** LLM mode with selected model (gpt-4o-mini, gpt-4o, etc.).

---

### 2. JIRA Integration

| Where to Add | File | Variable |
|--------------|------|----------|
| **Environment** | `backend/.env` | `JIRA_BASE_URL=https://yourorg.atlassian.net` |
| | | `JIRA_EMAIL=your@email.com` |
| | | `JIRA_API_TOKEN=<Atlassian API token>` |
| | | `JIRA_PROJECT_KEY=PROJ` |

**Get JIRA API token:** Atlassian Account → Security → API tokens.

**Frontend:** "JIRA" button in Remediation Tracking panel per finding.

---

### 3. Celery (Async Reports)

**Broker:** Uses `REDIS_URL` (same as app). Default: `redis://127.0.0.1:6379/1`.

**Start worker:**
```bash
cd /opt/navigator/backend && source venv/bin/activate
celery -A app.celery_app worker -l info
```

---

## Frontend Mapping

| Feature | Frontend Location | Component / Action |
|---------|-------------------|--------------------|
| Report | `projects/[id]/page.tsx` | Report dropdown → Download HTML/PDF/DOCX/JSON/CSV |
| Evidence | `projects/[id]/page.tsx` | Test case card → Evidence upload |
| AI Suggest | `projects/[id]/page.tsx` | Finding form → "✨ AI Suggest CWE/Remediation" |
| Findings | `projects/[id]/page.tsx` | "Findings" button → Remediation Tracking panel |
| JIRA | `projects/[id]/page.tsx` | Findings panel → "JIRA" button per finding |
| Audit | `admin/audit/page.tsx` | Admin → Audit |
| Users | `admin/users/page.tsx` | Admin → Users |
| Badges | `components/Navbar.tsx` | Badge icons in header |
| XP | `components/Navbar.tsx` | XP display |
| New Project | `projects/new/page.tsx` | Full onboarding wizard |

---

## Not Implemented / Partial

| Feature | Status | Notes |
|---------|--------|-------|
| **Skill Tree** | Not | Phase-based unlock UI; optional progression tree |
| **AI Assist (LLM)** | Done | Admin configures model + API key in Settings; env fallback |
| **Severity Recommendation (AI)** | Partial | Same as AI Assist |
| **CI/CD Integration** | Not | Webhook for scan completion; API key for automated runs |
| **Burp XML Import** | Not | Import findings from Burp Suite XML |
| **Screenshot Embedding** | Not | Attach screenshots to findings |
| **Signed Report Hash** | Not | SHA-256 hash for report integrity |
| **Organization Leaderboard** | Not | XP leaderboard per org |
| **MFA Login UI** | Partial | Backend ready; login flow not enforced |

---

## Admin Settings Page

**Path:** `/admin/settings` (admin only)

**Purpose:**
- Show API key / integration status (masked)
- Show where to add keys (env vars)
- Test JIRA connection
- Test AI (rule-based vs LLM)

---

## Quick Reference: Environment Variables

```bash
# backend/.env

# Database
DATABASE_URL=postgresql+asyncpg://...

# Redis
REDIS_URL=redis://127.0.0.1:6379/1

# JIRA (optional)
JIRA_BASE_URL=https://yourorg.atlassian.net
JIRA_EMAIL=your@email.com
JIRA_API_TOKEN=your_token
JIRA_PROJECT_KEY=PROJ

# AI (optional — enables LLM mode for AI Assist)
OPENAI_API_KEY=sk-...
```
