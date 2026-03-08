# CI/CD Pipeline: SAST + AI → Build → Incremental DAST

**Document Version:** 1.0  
**Date:** 2026-03-02  
**Purpose:** Complete guide to automating security testing in a continuous development flow—similar to Cursor/dev mode—where each merge to `main` triggers SAST (AI + Semgrep), build, and **incremental** DAST testing of only the changed features against Navigator's DAST rules.

---

## 1. Overview: Cursor-Style Continuous Development

### 1.1 The Analogy

| Cursor Development Mode | This Automation Pipeline |
|-------------------------|--------------------------|
| Edit code → Auto-save, hot reload | Push/merge → Trigger pipeline |
| AI assists as you type | AI + Semgrep SAST before build |
| Immediate feedback in IDE | Immediate feedback in CI |
| Focus on what changed | **Incremental DAST** — test only changed features |

### 1.2 Target Flow

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│  DEVELOPER                                                                       │
│  Push / Merge to main (new feature, bug fix, refactor)                           │
└─────────────────────────────────────────────────────────────────────────────────┘
                                        │
                                        ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│  GITHUB (or GitLab, etc.)                                                        │
│  Webhook / GitHub Actions triggered on push to main (or PR merge)                │
└─────────────────────────────────────────────────────────────────────────────────┘
                                        │
                    ┌───────────────────┼───────────────────┐
                    ▼                   ▼                   ▼
┌───────────────────────┐  ┌───────────────────────┐  ┌───────────────────────┐
│  STEP 1: SAST         │  │  STEP 2: BUILD        │  │  STEP 3: DAST         │
│  AI + Semgrep         │  │  Build application    │  │  Incremental scan     │
│  - Semgrep scan       │  │  - npm build, etc.    │  │  - Only new/changed   │
│  - AI code review     │  │  - Deploy to target   │  │    routes/features    │
│  - Custom rules       │  │  - Get target URL     │  │  - Navigator DAST API │
└───────────────────────┘  └───────────────────────┘  └───────────────────────┘
                    │                   │                   │
                    └───────────────────┼───────────────────┘
                                        ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│  RESULT                                                                          │
│  - SAST findings → block or warn                                                  │
│  - Build failure → block                                                          │
│  - DAST findings → report to Navigator; optional quality gate                     │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### 1.3 Key Principle: Incremental DAST

- **Full scan (baseline):** Run all 41+ DAST checks on entire app (e.g., weekly, or on first setup).
- **Incremental scan (per merge):** Run only DAST checks relevant to **changed features** — specific routes, API endpoints, or UI paths.

**Benefits:**
- Faster pipelines (minutes vs 30–60 min full scan)
- Lower alert fatigue (only new vulnerabilities)
- Cost-effective (less compute, API usage)
- Same methodology, smaller scope

---

## 2. Step-by-Step Breakdown

### 2.1 Step 1: SAST with AI + Semgrep

#### 2.1.1 Semgrep (Rule-Based SAST)

| Aspect | Details |
|--------|---------|
| **What** | Static analysis of source code; pattern matching for vulnerabilities |
| **How** | `semgrep scan --config auto` or custom rules |
| **Triggers** | Push, PR; **diff-aware** — can scan only changed files |
| **Output** | JSON/SARIF; findings with rule ID, severity, file:line |

**Resources:**
- [Semgrep](https://semgrep.dev/) — Open source, free tier
- [Semgrep Registry](https://semgrep.dev/explore) — OWASP, CWE, language-specific rules
- [GitHub Actions: semgrep-action](https://github.com/marketplace/actions/semgrep) or `semgrep ci`

#### 2.1.2 AI in SAST (Semgrep + LLM)

| Role | Description |
|------|-------------|
| **Semgrep Assistant** | GPT-4 powered: triage, autofix, custom rule creation from human language |
| **Navigator LLM** | Optional: post-process Semgrep findings → enrich severity, CWE, remediation via `/ai-assist/suggest` |
| **Custom rules** | "Create rule for X" in plain language → Semgrep rule |

**Flow:**
1. Semgrep runs on diff (changed files only) or full repo.
2. Findings → optional: send to Navigator AI for enrichment.
3. Quality gate: block merge if critical/high; or warn only.

#### 2.1.3 Navigator PR Security Review (GitHub App & Webhook)

Navigator can run a **diff scan** on pull requests and post review comments and commit status. Configure a GitHub App or webhook for the repository.

| Item | Details |
|------|---------|
| **Webhook** | In SAST → CI/CD, copy the PR webhook URL (e.g. `/api/sast/webhook/pr/{project_id}`). In GitHub repo → Settings → Webhooks, add this URL and subscribe to **Pull requests**. |
| **GitHub App permissions** | **Repository:** Contents (read), Metadata (read). For PR review and status checks: **Pull requests** (read & write), **Commit statuses** (read & write). |
| **Run scan on new commit** | On push or PR event, GitHub sends the webhook; Navigator runs the diff scan and posts the review. No extra polling needed. |
| **Policy** | In SAST → Policy, set **Audit** (comment only, status passes) or **Block** (request changes and fail status when critical/high findings). |

Scan metadata (commit SHA, branch) is stored and shown in the Results → Scan Metadata section.

### 2.2 Step 2: Build Application

| Aspect | Details |
|--------|---------|
| **Purpose** | Produce runnable application to test |
| **Examples** | `npm run build`, `docker build`, `mvn package`, etc. |
| **Deploy** | To staging/preview URL (e.g., Vercel preview, K8s ephemeral, Docker) |
| **Output** | Target URL for DAST (e.g., `https://preview-abc123.vercel.app`) |

**Important:** DAST needs a **live URL**. Options:
- Ephemeral preview (Vercel, Netlify, K8s preview)
- Staging server (always-on)
- Local + ngrok/tunnel (limited)

### 2.3 Step 3: Incremental DAST

#### 2.3.1 What Is "Changed Features"?

| Strategy | Description | Complexity |
|----------|-------------|------------|
| **A. Path/Route mapping** | Git diff → changed files → infer routes (e.g., `pages/api/login.ts` → `/api/login`) | Medium |
| **B. OpenAPI/Swagger** | If API has spec, diff spec versions → new/changed endpoints | Low (when spec exists) |
| **C. Feature-flag / PR labels** | PR tagged with feature area (e.g., `auth`, `payments`) → run subset of DAST checks | Low |
| **D. Full scan with scope filter** | Crawl only, then restrict DAST to URLs matching changed paths | Medium |
| **E. Baseline + diff** | Store last full crawl; compare with new crawl → new URLs = incremental scope | High |

#### 2.3.2 Navigator DAST Checks (Subset for Incremental)

Not all 41 checks are "incremental-friendly." Some apply to the whole app (headers, SSL). Others apply per-URL (XSS, SQLi).

| Check Type | Incremental? | Example |
|------------|--------------|---------|
| **App-wide** | Run once per pipeline (or weekly) | security_headers, ssl_tls, robots_txt, cors |
| **Per-URL** | Run only on changed URLs | xss_basic, sqli_error, sensitive_data, form_autocomplete |
| **Per-parameter** | Run on discovered params from changed endpoints | injection checks |

**Incremental subset strategy:**
- **Always run (lightweight):** `security_headers`, `ssl_tls`, `cors`, `robots_txt`, `api_docs_exposure` — ~5 checks.
- **Run on changed paths:** `xss_basic`, `sqli_error`, `sensitive_data`, `form_autocomplete`, `open_redirect`, `crlf_injection` — ~6 checks per URL.
- **Optional (new endpoints only):** Run crawl on target, get new URLs from diff, run per-URL checks on those.

### 2.3.3 Mapping Git Diff → DAST Scope

| Framework | File Pattern | Inferred Route/Feature |
|-----------|--------------|------------------------|
| Next.js | `app/api/**/route.ts` | `/api/*` |
| Next.js | `pages/api/*.ts` | `/api/*` |
| Next.js | `app/**/page.tsx` | `/*` |
| Express | `routes/*.js` | From router definitions |
| Django | `views.py`, `urls.py` | From URL config |
| Spring | `*Controller.java` | From `@RequestMapping` |

**Approach:**
1. Parse git diff for merge: `git diff main~1 main --name-only`
2. Map files → routes using framework conventions or config.
3. Build list: `["/api/login", "/api/users", "/dashboard"]`
4. Call Navigator API with `url_scope` or `checks` + `target_url`.

---

## 3. Required Changes to Navigator

### 3.1 New API: Incoming Webhook for CI Trigger

| Current State | Required |
|---------------|----------|
| No incoming webhook | `POST /api/v1/ci/trigger` — receives webhook from GitHub Actions |

**Payload (example):**
```json
{
  "event": "push",
  "repo": "owner/repo",
  "branch": "main",
  "commit_sha": "abc123",
  "target_url": "https://preview-xyz.vercel.app",
  "scope": {
    "mode": "incremental",
    "paths": ["/api/login", "/api/users", "/dashboard"]
  },
  "project_id": "uuid",
  "api_key": "ci-secret"
}
```

**Behavior:**
- Validate API key (org/project-scoped CI key)
- Create or reuse project; ensure `application_url` = `target_url`
- Start DAST scan with:
  - `target_url` = `target_url`
  - `checks` = subset based on `scope.mode` (full vs incremental)
  - `url_scope` = optional list of paths to limit crawl/scan (new param)

### 3.2 New API Parameter: `url_scope`

| Parameter | Type | Purpose |
|-----------|------|---------|
| `url_scope` | `list[str]` | Only run checks on URLs matching these paths (e.g., `/api/login`, `/api/users`) |

**Implementation:**
- In DAST runner: for each check that fetches a URL, restrict to `url_scope` if provided.
- Crawler: optionally pass `--include-path` or filter discovered URLs before running checks.
- Checks like `security_headers` run once on base URL; per-URL checks iterate only over `url_scope`.

### 3.3 New API Parameter: `scope_mode`

| Value | Behavior |
|-------|----------|
| `full` | Run all checks (current behavior) |
| `incremental` | Run lightweight app-wide + per-URL checks only on `url_scope` |
| `incremental_paths` | Same as incremental; `url_scope` required |

### 3.4 CI API Key

| Purpose | Storage |
|---------|---------|
| Authenticate webhook from GitHub Actions | Project or org setting: `ci_api_key` (hashed) |
| Scope | Project or org |
| Usage | `Authorization: Bearer <ci_api_key>` or `X-CI-Key: <ci_api_key>` |

---

## 4. Resources Required

### 4.1 GitHub / Git Hosting

| Resource | Purpose |
|----------|---------|
| GitHub repo | Source code; webhooks; Actions |
| GitHub Actions (or GitLab CI) | Run Semgrep, build, call Navigator API |
| Webhook secret | Verify webhook origin (optional) |

### 4.2 SAST

| Resource | Purpose |
|----------|---------|
| Semgrep | CLI or GitHub Action; `semgrep scan` or `semgrep ci` |
| Semgrep config | `auto` (default) or custom rules |
| Optional: Semgrep AppSec Platform | Diff-aware scans, AI triage, centralized findings |
| Optional: Navigator LLM | Enrich Semgrep findings via `/ai-assist/suggest` |

### 4.3 Build & Deploy

| Resource | Purpose |
|----------|---------|
| Build runner | GitHub Actions runner, self-hosted, etc. |
| Deploy target | Vercel, Netlify, K8s, Docker, EC2 |
| Preview URL | Unique URL per PR/commit for DAST target |

### 4.4 Navigator (AppSecD)

| Resource | Purpose |
|----------|---------|
| Navigator API | Running DAST scans |
| Project | One per app (or per branch); `application_url` = deploy URL |
| CI API key | Authenticate webhook |
| DAST tools | katana, ffuf, nuclei (if used); installed per [install-dast-tools.sh](../scripts/install-dast-tools.sh) |

### 4.5 Optional: AI

| Resource | Purpose |
|----------|---------|
| Semgrep Assistant | AI triage, custom rules (Semgrep Cloud) |
| Navigator LLM | OpenAI/Anthropic/Google for finding enrichment, payload crafting |
| API keys | Stored in Navigator org settings |

---

## 5. Implementation Example: GitHub Actions

### 5.1 Workflow Structure

```yaml
# .github/workflows/security-scan.yml
name: Security Pipeline (SAST + Build + DAST)

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  sast:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # Full history for diff

      - name: Semgrep SAST
        uses: returntocorp/semgrep-action@v1
        with:
          config: auto
          generateSarif: true
        env:
          SEMGREP_APP_TOKEN: ${{ secrets.SEMGREP_APP_TOKEN }}

  build:
    needs: sast
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
      - run: npm ci && npm run build

  deploy-preview:
    needs: build
    if: github.event_name == 'push' && github.ref == 'refs/heads/main'
    runs-on: ubuntu-latest
    steps:
      # Deploy to staging/preview (example: Vercel)
      - name: Deploy
        run: |
          # Your deploy step; output TARGET_URL
          echo "TARGET_URL=https://staging.example.com" >> $GITHUB_ENV

  incremental-dast:
    needs: deploy-preview
    if: github.event_name == 'push' && github.ref == 'refs/heads/main'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 2  # For diff

      - name: Get changed paths
        id: diff
        run: |
          git diff --name-only ${{ github.event.before }} ${{ github.sha }} > changed_files.txt
          # Optionally map to routes (simplified: use all /api, /app paths)
          grep -E '^(app|pages|src)/' changed_files.txt | sed 's|app/|/|; s|pages/|/|' | head -20 > scope_paths.txt
          echo "paths<<EOF" >> $GITHUB_OUTPUT
          cat scope_paths.txt >> $GITHUB_OUTPUT
          echo "EOF" >> $GITHUB_OUTPUT

      - name: Trigger Navigator DAST (incremental)
        run: |
          curl -X POST "${{ secrets.NAVIGATOR_API_URL }}/api/v1/ci/trigger" \
            -H "Authorization: Bearer ${{ secrets.NAVIGATOR_CI_KEY }}" \
            -H "Content-Type: application/json" \
            -d '{
              "event": "push",
              "repo": "${{ github.repository }}",
              "branch": "${{ github.ref_name }}",
              "commit_sha": "${{ github.sha }}",
              "target_url": "${{ env.TARGET_URL }}",
              "scope": {"mode": "incremental", "paths": '"$(cat scope_paths.txt | jq -R -s -c 'split("\n") | map(select(length>0))')"'},
              "project_id": "${{ secrets.NAVIGATOR_PROJECT_ID }}"
            }'
```

### 5.2 Secrets to Configure

| Secret | Purpose |
|--------|---------|
| `SEMGREP_APP_TOKEN` | Semgrep Cloud (optional; for diff-aware, AI) |
| `NAVIGATOR_API_URL` | e.g., `https://appsecd.com/api` or `http://navigator:5001` |
| `NAVIGATOR_CI_KEY` | Project/org CI API key from Navigator |
| `NAVIGATOR_PROJECT_ID` | Navigator project UUID |

---

## 6. Incremental Scan Strategies (Detailed)

### 6.1 Strategy A: Path Mapping from Git Diff

| Step | Action |
|------|--------|
| 1 | `git diff main~1 main --name-only` |
| 2 | Filter: `app/`, `pages/`, `src/routes/`, etc. |
| 3 | Map file → route (convention: `pages/api/login.ts` → `/api/login`) |
| 4 | Deduplicate; cap at N paths (e.g., 20) |
| 5 | Call Navigator with `url_scope: ["/api/login", ...]` |

### 6.2 Strategy B: OpenAPI/Swagger Diff

| Step | Action |
|------|--------|
| 1 | Generate OpenAPI from previous build (or from repo) |
| 2 | Generate OpenAPI from current build |
| 3 | Diff: new/changed endpoints |
| 4 | `url_scope` = list of new/changed paths |
| 5 | Call Navigator with `url_scope` |

### 6.3 Strategy C: PR Labels / Feature Tags

| Step | Action |
|------|--------|
| 1 | Require PR labels: `area:auth`, `area:api`, `area:payments` |
| 2 | Map label → DAST check subset (e.g., `area:auth` → cookie_security, rate_limiting, form_autocomplete) |
| 3 | Call Navigator with `checks: ["cookie_security", "rate_limiting", "form_autocomplete"]` |
| 4 | No `url_scope`; run subset on base URL + common paths |

### 6.4 Strategy D: Crawl Diff (Advanced)

| Step | Action |
|------|--------|
| 1 | Store last full crawl (URLs) in artifact or Navigator |
| 2 | Run new crawl on target |
| 3 | Diff: `new_urls = current_crawl - previous_crawl` |
| 4 | Run per-URL checks only on `new_urls` |
| 5 | Requires Navigator to support "crawl and return URLs" + "run checks on URL list" |

### 6.5 Recommended: Hybrid

- **Every merge:** Run lightweight app-wide checks (5–10) + per-URL checks on diff-mapped paths.
- **Weekly (or scheduled):** Full DAST scan (all 41 checks, full crawl).
- **On demand:** Manual full scan from Navigator UI.

---

## 7. DAST Check → Incremental Suitability

| Check ID | App-Wide | Per-URL | Incremental Use |
|----------|----------|---------|-----------------|
| DAST-HDR-01 | ✅ | | Every run |
| DAST-SSL-01 | ✅ | | Every run |
| DAST-CORS-01 | ✅ | | Every run |
| DAST-ROBO-01 | ✅ | | Every run |
| DAST-API-01 | ✅ | | Every run |
| DAST-XSS-01 | | ✅ | Per `url_scope` |
| DAST-SQLI-01 | | ✅ | Per `url_scope` |
| DAST-PII-01 | | ✅ | Per `url_scope` |
| DAST-FORM-01 | | ✅ | Per `url_scope` |
| DAST-REDIR-01 | | ✅ | Per `url_scope` |
| ... | | | |

**Lightweight set (incremental default):**  
`security_headers`, `ssl_tls`, `cors`, `robots_txt`, `api_docs_exposure`, `sitemap_xml`, `directory_listing`, `open_redirect`, `xss_basic`, `sqli_error`, `sensitive_data`, `form_autocomplete` — ~12 checks.

---

## 8. Navigator Changes Summary

| Change | Effort | Priority |
|--------|--------|----------|
| `POST /ci/trigger` webhook endpoint | Low | High |
| CI API key (project/org) | Low | High |
| `url_scope` parameter in DAST scan | Medium | High |
| `scope_mode: full \| incremental` | Low | High |
| Path filtering in DAST runner | Medium | High |
| Documentation for CI integration | Low | High |
| Polling endpoint for scan status (existing: `GET /dast/scan/{id}`) | Done | — |
| Optional: Store last crawl URLs per project | Medium | Medium |
| Optional: Quality gate (block pipeline if critical DAST finding) | Medium | Medium |

---

## 9. End-to-End Checklist

- [ ] Semgrep in CI (config: `auto` or custom)
- [ ] Optional: Semgrep Assistant / AI triage
- [ ] Build step producing deployable app
- [ ] Deploy to preview/staging with unique URL
- [ ] Git diff → path mapping logic
- [ ] Navigator: `POST /ci/trigger` implemented
- [ ] Navigator: `url_scope`, `scope_mode` in DAST
- [ ] CI key created in Navigator; stored as GitHub secret
- [ ] GitHub Actions workflow: SAST → build → deploy → DAST
- [ ] Optional: Block merge on SAST/DAST critical findings
- [ ] Weekly full DAST scan (scheduled or manual)

---

## 10. References

| Resource | URL |
|----------|-----|
| Semgrep CI | https://semgrep.dev/docs/deployment/add-semgrep-to-ci |
| Semgrep Assistant (AI) | https://semgrep.dev/docs/semgrep-assistant/overview |
| Incremental scanning (Escape) | https://docs.escape.tech/documentation/integrations/ci-cd/incremental-scanning/ |
| Navigator DAST API | `POST /dast/scan`, `GET /dast/scan/{id}` |
| Navigator install-dast-tools | `scripts/install-dast-tools.sh` |
| DAST Automation Master Plan | `docs/DAST_AUTOMATION_MASTER_PLAN.md` |
| DAST & LLM Audit | `docs/DAST_LLM_AUDIT_AND_ROADMAP.md` |

---

*End of document.*
