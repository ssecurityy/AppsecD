# VAPT Navigator — Feature Ideas & Implementation Guide

**Last updated:** 2026-02-27

This document lists all possible feature ideas for the platform, including AI/LLM enhancements, integrations, and improvements. Use as a roadmap and implementation reference.

---

## 1. AI & LLM Enhancements

| Idea | Description | Effort | Priority |
|------|-------------|--------|----------|
| **LLM-powered finding summarization** | Auto-generate executive summary of findings for reports | Medium | High |
| **AI severity recommendation** | LLM suggests severity based on CVSS, impact, exploitability | Low | High |
| **Natural language report queries** | "Show me all SQLi findings" via LLM → structured query | High | Medium |
| **Auto-findings from failed tests** | When test fails, AI suggests creating finding with pre-filled data | Medium | High |
| **LLM remediation suggestions** | Richer, context-aware remediation text (beyond rule-based) | Low | High |
| **Vulnerability trend analysis** | AI identifies patterns across projects (e.g. "XSS in 60% of apps") | High | Low |
| **Chat-style security assistant** | "How do I test for IDOR?" → step-by-step guidance | High | Medium |
| **Report summarization** | One-paragraph exec summary via LLM | Low | Medium |
| **Payload generation** | AI generates custom payloads for specific stack | Medium | Medium |

**Implementation notes:**
- Use `OPENAI_API_KEY` (already supported for AI Assist)
- Add admin setting for model selection (gpt-4o-mini, gpt-4o, etc.)
- Consider local LLMs (Ollama) for air-gapped deployments

---

## 2. Data & Storage (Completed)

| Feature | Status |
|---------|--------|
| PayloadsAllTheThings in PostgreSQL | Done |
| SecLists in PostgreSQL | Done |
| Copy wordlist content | Done |
| Download wordlist file | Done |
| 100% DB, no filesystem dependency | Done |

**Remaining:**
- Optional: Lazy-load very large wordlists (stream from DB)

**Completed (2026-02):**
- MAX_WORDLIST_SIZE increased to 200MB; 100% import including large files
- FuzzDB, BLNS, XSS Payloads, SQLi, Nuclei Templates, Intruder Payloads, OWASP WSTG in PostgreSQL
- OWASP WSTG test cases (126) imported into test_cases table

---

## 3. Integrations

| Idea | Description | Effort | Priority |
|------|-------------|--------|----------|
| **Burp Suite XML import** | Import findings from Burp Suite XML export | Medium | High |
| **DefectDojo sync** | Push findings to DefectDojo for compliance | High | Medium |
| **Slack/Teams notifications** | Notify on critical finding, remediation complete | Medium | Medium |
| **GitHub Issues** | Create GitHub issue from finding | Medium | Medium |
| **CI/CD webhook** | Trigger on project completion; API key for automated runs | Medium | High |
| **Nuclei integration** | Run Nuclei, import results as findings | High | Medium |
| **ZAP integration** | Import OWASP ZAP scan results | Medium | Medium |

---

## 4. Report & Presentation

| Idea | Description | Effort | Priority |
|------|-------------|--------|----------|
| **Signed report hash** | SHA-256 hash for report integrity | Low | Medium |
| **Report scheduling** | Weekly/monthly digest | Medium | Medium |
| **Custom report templates** | Org-specific branding, sections | High | Low |
| **Comparison reports** | Before/after remediation | High | Low |
| **Executive dashboard PDF** | One-page summary for C-level | Medium | Medium |

---

## 5. Test Cases & Methodology

| Idea | Description | Effort | Priority |
|------|-------------|--------|----------|
| **Tool command wordlist links** | Replace hardcoded paths with "Download from Navigator" links | Low | Medium |
| **Custom test case library** | Org-specific test cases | Medium | Medium |
| **Test case templates** | Reusable templates for common scenarios | Medium | Low |
| **Methodology versioning** | Track OWASP/PTES version used | Low | Low |

---

## 6. Security & Compliance

| Idea | Description | Effort | Priority |
|------|-------------|--------|----------|
| **SSO (SAML/OIDC)** | Enterprise single sign-on | High | Medium |
| **Report encryption** | Encrypt sensitive reports at rest | Medium | Low |
| **Data retention** | Auto-archive/delete old projects | Medium | Low |
| **RBAC refinement** | Fine-grained permissions per phase | Medium | Medium |

---

## 7. Performance & Scale

| Idea | Description | Effort | Priority |
|------|-------------|--------|----------|
| **Redis caching** | Cache project list, report metadata | Medium | Medium |
| **Database indexes** | Optimize for 1000+ test cases | Low | Done |
| **CDN for assets** | Static assets via CDN | Low | Low |
| **Read replicas** | PostgreSQL read replica for reports | High | Low |

---

## 8. UX & Engagement

| Idea | Description | Effort | Priority |
|------|-------------|--------|----------|
| **Skill tree** | Phase-based unlock, progression UI | High | Medium |
| **Org leaderboard** | XP leaderboard per organization | Medium | Medium |
| **Dark/light theme toggle** | User preference | Low | Low |
| **Keyboard shortcuts** | Power-user shortcuts | Low | Medium |
| **Mobile companion** | Lightweight mobile app for testers | High | Low |

---

## 9. Quick Wins (Low Effort)

1. Update test case tool_commands to reference "Download from Navigator" instead of hardcoded paths
2. Add `MAX_WORDLIST_SIZE` env var for import script
3. MFA enforcement on login for admin
4. Slack webhook on critical finding
5. Report SHA-256 hash in footer

---

## 10. Implementation Checklist for New Features

1. **Backend:** Add model/migration if needed
2. **API:** New endpoints with auth
3. **Frontend:** UI components, API client
4. **Tests:** Unit/integration tests
5. **Docs:** Update ARCHITECTURE.md, IMPLEMENTATION_STATUS.md
6. **Config:** Env vars, admin settings if needed

---

## 11. AI/LLM Implementation Guide

### Current State
- `OPENAI_API_KEY` in `.env` enables LLM mode for AI Assist
- Rule-based fallback when key missing
- Admin Settings page shows status

### Adding New LLM Features

```python
# backend/app/services/ai_assist_service.py pattern
from openai import AsyncOpenAI

async def llm_suggest(prompt: str, system: str = "") -> str:
    client = AsyncOpenAI(api_key=settings.openai_api_key)
    if not client.api_key:
        return ""  # Fallback to rule-based
    response = await client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": prompt},
        ],
    )
    return response.choices[0].message.content
```

### Recommended Models
- **gpt-4o-mini** — Fast, cheap, good for suggestions
- **gpt-4o** — Better quality for reports, summaries
- **Ollama (local)** — For air-gapped; add `OLLAMA_BASE_URL` support
