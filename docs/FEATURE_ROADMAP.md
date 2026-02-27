# VAPT Navigator — Feature Roadmap & Advisor

**Last updated:** 2026-02-27

This document outlines possible future features and enhancements, acting as an AI advisor for the platform.

---

## 1. Report & Presentation

| Feature | Status | Effort | Priority |
|---------|--------|--------|----------|
| **Charts in HTML report** | ✅ Done | — | — |
| **Table of contents** | ✅ Done | — | — |
| **Live report view** | ✅ Done | — | — |
| **Signed report hash** | Not | Low | Medium |
| **Custom report templates** | Not | High | Low |
| **Report scheduling** | Not | Medium | Medium |
| **Executive dashboard PDF** | Not | Medium | Medium |
| **Comparison reports** | Not | High | Low |

**Recommendations:**
- Add SHA-256 hash of report file for integrity verification.
- Add "Report scheduling" (e.g., weekly digest) for ongoing projects.

---

## 2. Testing & Engagement

| Feature | Status | Effort | Priority |
|---------|--------|--------|----------|
| **Skill tree** | Not | High | Medium |
| **Organization leaderboard** | Not | Medium | Medium |
| **Burp XML import** | Not | Medium | High |
| **CI/CD webhook** | Not | Medium | High |
| **Screenshot embedding** | ✅ Done | — | — |
| **Time tracking** | Partial | Low | Medium |
| **Test case templates** | Not | Medium | Low |
| **Gamification badges** | ✅ Done | — | — |

**Recommendations:**
- **Burp XML import** — High value for testers who use Burp Suite; import findings directly.
- **CI/CD webhook** — Trigger automated report generation or status updates on completion.
- **Skill tree** — Phase-based unlock UI; optional progression tree to increase engagement.

---

## 3. AI & Intelligence

| Feature | Status | Effort | Priority |
|---------|--------|--------|----------|
| **AI Assist (LLM)** | Partial | — | — |
| **Severity recommendation** | Partial | — | — |
| **Auto-findings from results** | Not | High | Medium |
| **Natural language queries** | Not | High | Low |
| **Report summarization** | Not | Medium | Medium |
| **Vulnerability trend analysis** | Not | High | Low |

**Recommendations:**
- **Auto-findings from results** — When a test fails, suggest creating a finding with pre-filled data.
- **Report summarization** — One-paragraph summary for executives via LLM.

---

## 4. Integrations

| Feature | Status | Effort | Priority |
|---------|--------|--------|----------|
| **JIRA** | ✅ Done | — | — |
| **Slack/Teams notifications** | Not | Medium | Medium |
| **DefectDojo** | Not | High | Medium |
| **GitHub Issues** | Not | Medium | Medium |
| **ServiceNow** | Not | High | Low |

**Recommendations:**
- **Slack/Teams** — Notify when critical findings are added or when remediation is complete.
- **DefectDojo** — Sync findings for compliance/DevSecOps workflows.

---

## 5. UI/UX & Psychology

| Feature | Status | Effort | Priority |
|---------|--------|--------|----------|
| **Professional design** | Partial | Medium | High |
| **Animations** | Partial | Low | Medium |
| **Dark theme** | ✅ Done | — | — |
| **Tester engagement cues** | Partial | Medium | High |
| **Progress visualization** | ✅ Done | — | — |
| **Reduced cognitive load** | Not | Medium | Medium |
| **Micro-interactions** | Not | Low | Medium |

**Recommendations:**
- **Professional design** — Use consistent typography, spacing, and color palette; avoid "childish" aesthetics.
- **Tester engagement** — Subtle progress cues, celebration animations, streak visibility.
- **Micro-interactions** — Hover states, smooth transitions, feedback on actions.

---

## 6. Security & Compliance

| Feature | Status | Effort | Priority |
|---------|--------|--------|----------|
| **MFA** | ✅ Done | — | — |
| **Audit logs** | ✅ Done | — | — |
| **Rate limiting** | ✅ Done | — | — |
| **RBAC refinement** | Partial | Medium | Medium |
| **SSO** | Not | High | Medium |
| **Report encryption** | Not | Medium | Low |
| **Data retention** | Not | Medium | Low |

**Recommendations:**
- **SSO** — SAML/OIDC for enterprise deployments.
- **RBAC** — Fine-grained permissions per project phase or finding type.

---

## 7. Performance & Scale

| Feature | Status | Effort | Priority |
|---------|--------|--------|----------|
| **WebSocket** | ✅ Done | — | — |
| **Celery async** | ✅ Done | — | — |
| **Redis caching** | Not | Medium | Medium |
| **Pagination** | Partial | Low | Medium |
| **Lazy loading** | Partial | Low | Medium |
| **CDN for assets** | Not | Low | Low |

**Recommendations:**
- **Redis caching** — Cache project list, test case counts, report metadata.
- **Pagination** — Ensure all list endpoints support cursor-based pagination.

---

## 8. Quick Wins (Low Effort, High Impact)

1. **Live report link** — ✅ Done (button on project page).
2. **Charts in HTML report** — ✅ Done.
3. **Table of contents in report** — ✅ Done.
4. **MFA login UI** — Enforce MFA flow on login for admin.
5. **Organization leaderboard** — XP leaderboard per org.
6. **Slack notification** — Webhook on critical finding.

---

## 9. Long-Term Vision

- **Platform as a service** — Multi-tenant SaaS with org isolation.
- **API-first** — Full REST API for CI/CD and third-party tools.
- **Mobile companion** — Lightweight mobile app for testers on the go.
- **Compliance automation** — Auto-map findings to compliance frameworks.

---

## 10. Summary

Priority areas for implementation:

1. **Report:** Charts, TOC, live view — ✅ Done.
2. **Architecture:** Documented in `ARCHITECTURE.md`.
3. **UI/UX:** Professional design, animations, tester engagement.
4. **Integrations:** Burp import, CI/CD webhook, Slack.
5. **AI:** Auto-findings from results, report summarization.
