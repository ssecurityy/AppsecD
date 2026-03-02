# Testing Applications Behind VPN — SaaS DAST Solution

**Document Version:** 1.0  
**Date:** 2026-03-01  
**Purpose:** How to use AppSecD (SaaS) to test applications that are behind a VPN or on internal/private networks. The SaaS platform runs in the cloud and **cannot directly reach** VPN-protected targets.

---

## 1. The Problem

| Component | Location | Can Reach Target? |
|-----------|----------|-------------------|
| AppSecD SaaS (API, UI, DB) | Cloud (e.g. appsecd.com) | ❌ No — target is on private/VPN network |
| Target application | Customer's internal network (e.g. 10.0.1.50:8080) | — |
| Tester (human) | Customer network (has VPN access) | ✅ Yes |

**DAST requires the scanner to send HTTP requests to the target.** If the target is only reachable via VPN, the cloud-hosted SaaS cannot perform the scan directly.

---

## 2. Solution Overview

**Best approach for SaaS + VPN/internal targets:** Run a **Scanner Agent** inside the customer's network. The agent:

1. Connects **outbound** to the SaaS API (no inbound firewall rules needed)
2. Receives scan jobs from the SaaS
3. Executes tests **locally** against internal targets (has VPN/network access)
4. Sends results back to the SaaS

```
┌─────────────────────────────────────────────────────────────────────────┐
│  CUSTOMER NETWORK (behind VPN / private)                                 │
│                                                                         │
│  ┌──────────────────┐         ┌─────────────────────┐                   │
│  │  Scanner Agent   │ ──────► │  Internal Target    │                   │
│  │  (Docker/VM)     │  HTTP   │  (10.0.1.50:8080)   │                   │
│  └────────┬─────────┘         └─────────────────────┘                   │
│           │                                                             │
└───────────┼─────────────────────────────────────────────────────────────┘
            │ outbound HTTPS (poll or WebSocket)
            ▼
┌───────────────────────────────────────────────────────────────────────────┐
│  CLOUD (appsecd.com)                                                       │
│                                                                            │
│  ┌─────────────┐    ┌─────────────┐    ┌──────────────┐                   │
│  │  AppSecD    │◄───│  API        │◄───│  PostgreSQL  │                   │
│  │  UI         │    │  (FastAPI)  │    │  Redis       │                   │
│  └─────────────┘    └──────┬──────┘    └──────────────┘                   │
│                            │                                              │
│                            │  Queue jobs / receive results                 │
│                            ▼                                              │
│                    ┌──────────────┐                                       │
│                    │  Job Queue   │                                       │
│                    │  (Celery/RQ) │                                       │
│                    └──────────────┘                                       │
└───────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Recommended: Agent-Based Architecture

### 3.1 How It Works

| Step | Action |
|------|--------|
| 1 | Customer deploys **AppSecD Scanner Agent** inside their network (VM, Docker, or Kubernetes). |
| 2 | Agent authenticates to SaaS (API key or org token). |
| 3 | User creates project in AppSecD UI; sets target URL to internal address (e.g. `http://internal-app:8080`). |
| 4 | User clicks "Run Scan" (or schedules it). |
| 5 | SaaS queues scan job; agent polls (or receives via WebSocket) and fetches job. |
| 6 | Agent runs tools (nuclei, ffuf, sqlmap, etc.) against target. |
| 7 | Agent parses output, posts results to SaaS API (`POST /api/v1/scan-results`). |
| 8 | SaaS stores results; UI shows pass/fail, findings, evidence. |

### 3.2 Why Agent-Based Is Best for SaaS

| Criteria | Agent | VPN from SaaS | Proxy Forward |
|----------|-------|---------------|---------------|
| **Multi-tenant** | ✅ Each customer runs own agent | ❌ SaaS would need VPN per customer | ⚠️ Complex |
| **No inbound firewall** | ✅ Agent uses outbound HTTPS only | ❌ Requires inbound VPN | ⚠️ Depends |
| **Scalability** | ✅ Customer scales own agents | ❌ Central bottleneck | ⚠️ Limited |
| **Security** | ✅ Agent in customer network; only results leave | ⚠️ Full network path exposed | ⚠️ Depends |
| **Industry pattern** | ✅ Snyk, Qualys, Tenable use agents | Rare for SaaS | Niche |

### 3.3 Agent Deployment Options

| Option | Use Case | Effort |
|--------|----------|--------|
| **Docker container** | Customer runs `docker run appsecd-agent` with API key and target config | Low |
| **Kubernetes DaemonSet/Deployment** | Enterprise with K8s; agent in same cluster as internal apps | Medium |
| **VM / bare metal** | Customer installs agent binary or Python package | Medium |
| **Docker Compose** | Dev/test; agent + optional local tools in one compose file | Low |

### 3.4 Agent Requirements

- **Outbound:** HTTPS to `https://appsecd.com` (or configured API URL)
- **Inbound:** None (agent initiates all connections)
- **Network access:** Must reach target URL (same subnet, VLAN, or VPN)
- **Tools:** nuclei, ffuf, sqlmap, curl, etc. (pre-installed in agent image or customer installs)
- **Credentials:** API key or org token (scoped to org/projects)

---

## 4. Alternative Approaches

### 4.1 Manual + Burp/ZAP Import (Current)

| Flow | Description |
|------|-------------|
| 1 | Tester connects to VPN, runs Burp Suite or ZAP locally. |
| 2 | Scans/crawls internal target from their machine. |
| 3 | Exports XML/JSON from Burp/ZAP. |
| 4 | Uploads to AppSecD via `POST /findings/import/burp`. |
| 5 | AppSecD creates findings; manual test case results still tracked in UI. |

**Pros:** Already supported; no new infra.  
**Cons:** Not automated; tester-driven; no "Run Scan" from SaaS.

### 4.2 SaaS VPN to Customer (Not Recommended)

- SaaS initiates VPN (e.g. IPsec, WireGuard) to customer's VPN concentrator.
- **Problems:** Per-customer VPN config; key management; operational burden; rarely done in multi-tenant SaaS.

### 4.3 Reverse Tunnel (e.g. ngrok, Tailscale)

- Customer runs tunnel that exposes internal target to a public URL.
- **Problems:** Exposes internal app to internet; security risk; not suitable for production.

### 4.4 Hybrid / On-Prem Navigator

- Run full AppSecD stack (API, UI, DB, scanner) on customer premises.
- **Use case:** Air-gapped or compliance (data never leaves customer network).
- **Trade-off:** No SaaS; self-managed deployment.

---

## 5. Implementation Roadmap

### Phase 1 — Agent MVP (4–6 weeks)

| Task | Description |
|------|-------------|
| Agent binary/container | Lightweight runner: poll jobs, execute tools, POST results |
| Job queue | `Project.scan_origin = 'agent'`; jobs in Redis/DB |
| API endpoints | `POST /api/v1/agent/register`, `GET /api/v1/agent/jobs`, `POST /api/v1/agent/results` |
| Project config | `scan_origin`: `server` \| `agent`; `agent_id` optional |
| Auth | API key or org-scoped token for agent |

### Phase 2 — Tool Execution & Parsing

| Task | Description |
|------|-------------|
| Variable substitution | `{{TARGET}}`, `{{AUTH_HEADER}}` in tool_commands |
| Tool runner | Execute nuclei, ffuf, sqlmap; capture stdout/stderr |
| Parser | Map tool output → pass/fail; attach request/response |
| Results API | `POST /api/v1/scan-results` with `project_id`, `test_case_id`, `status`, `evidence` |

### Phase 3 — UI & Scheduling

| Task | Description |
|------|-------------|
| "Run with Agent" button | Only shown when `scan_origin = agent` and agent online |
| Agent status | Show last heartbeat, version, assigned projects |
| Scheduled scans | Cron + queue; agent picks up at scheduled time |

---

## 6. Security Considerations

| Concern | Mitigation |
|---------|------------|
| **API key exposure** | Scoped keys; rotation; store in agent env/secret, not in code |
| **Data in transit** | TLS 1.2+ for all agent ↔ SaaS communication |
| **Sensitive results** | Results may contain request/response; encrypt at rest; audit access |
| **Agent compromise** | Agent has network access to internal targets; run in minimal privileges; network segmentation |
| **Supply chain** | Sign agent images; publish checksums; allow customer to build from source |

---

## 7. Summary

| Scenario | Recommended Solution |
|----------|---------------------|
| **SaaS AppSecD + internal/VPN target** | **Scanner Agent** in customer network |
| **Manual testing only** | Burp/ZAP import (current) |
| **Air-gapped / no cloud** | On-prem / hybrid Navigator |

**Bottom line:** For a SaaS-based DAST platform testing applications behind VPN, deploy a **Scanner Agent** inside the customer's network. The agent runs scans locally and reports results to the cloud. No VPN from SaaS to customer is required.
