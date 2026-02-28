# Kubernetes vs Current Architecture — Benefits Comparison

Document comparing the benefits of migrating VAPT Navigator to Kubernetes versus the current PM2 / bare-metal deployment.

---

## Current Architecture Summary

| Aspect | Current State |
|--------|---------------|
| **Orchestration** | PM2 on a single host |
| **Backend** | 1 instance (uvicorn), fixed at 5001 |
| **Frontend** | 1 instance (Next.js), fixed at 3000 |
| **Celery Worker** | Not managed by PM2 (manual start if used) |
| **Database** | Docker Postgres on host (port 5433) or system Postgres |
| **Redis** | Shared system Redis (6379) |
| **Deployment** | Manual: `git pull`, `pip install`, `npm run build`, `pm2 restart` |
| **Config** | `.env` file, hardcoded server IP in ecosystem.config.cjs |
| **Scaling** | Manual: increase PM2 instances, no auto-scale |
| **Failover** | None — single host, single process per service |
| **Rollback** | Manual git revert + restart |

---

## Kubernetes Architecture Summary

| Aspect | Target State |
|--------|--------------|
| **Orchestration** | Kubernetes (any cloud or on-prem) |
| **Backend** | 2–10 replicas, auto-scaled by HPA |
| **Frontend** | 2–6 replicas, auto-scaled |
| **Celery Worker** | Managed as Deployment, 1–5 replicas |
| **Database** | StatefulSet or managed (RDS/Cloud SQL) |
| **Redis** | Dedicated in-cluster or managed (ElastiCache) |
| **Deployment** | GitOps (Argo CD/Flux) or CI/CD pipeline |
| **Config** | ConfigMaps + Secrets (or External Secrets) |
| **Scaling** | HPA on CPU/memory, manual scaling if needed |
| **Failover** | Multiple replicas, pod restarts, node failure handling |
| **Rollback** | `kubectl rollout undo` or GitOps revert |

---

## Benefits Overview

| Category | Benefit |
|----------|---------|
| **Scalability** | Auto-scale on load; add replicas without downtime |
| **Reliability** | Self-healing; zero-downtime rolling updates |
| **Portability** | Run on any K8s cluster (cloud, on-prem, hybrid) |
| **Operations** | Declarative config, GitOps, consistent environments |
| **Migration** | Easier DR, backup/restore, multi-region |
| **Security** | RBAC, network policies, secrets management |
| **Cost** | Pay for what you use; scale down during idle |
| **Observability** | Built-in health checks, logs, metrics, probes |

---

## 1. Scalability Benefits

### Current

- **Single replica** per service (backend, frontend)
- **Manual scaling**: Edit `ecosystem.config.cjs` → `instances: 2` → restart
- **No auto-scale**: Spikes (e.g. report generation) can overload single process
- **Celery workers** not in PM2 — often forgotten or run ad hoc

### Kubernetes

- **Horizontal Pod Autoscaler (HPA)**: Scale backend 2→10 replicas based on CPU/memory
- **Reactive scaling**: Scale up under load, scale down when idle
- **Celery workers** as first-class Deployment with HPA
- **No manual intervention** for normal load changes

| Metric | Current | Kubernetes |
|--------|---------|------------|
| Max backend replicas (typical) | 1 | 2–10 (configurable) |
| Time to add 5 API replicas | Manual edit + restart | ~30 sec (HPA) |
| Report queue backlog | Single worker, manual add | Auto-scale workers |

---

## 2. Reliability & Availability Benefits

### Current

- **Single point of failure**: One host, one process per service
- **Restart behavior**: PM2 autorestart — brief downtime during crash
- **Deployments**: `pm2 restart` causes 5–30 sec outage
- **Host maintenance**: Requires scheduled downtime or complex manual failover

### Kubernetes

- **Multiple replicas**: Traffic spread across pods; one failure does not affect users
- **Self-healing**: Crashed pods replaced automatically
- **Rolling updates**: Zero-downtime deploys; old pods stay up until new ones are ready
- **Readiness probes**: Unhealthy pods removed from Service until healthy
- **PodDisruptionBudget**: Control how many pods can be down during node drains

| Metric | Current | Kubernetes |
|--------|---------|------------|
| Downtime on deploy | ~5–30 sec | 0 sec (rolling update) |
| Recovery from crash | ~5–15 sec (PM2 restart) | ~10–30 sec (pod restart) |
| Tolerance to 1 pod failure | N/A (single process) | No user impact |
| Planned node maintenance | Manual failover or downtime | Drain node, pods move to others |

---

## 3. Portability & Migration Benefits

### Current

- **Tied to host**: Paths like `/opt/navigator`, `/opt/navigator/backend/venv`
- **Shared Redis**: Conflict with other apps (dedsec-training, CyberSentinal, etc.)
- **Manual migration**: Follow 12-step checklist, reinstall packages, copy `.env`
- **Env drift**: Dev/stage/prod can diverge

### Kubernetes

- **Environment-agnostic**: Same manifests run on EKS, GKE, AKS, on-prem K8s
- **Isolated Redis**: Dedicated Redis instance for Navigator
- **Declarative migration**: Apply manifests + restore DB; no host-specific paths
- **Env parity**: Dev/stage/prod use same images, different ConfigMaps

| Task | Current | Kubernetes |
|------|---------|------------|
| Move to new server | ~2–4 hours (manual) | ~30–60 min (apply + restore) |
| New staging environment | Recreate steps 1–12 | `kubectl apply -k overlays/staging` |
| Multi-region DR | Complex, manual | Same manifests in another cluster |
| Switch cloud provider | Full reinstall | Change StorageClass, Ingress, apply |

---

## 4. Operational Benefits

### Current

- **Imperative ops**: Run bash commands, edit config files
- **No versioned config**: `.env` not in Git; drift over time
- **Logs**: PM2 logs to files; `pm2 logs` per process
- **Secrets**: In `.env`; risk of commit or exposure

### Kubernetes

- **Declarative ops**: Desired state in YAML; cluster converges
- **Versioned config**: ConfigMaps/Secrets in Git (or External Secrets)
- **Centralized logs**: Stdout → cluster logging (Loki, CloudWatch, etc.)
- **Secrets**: Kubernetes Secrets or External Secrets (Vault); not in app repo

| Task | Current | Kubernetes |
|------|---------|------------|
| Change env var | Edit `.env`, restart | Update ConfigMap, rolling restart |
| Rollback deploy | `git checkout`, rebuild, `pm2 restart` | `kubectl rollout undo` |
| View logs | `pm2 logs navigator-backend` | `kubectl logs -l app=backend -f` |
| Debug one pod | SSH + inspect | `kubectl exec -it <pod> -- bash` |
| Secrets rotation | Edit `.env`, restart all | Update Secret; pods can reload |

---

## 5. Security Benefits

### Current

- **Shared host**: Navigator runs alongside other apps
- **Process protection rules**: Must avoid touching nginx, redis, mongod, etc.
- **Secrets**: Plain text in `.env`
- **Network**: All services on same host; no network segmentation

### Kubernetes

- **Isolation**: Navigator in own namespace; resource limits per pod
- **No shared-process conflicts**: Each app in its own pods
- **Secrets**: Kubernetes Secrets (base64) or External Secrets (Vault)
- **Network policies**: Restrict backend → DB/Redis only; block unexpected traffic
- **RBAC**: Fine-grained access for operators
- **Pod security**: Non-root, read-only filesystem where possible

| Aspect | Current | Kubernetes |
|--------|---------|------------|
| Secret exposure risk | High (`.env` on disk) | Lower (Secrets API, encryption at rest) |
| Network isolation | None | NetworkPolicy |
| Principle of least privilege | Difficult | RBAC + NetworkPolicy |
| Image scanning | Manual | Trivy/Snyk in CI |

---

## 6. Cost & Resource Efficiency

### Current

- **Fixed capacity**: One server sized for peak; often over-provisioned
- **Idle waste**: Same resources 24/7 regardless of load
- **Shared Redis**: May limit Navigator tuning

### Kubernetes

- **Elastic scaling**: Scale down at night/weekends; scale up during business hours
- **Resource limits**: Prevent one service from consuming all CPU/RAM
- **Cluster sharing**: Navigator can share a cluster with other apps; bin packing
- **Spot/preemptible nodes**: Use for workers; reduce cost (with replica tolerance)

| Scenario | Current | Kubernetes |
|----------|---------|------------|
| Night (low traffic) | Full server running | 2 API + 1 frontend replicas |
| Report generation spike | Single worker, queue backlog | HPA adds workers |
| Add 2nd environment | New VM | Same cluster, new namespace |

---

## 7. Observability & Troubleshooting Benefits

### Current

- **Health checks**: `/health`, `/health/ready` exist but not wired to PM2
- **Metrics**: None built-in
- **Logs**: File-based; rotation manual
- **Debugging**: SSH to host, inspect processes

### Kubernetes

- **Probes**: Liveness/readiness wired to Deployment; K8s restarts unhealthy pods
- **Metrics**: Prometheus scrape; Grafana dashboards; HPA uses metrics
- **Logs**: Centralized; `kubectl logs`; integrate with Loki/ELK
- **Debugging**: `kubectl exec`, `kubectl describe`, events

| Capability | Current | Kubernetes |
|------------|---------|------------|
| Restart on failed health | No (PM2 restarts on exit only) | Yes (readiness/liveness) |
| CPU/memory metrics | Host-level | Per-pod, per-container |
| Request tracing | Manual | Integrate with Jaeger etc. |
| Event history | PM2 logs | `kubectl get events` |

---

## 8. Developer Experience Benefits

### Current

- **Local dev**: Different from prod (venv vs container)
- **CI/CD**: Usually manual deploy
- **Reproducibility**: "Works on my machine" vs prod drift

### Kubernetes

- **Containers everywhere**: Same image in dev, stage, prod
- **docker-compose for local**: Mirrors K8s services
- **GitOps**: Push to Git → auto-deploy (Argo CD/Flux)
- **Reproducibility**: Same image = same behavior

| Task | Current | Kubernetes |
|------|---------|------------|
| Reproduce prod bug | Match Python/Node versions, DB state | Run same image locally |
| Add dependency | Test locally, hope prod matches | Build new image, deploy |
| Onboard new dev | Long env setup | `minikube` or `kind` + apply |

---

## Summary Table

| Dimension | Current (PM2 / Bare Metal) | Kubernetes |
|-----------|----------------------------|------------|
| **Replicas** | 1 per service | 2–10+ per service |
| **Auto-scaling** | No | Yes (HPA) |
| **Zero-downtime deploy** | No | Yes (rolling update) |
| **Failover** | Manual | Automatic |
| **Migration effort** | 2–4 hours | ~1 hour |
| **Env parity** | Low | High |
| **Secrets handling** | .env file | Secrets / External Secrets |
| **Log aggregation** | PM2 files | Cluster logging |
| **Resource isolation** | Shared host | Per-pod limits |
| **Rollback** | Manual | `kubectl rollout undo` |
| **Portability** | Host-specific | Any K8s cluster |
| **Cost control** | Fixed VM | Scale up/down |

---

## When Kubernetes Makes Most Sense

- **Scale**: Expect growth in users or report generation
- **Reliability**: Need high availability and minimal downtime
- **Multi-environment**: Dev, staging, prod with consistency
- **Team**: Multiple operators; want declarative, versioned config
- **Cloud strategy**: Already using or planning K8s (EKS, GKE, AKS)
- **Security/compliance**: Need isolation, RBAC, network policies

---

## When to Stay on Current Architecture

- **Small team, single server**: Minimal ops overhead
- **Low traffic**: Single replica sufficient
- **No K8s expertise**: Learning curve and tooling setup
- **Budget**: Managed K8s has baseline cost (control plane, nodes)

---

## Conclusion

Migrating to Kubernetes gives Navigator:

1. **Higher availability** — multiple replicas, self-healing, rolling updates  
2. **Better scalability** — HPA and easy horizontal scaling  
3. **Easier migration** — move clusters or clouds with minimal rework  
4. **Simpler operations** — declarative config, GitOps, centralized logs  
5. **Stronger security** — isolation, RBAC, network policies, better secrets handling  
6. **More control over cost** — scale down when idle, share cluster resources  

The trade-off is initial setup (Docker, K8s manifests, CI/CD) and operational learning. For teams aiming for production-grade reliability, scalability, and portability, the benefits outweigh the migration effort.
