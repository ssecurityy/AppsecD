# VAPT Navigator — Kubernetes Deployment Plan

Modern containerized deployment plan for **VAPT Navigator** with best performance, easy migration, and operational simplicity.

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Component Inventory](#2-component-inventory)
3. [Target Architecture](#3-target-architecture)
4. [Implementation Phases](#4-implementation-phases)
5. [Docker Images](#5-docker-images)
6. [Kubernetes Manifests Structure](#6-kubernetes-manifests-structure)
7. [Secrets & Config Management](#7-secrets--config-management)
8. [Storage Strategy](#8-storage-strategy)
9. [Networking & Ingress](#9-networking--ingress)
10. [Performance & Scalability](#10-performance--scalability)
11. [Observability & Operations](#11-observability--operations)
12. [Migration & Backup](#12-migration--backup)
13. [Security Hardening](#13-security-hardening)
14. [File-by-File Checklist](#14-file-by-file-checklist)

---

## 1. Architecture Overview

### Current Stack (Non-Containerized)

| Component        | Technology        | Port | State     |
|------------------|-------------------|------|-----------|
| Backend API      | FastAPI / Uvicorn | 5001 | Stateless |
| Frontend         | Next.js 14        | 3000 | Stateless |
| Celery Worker    | Celery + Redis    | -    | Stateless |
| PostgreSQL       | Postgres 16       | 5432 | Stateful  |
| Redis            | Redis 7           | 6379 | Stateful  |
| Data (payloads)  | Git repos + FS    | -    | Read-only |
| Uploads          | Filesystem        | -    | Stateful  |

### Target: Kubernetes-Native Architecture

- **Stateless workloads**: API, Frontend, Celery workers — run as Deployments, scale horizontally
- **Stateful workloads**: PostgreSQL, Redis — run as StatefulSets or use managed services (RDS, ElastiCache, Cloud SQL)
- **Shared data**: Payloads / SecLists — init container or ReadOnlyMany PVC / NFS
- **User uploads**: PersistentVolumeClaim (ReadWriteOnce)

---

## 2. Component Inventory

| Component       | Image Base        | Resources (min)       | Scaling |
|-----------------|-------------------|------------------------|---------|
| backend         | python:3.12-slim  | 256Mi RAM, 100m CPU   | HPA 2–10 |
| frontend        | node:20-alpine    | 128Mi RAM, 50m CPU    | HPA 2–6  |
| celery-worker   | python:3.12-slim  | 256Mi RAM, 100m CPU   | HPA 1–5  |
| postgres        | postgres:16-alpine| 512Mi RAM, 250m CPU   | 1 replica |
| redis           | redis:7-alpine    | 128Mi RAM, 50m CPU    | 1 replica |

---

## 3. Target Architecture

```
                                    ┌─────────────────────────────────────────────────────────┐
                                    │                    Ingress / Load Balancer               │
                                    │                    (TLS termination, path routing)       │
                                    └─────────────────────────┬───────────────────────────────┘
                                                              │
                    ┌─────────────────────────────────────────┼─────────────────────────────────────────┐
                    │                                         │                                         │
                    ▼                                         ▼                                         ▼
           ┌───────────────┐                        ┌─────────────────┐                        ┌───────────────┐
           │   Frontend    │                        │   Backend API   │                        │  Celery       │
           │   (Next.js)   │◄──────────────────────│   (FastAPI)     │◄───────────────────────│  Worker       │
           │   Deployment  │   NEXT_PUBLIC_API_URL  │   Deployment    │   Redis (broker)       │  Deployment   │
           │   HPA 2-6     │                        │   HPA 2-10      │                        │  HPA 1-5      │
           └───────────────┘                        └────────┬────────┘                        └───────┬───────┘
                                                            │                                              │
                    ┌───────────────────────────────────────┼──────────────────────────────────────────────┘
                    │                                       │
                    ▼                                       ▼
           ┌───────────────┐                        ┌─────────────────┐
           │  PostgreSQL   │                        │     Redis       │
           │  StatefulSet  │                        │  Deployment/    │
           │  or External  │                        │  StatefulSet    │
           │  (RDS/Cloud)  │                        └─────────────────┘
           └───────────────┘
                    │
                    ▼
           ┌───────────────────────────────────────────────────────────┐
           │  PVC: navigator-data (payloads, uploads)                   │
           │  - PayloadsAllTheThings, SecLists (read-only or init)      │
           │  - data/uploads (ReadWriteOnce)                            │
           └───────────────────────────────────────────────────────────┘
```

---

## 4. Implementation Phases

### Phase 1: Dockerization (Week 1)

1. Create Dockerfiles for backend, frontend, celery-worker
2. Create `docker-compose.yml` for local/dev parity
3. Validate all services start and communicate

### Phase 2: Base Kubernetes (Week 2)

1. Namespace, ConfigMaps, Secrets
2. Deployments for backend, frontend, celery-worker
3. Services (ClusterIP)
4. PostgreSQL and Redis (in-cluster or external)

### Phase 3: Storage & Data (Week 2–3)

1. PVC for uploads
2. Init container or Job for payload data (clone/populate)
3. Optional: NFS/EFS for shared read-only payloads

### Phase 4: Production-Ready (Week 3–4)

1. Ingress + TLS
2. HPA, PDB
3. Liveness/readiness probes
4. Resource limits

### Phase 5: Observability & GitOps (Week 4+)

1. Prometheus + Grafana
2. Centralized logging (Loki or cloud-native)
3. Helm chart packaging
4. Optional: Argo CD / Flux for GitOps

---

## 5. Docker Images

### 5.1 Backend (FastAPI)

```dockerfile
# backend/Dockerfile
FROM python:3.12-slim AS builder
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

FROM python:3.12-slim
WORKDIR /app
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin
COPY . .

ENV PYTHONUNBUFFERED=1
EXPOSE 5001

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "5001"]
```

### 5.2 Frontend (Next.js)

```dockerfile
# frontend/Dockerfile
FROM node:20-alpine AS deps
WORKDIR /app
COPY package*.json ./
RUN npm ci

FROM node:20-alpine AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
ARG NEXT_PUBLIC_API_URL
ENV NEXT_PUBLIC_API_URL=$NEXT_PUBLIC_API_URL
RUN npm run build

FROM node:20-alpine
WORKDIR /app
ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
COPY --from=builder /app/public ./public
COPY --from=builder /app/.next/standalone ./
COPY --from=builder /app/.next/static ./.next/static

EXPOSE 3000
CMD ["node", "server.js"]
```

**Note**: Enable `output: 'standalone'` in `next.config.mjs` for smaller image.

### 5.3 Celery Worker

```dockerfile
# backend/Dockerfile.celery (or reuse backend image with different CMD)
FROM <navigator-backend-image>
CMD ["celery", "-A", "app.celery_app", "worker", "--loglevel=info"]
```

---

## 6. Kubernetes Manifests Structure

```
k8s/
├── base/
│   ├── namespace.yaml
│   ├── configmap.yaml
│   ├── secrets.yaml (template; use Sealed Secrets / External Secrets)
│   ├── backend/
│   │   ├── deployment.yaml
│   │   ├── service.yaml
│   │   └── hpa.yaml
│   ├── frontend/
│   │   ├── deployment.yaml
│   │   ├── service.yaml
│   │   └── hpa.yaml
│   ├── celery-worker/
│   │   ├── deployment.yaml
│   │   └── hpa.yaml
│   ├── postgres/
│   │   ├── statefulset.yaml
│   │   ├── service.yaml
│   │   └── pvc.yaml
│   ├── redis/
│   │   ├── deployment.yaml
│   │   └── service.yaml
│   ├── storage/
│   │   └── pvc-uploads.yaml
│   └── ingress.yaml
├── overlays/
│   ├── dev/
│   │   ├── kustomization.yaml
│   │   └── patches/
│   └── prod/
│       ├── kustomization.yaml
│       ├── patches/
│       └── ingress-tls.yaml
└── helm/
    └── navigator/
        ├── Chart.yaml
        ├── values.yaml
        └── templates/
            └── ... (all manifests as templates)
```

---

## 7. Secrets & Config Management

### Secrets (Do NOT commit raw values)

| Secret Key            | Description                    | Example Source           |
|-----------------------|--------------------------------|--------------------------|
| DATABASE_URL          | PostgreSQL connection string   | Vault / External Secrets |
| REDIS_URL             | Redis connection string        | Vault / External Secrets |
| SECRET_KEY            | JWT signing key                | Generate, store in Vault |
| SMTP_PASSWORD         | Optional email                 | Vault                    |
| JIRA_API_TOKEN        | Optional JIRA                  | Vault                    |
| SLACK_WEBHOOK_URL     | Optional notifications         | Vault                    |
| openai_api_key        | Optional AI assist             | Vault                    |

### ConfigMap (Non-sensitive)

| Key                 | Description                     |
|---------------------|---------------------------------|
| ALLOWED_ORIGINS     | CORS origins                    |
| FRONTEND_URL        | Frontend base URL               |
| CACHE_ENABLED       | true/false                      |
| payloads_path       | /data/payloads/PayloadsAllTheThings |
| seclists_path       | /data/payloads/SecLists         |
| uploads_path        | /data/uploads                   |
| DB_POOL_SIZE        | 20                              |
| DB_MAX_OVERFLOW     | 10                              |

### Recommended: External Secrets Operator

```yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: navigator-secrets
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: vault-backend
    kind: SecretStore
  target:
    name: navigator-secrets
  data:
    - secretKey: DATABASE_URL
      remoteRef:
        key: secret/navigator
        property: database_url
```

---

## 8. Storage Strategy

### Option A: Init Container + EmptyDir (Dev)

- Init container clones PayloadsAllTheThings and SecLists into EmptyDir
- Fast for dev; re-clone on each pod restart

### Option B: PersistentVolumeClaim + Init Job (Prod)

1. **PVC** `navigator-data` (ReadWriteMany if available, e.g. NFS/EFS)
2. **Job** `payload-init` runs once: clone repos into PVC
3. All backend/celery pods mount same PVC at `/data`
4. **Sub-path**:
   - `/data/payloads/PayloadsAllTheThings`
   - `/data/payloads/SecLists`
   - `/data/uploads` (ReadWriteOnce acceptable if single backend replica writes)

### Option C: Separate PVCs (Simple Prod)

| PVC              | Access Mode    | Size   | Usage                    |
|------------------|----------------|--------|--------------------------|
| navigator-pgdata | ReadWriteOnce  | 20Gi   | PostgreSQL data          |
| navigator-redis  | ReadWriteOnce  | 2Gi    | Redis persistence        |
| navigator-uploads| ReadWriteOnce  | 10Gi   | User uploads             |
| navigator-payloads| ReadOnlyMany* | 5Gi    | Payloads (cloned by Job) |

\* If ReadOnlyMany storage class exists (NFS, EFS). Otherwise use Init container per pod.

---

## 9. Networking & Ingress

### Services

| Service            | Type       | Port | Selector        |
|--------------------|------------|------|------------------|
| navigator-backend  | ClusterIP  | 5001 | app=backend      |
| navigator-frontend | ClusterIP  | 3000 | app=frontend     |
| navigator-postgres | ClusterIP  | 5432 | app=postgres     |
| navigator-redis    | ClusterIP  | 6379 | app=redis        |

### Ingress (nginx / traefik)

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: navigator
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
    nginx.ingress.kubernetes.io/proxy-body-size: "50m"
spec:
  ingressClassName: nginx
  tls:
    - hosts:
        - navigator.example.com
      secretName: navigator-tls
  rules:
    - host: navigator.example.com
      http:
        paths:
          - path: /api
            pathType: Prefix
            backend:
              service:
                name: navigator-backend
                port:
                  number: 5001
          - path: /
            pathType: Prefix
            backend:
              service:
                name: navigator-frontend
                port:
                  number: 3000
```

### Frontend API URL

- **Option 1**: Same host, path `/api` → proxy to backend. Set `NEXT_PUBLIC_API_URL=/api` (relative)
- **Option 2**: Subdomain `api.navigator.example.com` → `NEXT_PUBLIC_API_URL=https://api.navigator.example.com`

---

## 10. Performance & Scalability

### Horizontal Pod Autoscaler

```yaml
# backend HPA
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: navigator-backend
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: navigator-backend
  minReplicas: 2
  maxReplicas: 10
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 70
    - type: Resource
      resource:
        name: memory
        target:
          type: Utilization
          averageUtilization: 80
```

### Pod Disruption Budget

```yaml
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: navigator-backend-pdb
spec:
  minAvailable: 1
  selector:
    matchLabels:
      app: navigator-backend
```

### Resource Requests/Limits

| Component   | Requests    | Limits      |
|-------------|-------------|-------------|
| backend     | 256Mi, 100m | 1Gi, 1000m  |
| frontend    | 128Mi, 50m  | 512Mi, 500m |
| celery      | 256Mi, 100m | 1Gi, 1000m  |
| postgres    | 512Mi, 250m | 2Gi, 2000m  |
| redis       | 128Mi, 50m  | 256Mi, 200m |

### Connection Pooling

- Keep `DB_POOL_SIZE` and `DB_MAX_OVERFLOW` tuned for replica count: `pool_size = 20 / replicas` (approx)
- Consider PgBouncer sidecar if many API replicas

---

## 11. Observability & Operations

### Health Endpoints (Already Present)

- Backend: `GET /health` (liveness), `GET /health/ready` (readiness)
- Use in `livenessProbe` and `readinessProbe`

### Probes

```yaml
livenessProbe:
  httpGet:
    path: /health
    port: 5001
  initialDelaySeconds: 15
  periodSeconds: 10
readinessProbe:
  httpGet:
    path: /health/ready
    port: 5001
  initialDelaySeconds: 5
  periodSeconds: 5
```

### Logging

- JSON logging (structlog or similar) for backend
- Stdout/stderr → cluster logging (Fluentd, Loki, CloudWatch)

### Metrics

- Prometheus scrape `/metrics` if FastAPI exporter added
- Redis metrics, Postgres metrics via exporters
- Grafana dashboards for API latency, error rate, queue depth

### Alerts

- API 5xx rate
- DB connection failures
- Celery queue backlog
- PVC usage

---

## 12. Migration & Backup

### Database Migrations

- **Option 1**: Init container runs `alembic upgrade head` before API starts
- **Option 2**: Separate Kubernetes Job `navigator-migrate` runs before Deployment

### Backup Strategy

| Resource   | Method                          | Frequency  |
|------------|---------------------------------|------------|
| PostgreSQL | pg_dump / velero / cloud backup | Daily      |
| Redis      | RDB snapshot (if persistence)   | Optional   |
| PVC uploads| Volume snapshot / rsync         | Daily      |
| Payloads   | Git; re-clone on restore        | N/A        |

### Restore Procedure

1. Restore PostgreSQL from backup
2. Restore uploads PVC if needed
3. Run migrations if schema changed
4. Redeploy workloads
5. Re-run payload init Job if payloads PVC was recreated

### Migration from Bare Metal / VM

1. Export PostgreSQL: `pg_dump navigator > backup.sql`
2. Copy `data/uploads` to object storage or tar
3. Deploy K8s stack with empty DB
4. Restore: `psql < backup.sql` (or use Job)
5. Restore uploads to PVC
6. Update DNS to point to Ingress
7. Decommission old host

---

## 13. Security Hardening

- **Network Policies**: Restrict backend → postgres, redis only; frontend → backend; no direct DB/Redis from outside
- **Pod Security Standards**: Enforce `restricted` or `baseline`
- **Non-root**: Run containers as non-root user (define in Dockerfile)
- **Secrets**: Never commit; use External Secrets / Vault
- **Image scanning**: Trivy / Snyk in CI
- **RBAC**: Minimal service account per component

---

## 14. File-by-File Checklist

### To Create

| File                               | Purpose                                      |
|------------------------------------|----------------------------------------------|
| `backend/Dockerfile`               | Backend image                                |
| `frontend/Dockerfile`              | Frontend image (standalone)                   |
| `frontend/next.config.mjs`         | Add `output: 'standalone'`                    |
| `docker-compose.yml`               | Local dev with Docker                         |
| `k8s/base/namespace.yaml`          | `navigator` namespace                         |
| `k8s/base/configmap.yaml`          | Non-sensitive config                          |
| `k8s/base/secrets.yaml`            | Template (values from CI/Vault)               |
| `k8s/base/backend/deployment.yaml` | Backend Deployment                            |
| `k8s/base/backend/service.yaml`    | Backend Service                               |
| `k8s/base/backend/hpa.yaml`        | Backend HPA                                   |
| `k8s/base/frontend/deployment.yaml`| Frontend Deployment                           |
| `k8s/base/frontend/service.yaml`   | Frontend Service                              |
| `k8s/base/frontend/hpa.yaml`       | Frontend HPA                                  |
| `k8s/base/celery-worker/deployment.yaml` | Celery worker Deployment                 |
| `k8s/base/celery-worker/hpa.yaml`  | Celery HPA                                    |
| `k8s/base/postgres/statefulset.yaml`| PostgreSQL StatefulSet (or use Cloud SQL)    |
| `k8s/base/postgres/service.yaml`   | Postgres Service                              |
| `k8s/base/postgres/pvc.yaml`       | Postgres PVC                                  |
| `k8s/base/redis/deployment.yaml`   | Redis Deployment                              |
| `k8s/base/redis/service.yaml`      | Redis Service                                 |
| `k8s/base/storage/pvc-uploads.yaml`| Uploads PVC                                   |
| `k8s/base/ingress.yaml`            | Ingress definition                            |
| `k8s/base/kustomization.yaml`      | Kustomize base                                |
| `helm/navigator/Chart.yaml`        | Helm chart metadata                           |
| `helm/navigator/values.yaml`       | Helm default values                           |
| `helm/navigator/templates/*`       | Helm templates                                |
| `.github/workflows/build-push.yml` | CI: build and push images                     |
| `.github/workflows/deploy-k8s.yml` | CD: deploy to K8s (optional)                  |
| `scripts/k8s-payload-init-job.yaml`| Job to clone payload repos into PVC           |
| `docs/K8S-RUNBOOK.md`              | Operational runbook                           |

### Config Changes

| File                          | Change                                                         |
|-------------------------------|----------------------------------------------------------------|
| `backend/app/core/config.py`  | Support env vars for paths (already flexible)                  |
| `backend/app/core/security.py`| Use `SECRET_KEY` from env (remove hardcoded value)             |
| `frontend/next.config.mjs`    | Add `output: 'standalone'`                                     |
| `.dockerignore`               | Exclude venv, __pycache__, .git, node_modules, .next           |

---

## Summary

This plan transforms VAPT Navigator into a **Kubernetes-native, scalable, observable, and migration-friendly** deployment. Key outcomes:

- **Best performance**: HPA, resource limits, connection pooling
- **Easy migration**: Helm chart, documented backup/restore, Kustomize overlays
- **Easy to handle**: Centralized config, health probes, logging, metrics, runbooks
- **Modern architecture**: Stateless API/frontend/workers, managed or in-cluster stateful stores, GitOps-ready

Start with Phase 1 (Dockerization) and Phase 2 (base K8s), then iterate through phases 3–5 as needed for your environment.
