# VAPT Navigator — Installation & Migration Guide

This document records **all dependencies and installation steps** for migrating VAPT Navigator to a new server.

## System Requirements

- **OS**: Linux (Ubuntu 20.04+ recommended)
- **Python**: 3.11+
- **Node.js**: 18+ (for Next.js frontend)
- **Docker**: Optional, for PostgreSQL (or use system PostgreSQL)
- **Redis**: 7.x (used for cache, sessions, Celery broker)
- **PostgreSQL**: 16 (or 14+)

---

## 1. System Packages (apt)

```bash
# Python & build tools
apt-get update
apt-get install -y python3.11 python3.11-venv python3.12-venv python3-pip build-essential

# Node.js 18+ (if not present)
curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
apt-get install -y nodejs

# Git (for cloning repos)
apt-get install -y git

# Optional: PostgreSQL (if not using Docker)
# apt-get install -y postgresql postgresql-contrib
```

---

## 2. PostgreSQL (Docker — Recommended for Isolation)

```bash
# Run PostgreSQL 16 for Navigator only (port 5433 to avoid conflicts)
docker run -d \
  --name navigator-postgres \
  -e POSTGRES_USER=navigator \
  -e POSTGRES_PASSWORD=navigator_secure_password \
  -e POSTGRES_DB=navigator \
  -p 5433:5432 \
  -v navigator_pgdata:/var/lib/postgresql/data \
  postgres:16-alpine

# Verify
docker exec navigator-postgres psql -U navigator -d navigator -c "SELECT 1"
```

**Alternative: System PostgreSQL**

```bash
sudo -u postgres createuser -P navigator
sudo -u postgres createdb -O navigator navigator
```

---

## 3. Redis

Redis must be running. Navigator uses existing Redis at `127.0.0.1:6379`.

```bash
# If Redis not installed:
apt-get install -y redis-server
systemctl start redis-server
```

---

## 4. Payload & Wordlist Repositories

```bash
cd /opt/navigator
git clone --depth 1 https://github.com/swisskyrepo/PayloadsAllTheThings.git data/PayloadsAllTheThings
git clone --depth 1 https://github.com/danielmiessler/SecLists.git data/SecLists
```

---

## 5. Python Dependencies (Backend)

See `backend/requirements.txt`. Key packages:
- fastapi, uvicorn, sqlalchemy, asyncpg, alembic, redis, pydantic, pydantic-settings, python-dotenv, passlib, argon2-cffi, python-jose

```bash
cd /opt/navigator/backend
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
pip install -r requirements.txt
```

---

## 6. Node Dependencies (Frontend)

See `frontend/package.json`. Next.js 14, React, Tailwind CSS.

```bash
cd /opt/navigator/frontend
npm install
```

---

## 7. Environment Variables

Create `/opt/navigator/.env`:

```env
# Database (Docker PostgreSQL example)
DATABASE_URL=postgresql+asyncpg://navigator:navigator_secure_password@127.0.0.1:5433/navigator

# Redis (existing)
REDIS_URL=redis://127.0.0.1:6379/1

# JWT (generate: openssl genrsa -out private.pem 2048)
SECRET_KEY_PATH=./private.pem
JWT_PUBLIC_KEY_PATH=./public.pem

# App
ALLOWED_ORIGINS=http://localhost:3000,http://127.0.0.1:3000
FRONTEND_URL=http://localhost:3000
```

---

## 8. Database Migrations & Seed

```bash
cd /opt/navigator/backend
source venv/bin/activate
alembic upgrade head
python scripts/seed_db.py
```

---

## 9. Run Application

### Option A: PM2 (Recommended)

```bash
# Production (build + start)
./scripts/pm2-start.sh

# Or dev mode (hot reload, no build)
./scripts/pm2-dev.sh

# Commands
pm2 list
pm2 logs
pm2 restart navigator-backend navigator-frontend
pm2 stop navigator-backend navigator-frontend
```

### Option B: Manual

**Backend (FastAPI):**
```bash
cd /opt/navigator/backend
source venv/bin/activate
uvicorn app.main:app --host 0.0.0.0 --port 5001
```

**Frontend (Next.js):**
```bash
cd /opt/navigator/frontend
NEXT_PUBLIC_API_URL=http://YOUR_SERVER_IP:5001 npm run dev
# Production: npm run build && npm start
```

---

## 10. Ports Used by Navigator

| Service    | Port | Notes                    |
|-----------|------|--------------------------|
| Backend   | 5001 | FastAPI                  |
| Frontend  | 3000 | Next.js                  |
| PostgreSQL| 5433 | Docker (host mapping)    |
| Redis     | 6379 | Shared (existing)        |

## 11. Docker Containers (Navigator Only)

```bash
# PostgreSQL for Navigator
docker run -d --name navigator-postgres \
  -e POSTGRES_USER=navigator \
  -e POSTGRES_PASSWORD=navigator_secure_password \
  -e POSTGRES_DB=navigator \
  -p 5433:5432 \
  -v navigator_pgdata:/var/lib/postgresql/data \
  postgres:16-alpine
```

---

## Migration Checklist

When moving to a new server:

1. [ ] Install system packages (Python, Node, Git)
2. [ ] Start PostgreSQL (Docker or system)
3. [ ] Ensure Redis is running
4. [ ] Clone PayloadsAllTheThings and SecLists to `data/`
5. [ ] Copy `.env` and adjust `DATABASE_URL`, `REDIS_URL` if needed
6. [ ] Run `pip install -r backend/requirements.txt`
7. [ ] Run `npm install` in frontend
8. [ ] Run `alembic upgrade head`
9. [ ] Run `python scripts/seed_db.py`
10. [ ] Start backend and frontend

---

## Process Protection

**Do NOT** stop, restart, or modify these existing server processes:
- nginx, redis, mongod, docker, PM2, dedsec-training, CyberSentinal, serve (3001)

Navigator runs independently on ports 5001 (backend) and 3000 (frontend).
