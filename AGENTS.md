# AGENTS.md

## Cursor Cloud specific instructions

### Overview

VAPT Navigator is a full-stack web application for security testing management. It has a **FastAPI backend** (port 5001) and a **Next.js frontend** (port 3000), backed by **PostgreSQL 16** (Docker, port 5433) and **Redis** (port 6379, DB index 1).

### Process Protection

**CRITICAL**: This app runs alongside other services. Never stop/restart nginx, redis, mongod, docker, PM2, or other pre-existing processes. Navigator uses ports 5001 (backend) and 3000 (frontend) only. See `.cursor/rules/process-protection.mdc` for details.

### Starting services

1. **Docker + PostgreSQL**: `sudo dockerd &>/tmp/dockerd.log &` then `sudo docker start navigator-postgres` (or create the container per `INSTALLATION.md` Section 2 if it doesn't exist).
2. **Redis**: `sudo redis-server --daemonize yes` (if not already running; check with `redis-cli ping`).
3. **Backend**: `cd /workspace/backend && source venv/bin/activate && uvicorn app.main:app --host 0.0.0.0 --port 5001 --reload &`
4. **Frontend**: `cd /workspace/frontend && NEXT_PUBLIC_API_URL=http://localhost:5001 npm run dev -- --port 3000 &`

### Gotchas discovered during setup

- **Missing model files**: `backend/app/models/payload_category.py` and `backend/app/models/payload_source.py` were missing from the repo. Stub Pydantic models were created. These are non-DB models (no migration tables).
- **Missing migrations 010 & 011**: The original repo skipped from migration 009 to 012. Migrations 010 (users, project_test_results, extra project/test_case columns) and 011 (findings) were created. Also, migration 002 references the `users` table but it's not created until 010, so on a fresh DB you must use `Base.metadata.create_all` then `alembic stamp 012` instead of `alembic upgrade head`.
- **Backend .env resolution**: The backend `config.py` loads `.env` from CWD. A symlink `backend/.env -> /workspace/.env` ensures it works when running from the `backend/` directory.
- **Lint**: `npx next lint` in `frontend/`. No Python linter is configured in the repo.
- **Default credentials**: admin / `Admin@2026!`, tester / `Tester@2026!` (created by `seed_db.py`).
- **API route prefix**: Routes use no `/api` prefix (e.g., `/auth/login`, `/projects`, `/health`).
