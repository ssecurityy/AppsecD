# AGENTS.md

## Cursor Cloud specific instructions

### Project overview

VAPT Navigator (AppSecD) is a security testing platform with a FastAPI backend and Next.js 14 frontend. See `README.md` and `INSTALLATION.md` for full documentation.

### Services

| Service | Port | How to run |
|---------|------|------------|
| Backend (FastAPI) | 5001 | `cd backend && source venv/bin/activate && uvicorn app.main:app --host 0.0.0.0 --port 5001` |
| Frontend (Next.js) | 3000 | `cd frontend && npm run dev` |
| PostgreSQL | 5433 | `sudo docker start navigator-postgres` |
| Redis | 6379 | Already running as system service |

### Key caveats

- **Process protection**: NEVER stop/restart nginx, redis, mongod, PM2, or other server processes. Only manage Navigator's own processes. See `.cursor/rules/process-protection.mdc`.
- **Docker-in-Docker**: The cloud VM needs `fuse-overlayfs`, `iptables-legacy`, and a running `dockerd` before starting the PostgreSQL container. Run `sudo dockerd &>/tmp/dockerd.log &` then `sudo docker start navigator-postgres`.
- **Backend venv**: Always activate with `cd /workspace/backend && source venv/bin/activate` before running Python commands.
- **Backend verification**: Quick check: `cd /workspace/backend && source venv/bin/activate && python -c "from app.main import app; print('OK')"`.
- **Tests**: Existing tests use `pytest` against a `navigator_test` database. Some tests have pre-existing failures (test user uniqueness, app name mismatch). Create the test DB if needed: `sudo docker exec navigator-postgres psql -U navigator -d navigator -c "CREATE DATABASE navigator_test;"`.
- **LLM config**: Multi-provider (OpenAI, Anthropic, Google). Org-scoped via `org_settings_service.get_llm_config(db, org_id)`. No API keys needed for rule-based fallbacks.
- **Lint**: No dedicated linter configured in the repo. Use `python -m py_compile <file>` for syntax checks.
- **Build**: Backend has no build step (runs directly). Frontend builds via `npm run build` in `frontend/`.
- **Database init**: The Alembic migrations have dependency issues (migration 001 doesn't create all tables). Use `python scripts/init_db.py` to create all tables via `Base.metadata.create_all`, then `alembic stamp 016` to mark migrations as applied. The `audit_logs` table is missing from `app/models/__init__.py` exports, so after `init_db.py` you must also create it: `python -c "import asyncio; from app.core.database import engine, Base; from app.models.audit_log import AuditLog; asyncio.run((lambda: None)() or asyncio.coroutine(lambda: None)())"` or use the one-liner shown in the seed step below.
- **Redis in cloud VM**: Redis is NOT pre-installed in cloud VMs. Start it with `redis-server --daemonize yes` after the update script installs it.
- **Frontend lint**: `cd frontend && npx next lint` (ESLint via Next.js). Only 1 pre-existing warning (`<img>` vs `<Image />` in login page).
- **Default credentials**: superadmin / `SuperAdmin@2026!`, admin / `Admin@2026!`, tester / `Tester@2026!`.
