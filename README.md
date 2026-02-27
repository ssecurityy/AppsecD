# VAPT Navigator

Intelligent Web Application Security Testing Platform — gamified, guided, and trackable.

## Quick Start

**Access the application:**
- **Frontend:** http://31.97.239.245:3000
- **Backend API:** http://31.97.239.245:5001
- **API Docs:** http://31.97.239.245:5001/docs

## Tech Stack

- **Frontend:** Next.js 14, Tailwind CSS
- **Backend:** FastAPI (Python)
- **Database:** PostgreSQL 16 (Docker)
- **Cache:** Redis
- **Payloads:** [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- **Wordlists:** [SecLists](https://github.com/danielmiessler/SecLists)

## Project Structure

```
/opt/navigator/
├── backend/          # FastAPI backend
├── frontend/         # Next.js 14 frontend
├── data/             # PayloadsAllTheThings + SecLists
├── INSTALLATION.md    # Migration & setup guide
└── .cursor/rules/    # Process protection rules
```

## Run with PM2

```bash
# Production
./scripts/pm2-start.sh

# Dev (hot reload)
./scripts/pm2-dev.sh

pm2 logs
```

## Run Manually

```bash
# Backend
cd backend && source venv/bin/activate && uvicorn app.main:app --host 0.0.0.0 --port 5001

# Frontend (new terminal)
cd frontend && npm run dev
```

## Migration

See [INSTALLATION.md](INSTALLATION.md) for full dependency list and migration steps.

## Process Protection

This app runs alongside other services. **Never** stop/restart nginx, redis, mongod, PM2, or other applications. Navigator uses ports 5001 and 3000 only.
