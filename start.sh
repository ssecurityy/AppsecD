#!/bin/bash
# VAPT Navigator - Start Script
set -e

echo "================================="
echo "   VAPT Navigator - Starting..."
echo "================================="

mkdir -p /opt/navigator/logs

# Kill only navigator processes
pkill -f "uvicorn app.main" 2>/dev/null || true
pkill -f "next dev" 2>/dev/null || true
sleep 2

# Start Backend
echo "[1/2] Starting FastAPI backend on port 5001..."
cd /opt/navigator/backend
source venv/bin/activate
nohup uvicorn app.main:app --host 0.0.0.0 --port 5001 --workers 2 \
  > /opt/navigator/logs/backend.log 2>&1 &
BACKEND_PID=$!
echo "    Backend PID: $BACKEND_PID"
sleep 4

# Verify backend
if curl -s http://127.0.0.1:5001/health > /dev/null 2>&1; then
  echo "    ✅ Backend: RUNNING"
else
  echo "    ❌ Backend failed to start. Check logs/backend.log"
fi

# Start Frontend
echo "[2/2] Starting Next.js frontend on port 3000..."
cd /opt/navigator/frontend
nohup npm run dev -- --port 3000 \
  > /opt/navigator/logs/frontend.log 2>&1 &
FRONTEND_PID=$!
echo "    Frontend PID: $FRONTEND_PID"
sleep 8

echo ""
echo "================================="
echo "  VAPT Navigator is LIVE!"
echo "================================="
echo ""
echo "  🌐 Application:  http://31.97.239.245:3000"
echo "  🔌 API Docs:     http://31.97.239.245:5001/docs"
echo "  ❤️  Health:       http://31.97.239.245:5001/health"
echo ""
echo "  Default Credentials:"
echo "  👤 Super Admin: superadmin / SuperAdmin@2026!"
echo "  👤 Org Admin:   admin / Admin@2026!"
echo "  👤 Tester:      tester / Tester@2026!"
echo ""
echo "  Logs: /opt/navigator/logs/"
echo "================================="
