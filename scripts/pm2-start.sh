#!/bin/bash
# VAPT Navigator - PM2 Start Script
set -e

cd /opt/navigator
mkdir -p logs

# Stop only Navigator apps (do not touch other PM2 processes)
pm2 delete navigator-backend 2>/dev/null || true
pm2 delete navigator-frontend 2>/dev/null || true

echo "Building Next.js frontend..."
cd frontend && npm run build && cd ..

echo "Starting VAPT Navigator with PM2..."
pm2 start ecosystem.config.cjs

echo ""
echo "================================="
echo "  VAPT Navigator (PM2) - LIVE"
echo "================================="
echo ""
pm2 list
echo ""
echo "  App:    http://31.97.239.245:3000"
echo "  API:    http://31.97.239.245:5001"
echo "  Logs:   pm2 logs navigator-backend navigator-frontend"
echo "  Stop:   pm2 stop navigator-backend navigator-frontend"
echo "  Save:   pm2 save && pm2 startup  # persist across reboot"
echo "================================="
