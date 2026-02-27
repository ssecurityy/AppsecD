#!/bin/bash
# VAPT Navigator - PM2 Dev Mode (hot reload, no build)
set -e

cd /opt/navigator
mkdir -p logs

pm2 delete navigator-backend 2>/dev/null || true
pm2 delete navigator-frontend 2>/dev/null || true

echo "Starting VAPT Navigator (dev mode) with PM2..."
pm2 start ecosystem.dev.cjs

echo ""
echo "  Dev mode: hot reload enabled"
echo "  pm2 logs"
echo "================================="
