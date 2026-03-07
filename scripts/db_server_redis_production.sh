#!/bin/bash
# Production Redis on DB server (31.97.236.44).
# Shared by app servers for cache, sessions, Celery broker. Fail-safe: healthcheck + restart.
# Run on DB server as root.

set -e
CONTAINER_NAME="navigator-redis"
REDIS_PORT="${REDIS_PORT:-6379}"
VOLUME_NAME="navigator_redis_data"
# Allow these IPs to connect (Navigator app servers)
NAVIGATOR_APP_IP_1="31.97.239.245"
# NAVIGATOR_APP_IP_2="<SECOND_APP_SERVER_IP>"  # Add when second server is ready

MEM_LIMIT="1g"

echo "[1/5] Stopping and removing existing container (volume preserved)..."
docker stop "$CONTAINER_NAME" 2>/dev/null || true
docker rm "$CONTAINER_NAME" 2>/dev/null || true

echo "[2/5] UFW: allow Redis from Navigator app server(s)..."
if command -v ufw &>/dev/null; then
  ufw allow from "$NAVIGATOR_APP_IP_1" to any port "$REDIS_PORT" comment "Navigator Redis" 2>/dev/null || true
  ufw --force enable 2>/dev/null || true
  ufw reload 2>/dev/null || true
fi

echo "[3/5] Starting Redis 7 with persistence and healthcheck..."
docker run -d \
  --name "$CONTAINER_NAME" \
  --restart unless-stopped \
  --memory="$MEM_LIMIT" \
  --memory-swap="$MEM_LIMIT" \
  --health-cmd="redis-cli ping" \
  --health-interval=10s \
  --health-timeout=5s \
  --health-retries=3 \
  --health-start-period=10s \
  -p "${REDIS_PORT}:6379" \
  -v "${VOLUME_NAME}:/data" \
  redis:7-alpine \
  redis-server --appendonly yes --maxmemory 512mb --maxmemory-policy allkeys-lru

echo "[4/5] Waiting for Redis to be ready..."
for i in $(seq 1 20); do
  if docker exec "$CONTAINER_NAME" redis-cli ping 2>/dev/null | grep -q PONG; then
    echo "    Ready."
    break
  fi
  sleep 1
done
docker exec "$CONTAINER_NAME" redis-cli ping | grep -q PONG || { echo "Redis failed to start"; exit 1; }

echo "[5/5] Health status..."
docker inspect --format='{{.State.Health.Status}}' "$CONTAINER_NAME" 2>/dev/null || true

echo ""
echo "Redis is running. REDIS_URL for app servers: redis://31.97.236.44:${REDIS_PORT}/1"
