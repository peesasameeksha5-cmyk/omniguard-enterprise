#!/bin/sh
set -e

echo "============================================================"
echo "  OmniGuard Enterprise — Starting Services"
echo "============================================================"

# Load .env.credentials if mounted
if [ -f /run/secrets/omniguard-env ]; then
  export $(cat /run/secrets/omniguard-env | grep -v '^#' | xargs)
elif [ -f /app/.env.credentials ]; then
  export $(cat /app/.env.credentials | grep -v '^#' | xargs)
fi

echo "[1/3] Starting nginx (frontend on :8080)..."
nginx -g 'daemon off;' &
NGINX_PID=$!

echo "[2/3] Starting OmniGuard daemon (API on :5175)..."
node /app/cli/src/daemon.js &
DAEMON_PID=$!

# Wait for daemon to be ready
for i in $(seq 1 20); do
  if curl -sf http://localhost:5175/healthz > /dev/null 2>&1; then
    echo "[daemon] Ready on port 5175"
    break
  fi
  sleep 1
done

echo "[3/3] All services started"
echo ""
echo "  Dashboard:  http://localhost:8080"
echo "  Daemon API: http://localhost:5175"
echo "  Health:     http://localhost:5175/healthz"
echo ""

# Wait for either process to exit
wait $DAEMON_PID $NGINX_PID
