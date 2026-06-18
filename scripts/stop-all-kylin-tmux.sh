#!/usr/bin/env bash
set -e

ROOT=/home/zhu/multiple-agent/autonomous-defense-system
SESSION=ads
APP_PORTS=(5173 8001 8002 8080 8081)

echo "[0/5] Checking current user..."
if [ "$(id -un)" != "zhu" ]; then
  echo "ERROR: please run this script as user zhu, not root."
  exit 1
fi

echo "[1/5] Checking sudo permission..."
if ! sudo -v; then
  echo "ERROR: user zhu has no sudo permission."
  exit 1
fi

echo "[2/5] Stopping tmux session: $SESSION"
tmux kill-session -t "$SESSION" 2>/dev/null || true
tmux kill-session -t defense 2>/dev/null || true

echo "[3/5] Killing stale app processes by ports..."
for p in "${APP_PORTS[@]}"; do
  PIDS="$(sudo ss -lntp 2>/dev/null | grep ":${p} " | sed -n 's/.*pid=\([0-9]\+\).*/\1/p' | sort -u || true)"
  if [ -n "$PIDS" ]; then
    echo "[cleanup] port $p -> pids: $PIDS"
    sudo kill $PIDS 2>/dev/null || true
  fi
done

sleep 2

for p in "${APP_PORTS[@]}"; do
  PIDS="$(sudo ss -lntp 2>/dev/null | grep ":${p} " | sed -n 's/.*pid=\([0-9]\+\).*/\1/p' | sort -u || true)"
  if [ -n "$PIDS" ]; then
    echo "[cleanup] force killing port $p -> pids: $PIDS"
    sudo kill -9 $PIDS 2>/dev/null || true
  fi
done

echo "[4/5] Locating docker compose file..."
if [ -f "$ROOT/deploy/docker-compose.yml" ]; then
  COMPOSE_FILE="$ROOT/deploy/docker-compose.yml"
elif [ -f "$ROOT/deploy/docker-compose.yaml" ]; then
  COMPOSE_FILE="$ROOT/deploy/docker-compose.yaml"
elif [ -f "$ROOT/docker-compose.yml" ]; then
  COMPOSE_FILE="$ROOT/docker-compose.yml"
elif [ -f "$ROOT/docker-compose.yaml" ]; then
  COMPOSE_FILE="$ROOT/docker-compose.yaml"
else
  echo "No docker-compose file found, skip infra stop."
  exit 0
fi

if docker info >/dev/null 2>&1; then
  DOCKER_CMD="docker"
else
  DOCKER_CMD="sudo docker"
fi

if $DOCKER_CMD compose version >/dev/null 2>&1; then
  COMPOSE_CMD="$DOCKER_CMD compose"
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE_CMD="docker-compose"
else
  echo "No docker compose command found, skip infra stop."
  exit 0
fi

echo "[5/5] Stopping infrastructure containers..."
$COMPOSE_CMD -f "$COMPOSE_FILE" down

echo
echo "Stopped full stack."
echo "Note: Docker volumes are kept. MySQL data is not deleted."
echo
