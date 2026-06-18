#!/usr/bin/env bash
set -e

ROOT=/home/zhu/multiple-agent/autonomous-defense-system
SESSION=ads
JAVA21=/usr/lib/jvm/java-21-openjdk-21.0.10.7-10.p01.ky11.x86_64

APP_PORTS=(5173 8001 8002 8080 8081)
INFRA_PORTS=(2181 3307 9092)

echo "[0/10] Checking current user..."
if [ "$(id -un)" != "zhu" ]; then
  echo "ERROR: please run this script as user zhu, not root."
  exit 1
fi

echo "[1/10] Checking sudo permission..."
if ! sudo -v; then
  echo "ERROR: user zhu has no sudo permission."
  exit 1
fi

echo "[2/10] Checking required commands..."
if ! command -v tmux >/dev/null 2>&1; then
  echo "[setup] tmux not found, installing..."
  sudo dnf install -y tmux
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "ERROR: docker command not found. Docker Engine is not installed."
  exit 1
fi

echo "[3/10] Starting Docker daemon..."
if systemctl list-unit-files | grep -q '^docker\.service'; then
  sudo systemctl enable --now docker
else
  echo "ERROR: docker.service not found. Docker daemon may not be installed correctly."
  exit 1
fi

echo "[4/10] Checking Docker access..."
if docker info >/dev/null 2>&1; then
  DOCKER_CMD="docker"
else
  echo "[warn] zhu cannot access docker directly. Using sudo docker for this run."
  DOCKER_CMD="sudo docker"
fi

$DOCKER_CMD ps >/dev/null

echo "[5/10] Checking Docker Compose..."
install_compose_plugin() {
  echo "[setup] Trying to install docker-compose-plugin from dnf..."
  if sudo dnf install -y docker-compose-plugin; then
    return 0
  fi

  echo "[setup] dnf package docker-compose-plugin not available."

  echo "[setup] Trying to install legacy docker-compose from dnf..."
  if sudo dnf install -y docker-compose; then
    return 0
  fi

  echo "[setup] dnf package docker-compose also not available."
  echo "[setup] Installing Docker Compose plugin manually..."

  if ! command -v curl >/dev/null 2>&1; then
    sudo dnf install -y curl
  fi

  ARCH="$(uname -m)"
  case "$ARCH" in
    x86_64|amd64)
      COMPOSE_ARCH="x86_64"
      ;;
    aarch64|arm64)
      COMPOSE_ARCH="aarch64"
      ;;
    *)
      echo "ERROR: unsupported architecture for automatic Compose install: $ARCH"
      exit 1
      ;;
  esac

  sudo mkdir -p /usr/local/lib/docker/cli-plugins
  sudo curl -fL \
    "https://github.com/docker/compose/releases/latest/download/docker-compose-linux-${COMPOSE_ARCH}" \
    -o /usr/local/lib/docker/cli-plugins/docker-compose
  sudo chmod 0755 /usr/local/lib/docker/cli-plugins/docker-compose
}

if $DOCKER_CMD compose version >/dev/null 2>&1; then
  COMPOSE_CMD="$DOCKER_CMD compose"
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE_CMD="docker-compose"
else
  install_compose_plugin

  if $DOCKER_CMD compose version >/dev/null 2>&1; then
    COMPOSE_CMD="$DOCKER_CMD compose"
  elif command -v docker-compose >/dev/null 2>&1; then
    COMPOSE_CMD="docker-compose"
  else
    echo "ERROR: Docker Compose installation failed."
    exit 1
  fi
fi

echo "[compose] Using: $COMPOSE_CMD"
$COMPOSE_CMD version || true

echo "[6/10] Locating docker compose file..."
if [ -f "$ROOT/deploy/docker-compose.yml" ]; then
  COMPOSE_FILE="$ROOT/deploy/docker-compose.yml"
elif [ -f "$ROOT/deploy/docker-compose.yaml" ]; then
  COMPOSE_FILE="$ROOT/deploy/docker-compose.yaml"
elif [ -f "$ROOT/docker-compose.yml" ]; then
  COMPOSE_FILE="$ROOT/docker-compose.yml"
elif [ -f "$ROOT/docker-compose.yaml" ]; then
  COMPOSE_FILE="$ROOT/docker-compose.yaml"
else
  echo "ERROR: docker-compose.yml not found."
  exit 1
fi

echo "[infra] Compose file: $COMPOSE_FILE"

echo "[7/10] Opening firewall ports if firewalld is active..."
if systemctl is-active --quiet firewalld; then
  for p in "${APP_PORTS[@]}" "${INFRA_PORTS[@]}"; do
    sudo firewall-cmd --zone=public --add-port=${p}/tcp --permanent >/dev/null 2>&1 || true
  done
  sudo firewall-cmd --reload >/dev/null 2>&1 || true
  echo "[firewall] Opened ports: ${APP_PORTS[*]} ${INFRA_PORTS[*]}"
else
  echo "[firewall] firewalld is not active, skip."
fi

echo "[8/10] Starting infrastructure containers..."
$COMPOSE_CMD -f "$COMPOSE_FILE" up -d
$COMPOSE_CMD -f "$COMPOSE_FILE" ps

echo "[8.1/10] Waiting for MySQL..."
for i in $(seq 1 60); do
  if $DOCKER_CMD exec ads-mysql sh -c 'mysqladmin ping -uroot -p"$MYSQL_ROOT_PASSWORD" --silent' >/dev/null 2>&1; then
    echo "[infra] MySQL is ready."
    break
  fi

  if [ "$i" -eq 60 ]; then
    echo "ERROR: MySQL is not ready after waiting."
    $DOCKER_CMD logs --tail 100 ads-mysql || true
    exit 1
  fi

  sleep 2
done

echo "[8.2/10] Waiting for Kafka port..."
for i in $(seq 1 60); do
  if ss -lnt | grep -q ':9092'; then
    echo "[infra] Kafka port is listening."
    break
  fi

  if [ "$i" -eq 60 ]; then
    echo "ERROR: Kafka port 9092 is not listening after waiting."
    $DOCKER_CMD logs --tail 100 ads-kafka || true
    exit 1
  fi

  sleep 2
done

echo "[9/10] Preparing tmux session..."

if [ -n "${TMUX:-}" ]; then
  CURRENT_TMUX_SESSION="$(tmux display-message -p '#S' 2>/dev/null || true)"
  if [ "$CURRENT_TMUX_SESSION" = "$SESSION" ]; then
    echo "ERROR: you are currently inside tmux session '$SESSION'."
    echo "Detach first: Ctrl+b then d"
    echo "Then run this script again from a normal shell."
    exit 1
  fi
fi

tmux kill-session -t "$SESSION" 2>/dev/null || true

echo "[9.1/10] Cleaning stale app processes on ports: ${APP_PORTS[*]}"
for p in "${APP_PORTS[@]}"; do
  PIDS="$(sudo ss -lntp 2>/dev/null | grep ":${p} " | sed -n 's/.*pid=\([0-9]\+\).*/\1/p' | sort -u || true)"
  if [ -n "$PIDS" ]; then
    echo "[cleanup] killing port $p pids: $PIDS"
    sudo kill $PIDS 2>/dev/null || true
    sleep 1
  fi
done

echo "[10/10] Starting tmux session: $SESSION..."

tmux new-session -d -s "$SESSION" -n infra
tmux send-keys -t "$SESSION:infra" "cd $ROOT && $COMPOSE_CMD -f $COMPOSE_FILE logs -f" C-m

tmux new-window -t "$SESSION" -n formal
tmux send-keys -t "$SESSION:formal" "cd $ROOT/formal-verifier && source .venv/bin/activate && python -m uvicorn formal_verifier.main:app --host 0.0.0.0 --port 8002" C-m

tmux new-window -t "$SESSION" -n actuator
tmux send-keys -t "$SESSION:actuator" "cd $ROOT/actuator-service && export JAVA_HOME=$JAVA21 && export PATH=\$JAVA_HOME/bin:\$PATH && if ! ls target/*.jar >/dev/null 2>&1; then mvn -DskipTests clean package; fi && JAR=\$(ls target/*.jar | grep -v original | head -n 1) && java -jar \"\$JAR\" --server.port=8081" C-m

tmux new-window -t "$SESSION" -n agent
tmux send-keys -t "$SESSION:agent" "sleep 8 && cd $ROOT && ./scripts/start-agent-brain-kylin.sh" C-m

tmux new-window -t "$SESSION" -n defense
tmux send-keys -t "$SESSION:defense" "sleep 15 && cd $ROOT && ./scripts/start-defense-gateway-kylin.sh" C-m

tmux new-window -t "$SESSION" -n ui
tmux send-keys -t "$SESSION:ui" "sleep 8 && cd $ROOT/dashboard-ui && node node_modules/vite/bin/vite.js --host 0.0.0.0 --port 5173" C-m

echo
echo "Started full stack tmux session: $SESSION"
echo
echo "Windows / browser:"
echo "  http://192.168.127.138:5173"
echo
echo "Health checks:"
echo "  curl -sS http://localhost:8001/health"
echo "  curl -sS http://localhost:8002/health"
echo "  curl -sS http://localhost:8081/api/health"
echo "  curl -sS http://localhost:8080/api/health"
echo
echo "Attach with:"
echo "  tmux attach -t $SESSION"
echo
