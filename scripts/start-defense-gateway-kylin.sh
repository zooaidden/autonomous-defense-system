#!/usr/bin/env bash
set -e

ROOT=/home/zhu/multiple-agent/autonomous-defense-system
JAVA21=/usr/lib/jvm/java-21-openjdk-21.0.10.7-10.p01.ky11.x86_64

cd "$ROOT/defense-gateway"

export JAVA_HOME=$JAVA21
export PATH=$JAVA_HOME/bin:$PATH

export SERVER_PORT=8080
export AGENT_BRAIN_BASE_URL=http://localhost:8001
export FORMAL_VERIFIER_BASE_URL=http://localhost:8002
export ACTUATOR_SERVICE_BASE_URL=http://localhost:8081
export KAFKA_BOOTSTRAP_SERVERS=localhost:9092

echo "[gateway] Checking MySQL container..."
if ! docker ps --format '{{.Names}}' | grep -q '^ads-mysql$'; then
  echo "ERROR: ads-mysql container is not running."
  echo "Start infra first:"
  echo "  cd $ROOT"
  echo "  ./scripts/start-all-kylin-tmux.sh"
  exit 1
fi

echo "[gateway] Waiting for MySQL ready..."
for i in $(seq 1 60); do
  if docker exec ads-mysql sh -c 'mysqladmin ping -uroot -p"$MYSQL_ROOT_PASSWORD" --silent' >/dev/null 2>&1; then
    echo "[gateway] MySQL is ready."
    break
  fi

  if [ "$i" -eq 60 ]; then
    echo "ERROR: MySQL is not ready after waiting."
    docker logs --tail 80 ads-mysql
    exit 1
  fi

  sleep 2
done

DB_NAME="$(docker exec ads-mysql sh -c 'printf "%s" "${MYSQL_DATABASE:-autonomous_defense}"')"
DB_PASS="$(docker exec ads-mysql sh -c 'printf "%s" "$MYSQL_ROOT_PASSWORD"')"

if [ -z "$DB_PASS" ]; then
  echo "ERROR: MYSQL_ROOT_PASSWORD is empty in ads-mysql container."
  exit 1
fi

DB_USER="root"

echo "[gateway] Ensuring database exists: $DB_NAME"
docker exec ads-mysql sh -c "mysql -uroot -p\"\$MYSQL_ROOT_PASSWORD\" -e 'CREATE DATABASE IF NOT EXISTS \`${DB_NAME}\` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;'"

export SPRING_DATASOURCE_URL="jdbc:mysql://127.0.0.1:3307/${DB_NAME}?useSSL=false&allowPublicKeyRetrieval=true&serverTimezone=Asia/Shanghai&characterEncoding=utf8"
export SPRING_DATASOURCE_USERNAME="$DB_USER"
export SPRING_DATASOURCE_PASSWORD="$DB_PASS"
export SPRING_JPA_DATABASE_PLATFORM=org.hibernate.dialect.MySQLDialect

echo "[gateway] Starting defense-gateway:"
echo "  datasource.url=$SPRING_DATASOURCE_URL"
echo "  datasource.username=$SPRING_DATASOURCE_USERNAME"
echo "  datasource.password=<hidden>"

if [ -f "pom.xml" ]; then
  echo "[gateway] Detected Java/Maven defense-gateway."
  mvn -DskipTests clean package
  JAR=$(ls target/*.jar | grep -v original | head -n 1)
  java -jar "$JAR" --server.port=8080
else
  echo "ERROR: pom.xml not found in defense-gateway."
  exit 1
fi
