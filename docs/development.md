# 开发说明（本地单机）

## 运行前提

- JDK 21+（与 `defense-gateway`、`actuator-service` 的 `java.version` 一致）
- Python 3.11+
- Node.js 20+
- Docker Desktop（用于 Kafka）

## MCP（Model Context Protocol）

开启方式与三种 MCP Server、Client 模式说明见 **[docs/mcp.md](./docs/mcp.md)**。

最小示例（PowerShell）：

```powershell
cd autonomous-defense-system\agent-brain
$env:ENABLE_MCP="true"
$env:MCP_TOPOLOGY_MODE="local"
$env:MCP_POLICY_MODE="local"
pip install -e .
python -m uvicorn agent_brain.main:app --reload --port 8001
```

启动后访问 **`GET http://localhost:8001/health`**，确认 `mcp.policy.enabled` / `mcp.topology.enabled` 为 **`true`**，`mode` 为 **`local`**（或按你配置的 **`real`**）。

## 数据库端口

`deploy/docker-compose.yml` 将 MySQL 映射为**宿主机 3307 → 容器 3306**。`defense-gateway` 默认 `DB_PORT=3307`；若使用本机 3306 的 MySQL，请设置环境变量 `DB_PORT=3306`（或改数据源 URL）。

## 启动顺序

### 仅演示「旧后端 MVP」（REST + SSE + 博弈 /debate）

1. `agent-brain`（必须先）：`python -m uvicorn agent_brain.main:app --reload --port 8001`
2. `acd-orchestration-service`：`cd acd-orchestration-service && mvn spring-boot:run`（默认 **`8090`**）  
   - 根目录 **`dashboard/`** 已将 API 指向 `http://localhost:8090/api`。

### 完整纵深链路（网关 / Kafka / 大屏 …）

1. `deploy`：`docker compose up -d`（在 `deploy` 目录下执行）
2. `defense-gateway`：`mvn spring-boot:run`
3. `agent-brain`：`python -m uvicorn agent_brain.main:app --reload --port 8001`
4. `formal-verifier`：`python -m uvicorn formal_verifier.main:app --reload --port 8002`
5. `actuator-service`：`mvn spring-boot:run`
6. `dashboard-ui`：`npm run dev`

## 约定端口

- acd-orchestration-service (MVP 编排): `8090`
- defense-gateway: `8080`
- actuator-service: `8081`
- agent-brain: `8001`
- formal-verifier: `8002`
- dashboard-ui: `5173`

