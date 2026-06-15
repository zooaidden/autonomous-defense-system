# autonomous-defense-system

本项目是一个本地可运行的多模块安全防御系统骨架，包含事件接入、智能体决策、形式化校验、策略执行与可视化展示。

## 模块

- `defense-gateway` (Java/Spring Boot): 安全事件接收、规范化、消息发布
- `agent-brain` (Python): LangGraph 多智能体工作流占位实现
- `formal-verifier` (Python): 策略约束校验与 Z3/OPA 适配层占位
- `actuator-service` (Java/Spring Boot): 策略执行与回滚模拟
- `dashboard-ui` (React + TypeScript): 事件、策略、执行结果可视化
- `acd-orchestration-service` (Java/Spring Boot): **整合入口**，对齐旧仓库「后端 MVP」：`SecurityEvent` → `agent-brain` 的 `/debate`（LangGraph 博弈）→ Java 侧简化校验与模拟执行（`/api/events`、`SSE 模拟流`）
- `deploy`: 本地 docker-compose 与环境配置
- `docs`: 架构、API、开发文档；**[MCP 协议落地说明](./docs/mcp.md)**（环境变量、三种 Server、`local`/`real` 模式）

## 官方主线与兼容链路

- **官方主线（推荐 / 验收默认）**：
  `dashboard-ui` → `agent-brain (POST /workflow/run)` → MCP 感知（topology / policy / OS）
  → `formal-verifier` → **actuator MCP 预检（in-process，与 actuator-mcp-server 同套规则）**
  → `actuator-service (POST /api/strategies/execute)`。
- **兼容链路（仅 legacy demo，禁止用于验收）**：`acd-orchestration-service` +
  `agent-brain (/debate, /debate/stream)`，沿用旧仓库 MVP 契约的内存模拟校验
  与执行链路。新功能、A2 评审、答辩演示一律请走官方主线。

### 端口矩阵（默认）

| 模块 | 端口 | 说明 |
|---|---:|---|
| defense-gateway | 8080 | 事件接入（MySQL + Kafka） |
| agent-brain | 8001 | 多智能体与主工作流入口 `/workflow/run` |
| formal-verifier | 8002 | 形式化校验 |
| actuator-service | 8081 | 执行与回滚 |
| dashboard-ui | 5173 | 前端界面 |
| acd-orchestration-service | 8090 | 旧 MVP 编排兼容入口 |

> 开发建议：优先使用官方主线；仅在需要验证旧协议时启用 `acd-orchestration-service`。

### MCP（Model Context Protocol）落地

仓库已实现 **topology / policy / actuator** 三个 MCP Server（见 `mcp-servers/`），以及 **`TopologyMCPClient` / `PolicyMCPClient`**。在 **`agent-brain`** 中：

1. 设置 **`ENABLE_MCP=true`**（推荐再配合 **`MCP_*_MODE=local`**）即可在不单独拉起 `server.py` 的情况下走 **local** 落地（同进程加载 `*_service.py`）。
2. **`POST /workflow/run`** 已将 **`PolicyMCPClient`** 注入 **`Coordinator`**；Planner / Red-Team 默认使用 **`TopologyMCPClient`**（读取同一 `ENABLE_MCP`）。
3. **`GET /health`** 返回 **`mcp`** 字段，可核对 Policy/Topology 是否启用、`real` 模式所需 **`mcp`** PyPI 包是否已安装。

完整说明、变量表与排障见 **`docs/mcp.md`**；可复制本目录下 **`.env.example`** 为 `.env` 并按需修改。

### 「后端 MVP」整合说明（替代仓库根目录 `backend/` + `agent-service/`）

- **博弈推理**：由 **`agent-brain`** 提供与旧版兼容的 **`POST /debate`**、**`POST /debate/stream`**（原先独立进程 agent-service）。
- **编排与 SSE**：由 **`acd-orchestration-service`**（端口 **`8090`**）承接原先 Spring **`backend`** 的职责；仅需再起 **`agent-brain:8001`**，无须并行 Python MVP。
- **整条纵深链路（网关→Kafka→…）**：仍按下列顺序启动；编排层可按需接入或与网关并行演示。

## 本地开发建议

优先使用模块内独立启动方式，先跑通最小链路：

1. `deploy` 中基础依赖（Kafka）  
2. `defense-gateway`  
3. `agent-brain`  
4. `formal-verifier`  
5. `actuator-service`  
6. `dashboard-ui`

## 运行模式说明（保证兼容）

- `AGENT_BRAIN_FAILURE_MODE=strict`（**.env.example 现已默认**）：关键依赖不可达时
  返回失败信封，适合联调与 A2 验收；改为 `compat` 仅在离线演示场景使用，并明确
  告知评审「正在使用降级兜底」。
- `AGENT_BRAIN_ROOT_POLICY=refuse`（默认）：agent-brain 以 root / Administrator
  启动时直接退出；`degrade` 允许启动但 LeastPrivilegeExecutor 锁定只读模式。
- `WORKFLOW_GUARD_STRICT=true`（默认）：`POST /workflow/run` 在 prompt-injection
  或 system-config 护栏命中 BLOCK 时强制把 `nextAction` / `actuatorResponse`
  改为 `BLOCKED`，并附 `blockedBy` 字段。
- `ACTUATOR_MCP_GUARD_ENABLED=true`（默认）：agent-brain `ActuatorClient` 在
  提交策略前执行 actuator-mcp-server 同套预检（rollback plan / TTL / 高风险动作）；
  违规直接返回 `status=BLOCKED`，不发起 HTTP 调用。
- `ACTUATOR_DEFAULT_DRY_RUN=true`（默认）：agent-brain 向 actuator-service 提交
  的策略默认携带 `dryRun=true`；actuator-service 仅当请求体显式 `dryRun=false`
  才会走真实运行分支（当前实现仍为内存模拟，详见 actuator-service 节）。
- CORS 可按服务独立配置：`AGENT_BRAIN_CORS_ORIGINS`、`GATEWAY_CORS_ALLOWED_ORIGINS`、
  `ACD_ORCHESTRATION_CORS_ALLOWED_ORIGINS`（默认兼容）。
- 下游地址：`FORMAL_VERIFIER_BASE_URL`（默认 `:8002`）、`ACTUATOR_SERVICE_BASE_URL`
  （默认 `:8081`）；前端使用 `VITE_API_BASE_URL` / `VITE_AGENT_BRAIN_BASE_URL` /
  `VITE_ACTUATOR_BASE_URL` 区分三条 base。

## 安全护栏速览

| 层 | 守门点 | 触发后行为 |
|---|---|---|
| Prompt Injection Guard | `/ops/chat` 与 `/workflow/run` 的最前端 | 立刻返回 BLOCKED，记审计 `prompt_injection_detected` |
| System Config Guard | 关键配置文件路径写入检测 | 立刻返回 BLOCKED，记审计 `config_guard_blocked` |
| Intent Validator | 33 条意图规则（rm/chmod/mkfs/iptables/...） | ALLOW / REQUIRE_APPROVAL / BLOCK |
| LeastPrivilegeExecutor | 9 条只读命令白名单 + 拒绝 sudo/doas/su/pkexec | 不在白名单 → REJECTED；root 启动 → 进程拒启 |
| Actuator MCP Pre-check | `ActuatorClient.submit_strategy` | 高风险动作缺 rollbackPlan / TTL → BLOCKED |
| Formal Verifier 规则集 | 6+5 条策略约束（0.0.0.0/0、kube-system、TTL、rollbackPlan、DNS、prod 核心服务） | `passed=false` + `violatedConstraints` |
