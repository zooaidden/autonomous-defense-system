# MCP 协议落地说明（Model Context Protocol）

本目录 **`autonomous-defense-system`** 内的 MCP 实现分为三层：

1. **三个 MCP Server**（stdio / FastMCP）：`mcp-servers/topology-mcp-server`、`policy-mcp-server`、`actuator-mcp-server`，各自暴露工具（tools），统一返回信封 `{success, data, message}`。
2. **agent-brain 内 MCP Client**：`TopologyMCPClient`、`PolicyMCPClient`，支持 **`disabled` / `local` / `real`** 三档；默认 **`ENABLE_MCP=false`**，本地开发打开后为 **`local`**（同进程加载 `*_service.py`，无需单独进程）。
3. **消费侧**：Planner / Red-Teamer 使用拓扑 MCP（经 `TopologyMCPClient`）；Coordinator 使用 Policy MCP（经 `PolicyMCPClient`，需在编排器中注入）。

---

## 架构关系（简化）

```text
                    ENABLE_MCP=true
                           │
         ┌─────────────────┼─────────────────┐
         ▼                 ▼                 ▼
 TopologyMCPClient   PolicyMCPClient    （可选）actuator-mcp
 planner / red_team   Coordinator        人工/调度侧调用 execute_strategy
         │                 │
         └────────► agent-brain DebateWorkflow ◄───┘
                           │
                    dashboard-ui（mcp_trace 可视化）
```

`actuator-mcp-server` **不**由 Coordinator 自动拉起；它在策略获批后由上层（人或前端）通过 MCP 工具下发执行，详见该目录 README。

---

## 必需环境变量（总闸）

| 变量 | 默认值 | 含义 |
|------|--------|------|
| **`ENABLE_MCP`** | `false` | **`true`** 时拓扑客户端与策略客户端均视为开启（两者共用这一开关）。 |

以下为 **`ENABLE_MCP=true`** 时常用配置：

| 变量 | 默认值 | 含义 |
|------|--------|------|
| **`MCP_TOPOLOGY_MODE`** | `local` | `local`：直接加载 `topology_service.py`；`real`：子进程运行 `server.py`（需安装官方 `mcp` 包：`pip install -e ".[mcp]"`）。 |
| **`MCP_POLICY_MODE`** | `local` | 同上，对应 `policy-mcp-server`。 |
| **`TOPOLOGY_MCP_SERVER_PATH`** | 仓库内 `mcp-servers/topology-mcp-server` | 自定义路径时使用。 |
| **`POLICY_MCP_SERVER_PATH`** | 仓库内 `mcp-servers/policy-mcp-server` | 同上。 |
| **`MCP_PYTHON_EXECUTABLE`** | 当前解释器 | `real` 模式下启动各 `server.py`。 |
| **`MCP_REQUEST_TIMEOUT_S`** | `10` | `real` 模式单次工具超时（秒）。 |

Windows PowerShell 示例：

```powershell
cd autonomous-defense-system\agent-brain
$env:ENABLE_MCP="true"
$env:MCP_TOPOLOGY_MODE="local"
$env:MCP_POLICY_MODE="local"
pip install -e .
python -m uvicorn agent_brain.main:app --reload --port 8001
```

---

## agent-brain 运行时行为

- **`POST /workflow/run`**：走完整编排（博弈 → 可选 formal-verifier HTTP → actuator HTTP）。当 **`ENABLE_MCP=true`** 且已向 **`DebateOrchestrator` 注入 `PolicyMCPClient`** 时，Coordinator 会在决策链路中调用 **policy-mcp**（`validate_strategy` 等），并在响应里填充 **`mcp_trace` / `policy_validation`** 等字段（详见 Phase 6 模型）。
- **`GET /health`**：返回 **`llm`**（`mock` 或 `http_chat` + 模型名）、**`mcp`**（Policy/Topology 模式与路径）、以及 **`mcpSdkInstalled`**（是否已安装 PyPI `mcp` 包）。
- **`local` 模式**：不需要手动执行 `python server.py`；各 `*_service.py` 在进程内导入。
- **`real` 模式**：由 Client 以 stdio 拉起对应 **`server.py`**，需安装 **`pip install -e ".[mcp]"`**（或 `pip install "mcp>=1.2.0"`）。

---

## 三个 MCP Server 的职责速查

| Server | 路径 | 文档 |
|--------|------|------|
| topology | `mcp-servers/topology-mcp-server` | [README](../mcp-servers/topology-mcp-server/README.md) |
| policy | `mcp-servers/policy-mcp-server` | [README](../mcp-servers/policy-mcp-server/README.md) |
| actuator | `mcp-servers/actuator-mcp-server`（调用现有 actuator-service REST） | [README](../mcp-servers/actuator-mcp-server/README.md) |

---

## 与「仅 MVP /debate」的区别

- **`POST /debate`**：仅为旧版兼容的**纯博弈层**，**不**经过 Coordinator 的 Policy MCP 闸门（与旧 agent-service 对齐）。
- 若需要 **完整 MCP 数据链**，请使用 **`POST /workflow/run`** 并设置 **`ENABLE_MCP=true`**。

---

## 生产级「真实」链路（real MCP + 真实 LLM + 依赖服务）

### 目标是否已在代码中满足？

| 能力 | 状态 |
|------|------|
| **MCP `real` 模式**（stdio 子进程 `server.py` + 官方 SDK） | **已支持**：`MCP_TOPOLOGY_MODE=real`、`MCP_POLICY_MODE=real` 且 `pip install -e ".[mcp]"`。 |
| **真实多智能体 LLM**（非 Mock 字符串） | **已支持**：配置 **`AGENT_BRAIN_LLM_API_KEY`**（或 **`OPENAI_API_KEY`**）及 **`AGENT_BRAIN_LLM_BASE_URL` / `AGENT_BRAIN_LLM_MODEL`**；未配置则 **`llm.kind=mock`**。 |
| **形式化校验 / 执行 HTTP** | **需进程**：`formal-verifier`（8002）、`actuator-service`（8081）。 |

若 **`GET /health`** 中 **`llm.kind` 仍为 `mock`**，则不算业务意义上的真实推理博弈。

### 依赖安装（`agent-brain` 目录）

```powershell
pip install -e ".[mcp]"
```

### 环境变量示例（real MCP + 真实 LLM）

```powershell
$env:ENABLE_MCP="true"
$env:MCP_TOPOLOGY_MODE="real"
$env:MCP_POLICY_MODE="real"

$env:AGENT_BRAIN_LLM_API_KEY="你的_API_Key"
$env:AGENT_BRAIN_LLM_BASE_URL="https://api.siliconflow.cn/v1"
$env:AGENT_BRAIN_LLM_MODEL="Pro/deepseek-ai/DeepSeek-V3.2"
$env:AGENT_BRAIN_LLM_TIMEOUT_SECONDS="120"
```

### 建议启动顺序

1. `deploy`：`docker compose up -d`
2. **formal-verifier**：`python -m uvicorn formal_verifier.main:app --host 0.0.0.0 --port 8002`
3. **actuator-service**：`mvn spring-boot:run`（监听 **8081**）
4. **agent-brain**：在上述环境变量下 `python -m uvicorn agent_brain.main:app --host 0.0.0.0 --port 8001`

自检：**`GET http://localhost:8001/health`** — `llm.kind=http_chat`，`mcp.policy.mode=real`，`mcp.topology.mode=real`，`mcpSdkInstalled=true`。

5. （可选）**defense-gateway**、**dashboard-ui**

---

## 常见问题

**Q：`ENABLE_MCP=true` 但 `mcp_trace` 仍为空？**  
Check：`local` 模式下 Planner/Red-Team 是否实际发起了拓扑调用；Policy 是否在 Coordinator 阶段成功调用（若策略未进入校验分支也可能为空）。可用 **`GET /health`** 确认 `policy.mode` / `topology.mode` 不是 `disabled`。

**Q：`real` 模式报错找不到 `mcp`？**  
执行：`pip install -e ".[mcp]"`（在 `agent-brain` 目录）。

**Q：actuator-mcp 何时启动？**  
通常为策略获批后的执行通道；需 **`ACTUATOR_BASE_URL`**（默认 `http://localhost:8081`）指向已运行的 `actuator-service`。详见 `actuator-mcp-server/README.md`。
