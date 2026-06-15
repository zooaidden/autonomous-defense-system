# actuator-mcp-server

将现有 `actuator-service`（Spring Boot）暴露的 REST API 用 MCP 协议重新封装的 MCP Server。
属于自主防御多智能体系统第四阶段产物：**只新增 MCP Server，不修改 Coordinator 自动执行链路**。

## 与 actuator-service 的对应关系

底层调用的真实接口（来自 `actuator-service/StrategyController.java`）：

| 方法 | 路径 | 返回 |
|------|------|------|
| POST | `/api/strategies/execute` | `ApiResponse<ExecutionRecord>` |
| POST | `/api/strategies/{id}/rollback` | `ApiResponse<ExecutionRecord>` |
| GET  | `/api/executions` | `ApiResponse<List<ExecutionRecord>>` |
| GET  | `/api/executions/{id}` | `ApiResponse<ExecutionRecord>` |

`ApiResponse<T>.data` 由本服务自动解包出来塞进统一信封。

## 目录结构

```
actuator-mcp-server/
├─ server.py                  # MCP 协议薄壳：4 个 tool
├─ actuator_client.py         # 业务层：HTTP 调用 + 安全检查 + mock
├─ test_actuator_client.py    # 33 个本地单元测试，无需 mcp 包
├─ README.md
└─ requirements.txt
```

`server.py` 故意做得很薄，全部业务逻辑都在 `actuator_client.py`，方便测试和替换。

## 安装与运行

```powershell
cd autonomous-defense-system/mcp-servers/actuator-mcp-server
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

# 以 stdio 协议启动 MCP server
python server.py
```

## 环境变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `ACTUATOR_BASE_URL` | `http://localhost:8081` | actuator-service 根地址，与 `actuator-service/application.yml` 中 `server.port=8081` 对齐 |
| `ACTUATOR_MODE` | `real` | `real` / `mock`。real 模式下若目标不可达，会自动降级返回 mock 结果 |
| `ACTUATOR_HTTP_TIMEOUT` | `5` | 单次 HTTP 调用超时秒数 |

> 注意：用户初始需求中的 `http://localhost:8080` 与 actuator-service 实际监听端口不一致，
> 这里以 actuator-service 的真实配置（8081）为准。如需改成其它端口，覆盖 `ACTUATOR_BASE_URL` 即可。

## 三种运行模式

| 模式 | 触发条件 | 行为 |
|------|----------|------|
| `real` | `ACTUATOR_MODE=real` 且目标可达 | 直接 HTTP 调用 `actuator-service` |
| `mock_fallback` | `ACTUATOR_MODE=real` 且目标不可达 | 自动返回模拟 ExecutionRecord，并在 `data.warnings` 中说明原因 |
| `mock` | `ACTUATOR_MODE=mock` | 完全不发 HTTP，直接合成 ExecutionRecord，用于前端联调 |

返回的 `data.mode` 字段会显式标注当前命中的模式，便于前端区分。

## 暴露的 MCP tools

### 1. `execute_strategy(strategy: dict)`

下发执行最终策略。**调用 actuator-service 之前会做 4 项安全检查**：

| 序号 | 触发条件 | 处理 |
|------|----------|------|
| 1 | `human_approval_required=true`（或 `metadata.human_approval=true`） | **拒绝** |
| 2 | `status` 不等于 `approved_for_execution` | **拒绝** |
| 3 | 缺失 `rollback_plan` 且包含高风险动作 | **拒绝**；普通动作仅 warning |
| 4 | 缺失 `ttl` / `ttl_minutes` 且包含高风险动作 | **拒绝**；普通动作仅 warning |

高风险动作集合：`BLOCK_IP / BLOCK_DOMAIN / RESTRICT_EGRESS / ISOLATE_HOST / ISOLATE_POD / DISABLE_ACCOUNT / REVOKE_TOKEN`。

成功响应：

```json
{
  "success": true,
  "data": {
    "execution_record": { "executionId": "exec-001", "status": "SUCCEEDED", "...": "..." },
    "warnings": [],
    "mode": "real",
    "pre_check": { "violations": [], "warnings": [] }
  },
  "message": "strategy executed: exec-001"
}
```

被预检拒绝时：

```json
{
  "success": false,
  "data": {
    "pre_check": {
      "violations": [
        "human_approval_required=true: automatic execution is forbidden; submit through the manual approval channel"
      ],
      "warnings": []
    },
    "execution_record": null
  },
  "message": "pre-execute check failed: ..."
}
```

### 2. `rollback_strategy(strategy_id: str)`

调用 `POST /api/strategies/{id}/rollback`，返回回滚后的 ExecutionRecord。

### 3. `get_execution_status(execution_id: str)`

调用 `GET /api/executions/{id}`，返回执行记录最新状态。

### 4. `list_executions(limit: int = 20)`

调用 `GET /api/executions`，本地按 `limit` 裁剪（actuator-service 暂未支持分页参数）。

## 统一返回信封

所有工具均返回：

```json
{
  "success": true | false,
  "data":  ... | null,
  "message": "human-readable description"
}
```

`server.py` 还会兜底捕获所有未预期异常并包装成 `success=false`，保证 MCP 协议层不会抛出未处理异常。

## 请求体裁剪

actuator-service `DefenseStrategyRequest` 严格要求 7 个字段：
`strategyId / threatType / targetLayer / actions / scope / ttl / rollbackPlan`。

`actuator_client._build_strategy_request` 会从 Coordinator 输出中**只挑出这 7 个字段**，
丢弃 `status` / `human_approval_required` / `rationale` / `metadata` 等附加字段，
避免被 Spring 校验驳回。

## 安全分层

```
+--------------------+    pre-check (in-process)   +-----------------+
|   MCP Client       |  --------------------->     |  actuator-mcp   |
| (e.g. dashboard)   |                             |   server.py     |
+--------------------+                             +-------+---------+
                                                            |
                                                            v
                                              +---------------------------+
                                              |  actuator_client.py        |
                                              |  - 4 项安全检查            |
                                              |  - mock / real / fallback  |
                                              +-------+--------------------+
                                                      |   real HTTP
                                                      v
                                              +---------------------+
                                              |  actuator-service   |
                                              |  Spring Boot :8081  |
                                              +---------------------+
```

> 当前阶段 **不在 Coordinator 中自动执行策略**，
> Coordinator 只负责输出 `status=approved_for_execution`；
> 由人/前端/上层调度通过 MCP `execute_strategy` 发起执行，并继续受预检关卡保护。

## 运行测试

```powershell
cd autonomous-defense-system/mcp-servers/actuator-mcp-server
python -m unittest test_actuator_client.py -v
```

测试覆盖：
- 4 项安全检查的拒绝/告警路径
- 真实 HTTP 路径（`POST /api/strategies/execute` 的 URL/body/解包）
- real 模式不可达时降级 mock
- mock 模式合成 ExecutionRecord
- `list_executions` 本地按 `limit` 裁剪
- 输入参数校验
- 默认 base_url 是 `http://localhost:8081`

测试**不需要安装 mcp 包**，也不需要启动 actuator-service。
