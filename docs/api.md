# API 文档

> 本文与各模块 controller / FastAPI 路由保持同步，字段命名遵循 `domain-models.md`。

## defense-gateway （Java/Spring Boot, 默认端口 8080）

- `GET  /api/health`：健康检查
- `POST /api/events`：接收并规范化安全事件
- `GET  /api/events`：分页查询安全事件（query: `page`, `size`）
- `GET  /api/events/{id}`：按内部主键查询事件详情
- `POST /api/events/mock/log4j`：生成一条 Log4Shell 模拟事件
- `POST /api/events/mock/shell`：生成一条容器 shell 模拟事件

响应统一为 `ApiResponse<T>`：`{success, code, message, data, timestamp}`。

## agent-brain （Python/FastAPI, 默认端口 8001）

- `GET  /health`：健康检查
- `POST /workflow/run`：执行一次多智能体工作流，请求体 `{ "securityEvent": SecurityEvent }`，响应包含 `debateState / finalStrategy / verification / actuatorResponse`

## formal-verifier （Python/FastAPI, 默认端口 8002）

- `GET  /health`：健康检查
- `POST /verify`：请求体直接为 `DefenseStrategy` JSON，响应为 `VerificationResult`
  （`violatedConstraints` / `warnings` 为 `ConstraintIssue` 列表）

## actuator-service （Java/Spring Boot, 默认端口 8081）

- `GET  /api/health`：健康检查
- `POST /api/strategies/execute`：执行已批准且校验通过的策略，请求体为 `DefenseStrategyRequest`，响应为 `ApiResponse<ExecutionRecord>`
- `POST /api/strategies/{executionId}/rollback`：手动触发回滚（trigger=`MANUAL`）
- `GET  /api/executions`：列出全部 `ExecutionRecord`
- `GET  /api/executions/{executionId}`：按执行 ID 查询单条记录

> TTL 到期回滚由 `RollbackManager` 内部 `@Scheduled` 自动处理，trigger=`TTL_AUTO`，不暴露独立 HTTP 接口。

响应统一为 `ApiResponse<T>`：`{success, code, message, data, timestamp}`。
