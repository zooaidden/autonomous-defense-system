# actuator-service

Java 21 + Spring Boot 3.x 模拟执行服务。

## 功能

- 接收已验证策略并路由到 adapter
- 输出模拟配置：
  - K8s NetworkPolicy YAML
  - WAF Rule JSON
  - Firewall Rule JSON
- 生成执行记录 `ExecutionRecord`
- 支持回滚与回滚状态跟踪
- 支持 TTL 到期自动回滚（内存调度）
- 预留 GitOps 回滚执行器接口

## 接口

- `POST /api/strategies/execute`
- `POST /api/strategies/{id}/rollback`
- `GET /api/executions`
- `GET /api/executions/{id}`
- `GET /api/health`

## 启动

```bash
mvn spring-boot:run
```

## 自动回滚配置

```yaml
app:
  rollback:
    scheduler-enabled: true
    poll-interval-ms: 5000
```

## 测试数据（执行）

```bash
curl -X POST http://localhost:8081/api/strategies/execute \
  -H "Content-Type: application/json" \
  -d '{
    "strategyId":"stg-001",
    "threatType":"MALWARE",
    "targetLayer":"WORKLOAD",
    "ttl":1800,
    "rollbackPlan":{"planId":"rb-001","steps":["undo"],"triggerCondition":"manual"},
    "scope":{"assets":["payment-service"],"namespaces":["prod"],"tenantId":"tenant-a"},
    "actions":[
      {"type":"restrict_egress","target":"payment-service","parameters":{"policy":"deny_all"}},
      {"type":"apply_waf_rule","target":"/api/pay","parameters":{"signature":"log4j-jndi"}},
      {"type":"block_ip","target":"203.0.113.10","parameters":{"reason":"ioc"}}
    ]
  }'
```

## 回滚

```bash
curl -X POST http://localhost:8081/api/strategies/{executionId}/rollback
```

## 示例日志输出

```text
INFO  ... StrategyExecutionServiceImpl - Executing strategy. strategyId=stg-001, executionId=exe-123
INFO  ... RollbackManager - TTL rollback due. executionId=exe-123, strategyId=stg-001, ttl=1800, startTime=2026-04-14T08:00:00Z
INFO  ... RollbackServiceImpl - Rollback started. executionId=exe-123, trigger=TTL_AUTO, reason=ttl_expired
INFO  ... RollbackServiceImpl - Rollback succeeded. executionId=exe-123, strategyId=stg-001
```

## 完整运行示例

1. 执行带 TTL 的策略（例如 ttl=10）
2. `GET /api/executions/{executionId}` 查看 `rollbackStatus=AVAILABLE`
3. 等待约 10~15 秒（取决于调度间隔）
4. 再次查询执行记录，`rollbackStatus` 应为 `SUCCEEDED`，并有 `rollbackTrigger=TTL_AUTO`

## 查询

```bash
curl http://localhost:8081/api/executions
curl http://localhost:8081/api/executions/{executionId}
```

