# policy-mcp-server

为「自主网络安全防御系统」提供**策略合规性 + 业务影响评估**能力的 **MCP Server**（基于官方 MCP Python SDK 的 `FastMCP`）。

它与第一阶段的 `topology-mcp-server` 并列，作为多智能体决策的"安全护栏"工具底座；后续会被 `agent-brain` 中的 Coordinator / Revision 等智能体通过 MCP 协议调用，对 Planner 给出的防御策略做最后一道合规与业务影响校验。

## 目录结构

```text
mcp-servers/policy-mcp-server/
├── server.py                # MCP 协议薄壳，仅负责注册 tool 与统一信封
├── policy_service.py        # 纯 Python 业务层（4 个公共 API + 7 条规则实现）
├── policy_rules.json        # 策略规则、关键资产、生产路径、阈值等数据
├── test_policy_service.py   # 单元测试（unittest，可被 pytest 直接发现）
├── requirements.txt         # 仅依赖官方 mcp Python SDK
└── README.md                # 本文档
```

设计上严格分层，与 `topology-mcp-server` 保持一致：

- `policy_service.py` 提供**纯函数 API**，不依赖 `mcp` 包，便于独立测试与跨场景复用。
- `server.py` 只做两件事：① 把上述函数包成 MCP `tool`；② 把异常和返回值统一成 `{success, data, message}`。

## 安装与启动

```powershell
# 1) 进入本目录
cd autonomous-defense-system\mcp-servers\policy-mcp-server

# 2) 创建独立虚拟环境（推荐）
python -m venv .venv
.\.venv\Scripts\Activate.ps1     # Windows PowerShell
# source .venv/bin/activate      # Linux / macOS

# 3) 安装运行依赖
pip install -r requirements.txt

# 4) 启动 MCP server（通过 stdio 协议；由调用端作为子进程拉起）
python server.py
```

> 该 Server 通过 **stdio 协议**运行，调用端（agent-brain 的 MCP Client）会以子进程方式启动并交换 JSON-RPC 消息。

## 运行测试

测试**不需要安装 `mcp` 包**，因为它们直接 import `policy_service.py` 这一纯 Python 模块。

```powershell
cd autonomous-defense-system\mcp-servers\policy-mcp-server

# 方式一：标准库 unittest（任何 Python 环境都可用）
python -m unittest test_policy_service.py -v

# 方式二：脚本直接执行
python test_policy_service.py

# 方式三：pytest（需先 pip install pytest）
pytest -q
```

测试覆盖：

| 测试类 | 覆盖场景 |
|---|---|
| `ValidateStrategyTests` | 合法策略全通过、critical 数据库全量阻断 + 缺 human_approval 多违规、缺 TTL（RULE-002）、缺 rollback（RULE-003）、WAF 过宽（RULE-005）、Firewall 缺 5 元组（RULE-006）、K8s replicas < 2（RULE-004）、ingress_only 收敛后 RULE-001 / RULE-007 放行 |
| `CheckBusinessConstraintsTests` | 仅业务影响维度违规命中、合法策略放行、不会越权报告 RULE-003 |
| `RequireHumanApprovalTests` | 合法不需要、critical 资产强制升级、已声明 human_approval 不重复升级、HIGH 资产仅给 warning |
| `SuggestSaferStrategyTests` | RULE-001 / 002 / 003 的可执行 patch 形态校验 |
| `InputAndCustomRulesTests` | 非 dict 输入抛 TypeError、空 actions 直接 valid、自定义规则注入、默认规则文件加载与路径存在 |

## 暴露的 MCP Tools

每个 tool 都是 `policy_service.<同名函数>` 的薄壳，统一返回 `{success, data, message}`，其中 `data` 严格遵循以下契约：

```json
{
  "valid": true,
  "violations": [],
  "warnings": [],
  "requires_human_approval": false,
  "suggestions": []
}
```

| Tool | 用途 | 重点字段 |
|---|---|---|
| `validate_strategy(strategy)` | 跑全部 7 条规则做完整合规校验 | `valid` / `violations` / `warnings` / `requires_human_approval` / `suggestions` 全填 |
| `check_business_constraints(strategy)` | 只跑业务影响相关的规则（RULE-001/002/005/006） | 主要填 `violations` / `warnings` |
| `require_human_approval(strategy)` | 判定是否需要走人工审批 | 主要填 `requires_human_approval`，并以违规列表说明原因 |
| `suggest_safer_strategy(strategy)` | 根据违规反向给出可落地的安全策略修复建议 | 主要填 `suggestions[].patch` |

成功时：

```json
{ "success": true, "data": { /* ... */ }, "message": "validate_strategy: valid=false, violations=2, warnings=0, requires_human_approval=true" }
```

失败时（如 strategy 不是 dict）：

```json
{ "success": false, "data": null, "message": "strategy must be a dict, got str" }
```

## 7 条核心规则

| ID | 名称 | 严重度 | 触发条件（简） | 通过条件 |
|---|---|---|---|---|
| `RULE-001` | `no_full_block_on_critical_database` | critical | `BLOCK_IP / ISOLATE_HOST / ISOLATE_POD` 命中 critical 数据库资产 | `parameters.scope=ingress_only` 或 `parameters.allowlistedFlows` 非空 |
| `RULE-002` | `production_path_block_requires_ttl` | high | 影响 DMZ→DB / Internal→DB 路径的阻断动作 | 顶层 `ttl ∈ [60, 86400]` 秒（也接受 `ttl_minutes`） |
| `RULE-003` | `high_risk_action_requires_rollback` | high | 任意高风险动作 | `rollbackPlan.steps` 非空 + `triggerCondition` 非空 |
| `RULE-004` | `k8s_scaling_min_replicas` | medium | `SCALE_PROTECTION` 或带 `replicas` 参数的 action | `parameters.replicas >= limits.k8s_min_replicas`（默认 2） |
| `RULE-005` | `waf_block_must_specify_target` | medium | `APPLY_WAF_RULE` 且 `parameters.action ∈ {block, deny}`（缺省按 block） | `parameters` 至少含 `path` / `ip` / `user_agent` / `rule_id` / `pattern` 之一 |
| `RULE-006` | `firewall_deny_must_specify_5tuple` | medium | `APPLY_FIREWALL_RULE` 且 `parameters.action ∈ {deny, drop, block}`（缺省按 deny） | 同时含 `source` / `destination` / `port` / `protocol` |
| `RULE-007` | `critical_asset_action_requires_human_approval` | critical | 任意高风险动作命中 criticality=critical 资产 | `metadata.human_approval=true` 或顶层 `requires_human_approval=true` |

> **violation vs warning**：`severity ∈ {critical, high}` 进 `violations` 并把 `valid` 置为 `false`；`severity ∈ {medium, low}` 进 `warnings`，不影响 `valid`。

## 输入兼容（驼峰 / 蛇形双写）

为了让 `agent-brain`（驼峰）和外部脚手架（蛇形）共用，本服务对以下字段做了双写兼容：

| 字段 | 兼容写法 |
|---|---|
| TTL | `ttl`（秒） / `ttl_minutes`（分钟，自动 ×60） |
| 回滚计划 | `rollbackPlan` / `rollback_plan` |
| 回滚触发条件 | `rollbackPlan.triggerCondition` / `rollbackPlan.trigger_condition` |
| 人工审批 | `requires_human_approval` / `requiresHumanApproval` / `human_approval` / `humanApproval` / `metadata.human_approval` / `scope.human_approval` |
| WAF / 防火墙 allowlist | `parameters.allowlistedFlows` / `parameters.allowlisted_flows` |

## suggest_safer_strategy 返回的 patch 形态

每条 violation 都对应一条结构化建议，便于上游自动应用：

```json
{
  "rule_id": "RULE-003",
  "title": "Add rollback plan for high-risk action",
  "detail": "补充 rollbackPlan.steps 与 triggerCondition",
  "patch": {
    "field": "rollbackPlan",
    "operation": "set",
    "value": {
      "planId": "rb-auto",
      "steps": ["remove_temporary_rules", "restore_network_policy", "verify_business_path_recovery"],
      "triggerCondition": "false_positive_confirmed_or_business_impact_detected"
    }
  }
}
```

`patch.operation` 取值：`set` / `merge` / `append`，下游可据此实施合并。

## 与 agent-brain 集成（占位说明）

本阶段**只交付独立 MCP Server + 单元测试**，不修改 `agent-brain`。后续阶段会：

1. `TopologyMCPClient` 同款的 `PolicyMCPClient` 接入 `agent-brain/integrations/`，提供同样的 `disabled / local / real` 三档；
2. `RevisionAgent` 在生成修订策略前先 `validate_strategy`，把 `suggestions[].patch` 自动应用一遍；
3. `CoordinatorAgent` 在最终决策前再次 `validate_strategy + require_human_approval`，结果写入 `FinalDecision.executionConstraints` 与 `riskLevel`；
4. 调用证据写入 `mcpTrace`，由 dashboard-ui 渲染"策略合规链路"。

## 已知限制

- `policy_rules.json` 是出厂规则集，生产环境建议从 OPA / Cedar / Rego 等策略引擎导出；
- `_affects_production_path` 目前基于 zone 命中做静态判断，未与 `topology-mcp-server` 联动；后续可在调用方先 `evaluate_strategy_impact` 再传业务影响标注进来；
- 默认规则由 `policy_service` 在首次访问时缓存，运行期手动改 `policy_rules.json` 后请调用 `policy_service.reload_default_rules()` 或重启 server。
