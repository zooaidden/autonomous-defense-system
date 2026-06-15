# agent-brain

Python 3.11 + LangGraph 多智能体决策模块（本地可运行版）。

## 目录结构

```text
agent-brain/
├─ src/agent_brain/
│  ├─ agents/                # Planner / Red-Teamer / Coordinator 等智能体
│  ├─ workflows/             # LangGraph 编排（防御主链路）
│  ├─ models/                # Pydantic 数据模型（含 OpsChatResponse / WorkflowRunResult）
│  ├─ prompts/
│  ├─ services/              # OpsOrchestrator（/ops/chat 流水线）
│  ├─ integrations/          # topology / policy / os MCP 客户端
│  ├─ safety/                # 安全护栏
│  │  ├─ intent_validator.py        # 命令意图校验（ALLOW / REQUIRE_APPROVAL / BLOCK）
│  │  ├─ system_config_guard.py     # 关键配置文件确定性护栏（A2 #6）
│  │  └─ prompt_injection_guard.py  # 反提示词注入护栏（A2 #7）
│  ├─ executors/             # least_privilege_executor（白名单 + subprocess.run argv 模式）
│  ├─ audit/
│  │  ├─ audit_logger.py            # 单次请求 JSON 快照（auditFile）
│  │  └─ ops_audit_log.py           # OPS JSONL append-only 审计
│  └─ main.py                # FastAPI 入口（含 /system/status / /audit/{requestId}）
└─ tests/                    # 270+ 用例，含 guard / route / orchestrator
```

## 关键路由

| 方法 | 路径 | 说明 |
| ---- | ---- | ---- |
| POST | `/workflow/run` | 云原生安全闭环（事件 → 推理 → 验证 → 处置） |
| POST | `/ops/chat` | 自然语言运维 Agent（注入护栏 → 配置护栏 → 意图校验 → MCP → 最小权限执行） |
| GET  | `/audit/{requestId}` | 下载 `requestId` 对应的审计 JSON 快照（带路径穿越防护） |
| GET  | `/system/status` | 平台 / 服务 / MCP 目录 / 执行器白名单 / 护栏开关 |
| GET  | `/health` | 服务自检（含 MCP / OPS Agent 启用状态） |

## 三道安全护栏

1. **Prompt Injection Guard** — 流水线最前端拦截角色劫持、模板劫持、编码载荷、命令拼接、超长 paste-bomb。
2. **System Config Guard** — 在命令文本层防止对 `/etc/passwd` / `/etc/shadow` / `/etc/sudoers` /
   `/boot/*` 等关键文件做出写入。
3. **Intent Validator + Least-Privilege Executor** — 33 条意图规则 + 9 条命令白名单 +
   `subprocess.run(argv, shell=False)` 真正执行只读命令。

## 运行 demo（无需真实大模型）

```bash
pip install -e .
python -m agent_brain.main --demo
```

## 启动 API

```bash
python -m uvicorn agent_brain.main:app --reload --port 8001
```

## API 示例

```bash
curl -X POST http://localhost:8001/workflow/run \
  -H "Content-Type: application/json" \
  -d '{
    "securityEvent": {
      "eventId": "evt-api-001",
      "timestamp": "2026-04-14T15:00:00Z",
      "sourceType": "EDR",
      "subject": "pod/payment-processor-5d8df",
      "action": "shell_exec",
      "object": "/bin/sh",
      "context": {"iocDomain":"malicious.example"},
      "severity": "HIGH",
      "riskScore": 0.88,
      "labels": ["t1059"]
    }
  }'
```

