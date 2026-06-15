# formal-verifier

策略约束校验模块。**当前实现为基于规则的静态校验器**（参见
`src/formal_verifier/engine/rule_engine.py` 与 `continuity_checker.py`）。

> 重要声明：`providers.py` / `engine` 中的 `z3` / `opa` 入口位为**适配层占位**，
> 尚未接入真正的 Z3 SMT 求解器或 OPA Rego 评估器，因此 `formal-verifier` 当前
> 提供的不是“完整形式化验证”，而是“策略约束工程化校验”。请不要在对外宣传中
> 声称已具备完整的形式化验证能力；接入 Z3 / OPA 的工作仍在路线图中。

## 启动

```bash
pip install -e .
python -m uvicorn formal_verifier.main:app --reload --port 8002
```

## API

- `POST /verify`：输入 `DefenseStrategy`，输出 `VerificationResult`
- `GET /health`：健康检查

## 业务连续性约束（Mock 依赖图）

当前内置 continuity checker，会读取 mock 依赖快照并执行：

- `payment-service` 依赖 `auth-service` 和 `redis-auth`
- `core-dns` 不允许整体阻断
- `gateway-service` 不允许直接全量封禁
- `db-primary` 仅允许 `payment-service` 与 `auth-service` 连接
- `prod` 命名空间核心服务不能长时间隔离

违反时会在 `violatedConstraints` 返回具体 `code/description/severity/reason`。

## 测试

```bash
pytest tests -q
```

