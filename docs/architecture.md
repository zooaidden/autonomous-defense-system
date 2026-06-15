# 架构说明（骨架版）

## 目标

在本地单机环境中串联从安全事件输入到策略执行回滚的完整链路，后续逐步填充智能体决策与约束求解能力。

## 模块边界

- `defense-gateway`：事件接入、规范化、发布到 Kafka
- `agent-brain`：多智能体工作流（Planner / Red-Teamer / Coordinator）
- `formal-verifier`：策略校验，预留 Z3/OPA 接口
- `actuator-service`：策略执行、模拟规则下发、回滚
- `dashboard-ui`：可视化展示

## 数据流

1. 外部系统通过 REST 上报事件到 `defense-gateway`
2. `defense-gateway` 将规范化事件写入 Kafka
3. `agent-brain` 消费事件并输出候选策略
4. `formal-verifier` 校验策略约束并返回 verdict
5. `actuator-service` 执行策略并记录可回滚快照
6. `dashboard-ui` 聚合查看事件、策略、执行结果

