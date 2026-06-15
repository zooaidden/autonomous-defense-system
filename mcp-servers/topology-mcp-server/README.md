# topology-mcp-server

为「自主网络安全防御系统」提供拓扑感知能力的 **MCP Server**（基于官方 MCP Python SDK 的 `FastMCP`）。
作为多智能体决策的工具底座，被 `agent-brain` 中的 Planner / Red-Teamer / Revision / Coordinator 等智能体通过 MCP 协议调用。

## 目录结构

```text
mcp-servers/topology-mcp-server/
├── server.py                   # MCP 协议层（薄壳，仅注册 tools/resources）
├── topology_service.py         # 核心拓扑业务逻辑（纯 Python，无 MCP 依赖）
├── topology.json               # 模拟网络拓扑数据（4 个 zone / 12 个资产 / 20 条边）
├── test_topology_service.py    # 单元测试（unittest，可被 pytest 直接发现）
├── requirements.txt            # 仅依赖官方 mcp Python SDK
└── README.md                   # 本文档
```

设计上把"业务逻辑"和"协议封装"严格分层：

- `topology_service.py` 提供 **纯函数 API**（`load_topology` / `find_asset` / `get_neighbors` / `get_critical_assets` / `find_paths` / `check_connectivity` / `evaluate_strategy_impact`），不依赖 `mcp` 包，便于单元测试与跨场景复用。
- `server.py` 只做两件事：① 把上述函数包成 MCP `tool` / `resource`；② 把异常和返回值统一成 `{success, data, message}`。

## 安装与启动

```powershell
# 1) 进入本目录
cd autonomous-defense-system\mcp-servers\topology-mcp-server

# 2) 创建独立虚拟环境（推荐）
python -m venv .venv
.\.venv\Scripts\Activate.ps1     # Windows PowerShell
# source .venv/bin/activate      # Linux / macOS

# 3) 安装运行依赖
pip install -r requirements.txt

# 4) 启动 MCP server（通过 stdio 协议；由调用端作为子进程拉起）
python server.py
```

> 该 Server 通过 **stdio 协议**运行，调用端（agent-brain 的 MCP Client，第二阶段交付）会以子进程方式启动并交换 JSON-RPC 消息。本仓库不包含调用端实现。

## 运行测试

测试 **不需要安装 `mcp` 包**，因为它们直接 import `topology_service.py` 这一纯 Python 模块。

```powershell
cd autonomous-defense-system\mcp-servers\topology-mcp-server

# 方式一：标准库 unittest（任何 Python 环境都可用）
python -m unittest test_topology_service.py -v

# 方式二：脚本直接执行
python test_topology_service.py

# 方式三：pytest（需先 pip install pytest）
pytest -q
```

测试覆盖：

| 测试类 | 覆盖场景 |
|---|---|
| `FindAssetTests` | 按 `asset_id` / `ip` / `name` 命中、未命中、空字符串/空白 |
| `GetNeighborsTests` | DMZ api-gateway 的出/入向邻居、未命中抛 `AssetNotFoundError` |
| `GetCriticalAssetsTests` | 仅返回 HIGH/CRITICAL、已知关键资产命中、低关键性资产被排除 |
| `FindPathsTests` | DMZ→Database 路径、`allowed=false` 边被排除、未命中端点抛错、`max_depth<1` 抛 `ValueError` |
| `CheckConnectivityTests` | DMZ web→DB 联通且需经 api-gateway、Database 反向不可达、未命中端点抛错 |
| `EvaluateStrategyImpactTests` | block 关键资产 IP→HIGH、isolate 关键资产→CRITICAL（且打断 DMZ_TO_DATABASE）、isolate 低价值终端→MEDIUM、block 外部 IP→LOW + unmatched_targets、protective WAF 不上调、recommendation 文案、入参类型守卫 |
| `CustomTopologyTests` | 通过可选 `topology=` 参数注入自定义 mini 拓扑，验证函数纯净度 |

## 暴露的 MCP Tools

每个 tool 都是 `topology_service.<同名函数>` 的薄壳，统一返回 `{success, data, message}`。

| Tool | 入参 | `data` 结构 |
|---|---|---|
| `get_asset_info(ip_or_asset_id)` | `str` | `Asset` 对象 |
| `get_neighbors(ip_or_asset_id)` | `str` | `{asset_id, name, neighbor_count, neighbors[]}` |
| `get_critical_assets()` | — | `{count, assets[]}` |
| `find_paths(source, target, max_depth=4)` | `str, str, int` | `{source, target, max_depth, path_count, paths[], truncated}` |
| `check_connectivity(source, target)` | `str, str` | `{connected, source, target, shortest_hops, shortest_path, alternative_path_count}` |
| `evaluate_strategy_impact(strategy)` | `dict` | `{strategy_id, impact_level, affected_assets, affected_paths, unmatched_targets, recommendation, summary}` |

成功时：

```json
{ "success": true, "data": { /* ... */ }, "message": "..." }
```

失败时：

```json
{ "success": false, "data": null, "message": "..." }
```

## 暴露的 MCP Resources

| URI | MIME | 内容 |
|---|---|---|
| `topology://network` | `application/json` | 完整拓扑数据（zones + assets + edges + metadata） |
| `topology://assets` | `application/json` | 全部资产列表 |
| `topology://critical-assets` | `application/json` | `criticality ∈ {HIGH, CRITICAL}` 的资产列表 |

Resources 适合 LLM 在不调用 Tool 时获取拓扑全景，Tools 适合做精准查询与影响推理。

## 拓扑数据约定（`topology.json`）

- **zones**：固定 4 类 — `DMZ` / `Internal` / `Database` / `Management`
- **assets[].criticality**：`LOW` / `MEDIUM` / `HIGH` / `CRITICAL`
- **edges[].direction**：`outbound`（from→to）/ `inbound`（to→from）/ `bidirectional`
- **edges[].allowed**：`true` 才会进入路径搜索 / 连通性判断 / 影响评估的邻接表
- 修改 `topology.json` 后需 **重启 MCP server** 生效（首次访问时一次性加载）；`topology_service.reload_default_topology()` 可在程序内热重载。

## `evaluate_strategy_impact` 决策表

输入 `strategy` 的最小有效结构（与 `agent-brain` 的 `DefenseStrategy` 对齐）：

```json
{
  "strategyId": "stg-001",
  "actions": [
    { "type": "ISOLATE_POD", "target": "app-payment-01", "parameters": {} }
  ],
  "scope": { "assets": ["app-payment-01"], "namespaces": ["prod"] }
}
```

每条 `action` 按 `type` 分到一个 `effect`：

| Action Type | effect |
|---|---|
| `ISOLATE_POD`, `ISOLATE_HOST` | `disruptive` |
| `RESTRICT_EGRESS` | `partial_disruptive` |
| `BLOCK_IP`, `BLOCK_DOMAIN` | `network_block` |
| `APPLY_WAF_RULE`, `APPLY_FIREWALL_RULE`, `SCALE_PROTECTION` | `protective` |
| `DISABLE_ACCOUNT`, `REVOKE_TOKEN` | `identity` |
| `ALERT_ONLY` | `passive` |
| 其它 | `unknown` |

`effect × criticality → impact_level` 查表：

| effect \ criticality | LOW | MEDIUM | HIGH | CRITICAL |
|---|---|---|---|---|
| `disruptive` | LOW | MEDIUM | HIGH | **CRITICAL** |
| `partial_disruptive` | LOW | MEDIUM | MEDIUM | **HIGH** |
| `network_block` | LOW | LOW | MEDIUM | **HIGH** |
| `scope` | LOW | LOW | MEDIUM | MEDIUM |
| `protective` / `identity` / `passive` / `unknown` | 不上调 |

并叠加关键路径中断（**仅 disruptive / partial_disruptive / network_block 类动作的目标**会触发）：路径严重度由终点资产 criticality 决定，再按下表映射：

| 终点资产 criticality | 路径严重度 |
|---|---|
| `CRITICAL` | HIGH |
| `HIGH` | MEDIUM |
| `MEDIUM` / `LOW` | LOW（不计入结果） |

最终 `impact_level = max(所有命中规则)`。`recommendation` 字段会附带建议（人工审批 / 缩小 scope / 缩短 TTL / 加强监控等）。

## 与 agent-brain 集成（占位说明）

本阶段**只交付独立 MCP Server + 单元测试**，不修改 `agent-brain`。后续阶段会：

1. 在 `agent-brain/services/` 新增 `mcp_client.py`，封装 `MCPRegistry`，把本 Server 注册为 `topology` 命名空间
2. 把 `LLMClient` 接口扩展为 `generate_with_tools(...)`，支持 OpenAI / Anthropic 风格的 tool-use loop
3. `PlannerAgent` 在生成策略前调用 `get_critical_assets` / `find_paths`
4. `CoordinatorAgent` 在批准前调用 `evaluate_strategy_impact` 做最终把关
5. 调用证据写入 `DebateState.mcpTrace`，由 dashboard-ui 的 `/debate` 页渲染泳道

## 已知限制

- `topology.json` 是 mock 数据，不代表生产环境；二期可替换为 Neo4j 查询或 CMDB 拉取
- `find_paths` 单次调用最多返回 50 条路径，超过会标记 `truncated: true`
- `check_connectivity` 限定最大 4 跳；如需更深请用 `find_paths(max_depth=N)`
- 默认拓扑由 `topology_service` 在首次访问时加载到内存；运行期手动改 `topology.json` 后请调用 `reload_default_topology()` 或重启 server
