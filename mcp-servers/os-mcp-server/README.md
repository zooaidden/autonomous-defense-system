# os-mcp-server

为「面向麒麟操作系统的安全智能运维 Agent」提供 **OS 状态只读感知能力** 的 MCP Server（基于官方 MCP Python SDK 的 `FastMCP`）。

它与同目录下的 `topology-mcp-server` / `policy-mcp-server` 并列，**只暴露只读工具**，不会执行任何变更类操作（重启服务、kill 进程、修改文件等都属于后续 least-privilege executor 的范畴，与本模块严格分离）。

## 设计原则

- **协议层薄壳**：`server.py` 仅做 MCP tool 注册与软导入，所有业务逻辑都在 `os_service.py`，便于离线单元测试。
- **绝不使用 shell**：所有外部命令一律使用 `subprocess.run(argv, shell=False, timeout=...)` 数组形式调用；用户传入的 service 名 / 路径 / pid / since 表达式都先经过严格校验，杜绝注入。
- **失败永远结构化**：命令缺失、超时、非零退出、参数非法都返回统一信封 `{success, tool, data, summary, error}`，不会向调用方抛异常。
- **响应有界**：每条命令都有超时 + 输出字节上限 + 列表长度 clamp，避免巨型 `journalctl` / `lsof` 把上游 LLM 撑爆。
- **跨平台兼容**：Kylin / 其它 systemd Linux 是主目标；在 Windows / macOS / 精简容器里缺命令时返回 `error="tool_unavailable"`，服务依旧能跑。

## 目录结构

```text
mcp-servers/os-mcp-server/
├── server.py                # MCP protocol layer (FastMCP), 8 read-only tools
├── os_service.py            # Pure-Python business layer (subprocess + /proc parsing)
├── requirements.txt         # Only depends on the official mcp Python SDK
├── README.md                # This file
└── scripts/
    └── test_os_service.py   # Local smoke-test (no MCP protocol involved)
```

## 安装与启动

```powershell
# 1) 进入本目录
cd autonomous-defense-system\mcp-servers\os-mcp-server

# 2) 创建独立虚拟环境（推荐）
python -m venv .venv
.\.venv\Scripts\Activate.ps1     # Windows PowerShell
# source .venv/bin/activate      # Linux / macOS / Kylin

# 3) 安装运行依赖
pip install -r requirements.txt

# 4) 以 stdio 协议启动 MCP server（生产中由 MCP 客户端作为子进程拉起）
python server.py
```

> 该 Server 通过 **stdio 协议** 与上游对话；本模块没有自己的 HTTP 端口。在 `agent-brain` 中接入时，请仿照已有的 `TopologyMCPClient` / `PolicyMCPClient` 写一个 `OsMCPClient`，环境变量约定为 `MCP_OS_MODE=local|real`、`OS_MCP_SERVER_PATH=<本目录绝对路径>`。

## 本地冒烟测试（不接入 MCP 协议）

仓库自带的 `scripts/test_os_service.py` 直接 `import os_service` 调用全部只读工具，**只打印 `success` 与一行 `summary`**，不输出原始 `data`，所以无论目标主机有多少进程 / 套接字，控制台都能看清结果。

```powershell
# Windows PowerShell / Linux / macOS / 银河麒麟均可
cd autonomous-defense-system\mcp-servers\os-mcp-server
python scripts/test_os_service.py
```

可在任何 Python 3.11+ 环境中运行，不需要预先 `pip install mcp`（脚本不走 MCP 协议）。也可从仓库任意目录调用，例如：

```powershell
python autonomous-defense-system/mcp-servers/os-mcp-server/scripts/test_os_service.py
```

### 测试覆盖

依次执行以下 8 个只读工具：

1. `get_process_list`
2. `get_network_sockets`
3. `get_disk_usage`
4. `get_memory_status`
5. `get_cpu_load`
6. `get_uptime`
7. `get_system_logs`
8. `get_service_status`

### 输出语义

| 标记 | 含义 |
|---|---|
| `[PASS]` | 工具成功返回（`success=true`） |
| `[SKIP]` | 工具不可用（`error=tool_unavailable`），或在非 Linux 主机上被自动降级；属于预期行为 |
| `[FAIL]` | 仅在 Linux 上对真实失败（`command_failed` / `timeout` / `invalid_argument` / 未捕获异常）使用 |

进程退出码：`failed > 0` → `1`；其余 → `0`。**Windows / macOS 上脚本永远以 `0` 退出**，可放心接入 CI 作为冷启动健康检查。

### Windows 实测样例（全部 `[SKIP]`，退出码 0）

```text
Running os-mcp-server smoke-test (no MCP protocol involved).
  python   : 3.12.3
  platform : win32
  service  : os_service @ ...\os-mcp-server\os_service.py

  [SKIP] get_process_list       success=false summary=ps binary is not installed; cannot enumerate processes  -> graceful degradation: tool_unavailable
  [SKIP] get_network_sockets    success=false summary=netstat exited with code 1: ...  -> graceful degradation on non-Linux (win32): command_failed
  [SKIP] get_disk_usage         success=false summary=df is not installed; cannot enumerate disk usage  -> graceful degradation: tool_unavailable
  [SKIP] get_memory_status      success=false summary=/proc/meminfo missing and free is not installed  -> graceful degradation: tool_unavailable
  [SKIP] get_cpu_load           success=false summary=/proc/loadavg is not available on this host  -> graceful degradation: tool_unavailable
  [SKIP] get_system_logs        success=false summary=journalctl is not installed; cannot read system logs  -> graceful degradation: tool_unavailable
  [SKIP] get_service_status     success=false summary=systemctl is not installed; cannot query service status  -> graceful degradation: tool_unavailable

Summary: 0 passed, 7 skipped (tool_unavailable), 0 failed (out of 7)
```

### Kylin / Linux 期望输出

```text
Running os-mcp-server smoke-test (no MCP protocol involved).
  python   : 3.11.x
  platform : linux
  ...
  [PASS] get_process_list       success=true  summary=top 5 process(es) by CPU (sampled 287 total)
  [PASS] get_network_sockets    success=true  summary=5 socket(s) via ss (sampled 42 total)
  [PASS] get_disk_usage         success=true  summary=8 filesystem(s) reported
  [PASS] get_memory_status      success=true  summary=memory: 16.0 GiB total, 12.4 GiB available; swap 0 B used / 4.0 GiB
  [PASS] get_cpu_load           success=true  summary=load: 0.18/0.25/0.30 on 8 CPU(s) (2.25% per core)
  [PASS] get_system_logs        success=true  summary=20 log entry(ies) returned
  [PASS] get_service_status     success=true  summary=service 'sshd' is active

Summary: 7 passed, 0 skipped (tool_unavailable), 0 failed (out of 7)
```

> 若某条工具在 Linux 上仍以 `[SKIP]` 出现，通常是该 Kylin 实例没装对应包（`net-tools` / `lsof` / `procps-ng`），按需 `dnf install` 即可。

### 单条工具手测

如需查看完整 `data` 字段，仍可一行 Python 直接调：

```powershell
cd autonomous-defense-system\mcp-servers\os-mcp-server
python -c "import json, os_service as ops; print(json.dumps(ops.get_service_status('sshd'), ensure_ascii=False, indent=2))"
python -c "import json, os_service as ops; print(json.dumps(ops.get_open_files(top_n=10), ensure_ascii=False, indent=2))"
```

## 添加 unittest（可选，未实施）

按本仓库其它 MCP Server 惯例，可在模块根目录新建 `test_os_service.py`（与本测试脚本同名但**位于根目录**而非 `scripts/`），用 `unittest` 覆盖纯函数。建议至少覆盖：

- `_parse_ps_output` / `_parse_ss_output` / `_parse_netstat_output` / `_parse_lsof_output` / `_parse_df_output` / `_parse_meminfo` / `_parse_loadavg` / `_parse_systemctl_status`
- `_validate_service_name` / `_validate_lsof_path` / `_validate_pid` / `_validate_journal_since`
- 工具层在 `subprocess.run` 被 monkeypatch 时的信封形态

```powershell
cd autonomous-defense-system\mcp-servers\os-mcp-server
python -m unittest test_os_service.py -v
```

## 暴露的 MCP Tools

每个 tool 都是 `os_service.<同名函数>` 的薄壳，统一返回：

```json
{
  "success": true,
  "tool": "get_disk_usage",
  "data": [/* tool-specific payload */],
  "summary": "5 filesystem(s) reported",
  "error": null
}
```

| Tool | 主要数据来源 | 关键参数 | 说明 |
|---|---|---|---|
| `get_process_list` | `ps -eo pid,user,pcpu,pmem,etime,comm,args` | `top_n`（默认 50，clamp 1..500） | Python 侧按 cpu_percent 降序排序，避免依赖 GNU `--sort` 扩展 |
| `get_network_sockets` | `ss -H -tunap` ⇒ 优先；`ss` 缺失时回退 `netstat -tunap` | `state`（保留参数）、`top_n`（默认 500，clamp 1..2000） | `data.backend` 表明实际使用的工具 |
| `get_open_files` | `lsof -nP` | `path` / `pid` / `top_n`（默认 200，clamp 1..2000） | `path` 必须为绝对路径且无 shell 元字符；`pid` 必须为正整数 |
| `get_system_logs` | `journalctl --no-pager -o short-iso -n N [-u UNIT] [--since X]` | `unit` / `lines`（默认 200，clamp 1..2000）/ `since` | `unit` 与 `since` 都走严格正则校验，禁止 `-` 开头 |
| `get_disk_usage` | `df -P -k` | — | 字节单位统一从 KB 转为 Bytes |
| `get_memory_status` | `/proc/meminfo`（首选）⇒ 缺失时 `free -k`（仅返回 raw_text） | — | 返回 `total / available / free / buffers / cached / swap_*` 全部为 Bytes |
| `get_cpu_load` | `/proc/loadavg` + `os.cpu_count()` | — | 额外计算 `load_1m_per_cpu_percent` |
| `get_uptime` | `/proc/uptime` + 可选 `uptime -p` | — | 返回 `uptime_seconds`、`idle_seconds` 与人类可读的 `uptime_human` |
| `get_service_status` | `systemctl is-active <name>` + `systemctl status <name> --no-pager -l -n 20` | `service`（必填，正则 `^[A-Za-z0-9_@.\-]{1,128}$`） | 解析 `Loaded / Active / Main PID / Tasks / Memory / CGroup` 字段，原文也保留在 `raw_status` |

### 错误码（`error` 字段）

| 取值 | 含义 |
|---|---|
| `null` | 成功 |
| `tool_unavailable` | 底层命令 / `/proc` 文件不存在；Windows / macOS / 精简容器常见 |
| `invalid_argument` | 调用方传入的 service / path / pid / since 没通过白名单校验 |
| `timeout` | 命令超出本工具的 timeout（默认 5s，`journalctl` 10s，`systemctl status` 8s） |
| `command_failed` | 命令存在但返回非零、输出无法解析、或权限不足 |

## 常量与默认值（位于 `os_service.py`）

| 常量 | 默认值 | 说明 |
|---|---:|---|
| `DEFAULT_TIMEOUT_SECONDS` | `5.0` | 大多数命令的超时上限 |
| `SERVICE_TIMEOUT_SECONDS` | `8.0` | `systemctl status` 专用 |
| `LOG_TIMEOUT_SECONDS` | `10.0` | `journalctl` 专用 |
| `MAX_STDOUT_BYTES` | `262144` | 单条命令 stdout 字节上限（超出会追加 `... [truncated]` 标记） |
| `MAX_STDERR_BYTES` | `16384` | 同上，stderr |
| `DEFAULT_PROCESS_LIMIT` / `MAX_PROCESS_LIMIT` | `50` / `500` | `get_process_list` 列表 clamp |
| `DEFAULT_SOCKET_LIMIT` / `MAX_SOCKET_LIMIT` | `500` / `2000` | `get_network_sockets` 列表 clamp |
| `DEFAULT_OPEN_FILES_LIMIT` / `MAX_OPEN_FILES_LIMIT` | `200` / `2000` | `get_open_files` 列表 clamp |
| `DEFAULT_LOG_LINES` / `MAX_LOG_LINES` | `200` / `2000` | `get_system_logs` 行数 clamp |
| `DEFAULT_STATUS_TAIL_LINES` | `20` | `systemctl status -n` |

## 已知限制 / 后续工作

- **第一阶段只实现只读工具**，刻意不暴露任何变更动作（kill / systemctl restart / chmod 等）；变更动作会由后续的 `least_privilege_executor` + `command_validator` 模块承接，并强制走人工审批边界。
- `get_memory_status` 的 `free -k` 回退只把原文回传到 `data.raw_text`，没有做结构化解析；正常情况下 Linux 都有 `/proc/meminfo`，无需 fallback。
- 解析器目前未做语言本地化适配；若 Kylin 实机的 `systemctl` / `df` 输出在某个国际化场景下出现非英文 header 字段，建议把进程环境变量统一固定为 `LC_ALL=C` 后再运行 `python server.py`。
- Tool availability 的探测目前是「按需 + 失败降级」式的；如果上游需要一次性获得本机能力清单，可在后续阶段再追加一个 `get_tool_availability` 工具或 `osinfo://capabilities` 资源。
- 与 `agent-brain` 的集成（`OsMCPClient`、`/ops/chat` 入口、`OpsOrchestrator`）属于下一阶段，本目录刻意不做任何 `agent-brain` 侧改动。
