# `deploy/kylin/` — 银河麒麟 / LoongArch 部署脚本

完整文档见 [`docs/kylin-deployment.md`](../../docs/kylin-deployment.md)。本目录只放“能直接跑”的最小脚本与环境模板。

## 目录结构

```text
deploy/kylin/
├─ env.example       # full set of environment variables (copy to .env)
├─ start-all.sh      # boot 5 services in order
├─ stop-all.sh       # stop via pid file with port-based fallback
├─ check-health.sh   # probe ports 8080 / 8001 / 8002 / 8081 / 5173
├─ run/
│  ├─ logs/          # per-service stdout/stderr (auto-created)
│  └─ pids/          # per-service pid files     (auto-created)
└─ README.md
```

## 30 秒上手

```bash
# 1) 准备环境变量
cp deploy/kylin/env.example deploy/kylin/.env
chmod 600 deploy/kylin/.env
$EDITOR deploy/kylin/.env          # 至少检查端口与 LLM Key（留空就走 Mock）

# 2) 启动
bash deploy/kylin/start-all.sh

# 3) 健康检查
bash deploy/kylin/check-health.sh

# 4) 停止
bash deploy/kylin/stop-all.sh
```

## 默认端口

| 端口 | 服务 |
|---:|---|
| 8080 | defense-gateway |
| 8001 | agent-brain（含 `/ops/chat`、`/health`） |
| 8002 | formal-verifier |
| 8081 | actuator-service |
| 5173 | dashboard-ui（Vite） |

> os-mcp-server / topology-mcp-server / policy-mcp-server **不会** 被 `start-all.sh` 单独启动。`agent-brain` 在 `MCP_*_MODE=local`（默认）时同进程加载，在 `real` 模式下通过 stdio 拉子进程。

## 脚本约定

- **不使用 sudo**：所有脚本以普通用户运行；如需写 `/var/log/`，请提前 `chown ops-agent`。
- **不写真实 Key**：`env.example` 与脚本本身均不包含真实 LLM API Key；请在 `.env` 中填写并 `chmod 600`。
- **注释全英文**：脚本中所有注释为英文，避免在某些非 UTF-8 终端下乱码。
- **优雅退出**：`stop-all.sh` 先 SIGTERM、`GRACEFUL_WAIT_SECONDS`（默认 8s）后 SIGKILL，并在 PID 文件失效时按端口兜底。
- **可移植**：脚本兜底使用 `ss` / `netstat` / `lsof` / `fuser` / `/dev/tcp`，至少有一种可用即可。

## 常见排错

| 现象 | 处理 |
|---|---|
| `start-all.sh` 报 `defense-gateway jar not built` | `./mvnw -pl defense-gateway -am clean package -DskipTests` |
| `agent_brain package not installed in venv` | `cd agent-brain && python3.11 -m venv .venv && source .venv/bin/activate && pip install -e .[mcp]` |
| `node_modules missing` | 脚本会自动 `npm ci`；若网络受限请提前手动跑 |
| `check-health.sh` 8002/8081 红色 | Spring Boot 启动需要 8-15s，等 30s 再跑一次 |
| 多次启动后端口被占 | `bash deploy/kylin/stop-all.sh` 会按端口兜底 |

更多细节（systemd 集成、SELinux、firewalld、最小权限、A2 危险指令演示链路）见 [`docs/kylin-deployment.md`](../../docs/kylin-deployment.md)。
