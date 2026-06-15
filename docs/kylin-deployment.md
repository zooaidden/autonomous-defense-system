# 麒麟操作系统 / LoongArch 部署指南

> 适配版本：**银河麒麟高级服务器版 V10 SP3**（x86_64 / LoongArch64 / aarch64）
> 适用模块：`defense-gateway` / `agent-brain` / `formal-verifier` / `actuator-service` / `dashboard-ui` / `mcp-servers/*`

本文档面向 A2 赛题验收场景，给出完整的本地部署、最小权限运行、Docker / 非 Docker 双方案以及常见问题排查。脚本与配置位于 `deploy/kylin/`：

```text
deploy/kylin/
├─ env.example            # full set of environment variables
├─ start-all.sh           # boots formal-verifier / actuator-service / defense-gateway / agent-brain / dashboard-ui
├─ stop-all.sh            # graceful stop via pid file or port fallback
└─ check-health.sh        # probes 8080 / 8001 / 8002 / 8081 / 5173
```

---

## 1. 项目简介

`autonomous-defense-system` 是一个面向云原生安全的自治防御平台，覆盖：

- **事件感知**：`defense-gateway` 接收外部 EDR / IDS 上报，规范化后写 Kafka。
- **多智能体决策**：`agent-brain` 通过 LangGraph 编排 Planner / Red-Teamer / Coordinator 三个智能体进行博弈，并通过 MCP 协议读取拓扑、策略、操作系统状态。
- **形式化校验**：`formal-verifier` 运行业务连续性约束求解，对候选策略给出 PASS/FAIL。
- **最小权限执行**：`actuator-service` 模拟下发与回滚；`agent-brain` 内的 `LeastPrivilegeExecutor` 仅允许只读命令真正落到主机。
- **OS 安全运维 Agent（A2 题面）**：`POST /ops/chat` 接收自然语言运维指令，依次走 *MCP 状态采集 → 安全闸门 → 最小权限执行*；危险动作（`rm -rf /`、`chmod 777 /`、`iptables -F`、`curl|sh` 等）由安全闸门拦截，绝不会真正执行。
- **可视化**：`dashboard-ui`（React + Vite）提供仪表盘、博弈过程、策略执行、`/ops` 安全运维 Agent 等页面。

---

## 2. 系统架构

### 2.1 模块与端口矩阵

| 模块 | 端口 | 协议 | 说明 |
|---|---:|---|---|
| `defense-gateway` | **8080** | HTTP | 安全事件接入 / Kafka 发布 |
| `agent-brain` | **8001** | HTTP | 多智能体编排、`/workflow/run`、`/ops/chat`、`/ops/audit/{id}`、`/health` |
| `formal-verifier` | **8002** | HTTP | 形式化校验（`POST /verify`） |
| `actuator-service` | **8081** | HTTP | 策略执行与回滚 |
| `dashboard-ui` | **5173** | HTTP | 前端（开发模式 Vite，生产可换 nginx） |
| `acd-orchestration-service`（可选） | 8090 | HTTP | 旧版 MVP 编排兼容入口 |

### 2.2 主链路（A2 重点链路）

```
浏览器 /ops 页面
    │
    ▼
POST /ops/chat   ──►  agent-brain (8001)
                          │
        ┌─────────────────┼─────────────────────────────┐
        ▼                 ▼                             ▼
ops_intent_parser    OS MCP Client              IntentValidator
(意图识别)            (os-mcp-server stdio)       (33 条规则)
        │                 │                             │
        └────────► OpsOrchestrator ◄───────────────────┘
                          │
                          ▼
                LeastPrivilegeExecutor
                (subprocess + 白名单 + 5s timeout)
                          │
                          ▼
                 OpsAuditLog (JSONL)
```

### 2.3 防御主链路

```
defense-gateway (8080)
        │ Kafka security.events
        ▼
agent-brain (8001)  ─►  formal-verifier (8002)
        │
        ▼
actuator-service (8081)
        │
        ▼
dashboard-ui (5173)
```

---

## 3. 麒麟 OS / LoongArch 适配说明

### 3.1 推荐基线

| 项 | 推荐值 |
|---|---|
| OS | 银河麒麟高级服务器版 V10 SP3 |
| 内核 | ≥ 4.19（默认 4.19.90 OK） |
| CPU 架构 | x86_64 / LoongArch64 / aarch64 均可 |
| 用户 | 专用低权限账户 `ops-agent`（不要直接用 root） |
| SELinux | `permissive` 或 `disabled`（生产可改 `targeted`，需要为 nohup 写日志的目录加策略） |
| firewalld | 放通 8080 / 8001 / 8002 / 8081 / 5173；生产仅放 8080 + 5173 |

### 3.2 LoongArch 特别提醒

LoongArch64 与 x86_64 的差异主要落在 **JDK / Node 二进制可用性** 上：

1. **JDK**：
   - 推荐使用 **Loongnix Java 17**（`yum install java-17-openjdk-devel` 在 Loongnix 软件源中通常已就绪）。
   - 若 Loongnix 仓库不可用，可从 [openjdk-loongarch](https://openjdk.openeuler.org/) 下载预编译二进制，并设置 `JAVA_HOME`。
   - **避免** 使用 Oracle JDK 商用版（许可证）和 GraalVM（部分场景需重编 native image）。

2. **Node.js**：
   - 18.x / 20.x 已发布 `linux-loong64` 官方包，下载地址 `https://nodejs.org/dist/v20.*/node-v20.*-linux-loong64.tar.xz`。
   - 若网络受限，使用 **fnm** / **nvm** + 从源码编译 Node 也可（≥ 30 分钟）。
   - `npm install` 中常见的 `esbuild` / `rollup` 等依赖在 `npm` 9+ 上对 LoongArch 已较稳定；遇到原生模块失败时可加 `--ignore-scripts` 跳过 native 后置脚本。

3. **Python**：
   - 麒麟 V10 SP3 默认 `python3` 为 3.7/3.9，**`agent-brain` 需要 ≥ 3.11**。推荐：
     - 用 `dnf install python3.11 python3.11-pip python3.11-venv`；若仓库中无该版本，使用 EPEL-loongarch 或源码编译（≈ 8 分钟）。
     - 创建独立 venv：`python3.11 -m venv .venv` 之后所有 `pip install` 都在 venv 内执行，不污染系统包。

4. **OpenSSL**：
   - LoongArch 上 `pip install httpx` / `cryptography` 偶尔需要 `openssl-devel` 与 `libffi-devel`：
     ```bash
     sudo yum install -y gcc python3.11-devel openssl-devel libffi-devel
     ```

5. **MySQL / Kafka**：
   - 容器化：`mysql:5.7` / `confluentinc/cp-kafka` 在 LoongArch 上 **没有官方镜像**，请改用 RPM 安装的本地 MySQL 8 + Kafka，并在 `defense-gateway` 中通过 `DB_HOST`、`KAFKA_BOOTSTRAP_SERVERS` 指向本地实例。
   - 仅做 A2 的 OPS Agent 演示时 **可以完全不依赖** MySQL / Kafka（`agent-brain` 与 `actuator-service` 不强依赖）。

### 3.3 字符集 / 区域

确保系统区域为 UTF-8，否则 OPS 审计日志可能乱码：

```bash
sudo localectl set-locale LANG=zh_CN.UTF-8
echo 'export LANG=zh_CN.UTF-8' | sudo tee /etc/profile.d/utf8.sh
```

---

## 4. Java 环境要求

| 项 | 推荐 |
|---|---|
| JDK | OpenJDK **17 LTS**（最低 11） |
| 构建 | Maven 3.8+（已内置 `mvnw`，可不安装系统 Maven） |
| 内存 | 每个 Spring Boot 服务 ≥ 512 MiB |

```bash
# Kylin V10 SP3 (x86_64 / aarch64)
sudo dnf install -y java-17-openjdk-devel

# LoongArch64
sudo yum install -y java-17-openjdk-devel  # Loongnix repo

# 验证
java -version    # openjdk version "17.x"
./mvnw -v         # 项目根目录可直接用
```

构建（一次即可）：

```bash
cd autonomous-defense-system
./mvnw -pl shared-models,defense-gateway,actuator-service,acd-orchestration-service \
       -am clean package -DskipTests
```

构建产物（`*-1.0.0.jar`）位于 `<module>/target/`，被 `start-all.sh` 自动识别。

---

## 5. Python 环境要求

| 项 | 推荐 |
|---|---|
| Python | **3.11** 或 3.12（LangGraph 依赖） |
| pip | 24+ |
| 虚拟环境 | 强制使用，每个 Python 模块各一个 venv |

```bash
sudo dnf install -y python3.11 python3.11-devel python3.11-pip
python3.11 -m pip install -U pip wheel
```

为每个 Python 模块准备 venv（脚本会自动检测）：

```bash
# agent-brain
cd agent-brain
python3.11 -m venv .venv
source .venv/bin/activate
pip install -e .[mcp]      # mcp extra 用于 real 模式 stdio
deactivate

# formal-verifier
cd ../formal-verifier
python3.11 -m venv .venv
source .venv/bin/activate
pip install -e .
deactivate

# os-mcp-server / topology-mcp-server / policy-mcp-server (可选)
cd ../mcp-servers/os-mcp-server
python3.11 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
deactivate
```

> 仅当 `MCP_*_MODE=real` 时才需要为 mcp-servers 单独建立 venv；`local` 模式下 `agent-brain` 直接 `import` 服务模块，不会拉子进程。

---

## 6. Node 环境要求

| 项 | 推荐 |
|---|---|
| Node.js | **20 LTS**（最低 18） |
| npm | 10+ |

```bash
# x86_64 / aarch64
curl -fsSL https://rpm.nodesource.com/setup_20.x | sudo bash -
sudo dnf install -y nodejs

# LoongArch64：从官方下载预编译包
ARCH=loong64
VER=v20.18.0
curl -fLO "https://nodejs.org/dist/${VER}/node-${VER}-linux-${ARCH}.tar.xz"
sudo tar -xJf node-${VER}-linux-${ARCH}.tar.xz -C /opt
echo 'export PATH=/opt/node-v20.18.0-linux-loong64/bin:$PATH' | sudo tee /etc/profile.d/node.sh
source /etc/profile.d/node.sh
```

构建 / 安装依赖（一次即可）：

```bash
cd dashboard-ui
npm ci      # 严格按 package-lock.json 安装
```

---

## 7. MCP Server 启动方式

仓库提供 4 个 MCP Server（`mcp-servers/`），三种模式：

| 模式 | 配置 | 说明 |
|---|---|---|
| **不启用** | `ENABLE_MCP=false` | 走兼容兜底，无需任何 MCP 进程。 |
| **local** | `ENABLE_MCP=true` + `MCP_*_MODE=local` | `agent-brain` 直接 `import` 各 `*_service.py`，**最简单**，强烈推荐。 |
| **real** | `ENABLE_MCP=true` + `MCP_*_MODE=real` | `agent-brain` 通过 stdio 拉起 `server.py` 子进程；需要 `pip install -e .[mcp]`。 |

### 7.1 local 模式（推荐）

无需手工拉起任何 MCP 进程。`start-all.sh` 默认启用此模式，env.example 已写好。

### 7.2 real 模式（手动验证用）

```bash
# 例：单独验证 os-mcp-server
cd mcp-servers/os-mcp-server
source .venv/bin/activate
python server.py        # FastMCP 进入 stdio loop，Ctrl+C 退出
```

### 7.3 OS MCP Server 路径

`OS_MCP_SERVER_PATH` 必须指向 **目录**，不是 `server.py` 文件，例如：

```bash
OS_MCP_SERVER_PATH=/opt/autonomous-defense-system/mcp-servers/os-mcp-server
```

`agent-brain` 内部会自动拼接 `server.py`。

---

## 8. agent-brain 启动方式

### 8.1 开发模式（uvicorn auto-reload）

```bash
cd agent-brain
source .venv/bin/activate
export $(grep -v '^#' ../deploy/kylin/.env | xargs)   # 加载环境变量
uvicorn agent_brain.main:app --host 0.0.0.0 --port 8001 --reload
```

### 8.2 生产模式（多 worker）

```bash
uvicorn agent_brain.main:app \
  --host 0.0.0.0 --port 8001 \
  --workers 2 \
  --no-access-log
```

> 多 worker 注意：当前 `OpsAuditLog` 使用单进程 `threading.Lock`，多 worker 写同一 JSONL 文件可能交错。建议生产用 `--workers 1` 或为每个 worker 配独立的 `OPS_AUDIT_LOG_PATH`。

### 8.3 关键路径

- `POST /workflow/run` — 防御主链路
- `POST /ops/chat` — 自然语言运维（A2）
- `GET /ops/audit/{requestId}` — 审计回放
- `GET /health` — 含 `mcp` / `opsAgent` 子节点

---

## 9. dashboard-ui 启动方式

### 9.1 开发模式（Vite Dev Server，5173）

```bash
cd dashboard-ui
export VITE_AGENT_BRAIN_BASE_URL=http://localhost:8001
export VITE_API_BASE_URL=http://localhost:8080
export VITE_USE_MOCK=false
npm run dev -- --host 0.0.0.0 --port 5173
```

### 9.2 生产模式（静态 + nginx）

```bash
cd dashboard-ui
VITE_AGENT_BRAIN_BASE_URL=http://192.168.1.100:8001 \
VITE_API_BASE_URL=http://192.168.1.100:8080 \
VITE_USE_MOCK=false \
npm run build
# 产物在 dist/，可直接部署到 nginx
sudo cp -r dist/* /usr/share/nginx/html/
```

---

## 10. 不使用 Docker 的手动部署方式

> 推荐 A2 验收场景使用此方式（LoongArch 几乎没有现成镜像）。

### 10.1 一次性准备

```bash
sudo useradd -m -s /bin/bash ops-agent
sudo mkdir -p /opt/autonomous-defense-system
sudo chown ops-agent:ops-agent /opt/autonomous-defense-system

# 拷贝代码
sudo -u ops-agent rsync -a /path/to/repo/ /opt/autonomous-defense-system/

# 进入目录，按 §4-§6 准备 JDK / Python / Node
cd /opt/autonomous-defense-system

# 构建 Java
./mvnw -pl shared-models,defense-gateway,actuator-service,acd-orchestration-service -am clean package -DskipTests

# 安装 Python venv（见 §5）

# 前端构建
cd dashboard-ui && npm ci && cd ..
```

### 10.2 一键启停

```bash
cd /opt/autonomous-defense-system

# 复制环境变量模板
cp deploy/kylin/env.example deploy/kylin/.env
chmod 600 deploy/kylin/.env

# 编辑 .env：填写 LLM API Key（可空，自动 Mock）、调整端口与路径
$EDITOR deploy/kylin/.env

# 启动全部
bash deploy/kylin/start-all.sh

# 健康检查
bash deploy/kylin/check-health.sh

# 停止全部
bash deploy/kylin/stop-all.sh
```

启动日志位于 `deploy/kylin/run/logs/<service>.log`，PID 文件位于 `deploy/kylin/run/pids/<service>.pid`。

### 10.3 systemd 集成（可选）

把 `deploy/kylin/start-all.sh` 包到 `Type=forking` 的 systemd unit：

```ini
# /etc/systemd/system/autonomous-defense.service
[Unit]
Description=Autonomous Defense System (Kylin)
After=network-online.target
Wants=network-online.target

[Service]
Type=forking
User=ops-agent
WorkingDirectory=/opt/autonomous-defense-system
EnvironmentFile=/opt/autonomous-defense-system/deploy/kylin/.env
ExecStart=/bin/bash deploy/kylin/start-all.sh
ExecStop=/bin/bash deploy/kylin/stop-all.sh
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now autonomous-defense.service
sudo systemctl status autonomous-defense.service
```

---

## 11. 使用 Docker 的部署方式

> **说明**：`autonomous-defense-system/deploy/docker-compose.yml` 仅启动
> **基础依赖**（MySQL、Kafka、Zookeeper），并不能拉起 `agent-brain` /
> `actuator-service` / `defense-gateway` / `dashboard-ui` 这些业务容器。
> 业务容器化属于路线图项目，目前请按 §10 的非容器方式启动业务服务。


> 仅适用于 **x86_64 / aarch64**；LoongArch 推荐走 §10。

### 11.1 仅启动外部依赖（MySQL + Kafka）

仓库已自带 `deploy/docker-compose.yml`（mysql:5.7 + kafka + zookeeper）：

```bash
cd autonomous-defense-system/deploy
docker compose up -d
docker compose ps
```

`defense-gateway` 默认连接 `localhost:3307` MySQL 与 `localhost:9092` Kafka，与 compose 一致。

### 11.2 容器化业务服务（可选，需自行编写 Dockerfile）

`agent-brain` 示例 Dockerfile：

```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY agent-brain/ ./agent-brain/
RUN pip install -e ./agent-brain[mcp]
EXPOSE 8001
CMD ["uvicorn", "agent_brain.main:app", "--host", "0.0.0.0", "--port", "8001"]
```

`dashboard-ui` 示例 Dockerfile：

```dockerfile
FROM node:20-alpine AS build
WORKDIR /app
COPY dashboard-ui/ ./
RUN npm ci && VITE_AGENT_BRAIN_BASE_URL=http://agent-brain:8001 npm run build

FROM nginx:1.27-alpine
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
```

把上面两个 Dockerfile 加入 `deploy/docker-compose.yml` 的 `services:` 段即可。

---

## 12. 常见问题排查

### Q1. `agent-brain` 启动报 `ModuleNotFoundError: agent_brain`

未在 venv 中安装可编辑包：

```bash
cd agent-brain && source .venv/bin/activate && pip install -e .
```

### Q2. `pip install langgraph` 在 LoongArch 失败

`langgraph` 是纯 Python，但 transitive 依赖里 `pydantic-core` 含 Rust 扩展。解决：

```bash
sudo dnf install -y rust cargo openssl-devel
pip install --upgrade pip
pip install pydantic --no-binary pydantic-core   # 强制本地编译
```

### Q3. `defense-gateway` 启动报 `Communications link failure`

MySQL 端口或密码不对。检查 `.env` 中 `DB_HOST` / `DB_PORT` / `DB_PASSWORD`，或用 docker compose 默认值（`localhost:3307`）。

### Q4. 前端能访问 `/ops` 页面，但 `Run` 按钮永远报 `Failed to fetch`

- 确认 `agent-brain:8001` 在线：`curl http://localhost:8001/health`
- 确认 CORS：`AGENT_BRAIN_CORS_ORIGINS=http://localhost:5173`
- 浏览器开发者工具看预检 OPTIONS 是否 200

### Q5. `os-mcp-server` 在 Windows / 非 Linux 上工具大量返回 `tool_unavailable`

预期行为：`get_network_sockets`（依赖 `ss`）等命令仅在 Linux 可用。Kylin V10 SP3 上应全部 OK。

### Q6. `/ops/chat` 在危险命令上正确返回 BLOCK，但前端进度条节点不变红

刷新一下页面缓存（CSS hash 可能未刷新）。同时确认 `OpsAuditTrailItem.status` 字段被前端识别。

### Q7. 启动日志全部正常，但 `check-health.sh` 报 8002 / 8081 红色

这两个服务启动较慢（Spring Boot ≈ 8-15s，formal-verifier 1-2s）。等 30 秒再 check 一次。

### Q8. `npm install` 在 LoongArch 卡死在 `esbuild`

```bash
npm config set ignore-scripts true
npm install
# 或者
ESBUILD_BINARY_PATH=/opt/esbuild-loong64/bin/esbuild npm install
```

### Q9. `OPS_AUDIT_LOG_PATH` 写入失败 `Permission denied`

```bash
sudo mkdir -p /var/log/autonomous-defense
sudo chown ops-agent:ops-agent /var/log/autonomous-defense
echo 'OPS_AUDIT_LOG_PATH=/var/log/autonomous-defense/ops_audit.jsonl' >> deploy/kylin/.env
```

---

## 13. 权限安全说明

### 13.1 操作系统层面

- **专用账户**：所有服务以 `ops-agent`（无 sudo）运行；只读 `/proc`、`/sys` 与日志目录写权限即可。
  - 创建步骤（root 执行一次）：
    ```bash
    sudo useradd --system --create-home --shell /usr/sbin/nologin ops-agent
    sudo install -d -o ops-agent -g ops-agent /var/log/autonomous-defense/audit
    sudo chown -R ops-agent:ops-agent /opt/autonomous-defense-system
    ```
  - **systemd 单元示例**：`deploy/kylin/ops-agent.service`，已设置 `User=ops-agent`、
    `NoNewPrivileges=true`、`ProtectSystem=strict`、`ProtectHome=read-only`、
    `MemoryDenyWriteExecute=true`。把它拷到 `/etc/systemd/system/`，`systemctl
    daemon-reload && systemctl enable --now ops-agent.service` 即可。
- **启动期高权限拒绝**：`agent-brain` 在 `main.py` 启动时调用
  `is_running_as_root()`，当检测到 `uid=0` / Administrator 时按
  `AGENT_BRAIN_ROOT_POLICY` 处理：`refuse`（默认）退出进程；`degrade`
  保留运行但 `LeastPrivilegeExecutor` 锁死为只读；`off` 跳过检查（不推荐）。
- **SELinux**：保留 `targeted`，为 `OPS_AUDIT_LOG_PATH` 目录添加 `system_u:object_r:var_log_t:s0` 上下文。
- **firewalld**：默认仅放通 8080（事件接入）、5173（前端）；其他端口仅本机 `127.0.0.1` 监听。
  ```bash
  sudo firewall-cmd --permanent --add-port=8080/tcp
  sudo firewall-cmd --permanent --add-port=5173/tcp
  sudo firewall-cmd --reload
  ```
- **机密保护**：`deploy/kylin/.env` 务必 `chmod 600`，且 **禁止提交 git**。

### 13.2 应用层面

- **CORS**：开发期用 `http://localhost:5173`，生产期写明确域名（如 `https://ops.example.com`），不使用通配符。
- **审计**：`/ops/chat` 每次请求落 JSONL（`OPS_AUDIT_LOG_PATH`），覆盖 9 个生命周期阶段；建议接 logrotate 按天切，并 ship 到 SIEM。
- **LLM Key**：仅写入 `.env`，文件权限 600；不在日志、URL、`README` 中出现 Key 字面值。文档与脚本中 **绝不** 包含真实 Key。

---

## 14. 最小权限执行说明（A2 安全护栏）

`agent-brain` 通过两道闸门来保证“危险动作不能在主机上落地”：

### 14.1 第一道闸门 — Intent Validator

- 33 条静态规则（`agent_brain/safety/intent_rules.py`），覆盖：
  - **BLOCK**（14 条）：`rm -rf /`、`chmod 777 /`、`chown root /`、`mkfs`、`dd of=/dev`、`shutdown` / `reboot` / `halt` / `poweroff`、`curl|sh`、fork bomb、`iptables -F`、`firewall-cmd --permanent --remove`、`kubectl delete namespace`、`kubectl delete pod --all`、`rm /var/log`
  - **REQUIRE_APPROVAL**（9 条）：`kill -9`、`systemctl restart/stop/disable`、`sshd_config` 修改、防火墙变更、`chmod -R`、`chown -R`、`rm -rf <任意>`、清空日志
  - **ALLOW**（11 条）：`ps`、`top`、`df`、`free`、`uptime`、`journalctl`、`ss`、`netstat`、`lsof`、`systemctl status`、只读 `cat /proc/*`

### 14.2 第二道闸门 — Least-Privilege Executor

- `subprocess.run(argv, shell=False)`：永远不走 shell，杜绝 `;` / `|` 注入。
- **白名单**：仅 `ps / ss / netstat / lsof / df / free / uptime / journalctl / systemctl status` 被允许真正执行；其他一律 `REJECTED`。
- **5 秒超时**：超时即 SIGKILL。
- **16 KiB 输出截断**：防大量日志撑爆 stdout。
- **审计**：每次执行写 JSONL（`commandId / executedAs / startedAt / endedAt / exitCode / argv`）。

### 14.3 端到端验证

```bash
cd agent-brain
python scripts/test_ops_dangerous_flow.py
```

输出应为 7 条 `[OK]` + 最终 `PASS`，证明：

- 7 条危险输入全部被识别为 `INTENT_DANGEROUS_COMMAND` 或被 heuristic 命中。
- `subprocess.run` **零次** 调用。
- 每条审计链路都包含：`received_instruction → dangerous_intent_detected → safety_validation_blocked → execution_skipped`。
- finalAnswer 中文显式说明：`[BLOCKED · risk=...] 该指令已被安全策略拦截，未在主机上执行任何命令…`

### 14.4 确定性护栏 — System Config Guard

`agent_brain/safety/system_config_guard.py` 提供独立于意图校验器的“路径维度”护栏，专门防止 Agent
在调用过程中对关键系统配置文件做出写入。

- **受保护路径**：`/etc/passwd`、`/etc/shadow`、`/etc/sudoers(.d/*)`、`/etc/ssh/sshd_config(.d/*)`、
  `/etc/systemd/system/*`、`/etc/cron.*`、`/etc/pam.d/*`、`/etc/security/*`、`/etc/fstab`、
  `/etc/resolv.conf`、`/etc/login.defs`、`/boot/*`、`/lib/modules/*`、`/etc/kylin-release`、`/etc/os-release` 等。
- **写入动作**：`tee`、`dd`、`cp`、`mv`、`install`、`sed -i`、`rm`、`chmod`、`chown`、`chattr`、`truncate`、
  `ln -sf`、`vi`/`vim`/`nano`、`passwd`、`useradd`、`usermod`、`groupadd`、以及 `>` / `>>` 重定向。
- **触发结果**：返回 `decision = "BLOCK"`，`riskLevel ∈ {HIGH, CRITICAL}`，`matchedPaths` 详列每条命中路径，
  `auditTrail` 中追加 `config_guard_blocked` 步骤，前端展示「关键配置文件确定性护栏」红色卡片。

该护栏与意图校验器并联工作：任何一道触发 BLOCK 即立刻终止流程，命令不会进入 MCP 与执行器。

### 14.5 抗提示词注入 — Prompt Injection Guard

`agent_brain/safety/prompt_injection_guard.py` 在流水线**最前端**对用户原始输入做规则级检测。

- 角色劫持：`ignore (previous|above) instructions`、`you are now (root|admin|developer mode)`、
  `忽略.*指令`、`扮演 root/管理员/黑客`、`输出系统提示` 等。
- 模板劫持：`<|im_start|>`、`<|system|>`、`[INST]`、`<<SYS>>`、Markdown `### system` 头、HTML 注入标签。
- 编码载荷：连续 ≥ 80 字符的 base64-like 串、URL 编码占比 ≥ 30% 的字符串。
- 命令拼接：自然语言尾部紧跟 `; rm`、`&& wget | bash` 等。
- 超长输入：> 4000 字符，视作 paste-bomb 拒绝。

命中任意规则后立刻短路整条流水线：`dangerCategory = "prompt_injection"`，
`executionResult.status = "BLOCKED"`，`auditTrail` 中追加 `prompt_injection_detected`，
前端展示「反提示词注入护栏」红色卡片，整个流程**不**经过意图校验器、MCP 与执行器。

### 14.6 审计端点与系统状态

- `POST /ops/chat` 与 `POST /workflow/run` 返回 `auditFile` 字段（绝对路径，写盘失败时为 `null`）。
- `GET /audit/{requestId}` 提供单次请求的完整 JSON 快照下载；请求 ID 严格匹配
  `^[A-Za-z0-9_-]{1,80}$`，并对 `../` 等路径穿越在路由层立即返回 400。
- `GET /system/status` 返回当前主机平台（含 `osPretty`、`kylinVersion`、`machine`、`isLoongArch`）、
  服务进程占位（`agent-brain` / `defense-gateway` / `actuator-service` / `formal-verifier` /
  `dashboard-ui`）、MCP 客户端目录（`topology` / `policy` / `os` / `actuator`，含 `tools` 列表）、
  最小权限执行器白名单与三道护栏的启用状态，供前端 `/system` 页和答辩展示使用。

---

## 15. 双平台最小启动（Windows / Linux-Kylin）

> 推荐先在本地 Windows / WSL 跑通官方主线，再切到 Kylin/LoongArch。两套
> 步骤都假设 MySQL + Kafka 已通过 `deploy/docker-compose.yml` 启动。

### 15.1 Windows / PowerShell

```powershell
# 1) 复制 env 模板并填密码（注意 .env 已在 .gitignore）
Copy-Item autonomous-defense-system\.env.example autonomous-defense-system\.env
Copy-Item autonomous-defense-system\deploy\.env.example autonomous-defense-system\deploy\.env

# 2) 起基础依赖
docker compose -f autonomous-defense-system\deploy\docker-compose.yml --env-file autonomous-defense-system\deploy\.env up -d

# 3) 起 agent-brain（注意 strict 模式 + 拒绝 root）
cd autonomous-defense-system\agent-brain
python -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install -e .
$env:AGENT_BRAIN_FAILURE_MODE = "strict"
$env:AGENT_BRAIN_ROOT_POLICY = "refuse"
$env:WORKFLOW_GUARD_STRICT = "true"
python -m uvicorn agent_brain.main:app --reload --port 8001

# 4) 另开终端启 formal-verifier / actuator-service / defense-gateway / dashboard-ui
#    详见 §8、§9 ；前端 .env 切到联调模式：
Copy-Item autonomous-defense-system\dashboard-ui\.env.example autonomous-defense-system\dashboard-ui\.env
notepad autonomous-defense-system\dashboard-ui\.env   # 把 VITE_USE_MOCK 改为 false

# 5) 健康巡检
pwsh autonomous-defense-system\deploy\kylin\check-health.ps1
```

### 15.2 Linux / 银河麒麟 V11

```bash
# 1) 普通账户（不要 root）下创建 .env 并设权限
cp autonomous-defense-system/.env.example autonomous-defense-system/.env
cp autonomous-defense-system/deploy/.env.example autonomous-defense-system/deploy/.env
chmod 600 autonomous-defense-system/.env autonomous-defense-system/deploy/.env

# 2) 基础依赖
docker compose -f autonomous-defense-system/deploy/docker-compose.yml \
  --env-file autonomous-defense-system/deploy/.env up -d

# 3) 创建低权限运行账户并安装 systemd 单元
sudo useradd --system --create-home --shell /usr/sbin/nologin ops-agent
sudo cp autonomous-defense-system/deploy/kylin/ops-agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now ops-agent

# 4) 一键全量起停（必要时手动执行）
bash autonomous-defense-system/deploy/kylin/start-all.sh
bash autonomous-defense-system/deploy/kylin/check-health.sh
```

> 上面所有命令均 **以非 root 用户** 执行；`agent-brain` 启动期会自检
> `AGENT_BRAIN_ROOT_POLICY=refuse`，若发现 uid=0 直接退出。

---

## 附录 A：端口与日志快查

| 端口 | 服务 | 健康路径 | 日志 |
|---:|---|---|---|
| 8080 | defense-gateway | **`/api/health`** | `deploy/kylin/run/logs/defense-gateway.log` |
| 8001 | agent-brain | `/health` | `deploy/kylin/run/logs/agent-brain.log` |
| 8002 | formal-verifier | `/health` | `deploy/kylin/run/logs/formal-verifier.log` |
| 8081 | actuator-service | **`/api/health`** | `deploy/kylin/run/logs/actuator-service.log` |
| 5173 | dashboard-ui | `/` | `deploy/kylin/run/logs/dashboard-ui.log` |

> Spring Boot Actuator 端点（`/actuator/health`）**未启用**；项目以自定义
> `/api/health` 作为 Java 服务的健康探针；旧脚本里出现的 `/actuator/health`
> 均已替换。

## 附录 B：环境变量速查

完整列表见 `deploy/kylin/env.example`，常用项：

| 变量 | 缺省 | 说明 |
|---|---|---|
| `ENABLE_MCP` | `true` | 总开关 |
| `MCP_TOPOLOGY_MODE` | `local` | `local` / `real` |
| `MCP_POLICY_MODE` | `local` | 同上 |
| `MCP_OS_MODE` | `local` | 同上 |
| `OS_MCP_SERVER_PATH` | `mcp-servers/os-mcp-server` | **目录** 路径 |
| `AGENT_BRAIN_LLM_API_KEY` | （空） | 留空自动用 MockLLMClient |
| `AGENT_BRAIN_LLM_BASE_URL` | `https://api.siliconflow.cn/v1` | OpenAI 兼容 base |
| `AGENT_BRAIN_LLM_MODEL` | `Pro/deepseek-ai/DeepSeek-V3.2` | 模型名 |
| `OPS_AUDIT_LOG_PATH` | `agent-brain/data/ops_audit.jsonl` | OPS 审计 JSONL 路径 |
| `VITE_AGENT_BRAIN_BASE_URL` | `http://localhost:8001` | 前端调用 agent-brain 的地址 |
| `VITE_USE_MOCK` | `true` | 关闭后必须有真实后端 |

---

**版本 / 维护**：本文档跟随仓库 `main` 分支。若有适配问题，请在 `docs/` 目录下提 Issue 并附上 `check-health.sh` 输出与对应服务的 `*.log` 末尾 200 行。
