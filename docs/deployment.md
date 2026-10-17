# AIGuardFabric 部署指南

> 事实来源：`.env.example`（全量变量）、`scripts/env.ps1` / `scripts/init-env.ps1` / `scripts/selfcheck.ps1`、
> `docker-compose.yml` / `docker-compose.dev.yml` / `docker-compose.prod.yml`、
> `deploy/docker/Dockerfile` / `deploy/docker/nginx.conf`、`deploy/sql/migration_parts/`、
> `deploy/helm/aiguardfabric/**`、`Justfile`、`crates/agf-core/src/config.rs`。
>
> ⚠️ **实现状态前置声明**：编排层（compose/Helm/Dockerfile）、存储层（迁移/RLS/种子）与脚本层已核对；
> **`agf-server` / `agf-ingest` / `agf-scheduler` / `agfctl` 均已落地并实测可运行**
> （`docker compose up -d` 实测 **8 个容器全部 healthy**、`/healthz` 200 `mode:"database"`、
> `/readyz` 200 `degraded:false`、admin 首登强制改密、控制台 `:8081` 200，见
> [`docs/pending-verification.md`](pending-verification.md) PV-001）。仍未闭环的部分（真实凭据/真实设备/压测）
> 逐条登记在该文件里。

---

## 1. 两条部署路径

| 维度 | 开发机路径（Windows + PowerShell） | 生产路径 |
|---|---|---|
| 宿主 | Windows（PowerShell 5.1 或 pwsh 7+）+ Docker Desktop（Linux 容器） | Linux + 容器编排（Compose 或 K8s） |
| 依赖 | **只起依赖**（postgres/redis/nats/minio），应用在宿主上 `cargo` / `pnpm` 热重载 | 全栈容器化；数据面用**外部托管实例** |
| 编排文件 | `docker-compose.yml` + `docker-compose.dev.yml` | `docker-compose.prod.yml` 或 Helm Chart |
| 端口 | 默认映射到 `127.0.0.1` | 经 Ingress/SLB 暴露，TLS 终结在前置层 |
| 日志 | `AGF_LOG_FORMAT=pretty`（`.env.example` 默认） | `json`（`.prod.yml` 固定） |
| 加固 | `security_opt: no-new-privileges` | `read_only` 根文件系统 + `cap_drop: ALL` + `tmpfs` + 非 root + 资源 limits + 备份 sidecar |
| 凭据 | `.env`（`scripts/init-env.ps1` 随机生成） | Secret 外置（K8s Secret / Vault / 云 KMS） |

---

## 2. 开发机路径（Windows + PowerShell 5.1）

### 2.1 前置检查

```powershell
# 项目根即 Cargo.toml 所在目录；所有命令在项目根执行
pwsh -File scripts/selfcheck.ps1
```

打印 8 组检查：① 项目根与路径纪律（`Cargo.toml` / `.env.example` / `docker-compose.yml` / `crates` / `apps` /
`deploy` / `docs` / `scripts` / `tests` 是否齐全）② 工具链版本（rustc / cargo / rustfmt / cargo-clippy /
node / npm / pnpm / git / docker / docker compose）③ 数据卷占用 ④ 端口占用（11 个）⑤ Docker 守护状态 +
`docker compose config --quiet` ⑥ 配置强度（JWT 密钥 ≥32 字符 / 主密钥解码后 32 字节 / 数据库口令 ≥12 字符 / Mock 模式）
⑦ 缓存与产物重定向 ⑧ 只读工具链完整性（基线比对 + 全局安装痕迹）。
**退出码 1 = 存在阻断项。**

Windows 重启后如果 `docker info` 提示找不到 `dockerDesktopLinuxEngine` 管道，先在已登录的桌面会话运行 `docker desktop start`，等待 `docker info` 能返回服务端版本，再执行 `docker compose up -d` 并检查各服务健康状态。Docker 守护进程未启动与项目配置或数据库损坏无关，不要因此重建 `.env` 或清空数据卷。

### 2.2 环境变量初始化

```powershell
pwsh -File scripts/init-env.ps1              # 默认 -WhatIf：只打印计划
pwsh -File scripts/init-env.ps1 -Force        # 实际写入（已有的 .env 先备份为 .env.bak-<时间戳>）
pwsh -File scripts/init-env.ps1 -ShowSecrets  # 额外回显引导管理员账号与口令
```

`init-env.ps1` 的行为（已核对 322 行）：

| 步骤 | 行为 |
|---|---|
| 1/4 | 若 `.env` 已存在且未指定 `-Force` → **保持不动（幂等）**；指定 `-Force` → 先备份再重新生成 |
| 2/4 | 为 6 个敏感变量生成强随机值：`AGF_PG_PASSWORD`、`AGF_S3_SECRET_KEY`、`AGF_JWT_SECRET`、`AGF_MASTER_KEY_BASE64`（**恰好 32 字节 base64**）、`AGF_GRAFANA_ADMIN_PASSWORD`、`AGF_BOOTSTRAP_ADMIN_PASSWORD`（48 字符，用 `RandomNumberGenerator` 逐字节取模避免模偏差） |
| 3/4 | 写入 `.env`（**UTF-8 无 BOM**，先写临时文件再 `Move-Item`） |
| 4/4 | 创建 `data/` 下 9 个数据卷子目录，并放置 `.gitkeep` |
| 收尾 | 打印引导管理员账号与口令（`-ShowSecrets` 时显示明文） |

> ⚠️ **不覆盖 `CARGO_HOME` / `RUSTUP_HOME`**（`scripts/env.ps1:103-111` 有详细说明）：
> 本机 rustup 的代理二进制（`cargo.exe` / `rustc.exe` / `rustfmt.exe` / clippy）位于 `$CARGO_HOME\bin`，
> 把 `CARGO_HOME` 指向项目内空目录会导致 **cargo 找不到工具链**。因此策略是：
> 工具链与 registry 缓存**只读复用**既有环境，构建产物通过 `.cargo/config.toml` 的 `build.target-dir = "target"`
> + `CARGO_TARGET_DIR` 双保险重定向到项目内。

### 2.3 只起依赖 + 宿主热重载

```powershell
# 只启动 postgres / redis / nats / minio（应用服务被归入 profile "full"，不会启动）
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d
```

`docker-compose.dev.yml` 的作用是**只做减法**（不定义新的构建产物，保证与主 compose 配置同源）：

| 服务 | 归入 profile |
|---|---|
| `agf-server` / `agf-ingest` / `agf-scheduler` / `agf-web` | `full` |
| `minio-init` | `objects` |

然后分别启动应用：

```powershell
# 后端（编译整个 workspace）
cargo build --workspace

# 控制台（Vite 开发服务器）
cd apps/web
pnpm install
pnpm dev            # http://127.0.0.1:5173
```

> ⚠️ `Justfile:36` 的 `just up-deps` 调用 `scripts/dev-up.ps1`，**该脚本当前不存在**。
> 请使用上面的 `docker compose -f ... -f docker-compose.dev.yml up -d` 等价命令。

### 2.4 生成演示数据与离线演示

```powershell
# 生成合成夹具（幂等，固定随机种子 20260221，重复运行逐字节一致）
pwsh -File scripts/gen-fixtures.ps1
pwsh -File scripts/gen-fixtures.ps1 -WhatIf          # 只打印将要写出的文件

# 从公开来源抓取真实样本（默认干跑，必须显式 -Execute 才联网）
pwsh -File scripts/fetch-fixtures.ps1 -ListSources   # 列出内置来源清单（不发网络请求）
pwsh -File scripts/fetch-fixtures.ps1 -Verify        # 干跑 + HEAD 探活
pwsh -File scripts/fetch-fixtures.ps1 -Execute       # 真正下载

# 灌入演示数据（三种落地路径按可用性逐级降级并如实报告）
pwsh -File scripts/seed.ps1 -WhatIf                  # 只打印计划
pwsh -File scripts/seed.ps1 -ApiBase http://127.0.0.1:8080
pwsh -File scripts/seed.ps1 -NoCli                   # 只做离线校验 / HTTP 灌库

# 单机全链路演示：资产发现 → 风险检出 → 告警 → 案件 → 策略下发 → 拦截生效
pwsh -File scripts/demo.ps1 -LocalOnly               # 强制离线圈（不探测也不调用后端）
pwsh -File scripts/demo.ps1 -WhatIf                  # 只打印演示计划
pwsh -File scripts/demo.ps1 -Strict                  # 任何"预期未达成"返回退出码 1
```

**数据来源与降级**：

| 目录 / 脚本 | 性质 | 说明 |
|---|---|---|
| `tests/fixtures/logs/` | 18 个厂商样本 | **仅 1 个真实**（`suricata-eve-1.log`），其余 17 个 `synthetic=true`（`manifest.json`） |
| `tests/fixtures/synthetic/` | 合成夹具 | 由 `gen-fixtures.ps1` 生成，带 `synthetic=true` 与 `SOURCES.md` 说明 |
| `tests/fixtures/downloaded/` | 公开下载物 | 由 `fetch-fixtures.ps1` 抓取（含 `manifest.json` / `SOURCES.md`） |
| `data/seed/` | 演示数据集 | 由 `gen-fixtures.ps1` 生成，清单 `data/seed/index.json`；`seed.ps1` 消费 |

> **素材政策**：`fetch-fixtures.ps1` 的失败处理是**明确报错**（红色 `[FAIL]` + 非零退出码），
> 绝不静默跳过、绝不用合成内容冒充真实来源；`gen-fixtures.ps1` 产出的内容一律标注 `synthetic=true`。

### 2.5 PowerShell 5.1 兼容性注意事项

| 事项 | 事实 | 依据 |
|---|---|---|
| 脚本编码 | 全部 `scripts/*.ps1` 保存为 **UTF-8 with BOM** | `docs/roadmap.md` 实现注记（无 BOM 会导致 5.1 按 ANSI 解码，中文乱码） |
| 不使用 `param()` | `env.ps1` / `lib.ps1` 被 dot-source，**刻意不声明 `param()`**；静默开关走环境变量 `AGF_ENV_QUIET=1` | `env.ps1:17-18`、`lib.ps1` |
| 不覆盖 `CARGO_HOME` | 见 §2.2 说明 | `env.ps1:103-111` |
| `RandomNumberGenerator` | 5.1（.NET Framework 4.0）下必须走静态工厂 `Create()`，`New-Object` 会报 "Cannot find an appropriate constructor" | `init-env.ps1:73-75` |
| 严格模式 | `Set-StrictMode -Version Latest`；访问不存在的属性会抛异常（如空的 `Measure-Object` 没有 `.Sum`），故体积统计改为显式累加 | `env.ps1:24,205-220` |
| 编码设置 | 用 `UTF8Encoding($false)` + `[Console]::OutputEncoding`，某些宿主（ISE 重定向）不允许改编码时静默忽略 | `env.ps1:33-40` |

### 2.6 启动辅助库（`scripts/lib.ps1`）

`lib.ps1` 被其它脚本 dot-source（内部会再 dot-source `env.ps1`），提供：路径解析（`Join-Path $global:AgfRoot ...`）、
JSON/文件 IO、**确定性伪随机**、统一控制台输出。同样不使用 `param()`。

---

## 3. Docker Compose 三件套差异

| 项 | `docker-compose.yml` | `docker-compose.dev.yml` | `docker-compose.prod.yml` |
|---|---|---|---|
| `name` | `aiguardfabric` | （覆盖，不设 name） | `aiguardfabric-prod` |
| 网络 | `agf-net`（bridge） | 继承 | `agf-prod-net`（bridge） |
| postgres | ✅ 自建 `timescale/timescaledb:latest-pg16` | 继承 | ❌ **不自建**，连 `${AGF_PG_HOST:?}` 外部托管实例 |
| redis | ✅ 自建 `redis:7.4-alpine`（`--appendonly yes`、`--maxmemory 512mb`、`allkeys-lru`） | 继承 | ❌ 不自建（`${AGF_REDIS_URL:?}`） |
| nats | ✅ `nats:2.10-alpine` + JetStream（`-js -sd /data -m 8222`） | 继承 | ✅ 仍内置（可用 `AGF_NATS_URL` 指向外部集群） |
| minio | ✅ + `minio-init` 一次建桶 | `minio-init` 归入 profile `objects` | ❌ 不自建（`${AGF_S3_ENDPOINT:?}`） |
| clickhouse | profile `clickhouse`（默认关） | 继承 | 默认 `AGF_CLICKHOUSE_ENABLED=1` |
| grafana | profile `grafana`（默认关） | 继承 | 无 grafana 服务（指向外部） |
| 应用服务 | `agf-server` / `agf-ingest` / `agf-scheduler` / `agf-web` 全部启用 | 全部归入 profile `full`（**默认不启动**） | 全部启用，**从 `AGF_IMAGE_TAG` 拉镜像（不 build）** |
| 加固 | `restart: unless-stopped`、`no-new-privileges` | 继承 | `restart: always`、`read_only: true`、`cap_drop: ALL`、`tmpfs /tmp:64m`、`user 10001:10001`、`ulimits nofile`、`deploy.resources.limits` |
| 日志 | `json-file` `20m × 5` | 继承 | `json-file` `50m × 10` |
| 备份 | ❌ | ❌ | ✅ `backup` sidecar（`pg_dump` + 保留 7 份） |
| 强制变量 | `AGF_PG_PASSWORD`、`AGF_S3_SECRET_KEY`、`AGF_JWT_SECRET`、`AGF_MASTER_KEY_BASE64` | 继承 | 另加 `AGF_PG_HOST`、`AGF_PG_USER`、`AGF_REDIS_URL`、`AGF_IMAGE_TAG` |

**使用方式**：

```powershell
# 全栈（开发/单机演示）
docker compose up -d --build

# 附带可观测性组件
docker compose --profile clickhouse --profile grafana up -d

# 只起依赖（开发热重载）
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d

# 生产（需 .env.prod）
docker compose -f docker-compose.prod.yml --env-file .env.prod up -d
```

### 网络受限时从项目缓存构建服务镜像

标准 Dockerfile 使用固定的 `rust:1.97-slim` 工具链，不复制宿主机 `rust-toolchain.toml` 的 `stable` 覆盖配置，避免容器内无谓的 rustup 联网检查。若 crates.io 仍不可达，先检查项目的 `.cargo/registry` 是否已有依赖；缺少的依赖只补到项目目录。然后使用只读构建上下文，不把缓存打入运行镜像：

```powershell
cargo fetch --locked --target x86_64-unknown-linux-gnu
docker buildx build --load --pull=false --build-context agf-cargo-cache=./.cargo/registry `
  --build-context agf-upx-cache=./tools/upx/5.2.1 `
  -f deploy/docker/Dockerfile.offline -t aiguardfabric/agf-server:0.1.0 .
docker buildx build --load --pull=false --build-context agf-cargo-cache=./.cargo/registry `
  -f deploy/docker/Dockerfile.scheduler.offline -t aiguardfabric/agf-scheduler:0.1.0 .
docker compose build agf-web
docker compose up -d --no-build agf-server agf-scheduler agf-web
```

`Dockerfile.offline` 构建主服务与 Linux Agent，`Dockerfile.scheduler.offline` 构建调度器与运维 CLI；依赖源以只读挂载供 `cargo build --offline --locked` 使用。没有预备缓存时构建会明确失败，应先用上面的 `cargo fetch` 补齐，而不是改成未锁定版本。此方式不会更改 PostgreSQL、Redis、对象存储或测试数据。
服务器的 UPX 缓存也必须在联网准备阶段预置，离线时可从可信介质复制同一归档并重新校验。仅使用官方 [UPX 5.2.1 Linux amd64 发布](https://github.com/upx/upx/releases/tag/v5.2.1)的原版 `upx-5.2.1-amd64_linux.tar.xz`（664,048 字节），固定 SHA256 为 `402162AAD30AF47E60DBD767FB2E64CA394ACE9727BA1F40283641F1D1B91657`，与[官方发布校验和](https://github.com/upx/upx/releases/expanded_assets/v5.2.1)一致：

```powershell
$upxCache = Join-Path (Get-Location) 'tools/upx/5.2.1'
New-Item -ItemType Directory -Path $upxCache -Force | Out-Null
$upxArchive = Join-Path $upxCache 'upx-5.2.1-amd64_linux.tar.xz'
Invoke-WebRequest -Uri 'https://github.com/upx/upx/releases/download/v5.2.1/upx-5.2.1-amd64_linux.tar.xz' -OutFile $upxArchive
if ((Get-Item -LiteralPath $upxArchive).Length -ne 664048 -or
    (Get-FileHash -LiteralPath $upxArchive -Algorithm SHA256).Hash -cne '402162AAD30AF47E60DBD767FB2E64CA394ACE9727BA1F40283641F1D1B91657') {
    throw 'UPX 官方归档长度或校验和不符，停止构建'
}
$upxTar = Join-Path $upxCache 'upx-5.2.1-amd64_linux.tar'
# 复用既有 Python 标准库，只解压 xz 层；不重新打包，不安装 Python 包。
python -c "import lzma,pathlib,sys; pathlib.Path(sys.argv[2]).write_bytes(lzma.decompress(pathlib.Path(sys.argv[1]).read_bytes()))" $upxArchive $upxTar
if ($LASTEXITCODE -ne 0 -or (Get-Item -LiteralPath $upxTar).Length -ne 829440 -or
    (Get-FileHash -LiteralPath $upxTar -Algorithm SHA256).Hash -cne '2E1FD7577F8DFF116A31A5B55DAA47FEA3F87FB3590AB2046A60A3DFD26FAA5F') {
    throw 'UPX 原始 tar 字节校验失败，停止离线构建'
}
```

标准 Dockerfile 在构建阶段显式安装 `xz-utils`，以固定 HTTPS 地址及 `ADD --checksum` 取得相同归档。离线 Dockerfile 只读挂载 `agf-upx-cache`，同时固定官方 `.tar.xz` 与纯解压所得原始 `.tar` 的 SHA256，再用 `tar -xf` 读取，避免依赖离线工具链未安装的 `xz` 命令；原始 tar 为 829,440 字节，其 SHA256 为 `2E1FD7577F8DFF116A31A5B55DAA47FEA3F87FB3590AB2046A60A3DFD26FAA5F`。两者都仅压缩 `agf-server`，执行 `upx -t` 并解压后与原 ELF 逐字节比较；Linux Agent 与其他服务二进制保持原字节。UPX 工具只存在于构建阶段，运行镜像保留归档内完整 `LICENSE` 与 `COPYING`，路径为 `/app/licenses/UPX-LICENSE.txt`、`/app/licenses/UPX-COPYING.txt`；嵌入的中文字体、OFL 许可证与全部日志夹具照常保留。调度器构建不需要 UPX 上下文。

---

## 4. `.env` 全量变量说明（以 `.env.example` 为准）

`.env.example` 共 324 行、**17 个小节**。下表按小节逐项解释；「代码读取」列指明该变量是否真的被 Rust 代码消费
（这是部署排障的关键——**未读取的变量改了不会有任何效果**）。

### 4.1 §0 路径纪律

| 变量 | 默认值 | 说明 | 代码读取 |
|---|---|---|---|
| `AGF_PROJECT_ROOT` | `<项目根>` | 项目根（唯一可写区） | ✅ `AppConfig::project_root` |
| `AGF_ENV_ROOT` | 见 `.env.example` | 本机既有**只读**工具链根 | ❌ 仅脚本用（`env.ps1:98`） |
| `AGF_TOOLS_DIR` | `<项目根>/tools` | 项目内安装的 CLI | ❌ 仅脚本用（`env.ps1:94`） |
| `AGF_DATA_DIR` | `<项目根>/data` | 运行期数据卷（bind mount 到容器） | ✅ `AppConfig::data_dir` |
| `AGF_VENDOR_DIR` | `<项目根>/vendor` | 离线依赖/二进制 | ❌ 仅脚本用 |
| `AGF_MODELS_DIR` | `<项目根>/models` | 本地模型（可选） | ❌ 仅脚本用 |

> ⚠️ **`.env.example` 里这几个变量是绝对路径**（如 `AGF_PROJECT_ROOT=D:/GeneralTools/...`）。
> 铁律 4 要求脚本不硬编码绝对路径、路径一律从 `.env` 注入，因此迁移项目时**必须同步修改 `.env`**；
> 也可删除这些行让 `env.ps1` 用相对推导（`env.ps1:45` 从 `$PSScriptRoot\..` 推导项目根）。

### 4.2 §1 运行模式

| 变量 | 默认 | 说明 | 代码读取 |
|---|---|---|---|
| `AGF_MOCK_MODE` | `1` | `1` = 全部外部依赖走 Mock/回放（离线可演示）；`0` = 允许真实外部调用 | ✅ `AppConfig::mock_mode`（常量 `ENV_MOCK_MODE`）；网关 `mock_mode_enabled()`（接受 `1`/`true`/`yes`）；阿里云 `mock_mode_from_env()`（接受 `1`/`true`/`yes`/`on`） |
| `AGF_ENV` | `dev` | `dev` / `test` / `prod`（也接受 `development` / `testing` / `ci` / `production`） | ✅ `RunEnv::parse` — 生产环境触发更严格的安全校验 |
| `AGF_LOG_LEVEL` | `info` | `debug` / `info` / `warn` / `error` | ✅ 注入 `RUST_LOG` |
| `AGF_LOG_FORMAT` | `pretty` | `pretty`（`text` 亦可）/ `json` | ✅ `LogFormat` — **compose 的 `x-common-env` 覆盖为 `json`**，`.prod.yml` 固定 `json` |
| `AGF_DEGRADE_ON_MISSING` | `1` | 缺失外部依赖时降级而非报错 | ✅ `AppConfig::degrade_on_missing` |

### 4.3 §2 服务监听

| 变量 | 默认 | 说明 | 代码读取 |
|---|---|---|---|
| `AGF_SERVER_HOST` | `0.0.0.0` | API 主机 | ✅ `ServerConfig::host` |
| `AGF_SERVER_PORT` | `8080` | API 端口 | ✅ `ServerConfig::port` |
| `AGF_WEB_PORT` | `8081` | 控制台宿主机端口（容器内 nginx 监听 8080） | ❌ 仅 compose |
| `AGF_INGEST_HOST` | `0.0.0.0` | 接入服务主机 | ❌ compose 直接注入 |
| `AGF_INGEST_PORT` | `8090` | 接入服务端口 | ✅ `ServerConfig::ingest_port` |
| `AGF_SYSLOG_TCP_PORT` | `5514` | Syslog TCP（514 需特权，开发用 5514） | ✅ `ServerConfig::syslog_tcp_port` |
| `AGF_SYSLOG_UDP_PORT` | `5514` | Syslog UDP | ✅ `ServerConfig::syslog_udp_port` |
| `AGF_MCP_PROXY_PORT` | `8091` | MCP 代理监听 | ✅ `ServerConfig::mcp_proxy_port` |
| `AGF_MCP_PROXY_HOST_PORT` | `8092` | Compose 宿主机 MCP 代理映射 | ❌ 仅 Compose |
| `AGF_METRICS_PORT` | `9100` | Prometheus 指标 | ✅ `ServerConfig::metrics_port` |
| `AGF_API_PREFIX` | `/api/v1` | 指标/健康检查基路径 | ✅ `ServerConfig::api_prefix` |

> 另有**未在 `.env.example` 列出但被代码读取**的变量：
> `AGF_MAX_BODY_BYTES`（默认 16 MiB，`ServerConfig::max_body_bytes`）、
> `AGF_PG_CONNECT_TIMEOUT_SECS`（默认 10）、`AGF_FINGERPRINT_SALT`、`AGF_REDIS_PREFIX`（默认 `agf`）、
> `AGF_LLM_KEY_<CREDID>`（网关凭据）、`AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_SESSION_TOKEN`（Bedrock）、
> `AGF_SCHEDULER_BACKEND`（compose 注入，dev `local-cron` / prod `schedulerx3`）。

### 4.4 §3 数据库

| 变量 | 默认 | 说明 | 代码读取 |
|---|---|---|---|
| `AGF_PG_HOST` | `127.0.0.1` | 主机（容器内为 `postgres`） | ✅ |
| `AGF_PG_PORT` | `5432` | 端口 | ✅ |
| `AGF_PG_DB` | `aiguardfabric` | 库名 | ✅ |
| `AGF_PG_USER` | `agf` | 用户 | ✅ |
| `AGF_PG_PASSWORD` | `CHANGE_ME_dev_only_password` | 口令。**compose 用 `${AGF_PG_PASSWORD:?}` 强制要求**；`init-env.ps1` 随机生成；生产为占位/弱口令时 `enforce_safety()` **拒绝启动** | ✅ |
| `DATABASE_URL` | 由上面拼出 | SQLx 连接串（供 `agfctl migrate` / sqlx-cli 使用） | ✅ 有读取方：`agf-cli`（`migrate`/`db check-schema`/`backup`/`restore`）与 `agf-storage`（优先 `DATABASE_URL`，其次回退 `AGF_PG_*`） |
| `AGF_PG_POOL_MAX` | `20`（prod 默认 50） | 连接池上限 | ✅ |
| `AGF_PG_POOL_MIN` | `2` | 连接池下限 | ✅ |

**其他 PG 相关**：`AGF_PG_HOST_PORT`（compose 宿主机映射端口，默认 5432）、`AGF_PG_CONNECT_TIMEOUT_SECS`。
**连接池行为**：`acquire_timeout` = `AGF_PG_CONNECT_TIMEOUT_SECS`；`idle_timeout` 600s；`max_lifetime` 1800s；
`test_before_acquire(true)`；`application_name = "aiguardfabric"`；`statement_cache_capacity = 256`；
`ssl_mode`：`AGF_ENV=prod` → `VerifyFull`，否则 `Prefer`（`agf-storage/src/config.rs:111` → `db.rs:51`）。

### 4.5 §4 Redis

| 变量 | 默认 | 说明 | 代码读取 |
|---|---|---|---|
| `AGF_REDIS_URL` | `redis://127.0.0.1:6379/0` | 连接 URL | ✅ |
| `AGF_REDIS_PREFIX`（未列出） | `agf` | 键前缀（多租户共用实例时隔离） | ✅ |
| `AGF_REDIS_HOST_PORT`（未列出） | `6379` | 宿主机映射端口 | ❌ 仅 compose |
| `AGF_SHARED_RATELIMIT_REQUIRED` | 单机 Compose 默认 `false`；Helm 始终设为 `true` | 要求跨实例共享三级限流；Redis 启动时缺失则业务请求和 `/readyz` 返回 503 | ✅ |

Redis 连接成功时，API 的全局、租户与认证主体三级令牌桶使用服务端时间和单个 Lua 脚本原子判断、扣减；被拒绝的请求不会消耗其它维度。运行中 Redis 失败返回 503，不退回每副本独立额度。单机离线或未连接 Redis 且未开启强制共享时使用进程内令牌桶；多副本部署须保持上述强制开关。

> ⚠️ compose 的 redis 命令**没有设置 `requirepass`**（`docker-compose.yml:116-125`）。
> 生产必须启用认证并把 6379 放到私网。详见 [`docs/threat-model.md`](threat-model.md) R4。

### 4.6 §5 NATS

| 变量 | 默认 | 说明 | 代码读取 |
|---|---|---|---|
| `AGF_NATS_ENABLED` | `1` | 开启控制台 `/ws` 跨副本事件面及数据库事件出站队列；连接失败时 `/ws` 降级为本机广播，未投递事件保留在 SQL 队列 | ✅ |
| `AGF_NATS_URL` | `nats://127.0.0.1:4222` | 核心 NATS 和 JetStream 的连接 URL | ✅ |
| `AGF_NATS_STREAM` | `AGF_EVENTS` | 数据库事件出站和分析任务使用的 JetStream 流；`/ws` 即时事件走独立的 `agf.ws.>` 主题 | ✅ |
| `AGF_NATS_HOST_PORT` / `AGF_NATS_MONITOR_PORT`（未列出） | `4222` / `8222` | 宿主机映射 | ❌ 仅 compose |

> `/ws` 的即时通知使用核心 NATS 主题；服务端持久 SQL 出站队列、事件分析与 ingest 入向订阅使用 JetStream。ingest 订阅需单独设置 `AGF_INGEST_JETSTREAM_URL` 等变量，`/readyz` 能力矩阵会显示 `nats-jetstream`。不可把 `/ws` 本机降级视为跨副本事件仍然可见。
> 详见 [`docs/pending-verification.docs.md`](pending-verification.docs.md) DOC-PV-029 相关与 `docs/architecture.md` §3.1。

### 4.7 §6 ClickHouse（可选冷热分层）

| 变量 | 默认 | 说明 | 代码读取 |
|---|---|---|---|
| `AGF_CLICKHOUSE_ENABLED` | `0` | 是否启用 | ✅ `ClickHouseConfig::enabled` |
| `AGF_CLICKHOUSE_URL` | `http://127.0.0.1:8123` | HTTP 端点 | ✅ |
| `AGF_CLICKHOUSE_DB` | `agf` | 库名 | ✅ |
| `AGF_CLICKHOUSE_USER` | `default` | 用户 | ✅ |
| `AGF_CLICKHOUSE_PASSWORD` | 空 | 口令 | ✅ |
| `AGF_CLICKHOUSE_HOST_PORT` / `AGF_CLICKHOUSE_NATIVE_PORT`（未列出） | `8123` / `9000` | 宿主机映射 | ❌ 仅 compose |

> **降级**：`events` 表在 TimescaleDB 扩展不可用时**退化为普通表**（迁移 `0001_init_01.sql:18-29` 捕获异常并 `RAISE NOTICE`），功能降级但可用。

### 4.8 §7 对象存储

| 变量 | 默认 | 说明 | 代码读取 |
|---|---|---|---|
| `AGF_S3_ENDPOINT` | `http://127.0.0.1:9000` | 端点（MinIO / OSS / AWS S3） | ✅（**为空即降级本地目录**） |
| `AGF_S3_REGION` | `us-east-1` | 区域 | ✅ |
| `AGF_S3_BUCKET` | `agf-evidence` | 桶名 | ✅ |
| `AGF_S3_ACCESS_KEY` | `agfminio` | Access Key | ✅ |
| `AGF_S3_SECRET_KEY` | `CHANGE_ME_dev_only_secret` | Secret Key（compose `${...:?}` 强制） | ✅ |
| `AGF_S3_FORCE_PATH_STYLE` | `1` | MinIO 需要 path-style | ✅ |
| `AGF_MINIO_PORT` / `AGF_MINIO_CONSOLE_PORT` / `MINIO_BROWSER_REDIRECT_URL` / `MINIO_MC_IMAGE`（未列出） | `9000` / `9001` / — / `quay.io/minio/mc:latest` | compose 侧 | ❌ 仅 compose |

**三级自动降级**：S3 配置齐全 → `S3ObjectStore`；否则 → `LocalFileObjectStore`（`<data_dir>/objects`）；再失败 → `MemoryObjectStore`。
**桶初始化**：`minio-init` 一次性任务创建 `agf-evidence`、`agf-raw-logs`、`agf-reports`，并对 `agf-evidence` 执行 `mc anonymous set none`。

### 4.9 §8 安全：JWT / 主密钥 / 引导管理员

| 变量 | 默认 | 说明 | 代码读取 |
|---|---|---|---|
| `AGF_JWT_SECRET` | `CHANGE_ME_...` | JWT 签名密钥，**≥32 字节**；`selfcheck.ps1` 检查长度；生产占位/过短 → 拒绝启动 | ✅ |
| `AGF_JWT_ACCESS_TTL_SECS` | `3600` | 访问令牌有效期 | ✅ |
| `AGF_JWT_REFRESH_TTL_SECS` | `259200`（7 天） | 刷新令牌有效期 | ✅ |
| `AGF_JWT_ISSUER` | `aiguardfabric` | 签发者 | ✅ |
| `AGF_MASTER_KEY_BASE64` | `CHANGE_ME_base64_32_bytes` | **数据加密主密钥，base64 编码恰好 32 字节**（AES-256）；生产未配置 → 拒绝启动 | ✅ |
| `AGF_KMS_BACKEND` | `local-file` | `none` / `local-file` / `aliyun-kms`（也接受 `kms` / `aws-kms` / `vault` / `mock`，未知值回落 `local-file`） | ✅ `parse_key_backend` |
| `AGF_KMS_KEY_ID` | 空 | KMS 密钥 id | ✅（prod compose 注入） |
| `AGF_BOOTSTRAP_ADMIN_USER` | `admin` | 引导管理员用户名 | ✅ |
| `AGF_BOOTSTRAP_ADMIN_EMAIL` | `admin@aiguardfabric.local` | 邮箱 | ✅ |
| `AGF_BOOTSTRAP_ADMIN_PASSWORD` | 空 | 留空 = 首启随机生成并写入 `data/seed/bootstrap-admin.txt`（0600）。**实践中 `init-env.ps1` 会直接写入 48 字符随机口令，不会走到"留空"分支** | ✅ |
| `AGF_FORCE_PASSWORD_CHANGE` | `1` | 强制首登改密（安全基线，不建议关闭） | ✅ |
| `AGF_PASSWORD_MIN_LENGTH` | `12` | 口令最小长度 | ✅ |
| `AGF_PASSWORD_REQUIRE_CLASSES` | `1` | 是否要求字符类别 | ❌ **无代码读取**（`SecurityConfig` 无该字段） |
| `AGF_LOGIN_MAX_FAILURES` | `5` | 登录失败锁定阈值 | ✅ |
| `AGF_LOGIN_LOCKOUT_SECS` | `900` | 锁定持续秒数 | ✅ |
| `AGF_FINGERPRINT_SALT`（未列出） | `aiguardfabric-default-salt-change-in-prod` | 凭据指纹盐 | ✅ |

**生产环境安全校验（`AppConfig::enforce_safety()`）**——以下任一项不满足即 **拒绝启动**：

| 检查项 | 判定 |
|---|---|
| JWT 密钥 | `len >= 32 && !contains("change_me")`（大小写不敏感） |
| 主密钥 | 非空、非 `change_me`、base64 解码后**恰好 32 字节** |
| 数据库口令 | 非空、不含 `change_me`/`changeme`/`password`、长度 ≥ 12 |
| 强制改密 | `AGF_FORCE_PASSWORD_CHANGE` 必须为真 |
| 引导管理员 | 用户名 `admin` 且显式设置了口令 → 警告"请改为随机生成" |
| Mock 模式 | 生产仍开 `AGF_MOCK_MODE` → 警告"所有外部适配器返回模拟数据" |

开发环境（`AGF_ENV=dev`）下这些只产出**警告列表**，不阻塞启动。

### 4.10 §9 多租户与配额

| 变量 | 默认 | 说明 | 代码读取 |
|---|---|---|---|
| `AGF_DEFAULT_TENANT_ID` | `00000000-0000-0000-0000-000000000001` | 默认租户 id（与迁移种子一致） | ❌ **无代码读取**（迁移中硬编码同一 uuid） |
| `AGF_DEFAULT_TENANT_SLUG` | `default` | 默认租户 slug | ❌ 无代码读取 |
| `AGF_TENANT_PHYSICAL_ISOLATION` | `0` | 是否物理隔离 | ❌ 无代码读取（`tenants.isolation` 字段已预留） |
| `AGF_QUOTA_TENANT_TOKENS_PER_DAY` | `5000000` | 租户每日 token | ✅ `QuotaDefaults` |
| `AGF_QUOTA_AGENT_TOKENS_PER_DAY` | `500000` | Agent 每日 token | ✅ |
| `AGF_QUOTA_SESSION_TOKENS` | `100000` | 会话 token | ✅ |
| `AGF_QUOTA_TENANT_REQ_PER_MIN` | `6000` | 租户每分钟请求数 | ✅（同时映射为 `SecurityConfig::tenant_rate_per_5min`） |

### 4.11 §10 大模型厂商凭据

**7 个策略项 + 15 个上游**。⚠️ **本小节所有变量在 Rust 代码中零引用**（`agf-core/src/config.rs` 的 `AppConfig` 无 LLM 配置段），
即**改这些值不会影响任何运行行为**。实际接入请使用“模型网关 → 模型接入配置”，在当前租户中填写厂商、模型 ID、Base URL 和加密凭据；按 [模型操作指南](model-usage-guide.md) 试调用。不要在这些未读取的变量中填真实密钥。

| 变量组 | 内容 |
|---|---|
| 策略 | `AGF_LLM_DEFAULT_PROVIDER`（`mock`）、`AGF_LLM_DEFAULT_MODEL`（`mock-analyst-1`）、`AGF_LLM_ROUTING_STRATEGY`（`cost-first`）、`AGF_LLM_REQUEST_TIMEOUT_SECS`（`60`）、`AGF_LLM_MAX_RETRIES`（`2`）、`AGF_LLM_SEMANTIC_CACHE`（`1`）、`AGF_LLM_PRESCREEN`（`1`） |
| OpenAI | `AGF_OPENAI_BASE_URL` / `AGF_OPENAI_API_KEY` / `AGF_OPENAI_ORG` |
| Anthropic | `AGF_ANTHROPIC_BASE_URL` / `AGF_ANTHROPIC_API_KEY` / `AGF_ANTHROPIC_VERSION` |
| Gemini | `AGF_GEMINI_BASE_URL` / `AGF_GEMINI_API_KEY` |
| Azure OpenAI | `AGF_AZURE_OPENAI_ENDPOINT` / `_API_KEY` / `_API_VERSION` / `_DEPLOYMENT` |
| Bedrock | `AGF_BEDROCK_REGION` / `AGF_BEDROCK_ACCESS_KEY_ID` / `AGF_BEDROCK_SECRET_ACCESS_KEY` |
| 百炼/通义 | `AGF_DASHSCOPE_BASE_URL` / `AGF_DASHSCOPE_API_KEY` |
| 火山方舟/豆包 | `AGF_ARK_BASE_URL` / `AGF_ARK_API_KEY` |
| 腾讯混元 | `AGF_HUNYUAN_BASE_URL` / `AGF_HUNYUAN_API_KEY` |
| 百度文心 | `AGF_QIANFAN_BASE_URL` / `AGF_QIANFAN_API_KEY` |
| Kimi | `AGF_MOONSHOT_BASE_URL` / `AGF_MOONSHOT_API_KEY` |
| DeepSeek | `AGF_DEEPSEEK_BASE_URL` / `AGF_DEEPSEEK_API_KEY` |
| 智谱 GLM | `AGF_ZHIPU_BASE_URL` / `AGF_ZHIPU_API_KEY` |
| MiniMax | `AGF_MINIMAX_BASE_URL` / `AGF_MINIMAX_API_KEY` |
| 本地推理 | `AGF_OLLAMA_BASE_URL` / `AGF_VLLM_BASE_URL` |

**实际被代码读取的 LLM 凭据方式**：`AGF_MOCK_MODE`、`AGF_LLM_KEY_<CREDID>`（`credential_ref` 的 `-` 去掉后大写，
`provider.rs:187`）、`AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_SESSION_TOKEN`（Bedrock）。
`default_base_url()` 为**全部 17 个 `LlmProvider` 变体**给出默认地址（含 Azure 的 `YOUR-RESOURCE` / `YOUR-DEPLOYMENT` 占位）。

### 4.12 §11 阿里云 AgentTeams 与五底座服务

| 变量 | 默认 | 说明 | 代码读取 |
|---|---|---|---|
| `AGF_ALIYUN_ENABLED` | `0` | 总开关 | ❌ 无代码读取（按服务分别配置 `AdapterConfig`） |
| `AGF_ALIYUN_REGION_ID` | `cn-hangzhou` | 地域（**非法值会被 `from_configs` 拒绝**） | ⚠️ 经 `AdapterConfig.settings.region_id` |
| `AGF_ALIYUN_ACCESS_KEY_ID` / `_SECRET` | 空 | 长期 AK（**不推荐**） | ⚠️ 经 `EnvResolver`（前缀 `AGF_ALIYUN_`） |
| `AGF_ALIYUN_STS_TOKEN` / `_EXPIRE` | 空 | STS 临时凭据（优先） | ⚠️ 经 `EnvResolver` |
| `AGF_ALIYUN_ASSUME_ROLE_ARN` | 空 | 跨账号 AssumeRole | ⚠️ 经 `AssumeRoleResolver::require_role_arn`（**真实调用未实现**） |
| `AGF_ALIYUN_ROLE_SESSION_NAME` | `agf-cross-account` | 会话名（`sanitize_session_name` 会净化） | ⚠️ 同上 |
| `AGF_ALIYUN_ENDPOINT_CMS` / `_APIG` / `_MSE` / `_PRIVATELINK` / `_SCHEDULERX3` / `_AGENTTEAMS` | 空 | 各服务 endpoint（留空用 SDK 默认；Privatelink 场景填私网 endpoint） | ⚠️ 经 `AdapterConfig.settings` |
| `AGF_ALIYUN_SCHEDULERX3_NAMESPACE` | 空 | SchedulerX3 命名空间 | ⚠️ 同上 |
| `AGF_ALIYUN_SCHEDULERX3_GROUP` | `agf` | 分组 | ⚠️ 同上 |
| `AGF_ALIYUN_APIG_INSTANCE_ID` / `_GATEWAY_ID` | 空 | APIG 实例与网关 | ⚠️ 同上 |
| `AGF_ALIYUN_MSE_NAMESPACE` | 空 | MSE 命名空间 | ⚠️ 同上 |
| `AGF_ALIYUN_PRIVATELINK_ENDPOINT_ID` | 空 | PrivateLink 终端节点 | ⚠️ 同上 |
| `AGF_ALIYUN_AGENTTEAMS_TEAM_ID` | 空 | AgentTeams 团队 id | ⚠️ 同上 |

> **凭据优先级**：RAM Role / STS > 临时凭据 > 长期 AK。**禁止长期 AK 明文落盘**（`.env.example:213` 原话建议改用 `agfctl secret set` 写库，但该子命令未实现）。
> **无云凭据时**：六适配器全部走确定性 Mock，平台主流程不受影响。详见 [`docs/adapter-spec.md`](adapter-spec.md) §5.1。

### 4.13 §12 外部告警设备接入

| 变量 | 默认 | 说明 | 代码读取 |
|---|---|---|---|
| `AGF_QINGTENG_ENABLED` | `0` | 青藤云总开关 | ✅ `AppConfig::device_adapters`（13 个开关之一） |
| `AGF_QINGTENG_MCP_URL` / `_API_URL` / `_API_TOKEN` | 空 | 青藤云接入参数 | ❌ **无代码读取** |
| `AGF_ALIYUN_WAF_ENABLED` | `0` | 阿里云 WAF | ✅ |
| `AGF_HUAWEI_WAF_ENABLED` | `0` | 华为云 WAF | ✅ |
| `AGF_HUAWEI_HSS_ENABLED` | `0` | 华为云 HSS | ✅ |
| `AGF_TENCENT_ENABLED` | `0` | 腾讯云 | ✅ |
| `AGF_SANGFOR_ENABLED` | `0` | 深信服 | ✅ |
| `AGF_QIANXIN_ENABLED` | `0` | 奇安信 | ✅ |
| `AGF_NSFOCUS_ENABLED` | `0` | 绿盟 | ✅ |
| `AGF_TOPSEC_ENABLED` | `0` | 天融信 | ✅ |
| `AGF_FORTINET_ENABLED` | `0` | Fortinet | ✅ |
| `AGF_PALOALTO_ENABLED` | `0` | Palo Alto | ✅ |
| `AGF_CROWDSTRIKE_ENABLED` | `0` | CrowdStrike | ✅ |
| `AGF_WAZUH_ENABLED` | `0` | Wazuh | ✅ |

> **13 个开关全部被 `AppConfig::device_adapters` 解析**（`agf-core/src/config.rs:570-587`，`device_adapters.len() == 13` 有测试断言），
> 可用 `AppConfig::adapter_enabled(name)` 查询，并由 `/api/v1/settings` 与 `/api/v1/integrations/adapters` 如实投影。
> **但没有任何适配器实现读取它们**：`crates/agf-adapters` 的 11 个内置适配器（`feishu`/`dingtalk`/`wecom`/
> `email`/`webhook`/`slack`/`jira`/`servicenow`/`zentao`/`syslog-forwarder`/`edr-isolation`）**均有真实传输**，
> 但它们从 `AdapterConfig.settings` 取参、注册名也与这 13 个设备开关不对应 ⇒ 开这 13 个开关**不会**启用任何适配器。
> 设备接入的可行方式是让设备通过 **Syslog / Webhook 转发**到 `agf-ingest`（`parsers/` 已内置 117 个模板）。

### 4.14 §13 南向采集网关

| 变量 | 默认 | 说明 | 代码读取 |
|---|---|---|---|
| `AGF_COLLECTOR_ENABLED` | `0` | 是否启用采集器 | ❌ 无代码读取（客户端由 `agf-agent` 二进制按 `AGF_AGENT_*` 配置） |
| `AGF_COLLECTOR_MTLS_CA` | 空 | mTLS CA | ⚠️ 校验逻辑在 `agf-ingest/src/receiver.rs`（`CollectorUplinkAuth`）；**客户端侧**改用 `AGF_AGENT_TLS_CA`（`agf-agent` 的 `client::TlsConfig`） |
| `AGF_COLLECTOR_CERT` | 空 | 客户端证书 | ⚠️ 同上（客户端侧为 `AGF_AGENT_TLS_CERT`） |
| `AGF_COLLECTOR_KEY` | 空 | 客户端私钥 | ⚠️ 同上（客户端侧为 `AGF_AGENT_TLS_KEY`） |
| `AGF_COLLECTOR_UPLINK` | `https://127.0.0.1:8090/api/v1/ingest/agent` | 上行地址 | ✅ **端点已注册**（`crates/agf-api/src/routes/ingest/agent.rs`，`POST /api/v1/ingest/agent`）：mTLS 证书身份（入口网关透传 `X-SSL-Client-Verify` + `X-SSL-Client-Cert` / `X-AGF-Client-Cert-Der`）或 Bearer / `X-AGF-Key`；载荷交给既有 `agf-ingest` 流水线，响应与 webhook 同口径；证书主体 → 角色/租户由 `AGF_AGENT_MTLS_MAP` 显式映射，**无映射即 403**（不默认全权） |
| `AGF_COLLECTOR_INTERVAL_SECS` | `30` | 上报间隔 | ⚠️ 客户端侧为 `AGF_AGENT_HEARTBEAT_SECS`（`agf-agent`） |

> 采集器上行的真机端到端（自签 PKI + mTLS 终结器 + 采集器上行 + 幂等重放）：
> `powershell -File tools/simulators/run_agent_mtls_e2e.ps1`（只起本机进程，不动 compose 容器）。

### 4.15 §14 通知渠道

| 变量 | 默认 | 说明 | 代码读取 |
|---|---|---|---|
| `AGF_NOTIFY_DINGTALK_WEBHOOK` | 空 | 钉钉机器人 | ❌ 无代码读取 |
| `AGF_NOTIFY_FEISHU_WEBHOOK` | 空 | 飞书机器人 | ❌ |
| `AGF_NOTIFY_WECOM_WEBHOOK` | 空 | 企业微信机器人 | ❌ |
| `AGF_NOTIFY_SMTP_HOST` / `_PORT`（`587`）/ `_USER` / `_PASSWORD` / `_FROM` | 空 | 邮件 | ❌ 无代码读取（适配器从 `AdapterConfig.settings` 取参；env→settings 接线见 `TODO(adapter-email-env-wiring)`） |
| `AGF_NOTIFY_SMTP_TO` / `_SECURITY`（`starttls`）/ `_SUBJECT_PREFIX` / `AGF_ADAPTER_EMAIL_SMTP_PASSWORD` | 空 / `starttls` / `[AIGuardFabric]` | 邮件（补充项） | ❌ 同上（**变量名已登记，尚未接线**） |
| `AGF_NOTIFY_PAGERDUTY_KEY` | 空 | PagerDuty | ❌ |
| `AGF_NOTIFY_GENERIC_WEBHOOK` | 空 | 通用 Webhook | ❌ |

> 通知的**模型与模板渲染已实现**（`agf-core/src/notify.rs`，支持 `{{title}}` / `{{severity}}` 占位符，未知占位符保留原样），
> `POST /api/v1/notifications/send` 走 `NotificationDispatcher` 的完整决策链（去重/维护窗/限流/退避）。
> **`email` 适配器已实现真实 SMTP 投递**（`lettre`，真实 `EHLO`/`STARTTLS`/`AUTH`/`DATA`），
> 但它读取的是适配器设置（`smtp_host`/`from`/…），**不读上面这些 `AGF_NOTIFY_*` 环境变量**；
> 企业侧要走环境变量供参需等 env→`AdapterConfig.settings` 接线落地（`TODO(adapter-email-env-wiring)`）。

### 4.16 §15 可观测性

| 变量 | 默认 | 说明 | 代码读取 |
|---|---|---|---|
| `AGF_OTEL_ENABLED` | `0` | 是否启用 OTLP | ✅ `ObservabilityConfig::otel_enabled` |
| `AGF_OTEL_ENDPOINT` | `http://127.0.0.1:4318` | OTLP 端点 | ✅ |
| `AGF_OTEL_SERVICE_NAME` | `agf-server` | 服务名 | ✅ |
| `AGF_PROMETHEUS_ENABLED` | `1` | 是否启用 Prometheus | ✅ |
| `AGF_GRAFANA_ENABLED` | `0` | Grafana 开关 | ❌ 无代码读取（靠 compose profile） |
| `AGF_GRAFANA_ADMIN_PASSWORD` | `CHANGE_ME_dev_only_grafana` | Grafana 管理员口令（compose `${...:?}` 强制，**仅 `--profile grafana` 时校验**） | ❌ 仅 compose |
| `AGF_GRAFANA_PORT`（未列出） | `3000` | 宿主机映射 | ❌ 仅 compose |

> **当前状态**：配置项与依赖（`tracing-opentelemetry` / `opentelemetry-otlp` / `metrics-exporter-prometheus`）齐备，
> 但 `/metrics` 端点与 OTLP exporter **未在代码中暴露**（`*.rs` 中 grep `/metrics` 零命中）。
> Grafana 的 `deploy/grafana/provisioning/` 与 `deploy/grafana/dashboards/` 已存在（datasources.yaml、dashboards.yaml、01-platform-overview.json）。

### 4.17 §16 前端（Vite）

| 变量 | 默认 | 说明 |
|---|---|---|
| `VITE_API_BASE_URL` | `http://127.0.0.1:8080` | API 基地址（**空串 = 同源 `/api`**，走 Vite dev 代理或 nginx 反代） |
| `VITE_WS_BASE_URL` | `ws://127.0.0.1:8080` | WebSocket 基地址。⚠️ 前端**没有任何 WebSocket 客户端代码**（grep 仅命中 MCP transport 枚举与 i18n 文案） |
| `VITE_DEFAULT_LOCALE` | `zh-CN` | 默认语言（`zh-CN` / `en-US`） |
| `VITE_APP_TITLE` | `AIGuardFabric 智御矩阵` | 应用标题 |

> **未在 `.env.example` 列出但前端读取的变量**：`VITE_FORCE_DEMO`（`=true` 强制演示模式）、
> `VITE_API_TIMEOUT_MS`（默认 2500）。见 `apps/web/src/api/client.ts:84-91` 与 `apps/web/README.md`。
> **演示降级规则**：`status >= 500 || status === 404` 才回退；**401/403/422 等 4xx 不回退而是抛出**（有意设计，鉴权失败不被演示数据掩盖）。

### 4.18 §17 测试与门禁

| 变量 | 默认 | 说明 | 代码读取 |
|---|---|---|---|
| `AGF_COVERAGE_MIN` | `70` | 覆盖率下限 | ❌ 仅脚本（`coverage.ps1` 不存在） |
| `AGF_FIXTURE_LIVE_FETCH` | `0` | 是否允许联网抓夹具 | ❌ 仅脚本 |
| `AGF_REPLAY_DIR` | `<项目根>/tests/replay` | 回放目录 | ❌ 无代码读取 |
| `AGF_REDTEAM_CASE_DIR` | `<项目根>/redteam` | 红队用例目录 | ❌ **无 Rust 读取方**（`CaseLibrary::load_dir(root)` 需调用方显式传路径；`init-env.ps1:203` 写入该键） |
| `AGF_RULES_DIR` | `<项目根>/rules` | 规则目录 | ❌ **无 Rust 读取方**（`RulePackLoader::load_dir(&RulesDir)` 需调用方显式传路径；`init-env.ps1:204` 写入该键） |

### 4.19 镜像版本（仅 compose 使用）

| 变量 | 默认 |
|---|---|
| `AGF_IMAGE_TAG` | `0.1.0` |
| `AGF_IMAGE_PREFIX`（未列出） | `aiguardfabric` |
| `POSTGRES_IMAGE` | `timescale/timescaledb:latest-pg16` |
| `REDIS_IMAGE` | `redis:7.4-alpine` |
| `NATS_IMAGE` | `nats:2.10-alpine` |
| `CLICKHOUSE_IMAGE` | `clickhouse/clickhouse-server:24.8-alpine` |
| `MINIO_IMAGE` | `quay.io/minio/minio:latest` |
| `GRAFANA_IMAGE` | `grafana/grafana:11.4.0` |

---

## 5. 数据卷：bind mount 到 `<项目根>/data/`

**全部**数据卷都是 bind mount，**不使用匿名卷**（铁律：`docker compose down -v` 可完全清理，但宿主机目录内容不会被删）。

| 宿主路径 | 容器路径 | 归属 | 服务 |
|---|---|---|---|
| `${AGF_DATA_DIR}/pg` | `/var/lib/postgresql/data` | 数据库 | postgres |
| `${AGF_DATA_DIR}/redis` | `/data` | Redis AOF/RDB | redis |
| `${AGF_DATA_DIR}/nats` | `/data` | JetStream 存储 | nats |
| `${AGF_DATA_DIR}/clickhouse` | `/var/lib/clickhouse` | 列存 | clickhouse |
| `${AGF_DATA_DIR}/minio` | `/data` | 对象数据 | minio |
| `${AGF_DATA_DIR}/grafana` | `/var/lib/grafana` | Grafana | grafana |
| `${AGF_DATA_DIR}/evidence` | `/data/evidence` | 证据包 | agf-server / agf-ingest |
| `${AGF_DATA_DIR}/backup` | `/backup` | 备份产物 | backup sidecar（仅 prod） |
| `${AGF_DATA_DIR}/seed` | — | 引导凭据 / 演示数据 | 脚本 |

**目录自动创建**：`scripts/init-env.ps1` 的第 4/4 步创建这 9 个目录 + `.gitkeep`；
`scripts/selfcheck.ps1` 在统计占用时也会顺手创建缺失目录。

**只读挂载（额外）**：

| 宿主 | 容器 | 服务 | 说明 |
|---|---|---|---|
| `./rules` | `/app/rules:ro` | agf-server / agf-ingest / agf-scheduler | 规则热更新的落点；默认 54 条 YAML 规则 |
| `./deploy/sql/migrations` | `/app/deploy/sql/migrations:ro` | agf-server | 后续迁移文件；应用实际使用编译时内嵌的完整迁移集 |
| `./rules` | `/app/rules:ro` | （prod）agf-server / agf-scheduler | 同上 |
| `${AGF_DATA_DIR}/evidence` | `/data/evidence` | （prod）agf-server | 只读根文件系统下的唯一可写业务路径 |

---

## 6. 首次启动：迁移与管理员

### 6.1 迁移的两条路径

| 路径 | 触发方式 | 行为 |
|---|---|---|
| **应用 SQLx 迁移** | 服务启动时 `Database::migrate()`；手动运行 `agfctl migrate` | 幂等、仅向前。历史 0001 从 `deploy/sql/migration_parts/` 的四个文件按原字节合并，其 SHA-384 与线上已应用版本一致；后续版本从 `deploy/sql/migrations/` 内嵌 |
| **PostgreSQL 自定义 initdb** | 可选的数据库初始化配置 | 仅放数据库级自定义 SQL；不要在这里执行应用迁移，否则会出现“表已建、SQLx 版本表为空”的双写状态 |

> ⚠️ `/docker-entrypoint-initdb.d` 只在数据目录为空时执行，不是应用迁移入口。已有数据库只接受校验和一致的历史版本和新增的后续版本；不要修改四个 0001 分片的合并字节。普通部署由服务启动迁移，手动操作用 `agfctl migrate`；显式指定默认目录也使用相同内嵌迁移集，其它 `--dir` 仅用于包含完整迁移集的自定义目录。详见[迁移说明](migration-layout.md)。
> ⚠️ 迁移的**执行者**（`Database::migrate()`）在 `agf-server` 启动时调用（**已实测**：容器实测
> `/healthz` → `mode:"database"`、`/readyz` → `degraded:false`，PV-001），`agfctl migrate` 亦可用；
> 期间修复过一个真实硬伤：迁移里保留字 `window` 未加引号导致**迁移第 1 条语句即失败**，以及
> initdb 与 sqlx **重复执行迁移**的问题（PV-001）。

### 6.2 种子数据（内嵌 0001 迁移的第 10 节）

| 种子 | 内容 |
|---|---|
| 默认租户 | `id = 00000000-0000-0000-0000-000000000001`、`slug = default`、`isolation = logical`、`default_data_class = internal`、白标 `{"product_name":"AIGuardFabric 智御矩阵","primary_color":"#1677ff","default_locale":"zh-CN"}` |
| 权限点字典 | `permissions`（resource_group + action + code + description） |
| 内置角色 | `roles`（含 `builtin = true` 标记） |
| 资产类型 | `asset_types`（code + display_name + category） |
| 配额默认值 | `quotas`（scope + dimension + window + limit_ + soft_threshold + on_exceed） |

### 6.3 引导管理员与强制改密

| 项 | 事实 |
|---|---|
| 用户名 / 邮箱 | `AGF_BOOTSTRAP_ADMIN_USER=admin` / `AGF_BOOTSTRAP_ADMIN_EMAIL=admin@aiguardfabric.local` |
| 口令来源 | `.env.example` 承诺"留空 = 首启随机生成并写入 `data/seed/bootstrap-admin.txt`（0600），并打日志提示"；**但实践中 `scripts/init-env.ps1` 会直接写入 48 字符随机口令到 `AGF_BOOTSTRAP_ADMIN_PASSWORD`**，因此不会走到"留空"分支 |
| 强制改密 | `AGF_FORCE_PASSWORD_CHANGE=1`（默认）。库层已就绪：`AuthService::change_password`、`LoginOutcome::MustChangePassword`（`agf-auth/src/service.rs`）、`DomainError::PreconditionFailed`（412，"如首登未改密、策略未签名"） |
| ⚠️ 当前状态 | 执行点已落地：`POST /api/v1/auth/login` 实测返回 `must_change_password:true` 且**只发 `change_token`、不发访问令牌**，改密走 `POST /api/v1/auth/change-password`（PV-001 实测） |
| 口令策略 | 最小长度 `AGF_PASSWORD_MIN_LENGTH=12`；`PasswordHasher::check_policy(password, username)`（含用户名相似度检查）；失败锁定 `AGF_LOGIN_MAX_FAILURES=5` / `AGF_LOGIN_LOCKOUT_SECS=900` |

### 6.4 容器 healthcheck（当前状态）

| 服务 | healthcheck 命令 | 状态 |
|---|---|---|
| `postgres` | `pg_isready -U $AGF_PG_USER -d $AGF_PG_DB` | ✅ 可用 |
| `redis` | `redis-cli ping` | ✅ 可用 |
| `nats` | `wget -q -O - http://127.0.0.1:8222/healthz` | ✅ 可用 |
| `minio` | `mc ready local` | ✅ 可用 |
| `agf-server` | `/usr/local/bin/agf-server healthcheck --url http://127.0.0.1:8080/healthz` | ✅ **可用**：`healthcheck` 子命令与 `/healthz` 端点均已实现（探针在配置/日志初始化前短路） |
| `agf-ingest` | `/usr/local/bin/agf-ingest healthcheck --url http://127.0.0.1:8090/healthz` | ✅ **可用**：已由 `wget` 改为自带 `healthcheck` 子命令（distroless runtime 无 `wget`） |
| `agf-scheduler` | `/usr/local/bin/agf-scheduler healthcheck --url http://127.0.0.1:9101/healthz` | ✅ **可用**：同上 |
| `agf-web` | `wget -q -O - http://127.0.0.1:8080/` | ✅ 可用（nginx-unprivileged 有 wget） |

> **结果**：`docker compose up -d` 实测 **8 个容器全部 healthy**（见 PV-001）；
> 此前"`agf-server` / `agf-ingest` / `agf-scheduler` 永久 unhealthy 并在 `restart: unless-stopped` 下反复重启"的缺口已闭环。

---

## 7. 备份与恢复

### 7.1 生产：内置 backup sidecar（已可用）

`docker-compose.prod.yml` 第 182–218 行定义：

| 项 | 值 |
|---|---|
| 镜像 | `${POSTGRES_IMAGE:-timescale/timescaledb:latest-pg16}`（自带 `pg_dump`） |
| 周期 | `AGF_BACKUP_INTERVAL_SECS`，**默认 86400 秒（24 小时）** |
| 命令 | `pg_dump -h $AGF_PG_HOST -p $AGF_PG_PORT -U $AGF_PG_USER -d $AGF_PG_DB --format=custom --compress=6 --file=/backup/agf-<UTC时间戳>.dump` |
| 产物路径 | 容器 `/backup` → 宿主 `${AGF_DATA_DIR}/backup`（bind mount，**宿主可见**） |
| 保留 | **最近 7 份**（`ls -1t /backup/agf-*.dump \| tail -n +8 \| xargs -r rm -f`） |
| 失败行为 | `pg_dump` 失败只打印 `[backup] dump failed` 后继续循环（**不退出、不告警**） |

**手工触发一次备份**：

```powershell
docker compose -f docker-compose.prod.yml --env-file .env.prod exec backup /bin/bash -c `
  'PGPASSWORD="$AGF_PG_PASSWORD" pg_dump -h "$AGF_PG_HOST" -p "$AGF_PG_PORT" -U "$AGF_PG_USER" -d "$AGF_PG_DB" --format=custom --compress=6 --file=/backup/agf-manual.dump'
```

### 7.2 开发：直接使用 pg_dump / pg_restore

```powershell
# 备份（从容器内导出到项目内 data/backup）
docker compose exec -T postgres pg_dump -U $env:AGF_PG_USER -d $env:AGF_PG_DB --format=custom --compress=6 > data\backup\agf-dev.dump

# 恢复
docker compose exec -T postgres pg_restore -U $env:AGF_PG_USER -d $env:AGF_PG_DB --clean --if-exists < data\backup\agf-dev.dump
```

### 7.3 对象存储证据包

| 项 | 事实 |
|---|---|
| 桶 | `agf-evidence`（证据）、`agf-raw-logs`（原始日志归档）、`agf-reports`（报表）—— 由 `minio-init` 创建 |
| 宿主落点 | `${AGF_DATA_DIR}/minio`（MinIO 数据目录直接 bind mount），因此**备份 MinIO 数据即备份对象** |
| 归档对象键 | `agf-events/dt=YYYY-MM-DD/hour=HH/events-<uuid>-<seq>.ndjson.gz`（`coldarchive.rs:135`） |
| 生产 | `AGF_S3_ENDPOINT` 指向外部 OSS/S3；归档对象需按对象存储侧的生命周期策略单独备份 |
| 降级 | 未配置对象存储 → 本地 `<data_dir>/objects`（`LocalFileObjectStore`） |

### 7.4 ⚠️ `scripts/backup.ps1` / `scripts/restore.ps1` 不存在

`Justfile:152-156` 定义了 `just backup` / `just restore <file>`，分别调用 `scripts/backup.ps1` 与 `scripts/restore.ps1`，
但**这两个脚本当前不存在**（`scripts/` 下实有：`env.ps1`、`lib.ps1`、`init-env.ps1`、`selfcheck.ps1`、
`gen-fixtures.ps1`、`fetch-fixtures.ps1`、`seed.ps1`、`demo.ps1`、`_probe.ps1`）。
在它们落地前请使用 §7.1 / §7.2 的直接命令。详见 [`docs/pending-verification.docs.md`](pending-verification.docs.md) DOC-PV-008。

---

## 8. Helm（`deploy/helm/aiguardfabric/`）

**Chart 已生成**（此前为空缺，现已补齐）：`Chart.yaml`、`values.yaml`、`values-prod.yaml`、`values-airgap.yaml`、
`README.md`、`.helmignore`，以及 `templates/` 下 25 个模板。

### 8.1 模板清单

| 类别 | 模板 |
|---|---|
| 应用 | `deployment-server.yaml`、`deployment-ingest.yaml`、`deployment-scheduler.yaml`、`deployment-web.yaml`、`services.yaml`、`configmap.yaml`、`secret.yaml`、`serviceaccount.yaml` |
| 入口与网络 | `ingress.yaml`、`networkpolicy.yaml`、`privatelink.yaml` |
| 高可用与治理 | `hpa.yaml`、`pdb.yaml`、`servicemonitor.yaml`、`pvc-evidence.yaml` |
| 可选内置数据面 | `postgresql.yaml`、`redis.yaml`、`nats.yaml`、`minio.yaml`、`clickhouse.yaml`、`grafana.yaml` |
| 辅助 | `_helpers.tpl`、`NOTES.txt`、`extra-manifests.yaml` |

### 8.2 `values.yaml` 顶层键（已核对）

```text
nameOverride / fullnameOverride / global
image / imagePullSecrets / podSecurityContext / containerSecurityContext
nodeSelector / tolerations / affinity / serviceAccount
config / extraConfig / secrets / volumes / ports
server / ingest / scheduler / web
ingress / privateLink / hpa / pdb / networkPolicy / serviceMonitor
postgresql / redis / nats / minio / clickhouse / grafana
extraManifests
```

### 8.3 前置条件（`Chart.yaml` 与 `README.md`）

| 项 | 要求 |
|---|---|
| Kubernetes | **`>=1.27.0-0`**（`Chart.yaml:23`；依赖 `autoscaling/v2`、`policy/v1`、`networking.k8s.io/v1`） |
| Helm | `>= 3.12`（使用 `fail` / `tpl`；OCI registry 建议 3.13+） |
| chart 版本 | `version: 0.1.0`、`appVersion: "0.1.0"`（与 `AGF_IMAGE_TAG` 默认值对齐） |
| 存储 | 至少一个 StorageClass（证据卷 PVC + 可选内置组件持久卷） |
| metrics-server | HPA 需要；否则 `hpa.*.enabled=false` |
| Prometheus Operator | 仅 `serviceMonitor.enabled=true` 时需要 |
| ingress-nginx 或阿里云 ALB Ingress | 仅 `ingress.enabled=true` 时需要 |
| 外部依赖 | PostgreSQL 16+TimescaleDB、Redis 7+、NATS 2.10+、S3 兼容对象存储（**生产必须外部托管**） |
| 注解 | `aiguardfabric.io/run-as-uid: "10001"`、`aiguardfabric.io/spec-version` |

### 8.4 常用命令

```bash
# 渲染检查（本地，不需要集群）
helm template aiguardfabric deploy/helm/aiguardfabric -f values-prod.yaml > /tmp/agf.yaml
helm lint deploy/helm/aiguardfabric

# 预演（强烈建议每次升级前执行）
helm upgrade --install aiguardfabric deploy/helm/aiguardfabric -n agf --create-namespace \
  -f deploy/helm/aiguardfabric/values-prod.yaml --dry-run

# 正式安装
helm upgrade --install aiguardfabric deploy/helm/aiguardfabric -n agf --create-namespace \
  -f deploy/helm/aiguardfabric/values-prod.yaml

# 回滚
helm rollback aiguardfabric -n agf
```

- **Secret 注入两种方式**（模板 `fail` 会明确报错）：`secrets.existingSecret`（推荐）或直接填 `secrets.*`。
- **气隙安装**：用 `values-airgap.yaml` + 私有 registry。
- **PrivateLink**：`privateLink.*` + `templates/privatelink.yaml`。
- **web 组件的只读根例外**：`/var/cache/nginx` 与 `/tmp` 已挂 `emptyDir`（README §3.1）。
- **证据 PVC**：`resource-policy: keep`，卸载时保留。

> ⚠️ **本轮未执行 `helm lint` / `helm template`**（环境未确认有 helm 且属外部工具），
> 因此"Chart 可渲染通过"**未经实测**。渲染命令见上，属待验证项。

---

## 9. 升级与回滚

### 9.1 Compose（生产）

| 阶段 | 命令 / 动作 |
|---|---|
| 1. 升级前 | ① 手工触发一次 `pg_dump`（§7.1）；② 记录当前 `AGF_IMAGE_TAG`；③ `docker compose -f docker-compose.prod.yml config --quiet` 校验变量 |
| 2. 拉新镜像 | `AGF_IMAGE_TAG=<新版本> docker compose -f docker-compose.prod.yml --env-file .env.prod pull` |
| 3. 迁移 | 新迁移文件落 `deploy/sql/migrations/`（文件名递增），由应用启动时 `MIGRATOR.run()` 执行。**无回滚脚本（仅向前）** |
| 4. 滚动重启 | `docker compose -f docker-compose.prod.yml --env-file .env.prod up -d` |
| 5. 校验 | `docker compose ps`（数据面应 healthy）；`curl http://127.0.0.1:8080/healthz`（**已实现**，200 即通过）；辅以 `Database::server_info()` 的 `rls_enabled_tables` 计数、`Store::health()` |
| 6. 回滚（仅代码） | **仅当旧镜像内嵌的迁移集包含数据库已经执行的全部版本时**，才能设置 `AGF_IMAGE_TAG=<旧版本>` 并重新 `up -d`；先核对 `_sqlx_migrations` 最大版本与旧镜像迁移集。否则旧服务会拒绝启动，须使用包含相同迁移集的上一业务代码镜像，或按第 7 步恢复升级前数据库备份。 |
| 7. 回滚（含数据库） | `pg_restore` 从 §7 的备份恢复 |

### 9.2 Helm

```bash
helm upgrade aiguardfabric deploy/helm/aiguardfabric -n agf -f values-prod.yaml   # 升级（只换镜像版本最常用）
helm upgrade --install ... --dry-run                                              # 预演
helm rollback aiguardfabric -n agf                                               # 回滚
helm history aiguardfabric -n agf                                                # 版本历史
```

Helm 回滚同样受迁移集限制；先核对待回滚镜像内嵌的迁移版本，不要把 `helm rollback` 成功提交当作 API 已恢复健康。

### 9.3 迁移的不可逆性（重要）

| 事实 | 影响 |
|---|---|
| 历史 0001 的四个分片合并后保持原始 SHA-384 | 已应用数据库可继续校验；变更数据库结构须新增迁移，不能改写历史字节 |
| `MIGRATOR` 内嵌在服务与 `agfctl` 中 | 迁移集与二进制版本绑定；换二进制即换迁移集 |
| 数据库已应用比旧二进制更多的迁移 | SQLx 会拒绝旧二进制启动。2026-09-27 添加 0018 后，实测回切仅含 0017 的 API 镜像立即失败；已恢复含 0018 的镜像。应预先构建兼容新迁移的回滚镜像并检查服务健康。 |
| `/docker-entrypoint-initdb.d` 只在空数据目录执行 | 它不是应用迁移入口，不能靠修改初始化脚本升级数据库 |
| **回滚数据库只能靠 `pg_restore`** | 必须在升级前完成备份（§7） |

### 9.4 升级期风险清单

| 风险 | 说明 | 缓解 |
|---|---|---|
| RLS 策略被新迁移误删 | `DROP POLICY IF EXISTS` + `CREATE POLICY` 是幂等重建，但若循环表清单漏表则该表失去 RLS | 升级后跑一次 RLS 覆盖率巡检（`Database::server_info()` 的 `rls_enabled_tables`） |
| 新迁移阻塞大表 | 无并发索引创建（未使用 `CREATE INDEX CONCURRENTLY`） | 在维护窗口执行；大表前先评估 |
| 规则包与二进制不匹配 | `rules/` 是 bind mount，可与镜像版本解耦 | 规则改动走 `rule_versions` 版本化 + 灰度 |
| 密钥轮换 | `FieldCipher` 的 `key_id` 校验会在密钥不一致时拒绝解密 | 用 `rewrap(material, new_aad)` 做 AAD 变更；密钥轮换需保留旧 `key_id` 的解密能力 |

---

## 10. 端口清单

### 10.1 应用端口

| 端口 | 服务 | 用途 | 配置变量 | 暴露建议 |
|---|---|---|---|---|
| 8080 | agf-server | HTTP API | `AGF_SERVER_PORT` | 仅经 nginx/Ingress |
| 8081 | agf-web | 控制台（宿主机映射） | `AGF_WEB_PORT` | 经 Ingress + TLS |
| 8090 | agf-ingest | 接入服务（Webhook / 采集器上行） | `AGF_INGEST_PORT` | 仅内网 |
| 5514/tcp+udp | agf-ingest | Syslog RFC3164/5424 | `AGF_SYSLOG_TCP_PORT` / `AGF_SYSLOG_UDP_PORT` | **仅内网**（无鉴权、无 TLS） |
| 8092 | agf-server | 独立 MCP HTTP 代理（容器内 8091） | `AGF_MCP_PROXY_HOST_PORT` | 仅被管 Agent 网段 |
| 9100 | agf-server | Prometheus 指标 | `AGF_METRICS_PORT` | 仅监控网段 |
| 9101 | agf-scheduler | 健康端点（容器内） | — | 不映射到宿主 |

### 10.2 数据面端口

| 端口 | 服务 | 说明 | 变量 |
|---|---|---|---|
| 5432 | postgres | `password_encryption=scram-sha-256`、`max_connections=200` | `AGF_PG_HOST_PORT` |
| 6379 | redis | `--appendonly yes`、`--maxmemory 512mb`、`allkeys-lru` | `AGF_REDIS_HOST_PORT` |
| 4222 | nats | 客户端 | `AGF_NATS_HOST_PORT` |
| 8222 | nats | 监控（`/healthz`） | `AGF_NATS_MONITOR_PORT` |
| 9000 | minio | S3 API | `AGF_MINIO_PORT` |
| 9001 | minio | 控制台 | `AGF_MINIO_CONSOLE_PORT` |
| 8123 | clickhouse | HTTP（**与 minio 的 9000 宿主映射冲突，注意 `AGF_CLICKHOUSE_NATIVE_PORT`**） | `AGF_CLICKHOUSE_HOST_PORT` / `AGF_CLICKHOUSE_NATIVE_PORT` |
| 3000 | grafana | Web | `AGF_GRAFANA_PORT` |

### 10.3 开发机端口

| 端口 | 用途 |
|---|---|
| 5173 | Vite dev server（`vite.config.ts`，host `127.0.0.1`，`strictPort: false`） |
| 4173 | `vite preview` |
| 4318 | OTLP HTTP（`AGF_OTEL_ENDPOINT` 默认） |

**端口冲突预检**：`scripts/selfcheck.ps1` 逐个探测 8080 / 8081 / 8090 / 8092 / 5514 / 9100 / 5432 / 6379 / 4222 /
9000 / 3000，输出"空闲 / 已被占用"。

> ⚠️ **已知端口映射冲突**：`docker-compose.yml` 把 minio 映射到宿主 `9000`，同时 clickhouse 的 native 端口也默认映射到宿主 `9000`
> （`AGF_CLICKHOUSE_NATIVE_PORT:-9000`）。**同时启用两个 profile 会冲突**，需改其中一个的宿主端口。

---

## 11. 故障排查表

| 症状 | 可能原因 | 处置 |
|---|---|---|
| `docker compose up` 报 `AGF_PG_PASSWORD 必须设置` | 缺少 `.env` | `pwsh -File scripts/init-env.ps1 -Force` |
| 报 `AGF_S3_SECRET_KEY 必须设置` / `AGF_JWT_SECRET 必须设置` / `AGF_MASTER_KEY_BASE64 必须设置` | 同上（compose 用 `${VAR:?msg}` 强制校验） | 同上 |
| 报 `AGF_GRAFANA_ADMIN_PASSWORD 必须设置` | 只在 `--profile grafana` 时触发 | 同上 |
| 报 `生产环境必须指定托管数据库主机` / `必须指定托管 Redis` / `必须指定对象存储端点` | 用了 `docker-compose.prod.yml` 但未设对应变量 | 补齐 `.env.prod` 的 `AGF_PG_HOST` / `AGF_REDIS_URL` / `AGF_S3_ENDPOINT` |
| 报 `必须指定镜像 tag` | prod 用 `${AGF_IMAGE_TAG:?}` | 设置 `AGF_IMAGE_TAG` |
| 应用启动即退出、日志只有一行中文提示 | **已过时**：三个二进制均已落地（PV-001/DOC-PV-001/003 已闭环）；若仍看到旧提示，说明跑的是仓库里的旧基线二进制 `tools/simulators/out/baseline/*-before.exe` | 见 [`docs/pending-verification.md`](pending-verification.md) PV-001 |
| `agf-server` 容器反复重启 | healthcheck 子命令探测失败 | `DOC-PV-021`；`agf-server healthcheck --url ...` **已实现**（PV-001 实测 8 容器全 healthy） |
| `agf-ingest` healthcheck 永久失败 | 曾因 distroless 镜像无 `wget` | **已修**：三个应用容器的 healthcheck 改为自带 `healthcheck --url` 子命令 |
| 控制台页面可用但数据全是演示数据 | `AGF_SEED_FIXTURES` 未开或 API 不可达；前端 5xx/404 回退演示 | 顶栏应有黄色演示横幅；见 `VITE_FORCE_DEMO` |
| 控制台接口报 401/403 且不显示演示数据 | **有意行为**：4xx 不回退（鉴权失败不被演示数据掩盖） | 检查令牌与权限 |
| postgres 起不来 | `data/pg` 权限/残留；`shared_preload_libraries=timescaledb` 失败 | `docker compose logs postgres`；确认镜像是 `timescale/timescaledb` |
| 建表失败但容器 healthy | 应用迁移失败或连接到了错误的数据库 | 查 `agf-server` 迁移日志；备份后运行 `agfctl migrate` 与 `agfctl db check-schema`，参见[迁移说明](migration-layout.md) |
| `agfctl db check-schema` 报 RLS 异常表或运行角色不安全 | 租户表未启用行级策略、策略被改动，或 `agf_tenant_runtime` 可绕过隔离 | 停止上线；核对迁移与数据库角色。该命令要求每张含 `tenant_id` 的表使用预期租户策略，并用两个租户标识只读验证策略函数；修复后重跑至退出码 0，不要用平台管理员连接的查询结果代替运行角色验证 |
| minio-init 失败 | `AGF_S3_SECRET_KEY` 与 minio 实际口令不一致 | 三个变量同源：`MINIO_ROOT_PASSWORD` 与 `AGF_S3_SECRET_KEY` 都取该值 |
| compose 校验失败 | 变量插值缺失 | `docker compose config --quiet` |
| 端口被占用 | 与本机既有服务冲突 | `pwsh -File scripts/selfcheck.ps1` 查端口段 |
| `cargo` 提示找不到工具链 | `CARGO_HOME` 被指向项目内空目录 | **不要覆盖 `CARGO_HOME`/`RUSTUP_HOME`**（`env.ps1:103-111`） |
| PowerShell 中文乱码 | 脚本保存为 UTF-8 无 BOM | 保存为 **UTF-8 with BOM** |
| dot-source 后函数未定义 | 脚本声明了 `param()` | 被 dot-source 的脚本（`env.ps1` / `lib.ps1`）**不得使用 `param()`** |
| `helm template` 报 "缺少密钥来源" | Secret 模板 `fail` | 二选一：设 `secrets.existingSecret` 或填 `secrets.*` |
| Pod readiness 失败 | 数据库连不上 → `/healthz` 非 200 | 检查 `AGF_PG_PASSWORD` |
| Pod liveness 反复重启 | 只读根下 `/tmp` 未挂载 | Chart 已挂 `emptyDir`；自建模板需自查 |
| `agf-web` CrashLoop | `/var/cache/nginx` 不可写 | 同上 |
| NetworkPolicy 下"连不上" | 默认拒绝 | 按 `values.networkPolicy` 放行 |
| PrivateLink 未拿到私网 IP | 终端节点/安全组配置 | 见 Chart README §4 |

---

## 12. 相关文档

- 架构与部署拓扑：[`docs/architecture.md`](architecture.md)
- 安全加固与威胁分析：[`docs/threat-model.md`](threat-model.md)
- 适配器配置与凭据优先级：[`docs/adapter-spec.md`](adapter-spec.md)
- 日常运维手册：[`docs/operations.md`](operations.md)
- 缺口清单：[`docs/pending-verification.docs.md`](pending-verification.docs.md)
- 项目门面：[`README.md`](../README.md)
