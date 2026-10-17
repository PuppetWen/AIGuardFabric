# AIGuardFabric 运维手册

> 适用对象：平台运维 / SRE / 安全运营。
> 事实来源：`docker-compose.yml`、`docker-compose.prod.yml`、`deploy/docker/Dockerfile`、
> `deploy/docker/nginx.conf`、`deploy/sql/migration_parts/`、`.env.example`、
> `scripts/env.ps1`、`scripts/init-env.ps1`、`scripts/selfcheck.ps1`、`Justfile`、各 crate 源码。
>
> ⚠️ **实现状态前置声明（务必先读）**：本手册中的**编排层、存储层、库层**命令与配置均已核对可执行；
> **HTTP API / 健康端点 / 指标端点 / 三个服务二进制**（`agf-server` / `agf-ingest` / `agf-scheduler`）
> **已落地并实测可达**（`GET /healthz` → 200 `{"mode":"offline"}`；`GET /readyz` → 200 且报告 `rules=54` /
> `redteam=220` / `parsers{total:130,loaded:117}`；`GET /api/v1/openapi.json` → OpenAPI 3.1.0 / **120 条路径 / 17 个 schema**；
> `GET /metrics` → Prometheus 文本；`agf-server healthcheck --url ...` 退出码 0；
> `/settings` 的 `persistence` 段与 `/readyz` 的 `checks.persistence` 由 `PersistenceReport` **实时**生成）。
> **仍未落地的部分**逐条标注在"当前实现状态"列中
> （仍仅内存的资源、OTLP 的**真实 collector 联调**、`agfctl` 的真库路径）。
> 已闭环的旧缺口：7+2 个 501 端点（现为 **0 条**）、OTLP span 导出装配、Helm lint/template、
> `agfctl version` 元数据（见 `docs/pending-verification.md` PV-011/023/030）。
>
> 📏 **规模数字口径**：本手册中的行数为**本轮实测**（读取全文后统计 `\n` 字节数）。

---

## 1. 日常运维

### 1.1 服务拓扑与端口清单

`docker-compose.yml` 定义的服务与端口（宿主机侧变量来自 `.env`）：

| 服务 | 容器名 | 宿主机端口（默认） | 容器端口 | 依赖 | 当前实现状态 |
|---|---|---|---|---|---|
| `postgres` | `agf-postgres` | `${AGF_PG_HOST_PORT:-5432}` | 5432 | — | ✅ 镜像 `timescale/timescaledb:latest-pg16`，健康检查 `pg_isready` |
| `redis` | `agf-redis` | `${AGF_REDIS_HOST_PORT:-6379}` | 6379 | — | ✅ 健康检查 `redis-cli ping` |
| `nats` | `agf-nats` | `${AGF_NATS_HOST_PORT:-4222}` / `${AGF_NATS_MONITOR_PORT:-8222}` | 4222 / 8222 | — | ✅ JetStream（`-js -sd /data`），健康检查 `/healthz` |
| `minio` | `agf-minio` | `${AGF_MINIO_PORT:-9000}` / `${AGF_MINIO_CONSOLE_PORT:-9001}` | 9000 / 9001 | — | ✅ 健康检查 `mc ready local` |
| `minio-init` | `agf-minio-init` | — | — | `minio` healthy | ✅ 一次性建桶：`agf-evidence`、`agf-raw-logs`、`agf-reports` |
| `clickhouse` | `agf-clickhouse` | `${AGF_CLICKHOUSE_HOST_PORT:-8123}` / `${AGF_CLICKHOUSE_NATIVE_PORT:-9000}` | 8123 / 9000 | — | ⚙️ `profiles: ["clickhouse"]`，默认不启动 |
| `grafana` | `agf-grafana` | `${AGF_GRAFANA_PORT:-3000}` | 3000 | `agf-server` started | ⚙️ `profiles: ["grafana"]`，默认不启动 |
| `agf-server` | `agf-server` | `${AGF_SERVER_PORT:-8080}` / `${AGF_MCP_PROXY_HOST_PORT:-8092}` / `${AGF_METRICS_PORT:-9100}` | 8080 / 8091 / 9100 | postgres/redis/nats healthy | 🟢 主 API、独立 MCP HTTP 代理与指标；MCP 客户端用宿主机 8092 或 HTTPS 入口 |
| `agf-ingest` | `agf-ingest` | `${AGF_INGEST_PORT:-8090}`、`5514/tcp`、`5514/udp` | 8090 / 5514 | postgres/nats healthy | 🟢 日志/遥测接入；不提供 MCP 代理 |
| `agf-scheduler` | `agf-scheduler` | 无宿主映射（容器内 9101） | 9101 | postgres/nats healthy | 🟢 `apps/scheduler/src/main.rs` 实测 421 行；新增只读卷 `./rules`、`./redteam` 与数据卷 `reports` |
| `agf-web` | `agf-web` | `${AGF_WEB_PORT:-8081}` | 8080（nginx） | `agf-server` started | ✅ 静态控制台已构建（`apps/web/dist/` 存在） |

> **端口冲突预检**：`scripts/selfcheck.ps1` 会逐个探测 8080 / 8081 / 8090 / 8092 / 5514 / 9100 /
> 5432 / 6379 / 4222 / 9000 / 3000，输出"空闲 / 已被占用"。

### 1.2 启停

```powershell
# 全栈启动（默认不启用 clickhouse / grafana）
docker compose up -d

# 首次或代码变更后重建镜像
docker compose up -d --build

# 附带可观测性组件
docker compose --profile clickhouse --profile grafana up -d

# 只起依赖，应用在宿主上用 cargo/pnpm 热重载（开发路径）
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d
```

`docker-compose.dev.yml` 的作用是**做减法**：把 `agf-server` / `agf-ingest` / `agf-scheduler` /
`agf-web` 归入 `profiles: ["full"]`、把 `minio-init` 归入 `["objects"]`，因此合并后默认只起
`postgres` / `redis` / `nats` / `minio`。

```powershell
# 停止（保留数据卷）
docker compose down

# 停止并彻底清理数据（data/ 下 bind mount 的内容会保留，见 §1.4）
docker compose down -v

# 查看状态 / 日志
docker compose ps
docker compose logs -f --tail=200
docker compose logs -f agf-server          # 单服务
```

### 1.3 日志

| 项目 | 事实 |
|---|---|
| 容器日志驱动 | `json-file`，`max-size: 20m`、`max-file: 5`（`x-app-defaults`）；生产 `.prod.yml` 为 `50m` × `10` |
| 应用日志级别 | `AGF_LOG_LEVEL`（默认 `info`）；容器内同时注入 `RUST_LOG=${AGF_LOG_LEVEL:-info}` |
| 应用日志格式 | `AGF_LOG_FORMAT`：`pretty`（默认，`.env.example`）或 `json`。**注意**：compose 的 `x-common-env` 覆盖为 `json`（第 23 行），`.prod.yml` 固定 `json` |
| 敏感信息 | `AppConfig` 的 `Debug` 实现自动打码 `jwt_secret` / `master_key_b64` / 数据库 DSN / Redis URL（`crates/agf-core/src/config.rs:671-695`）；`FieldCipher` 的 `Debug` 打印 `<redacted 32 bytes>`（`crates/agf-storage/src/crypto.rs:36-44`） |
| 慢 SQL | `log_min_duration_statement=1000`（PostgreSQL）；SQLx 侧 `log_slow_statements(Warn, 800ms)`（`crates/agf-storage/src/db.rs:55`） |

查看某关键字：

```powershell
docker compose logs --since 30m agf-server | Select-String -Pattern 'ERROR|WARN'
```

### 1.4 数据卷（bind mount 到 `<项目根>/data/`）

**全部**数据卷都是 bind mount，不使用匿名卷（`docker compose down -v` 不会删除宿主机目录内容）：

| 宿主路径 | 容器路径 | 归属服务 |
|---|---|---|
| `${AGF_DATA_DIR}/pg` | `/var/lib/postgresql/data` | postgres |
| `${AGF_DATA_DIR}/redis` | `/data` | redis |
| `${AGF_DATA_DIR}/nats` | `/data` | nats |
| `${AGF_DATA_DIR}/clickhouse` | `/var/lib/clickhouse` | clickhouse |
| `${AGF_DATA_DIR}/minio` | `/data` | minio |
| `${AGF_DATA_DIR}/grafana` | `/var/lib/grafana` | grafana |
| `${AGF_DATA_DIR}/evidence` | `/data/evidence` | agf-server / agf-ingest |
| `${AGF_DATA_DIR}/backup` | `/backup` | backup sidecar（仅 prod） |
| `${AGF_DATA_DIR}/seed` | — | 引导凭据落盘位置（`.env.example:119`） |

`scripts/selfcheck.ps1` 会逐个统计这些目录的占用并输出合计（`data/pg`、`data/redis`、`data/nats`、
`data/clickhouse`、`data/minio`、`data/evidence`、`data/seed`、`data/backup`、`data/grafana`），
并对不存在的目录主动创建。

### 1.5 健康检查端点

| 端点 | 期望方 | 影响方 | 当前实现状态 |
|---|---|---|---|
| `GET http://127.0.0.1:8080/healthz` | `agf-server` | `docker-compose.yml:256-257`（`agf-server healthcheck --url ...`）、`nginx.conf`（`/healthz` 反代） | ✅ **已实现并实测**：200 `{"status":"ok","service":"agf-server","version":"0.1.0","mode":"offline",...}`。**不检查任何依赖**（数据库/Redis 挂了也返回 200） |
| `GET http://127.0.0.1:8080/readyz` | 就绪探针 / 负载均衡 | `docs/deployment.md` §6.4 | ✅ **已实现并实测**：200，返回 `mode` / `degraded` / `checks`（`database` / `redis` / `objects` / `rules` / `redteam`）/ `notes`。离线内存模式下 `degraded:true` |
| `GET http://127.0.0.1:8090/healthz` | `agf-ingest` | `docker-compose.yml:294-296`、`.prod.yml` | ✅ **已实现**（healthcheck 已改为 `agf-ingest healthcheck --url ...`，不再依赖 distroless 里没有的 `wget`）；`/readyz` 另返回接收器能力矩阵 |
| `GET http://127.0.0.1:9101/healthz` | `agf-scheduler` | `docker-compose.yml:329-331`、`.prod.yml` | ✅ **已实现**（healthcheck 已改为 `agf-scheduler healthcheck --url ...`）；`/readyz` 在降级时返回 degraded 并说明原因，`/tasks` 实测 **8/8 implemented / 0 todo**（PV-031） |
| `GET http://127.0.0.1:9100/metrics` | Prometheus 抓取 | `AGF_METRICS_PORT=9100`、`AGF_PROMETHEUS_ENABLED=1` | ✅ **已实现并实测**：`GET /metrics` 返回 Prometheus 文本（`agf_build_info`、`agf_http_request_duration_seconds` 等）。**OTLP span 导出已接线**：由 `AGF_OTLP_ENDPOINT`（或 `AGF_OTEL_ENABLED=1` + `AGF_OTEL_ENDPOINT`）门控，未设置时不建导出器（零开销）；**真实 collector 联调**仍属阶段二 |
| `POST http://127.0.0.1:8092/api/v1/mcp/proxy/<端点 ID>` | 被管 Agent 的 MCP 客户端 | `AGF_MCP_PROXY_HOST_PORT=8092` | ✅ `agf-server` 独立监听 MCP HTTP；需平台 API Key 与已配置的上游端点 |
| `GET http://127.0.0.1:8081/` | 控制台 | `docker-compose.yml` | ✅ nginx 静态站点 |

**库层健康探测（已实现，可由未来 API 直接复用）**：

| 方法 | 文件 | 语义 |
|---|---|---|
| `Database::ping()` | `crates/agf-storage/src/db.rs:111` | `SELECT 1` |
| `Database::server_info()` | `db.rs:192` | 返回 `version` / `timescaledb_version` / `rls_enabled_tables` / `pool_size` / `pool_idle` |
| `RedisStore::ping()` | `crates/agf-storage/src/redis_store.rs:115` | `PING` 必须返回 `PONG` |
| `Store::health()` | `crates/agf-storage/src/repository.rs:101` | 汇总 db / redis / 对象存储可用性与后端名（`StoreHealth`） |
| `ObjectStore::health()` | `crates/agf-storage/src/objectstore.rs:98` | S3 / 本地 / 内存三实现各自探测 |
| `Adapter::health()` | `crates/agf-core/src/adapter.rs:654` | 每个外部适配器返回 `AdapterHealth`（含熔断快照） |
| `AliCloudRegistry::health_all()` | `crates/agf-alicloud/src/registry.rs:295` | 六个阿里云适配器的健康汇总 |
| `CloudSelfCheckSuite` / `build_report` | `crates/agf-alicloud/src/selfcheck.rs` | 云环境自检（连通性 / 最小权限 / 配额余量）+ 合并 RAM 策略，可输出 Markdown |

### 1.6 指标

| 事实 | 位置 |
|---|---|
| 环境开关 | `AGF_PROMETHEUS_ENABLED=1`、`AGF_METRICS_PORT=9100`、`AGF_OTEL_ENABLED=0`、`AGF_OTEL_ENDPOINT=http://127.0.0.1:4318`、`AGF_OTEL_SERVICE_NAME=agf-server` |
| 配置结构 | `crates/agf-core/src/config.rs:413-434`（`ObservabilityConfig`） |
| 依赖 | workspace `Cargo.toml:168-177`：`tracing` / `tracing-subscriber` / `tracing-opentelemetry` / `opentelemetry` / `opentelemetry_sdk` / `opentelemetry-otlp` / `metrics` / `metrics-exporter-prometheus` / `prometheus` |
| 端点 | ✅ **已注册并实测**：`GET /metrics`（`agf-api/src/lib.rs` 的 `public_router` 注册 `/metrics`，`metrics.rs` 渲染 Prometheus 文本，`Content-Type: text/plain; version=0.0.4`）。**OTLP span 导出已接线**（`agf-api/src/metrics.rs` 的 `otel` 子模块 + `apps/server` 装配）：`AGF_OTLP_ENDPOINT` 非空即启用；否则需 `AGF_OTEL_ENABLED=1` **且** `AGF_OTEL_ENDPOINT` 非空。**未启用时不构建任何导出器**（无后台线程/网络客户端）；退出前 `shutdown()` 冲刷批次。**真实 collector 联调**仍属阶段二（`DOC-PV-020`） |
| Grafana | `deploy/grafana/provisioning` 与 `deploy/grafana/dashboards` 被 compose 挂载，但**这两个目录当前不含任何文件** |

**当前可行的可观测手段**（本轮实测）：
- 应用指标：`GET http://127.0.0.1:9100/metrics`（或 `agf-server` 同端口的 `/metrics`）已可用；
  `agf-ingest` 另暴露 `agf_ingest_syslog_frames_total` / `agf_ingest_syslog_frames_dropped_total` /
  `agf_ingest_webhook_matched_total` / `agf_ingest_parse_failures_total`，
  `agf-scheduler` 暴露 `agf_scheduler_task_runs_total` 等。
- 就绪与能力矩阵：`GET /readyz`（server / ingest / scheduler 三处均有）；`agf-server` 的 `/readyz`
  另含 `checks.persistence`（**实时**写后队列计数：`queued`/`applied`/`failed`/`dropped`/`depth`/`id_remapped`，
  失败或丢弃非 0 时 `degraded:true` 并给 note）；`agf-scheduler` 的 `/tasks` 直接列出各任务的真实状态。
- 容器健康：`docker compose ps`（依赖 postgres/redis/nats/minio 自身的 healthcheck，这四个是真实可用的）；
  三个应用容器现在用**自带 `healthcheck` 子命令**探活（distroless 无 `wget`）。
- 日志：`AGF_LOG_FORMAT=json` + `docker compose logs`。

---

## 2. 告警与升级路由

### 2.1 数据模型（已建表，实现待接）

| 表 | 用途 | 迁移位置 |
|---|---|---|
| `alerts` | 告警主表，含 `dedup_key`（去重）、`state`、`severity`、`sla_due_at`、`last_seen_at` | `0001_init_03.sql:157` |
| 索引 `ix_alerts_dedup` | `(tenant_id, dedup_key, state)` —— 聚合去重 | `0001_init_03.sql:183` |
| 索引 `ix_alerts_sla` | `(tenant_id, sla_due_at) WHERE state IN ('open','acknowledged','escalated')` —— SLA 计时扫描 | `0001_init_03.sql:185` |
| `aggregation_policies` | 告警聚合/抑制策略 | `0001_init_03.sql:187` |
| `escalation_rules` | 升级路由规则 | `0001_init_03.sql:199` |
| `notification_channels` | 通知渠道配置 | `0001_init_03.sql:273` |
| `notifications` | 通知发送记录与状态 | `0001_init_03.sql:292` |
| `cases` / `case_events` / `timelines` | 案件闭环与时间线 | `0001_init_03.sql:216` / `:245` / `:258` |
| `playbooks` / `playbook_runs` | SOAR-lite 剧本 | `0001_init_03.sql:312` / `:328` |
| `schedules` | 调度任务登记 | `0001_init_04.sql:3` |

### 2.2 通知渠道（`.env.example` §14）

| 变量 | 渠道 |
|---|---|
| `AGF_NOTIFY_DINGTALK_WEBHOOK` | 钉钉机器人 |
| `AGF_NOTIFY_FEISHU_WEBHOOK` | 飞书机器人 |
| `AGF_NOTIFY_WECOM_WEBHOOK` | 企业微信机器人 |
| `AGF_NOTIFY_SMTP_HOST` / `_PORT` / `_USER` / `_PASSWORD` / `_FROM` | 邮件（默认端口 587） |
| `AGF_NOTIFY_PAGERDUTY_KEY` | PagerDuty |
| `AGF_NOTIFY_GENERIC_WEBHOOK` | 通用 Webhook |

模板渲染与占位符替换已实现：`crates/agf-core/src/notify.rs`（`{{title}}` / `{{severity}}` 等，
未知占位符保留原样便于发现模板写错，第 246-248 行）。

### 2.3 升级路由与 SLA 运维动作

| 动作 | 依据 | 状态 |
|---|---|---|
| SLA 超时扫描 | `AlertRepo::list_active` / `AlertRepo::set_state`（`repository.rs:1717,1736`）；索引 `ix_alerts_sla` | 库层 ✅ / 调度触发 ⛔ |
| 告警去重聚合 | `AlertRepo::upsert_dedup` 返回 `(告警 id, 是否新建)`（`repository.rs:1630`） | 库层 ✅ |
| 通知发送 | `notify.rs` 模型与模板 ✅；实际投递落地（HTTP/SMTP 客户端）未在本次核对中确认 | 部分 |
| 案件创建与时间线 | `crates/agf-core/src/case.rs` + `CaseRepo` ✅ | 库层 ✅ |

> **跨章节一致性**：告警→案件→处置的完整闭环依赖 `agf-server`/`agf-scheduler` 落地，
> 见 `docs/architecture.md` 的"当前实现状态"表。

---

## 3. 配额调整

### 3.1 三级配额与维度

| 层级 | 默认值变量 | 默认值 |
|---|---|---|
| 租户每日 token | `AGF_QUOTA_TENANT_TOKENS_PER_DAY` | 5,000,000 |
| Agent 每日 token | `AGF_QUOTA_AGENT_TOKENS_PER_DAY` | 500,000 |
| 会话 token | `AGF_QUOTA_SESSION_TOKENS` | 100,000 |
| 租户每分钟请求 | `AGF_QUOTA_TENANT_REQ_PER_MIN` | 6,000 |

解析位置：`crates/agf-core/src/config.rs:555-560`（`QuotaDefaults`，`Default` 实现见 `:401-410`）。

### 3.2 运行时计数（Redis Lua）

| 机制 | 实现 |
|---|---|
| 原子"检查 + 消费" | `QuotaCounter::check_and_consume(limit, amount, window_secs, fail_closed)`，Lua 脚本 `QUOTA_SCRIPT`（`redis_store.rs:23-37`）——服务端时间做窗口，避免多实例时钟漂移 |
| 归还额度 | `QuotaCounter::release(amount)`，Lua `QUOTA_RELEASE_SCRIPT`（`:40-51`），`KEEPTTL` 保留窗口 |
| 只读查询 | `QuotaCounter::peek()`（`:373`） |
| 管理员重置 | `QuotaCounter::reset()`（`:389`） |
| 键布局 | `agf:quota:<tenant>:<scope>:<dimension>:<bucket>[:<target>]`（`RedisStore::quota`，`:208`；`redis_store.rs:416-420` 的测试断言布局必须稳定） |
| 失败策略 | `fail_closed = true` → Redis 不可达时**拒绝**（配额是安全控制，宁可少服务）；`false` → 放行（非关键计量）（`:318-320`） |
| HTTP API 三级限流 | `RedisStore::rate_limits_atomic` 使用 Redis 服务器时间与单次 Lua 脚本同时检查全局、租户、认证主体令牌桶；全部放行才一并扣减。Redis 运行中失败返回 503。Helm 强制共享，单机未连 Redis 时使用进程内桶。检查 `/readyz` 的 Redis 状态和响应的 `X-RateLimit-*` / `Retry-After`。 |
| 固定窗口辅助接口 | `RedisStore::rate_limit(name, limit, window_secs)` 仍保留，HTTP API 中间件不使用它。 |

### 3.3 调整步骤

1. **改默认值**：编辑 `.env` 中对应变量 → 重启 `agf-server`（二进制已实现，重启即生效；可观测手段见 §1.5）。
2. **改单租户配额**：写 `quotas` 表（`0001_init_02.sql:407`，字段 `scope` / `dimension` / `window` /
   `limit_` / `soft_threshold` / `on_exceed`），种子数据在 `0001_init_04.sql:398`。
3. **临时重置计数**：删除 Redis 中 `agf:quota:*` 对应键（或未来经 `QuotaCounter::reset()`）。
4. **验证**：`quota_usage` 表（`0001_init_03.sql:4`）记录窗口用量，索引 `ix_quota_usage_tenant (tenant_id, window, bucket)`。

> **注意**：Redis 键**必须**带租户前缀（`AGF_REDIS_PREFIX`，默认 `agf`），多租户共用一个 Redis 实例时
> 这是防串号的唯一手段。

---

## 4. 规则热更新与灰度

### 4.1 规则存放与加载

| 项目 | 事实 |
|---|---|
| 目录 | `AGF_RULES_DIR=<项目根>/rules`（`.env.example:315`） |
| 挂载 | `docker-compose.yml:244`（server，`:ro`）、`:283`（ingest，`:ro`）、`:315`（scheduler，`:ro`）；`.prod.yml:93-96`、`:148-151` 同样只读 |
| 镜像内路径 | `/app/rules`（`Dockerfile:95,100,106`） |
| 加载器 | `crates/agf-scan/src/loader.rs`（543 行，规则目录加载 + 版本/灰度） |
| 规则模型 | `crates/agf-core/src/rule.rs`（502 行，含**正负样本**结构） |
| 版本表 | `risk_rules`（`0001_init_02.sql:201`）、`rule_versions`（`0001_init_02.sql:223`） |
| 校验命令 | `cargo run -p agf-cli -- rules verify --dir rules`（`Justfile:103`）—— ✅ **已实测**：54 条规则 + 正样本 111/111 + 负样本 113/113，exit 0（PV-004） |
| 当前内容 | ✅ **`rules/` 下 54 个 `*.yaml`**（`credential-leak` 12 / `model-data` 10 / `prompt-attack` 12 / `rag-poison` 10 / `tool-abuse` 10），正负样本随规则一起提交；`rules/_gen/{agf_rules,agf_shadow,run}.py` 为生成器脚本 |

### 4.2 热更新流程（设计口径）

1. 编辑 `<项目根>/rules/**` 下的规则文件（正负样本必须随规则一起提交）。
2. 校验：`rules verify`（正负样本全绿是准入条件，§11 验收 7）。
3. 发布：写入 `risk_rules` + `rule_versions`（新版本行，旧版本保留）。
4. 灰度：按 `rule_versions.state` 控制生效范围（灰度/全量）。
5. 观察：`policy_hits`（`0001_init_02.sql:389`）与 `findings`（`0001_init_02.sql:139`）的命中变化。

> 容器侧因 `./rules` 是**只读 bind mount**，热更新发生在宿主目录（`<项目根>/rules`），
> 无需重建镜像；但**加载时机**取决于 `agf-scan` loader 的触发方式（文件监听或轮询），
> `agf-scan` 侧未在本次核对中确认 watcher 实现，故不作断言。

### 4.3 规则/用例库双校验

```powershell
cargo run -p agf-cli -- rules verify   --dir rules      # 规则包：数量 + 字段 + 正负样本
cargo run -p agf-cli -- redteam verify --dir redteam    # 红队用例库：数量 + 字段完整性
```

`redteam/` 已备齐用例库（`redteam/README.md`、`redteam/catalog.md` 及按家族分目录的 YAML）。
两条命令均已实测可跑（`rules verify` 54/54；2026-09-28 `redteam verify` 225 用例 / 12 类目 / 公开 PoC 39.6%，exit 0）。

---

## 5. 审计链校验

### 5.1 防篡改设计

| 环节 | 实现 |
|---|---|
| 单条记录 | `entry_hash = SHA256(prev_hash ‖ 规范化载荷)`，实现位于 `crates/agf-core/src/audit/` |
| 链式衔接 | `prev_hash` 指向同租户上一条记录的 `entry_hash`；创世哈希为 64 个 `0` |
| 提交与读取 | `AppState::audit` 等待 PostgreSQL 封链事务提交；列表、统计、报表和校验读取已提交链。无数据库时使用进程内链 |
| 链校验 | `ChainVerifier` 分页检查完整链，包括首条序号、创世哈希、逐条内容哈希及跨页前序哈希 |
| 锚点签名 | `AuditChainAnchor` 类型与签名载荷已定义；定期生成、外部保存和验证签名的服务流程**尚未接通**，不能据此宣称可抵抗整链重算 |
| 事务边界 | 审计提交与业务记录写入仍可能分属两个事务；业务成功后审计失败须人工核对 |

### 5.2 校验操作

在控制台打开“审计日志”，按操作者、动作/详情、结果或敏感动作筛选；分页与筛选由服务端执行，不会只搜索当前页。点击“校验哈希链”查看已检查条数、序号区间和问题；“导出筛选结果”会按序号拉取全部匹配页，下载含租户、筛选条件和条目的 JSON。导出期间不要切换租户或登录账号，若数据发生变化请重试。需要 `audit:read` 权限；导出文件可能含敏感审计详情，按企业保密策略保存。

API 可使用 `GET /api/v1/audit?page=1&page_size=200&q=...`、`GET /api/v1/audit/verify` 与 `GET /api/v1/audit/stats`。列表还支持 `actor`、`action`、`outcome`、`sensitive_only` 和 `from_sequence`。校验的 `chain.source` 为 `postgres` 或 `memory`；只有前者能跨实例读取。用 `cargo test -p agf-core audit` 验证核心链算法。

### 5.3 审计链中断的处置

| 症状 | 含义 | 处置 |
|---|---|---|
| `prev_gap` 或 `sequence_gap` | 链衔接异常或记录缺失 | 暂停该租户相关写入，保留数据库及备份证据，核对异常序号和对应操作；恢复前先确定原因 |
| `hash_mismatch` | 记录内容和已存哈希不符 | 按高优先级安全事件处理，保留原始行及数据库日志，核对备份 |
| 首条创世哈希错误 | 链首缺失或被替换 | 核对迁移、清理及备份历史；当前尚无可信外部锚点自动裁决 |

---

## 6. 容量与保留策略

### 6.1 热/冷分层

| 层 | 存储 | 保留 | 实现 |
|---|---|---|---|
| 热 | ClickHouse / TimescaleDB | `hot_days`，**默认 30 天** | `crates/agf-ingest/src/coldarchive.rs:80,93`（`ArchiveConfig::hot_days`），`:438` 测试断言"热层默认 30 天（§4.5）" |
| 冷 | 对象存储（S3 / MinIO / OSS） | 由对象存储生命周期策略控制 | `coldarchive.rs` 的 `retention_plan(hot_days, cold_days)`（`:128`）生成可执行计划 |
| 保留计划输出 | — | — | `retention_plan` 产出：① 热层按天分区，过期分区 DETACH；② 归档作业每日扫描 `[now-hot_days-1d, now-hot_days)` 的事件并 `ColdArchiver::archive_batch`；③ 对象存储生命周期 `hot_days` 后转储、`cold_days` 后转 IA/归档、`cold_days+` 删除（`coldarchive.rs:137-142`） |

**冷归档格式现状**：**默认格式即列式 Parquet（SNAPPY）**——`coldarchive.rs` 的 `ColdFormat::Parquet`
走 `parquet` crate 的低层列式 API（`parquet::schema` / `column::writer` / `file::writer|reader` / `record`），
**不开 `arrow` 特性**，整条 arrow 生态不进依赖树；Parquet 编码失败自动回落 **gzip 压缩 NDJSON** 并 `warn!`
（对象键后缀随内容切换，读取侧 `ColdFormat::sniff` 按内容魔数判格式，回落对象也能原样读回）。
`ColdFormat::is_implemented()` 现恒为 `true`（见 `docs/pending-verification.docs.md` DOC-PV-019，已闭环）。

### 6.2 事件表容量

| 项目 | 事实 |
|---|---|
| 表 | `events`（`0001_init_03.sql:72`），TimescaleDB 可用时转 hypertable；不可用时退化为普通表（`0001_init_01.sql:18-29` 的异常捕获块会 `RAISE NOTICE`）。初始迁移共 72 张表，分为四个文件 |
| 索引 | `ix_events_source` / `ix_events_severity` / `ix_events_category`（均含 `time DESC`）、`ix_events_raw_hash`、`ix_events_ai_agent`（GIN on `ai jsonb_path_ops`）（`0001_init_03.sql:101-105`） |
| RLS | `events` 单独配策略（`0001_init_04.sql:267-275`，复合主键无 tenant_id 外键约束） |
| 原始载荷保真 | `raw_logs`（`0001_init_03.sql:120`），索引含 `ix_raw_logs_unparsed WHERE NOT parsed`（供重解析/回放）+ `ix_raw_logs_hash`（去重） |
| 软删除清理 | `Database::purge_soft_deleted(table, older_than_days)`（`db.rs:228`），要求 `deleted_at` 列存在 |

### 6.3 备份产物保留

`docker-compose.prod.yml` 的 backup sidecar（第 185-218 行）：

| 项目 | 事实 |
|---|---|
| 周期 | `AGF_BACKUP_INTERVAL_SECS`，默认 86400 秒 |
| 命令 | `pg_dump --format=custom --compress=6 --file=/backup/agf-<UTC时间戳>.dump` |
| 保留 | 最近 **7 份**（`ls -1t /backup/agf-*.dump \| tail -n +8 \| xargs -r rm -f`） |
| 落盘 | `${AGF_DATA_DIR}/backup`（bind mount，宿主可见） |
| 失败行为 | `pg_dump` 失败只打印 `[backup] dump failed` 后继续循环（不退出，不告警） |

### 6.4 磁盘容量预检

```powershell
# 数据卷占用（含分项与合计）
& scripts\selfcheck.ps1

# 仅 JSON（便于接监控）
& scripts\selfcheck.ps1 -Json
```

关注项：`data/pg`（增长最快）、`data/clickhouse`、`data/minio`、`data/evidence`、`data/backup`。

---

## 7. 常见问题与处置

### 7.1 事件积压

| 排查 | 命令/依据 |
|---|---|
| 是否解析失败堆积 | 查 `raw_logs` 中 `parsed = false` 的行数（索引 `ix_raw_logs_unparsed`）；库层 `EventRepo::unparsed_raw(limit)`（`repository.rs:1559`） |
| 接收器是否在跑 | ✅ `agf-ingest` 已把接收器装配成进程（PV-001/DOC-PV-003 已闭环）：`docker compose ps` 看 `agf-ingest` 是否 healthy；`GET http://127.0.0.1:8090/readyz` 看 `receivers_ready/receivers_total` 与能力矩阵 |
| 总线是否可用 | `AGF_NATS_ENABLED=1` 时依赖 NATS healthy；`docker compose ps` 看 `agf-nats`；`docker compose logs agf-nats`。置 `0` 时退化为进程内广播（`.env.example:94`） |
| 上游是否超时 | `${AGF_NATS_MONITOR_PORT:-8222}` 的 `/healthz`；NATS 监控端口 8222 |

**处置顺序**：① 确认 NATS healthy → ② 确认解析失败率（见 §7.2）→ ③ 若为落库瓶颈，查 PostgreSQL
连接池（`AGF_PG_POOL_MAX` 默认 20，prod 默认 50）与 `pg_isready` → ④ 若为磁盘满，见 §7.5。

### 7.2 解析失败率升高

| 步骤 | 动作 |
|---|---|
| 1. 定位 | `EventRepo::unparsed_raw()` 取未解析原始日志，按 `source_id` 分组（`ix_raw_logs_unparsed`） |
| 2. 归因 | 逐条对照 `crates/agf-ingest/src/engine.rs`（引擎管线）、`registry.rs`（模板注册表）、`template.rs`（模板定义）；引擎类型支持情况见 `engine.rs:31-42` 的能力矩阵 |
| 3. 引擎实现状态 | **13 个引擎全部已实现**（`engine_support_matrix` 逐条如实）：Grok/Regex/JSONPath/JQ/Syslog/CEF/LEEF/GELF/CSV/KV/AI 启发式/CEL 派生字段（非独立抽取引擎）/**Rust 动态库插件**（`ParserEngine::Plugin`，见 `crates/agf-ingest/src/engine/plugin.rs`）。**插件引擎的三条如实局限**：① 插件不参与样本打分（调用插件本身就是"命中与否"的判定，重复调用只会重复副作用/重复计数）；② 超时（`AGF_INGEST_PLUGIN_TIMEOUT_MS`，默认 500ms）只**放弃结果**，同进程调用**无法中断**，被放弃的插件线程仍在跑；③ ABI v1 只导出 `normalize` 一个入口（`entry=` 写别的值加载期报错）。**未装载插件时的降级**：`AGF_INGEST_PLUGIN_DIR` 未配置且缺省 `<项目根>/plugins` 不存在 ⇒ 该模板如实报"插件引擎不可用"并**未命中**，原始日志照常落库（不 panic、不静默丢弃）。排查入口：`GET /readyz` 的 `notes`（**启动期快照**的装载/失败清单）与 `tracing` 的 `agf_ingest::engine::plugin` debug 日志（运行期五类失败原因） |
| 4. 远程 AI 推断 | `ai_parser.rs:110-130` 的 `RemoteAiParser` 返回 `NotImplemented`（`TODO ingest-ai-parser-remote`） |
| 5. 提工单 | 若样本来自新厂商，按 `tests/fixtures/logs/SOURCES.md` 的方式补样本 + 模板 + 正负样本回归 |

### 7.2.1 Rust 动态库插件（`engine: plugin`）的部署与排障

| 项 | 口径 |
|---|---|
| 插件目录 | `AGF_INGEST_PLUGIN_DIR`（未配置时 `<项目根>/plugins`，容器里建议显式挂载该路径）；**未配置且缺省目录不存在 ⇒ 不装载**（缺插件不是错误，进程照常启动）；填 `0`/`off`/`none`/`false` ⇒ **显式关闭** |
| 超时 | `AGF_INGEST_PLUGIN_TIMEOUT_MS`（默认 `500`；`0` = 不启用超时 = 同线程直调，插件卡死会拖住解析线程） |
| 装载时机 | 进程启动期一次性装载（`apps/ingest` 的插件目录加载段 → `agf_ingest::engine::plugin::install_plugin_runtime_from_env`）；**坏插件只 `warn` 并登记**，同一目录里的好插件照常可用 |
| 模板写法 | `engine: plugin` + `pattern: "plugin=<插件名> [entry=normalize] [ctx=raw\|envelope]"`；`entry` 只接受 `normalize`（ABI v1 只有一个入口），`ctx=envelope` 时插件收到 `{"input": 原始行, "context": {protocol, source, received_at}}` |
| 输出约定 | 插件返回**顶层为对象**的 AGF-ECS JSON；宿主把嵌套对象扁平化成点号键后走**既有**`mapping`/归一化路径（`mapping.map` 用**插件输出的字段名**书写，`mapping.time_field: "@timestamp"` 可把插件时间戳落到 `event.time`） |
| 观测 | `GET /readyz` 的 `notes`（**启动期快照**：装载数 / 装载失败清单）与 `capabilities`；运行期调用失败计数与最近 32 条诊断经库 API `agf_ingest::engine::plugin::plugin_runtime_status()` 读取，并按 `RUST_LOG=info,agf_ingest::engine::plugin=debug` 打进进程日志 |
| 失败五分类 | `unavailable`（未装载运行时）/ `unknown_plugin`（名字不在已装载集合）/ `call_error`（插件业务失败）/ `bad_output`（非法 JSON、顶层非对象、空对象）/ `timeout`。**五类都只让该模板未命中**：原始日志照常落库、事件按 raw 兜底，绝不 panic、绝不静默丢弃 |
| 排障顺序 | ① 看 `/readyz` 的 notes 是否有装载失败（ABI 不匹配 / 缺符号 / 非法描述符 / 非法动态库，原因逐条写明）；② 确认 `pattern` 里的插件名与插件描述符的 `name` **逐字一致**；③ 用 `cargo test -p agf-plugin` 的样例确认插件本身能被装载与调用；④ 超时类问题看插件内部是否阻塞（宿主无法中断它） |
| 真机验证 | `pwsh tools/simulators/verify_plugin_engine.ps1`（起 `agf-ingest` → 打 webhook → 断言事件字段来自插件；覆盖坏插件、非法 JSON、目录缺失、关闭插件四条降级路径） |
| 安全边界 | 插件与宿主**同进程、同权限**：加载即执行其初始化例程，可读写任意文件/发起任意网络请求。**只应加载可信来源的插件**；本平台不提供沙箱，需隔离必须换进程边界 |

### 7.3 Redis 不可用

| 影响面 | 降级行为 | 依据 |
|---|---|---|
| 存储层启动 | **不阻塞启动**；`build_store` 把 Redis 失败收集为降级说明并返回 `redis = None` | `crates/agf-storage/src/lib.rs:112-118` |
| 缓存读写 | `get_string` 失败返回 `Ok(None)`（视作缓存未命中）；`set_string` 失败仅告警 | `redis_store.rs:137-164` |
| 配额检查 | `fail_closed = true` → 返回 `DependencyUnavailable`（**拒绝服务**）；`false` → 记录告警后放行 | `redis_store.rs:323-353` |
| 分布式锁 | **返回错误而不是假定成功**（避免多实例同时执行同一任务） | `redis_store.rs:224-241` |
| 语义缓存 | 网关自动降级为纯内存实现，功能不中断 | `crates/agf-aigw/src/lib.rs:31` |
| 计数器 | `incr` 失败返回 `Ok(None)` | `redis_store.rs:272-289` |

**处置**：`docker compose ps agf-redis` → `docker compose logs agf-redis` → `docker compose restart redis` →
若为内存策略导致逐出，检查 `--maxmemory 512mb` / `--maxmemory-policy allkeys-lru`
（`docker-compose.yml:116-125`）。

### 7.4 队列不可用（NATS）

| 项目 | 事实 |
|---|---|
| 健康检查 | `wget -q -O - http://127.0.0.1:8222/healthz`（`docker-compose.yml:154`） |
| 数据目录 | `${AGF_DATA_DIR}/nats` |
| 开关 | `AGF_NATS_ENABLED=0` → 进程内广播（`.env.example:94` 明确"置 0 则用进程内广播"） |
| Stream 名 | `AGF_NATS_STREAM=AGF_EVENTS` |
| 影响 | `agf-server` / `agf-ingest` / `agf-scheduler` 的 `depends_on` 均要求 `nats: service_healthy`，NATS 不健康时这三个容器**不会启动** |

### 7.5 磁盘写满

| 优先级 | 动作 |
|---|---|
| 1 | 确认哪个卷满：`& scripts\selfcheck.ps1`（分项占用）或宿主机磁盘工具 |
| 2 | `data/backup` 满 → prod sidecar 保留最近 7 份，手工清理更早的 `agf-*.dump` |
| 3 | `data/pg` 满 → 清理软删除（`Database::purge_soft_deleted`）+ 检查 WAL；**不要**手工删 `data/pg` 内文件 |
| 4 | `data/evidence` / `data/minio` 满 → 归档对象转移；确认对象存储后端（`AGF_S3_ENDPOINT` 为空时降级为本地 `<data_dir>/objects`） |
| 5 | `data/clickhouse` 满 → 按 `retention_plan` 的 DETACH 过期分区 |
| 6 | 应急腾挪 → 在 `docker-compose.prod.yml` 中把 `agf-server` 的 `tmpfs: /tmp:size=64m` 调大（只读根文件系统下 `/tmp` 是唯一可写临时区） |

### 7.6 容器启动失败排查表

| 症状 | 可能原因 | 处置 |
|---|---|---|
| `docker compose up` 报 `AGF_PG_PASSWORD 必须设置` | 缺少 `.env` | `pwsh -File scripts/init-env.ps1 -Force`（幂等，已存在的 `.env` 会先备份为 `.env.bak-<时间戳>`） |
| 报 `AGF_S3_SECRET_KEY 必须设置` / `AGF_JWT_SECRET 必须设置` / `AGF_MASTER_KEY_BASE64 必须设置` | 同上（compose 使用 `${VAR:?msg}` 强制校验） | 同上 |
| 报 `AGF_GRAFANA_ADMIN_PASSWORD 必须设置` | 只在使用 `--profile grafana` 时触发 | 同上 |
| ~~`agf-server` 反复重启~~ **已闭环** | 曾因 `healthcheck` 子命令未实现；现 `agf-server healthcheck --url` 已实现（探针短路，不初始化配置与日志，配置损坏时也能给出退出码） | PV-001（实测 8 容器全部 healthy）；DOC-PV-021 ✅ |
| ~~`agf-ingest` healthcheck 永久失败~~ **已闭环** | 曾因 runtime 镜像是 distroless、**不含 `wget`**；现三个应用容器统一改用二进制自带的 `healthcheck --url` 子命令 | 同上 |
| 控制台 404 / 空白 | 静态产物缺失或 nginx 未起来 | `docker compose logs agf-web`；确认 `apps/web/dist/index.html` 存在 |
| 控制台接口全部失败但页面可用 | API 不可达（进程未启动 / 端口不通 / 鉴权失败）——**API 本身已实现**（`/api/v1/**` 已注册，501 端点为 0），此时前端进入演示降级模式 | 见 `apps/web/src/components/DemoModeBanner.tsx` 与 `apps/web/src/api/demo/` |
| compose 校验失败 | 变量插值缺失 | `docker compose config --quiet`（`Justfile:59`）或 `& scripts\selfcheck.ps1` 的"compose 配置"检查项 |

### 7.7 首次部署与管理员口令

| 步骤 | 命令 | 说明 |
|---|---|---|
| 1 | `pwsh -File scripts/init-env.ps1` | 默认 `-WhatIf` 只打印计划；生成 `.env` 时随机生成 `AGF_PG_PASSWORD` / `AGF_S3_SECRET_KEY` / `AGF_JWT_SECRET` / `AGF_MASTER_KEY_BASE64`（32 字节 base64）/ `AGF_GRAFANA_ADMIN_PASSWORD` / `AGF_BOOTSTRAP_ADMIN_PASSWORD` |
| 2 | `pwsh -File scripts/init-env.ps1 -Force` | 覆盖已存在的 `.env`（先备份为 `.env.bak-<时间戳>`） |
| 3 | `pwsh -File scripts/init-env.ps1 -ShowSecrets` | 在控制台回显生成的引导管理员账号与口令 |
| 4 | `& scripts\selfcheck.ps1` | 校验 JWT 密钥长度 ≥32、主密钥解码后 32 字节、数据库口令 ≥12 字符 |
| 5 | `docker compose up -d` | 首启由 `agf-server` 的内嵌 SQLx 迁移初始化 schema，并写入 `_sqlx_migrations`；不把应用迁移挂入 PostgreSQL initdb |
| 6 | 首登改密 | `AGF_FORCE_PASSWORD_CHANGE=1`（默认）。⛔ 强制改密的执行点在 `agf-server`/`agf-auth` 的登录流程，服务未落地前**无法实际验证** |

> **重要**：应用迁移只由服务启动或 `agfctl migrate` 执行，不能交给 PostgreSQL initdb 重复执行。历史 0001 的四个源码分片按原字节合并，校验和与现有数据库一致；后续结构变更只能新增迁移版本。

### 7.8 升级与回滚

| 阶段 | 动作 | 依据 |
|---|---|---|
| 升级前 | ① `pg_dump`（`Database` 层或 prod backup sidecar）；② 记录 `AGF_IMAGE_TAG` 当前值 | `.prod.yml:196-206` |
| 镜像升级 | `AGF_IMAGE_TAG=<新版本>` → `docker compose pull` → `docker compose up -d` | `AGF_IMAGE_TAG` 默认 `0.1.0` |
| 数据库迁移 | 新迁移文件落 `deploy/sql/migrations/`（文件名递增），由应用启动时 `MIGRATOR.run()` 执行；无回滚脚本（仅向前） | `db.rs:28,99-105` |
| 回滚（仅代码） | `AGF_IMAGE_TAG=<旧版本>` → `docker compose up -d` | — |
| 回滚（含数据库） | 从备份恢复：`pg_restore`（backup sidecar 产物为 `--format=custom`） | `.prod.yml:200` |
| 回滚校验 | `curl http://127.0.0.1:8080/healthz`（**已实现**，200 即通过）；辅以 `docker compose ps` + `Store::server_info()` 的 `rls_enabled_tables` 计数 | — |

> **注意**：`scripts/backup.ps1` / `scripts/restore.ps1` 被 `Justfile:153,156` 引用，现**均已在 `scripts/` 落地**
> （`docs/pending-verification.docs.md` DOC-PV-008 已闭环）；亦可直接用 `pg_dump` / `pg_restore` 或 prod 的 backup sidecar。

---

## 8. 运维检查清单（Copy-Paste）

```powershell
# ---- 环境与路径纪律 ----
& scripts\selfcheck.ps1                       # 分项自检；退出码 1 表示存在阻断项
& scripts\selfcheck.ps1 -Json                 # 机器可读（CI 用）
& scripts\selfcheck.ps1 -SkipDocker           # Docker 未启动时
& scripts\selfcheck.ps1 -WriteBaseline        # 记录只读工具链 mtime 基线

# ---- compose 健康 ----
docker compose config --quiet
docker compose ps
docker compose logs --tail=100 agf-server agf-ingest agf-scheduler agf-web

# ---- 依赖服务探活 ----
docker compose exec postgres pg_isready -U $env:AGF_PG_USER -d $env:AGF_PG_DB
docker compose exec redis redis-cli ping
docker compose exec nats wget -q -O - http://127.0.0.1:8222/healthz
docker compose exec minio mc ready local

# ---- 数据卷 ----
docker compose exec postgres psql -U $env:AGF_PG_USER -d $env:AGF_PG_DB -c "\dt"
docker compose exec postgres psql -U $env:AGF_PG_USER -d $env:AGF_PG_DB -c "SELECT count(*) FROM pg_tables t JOIN pg_class c ON c.relname=t.tablename WHERE c.relrowsecurity"

# ---- 审计链 ----
cargo test -p agf-core audit                  # 核心算法单测

# ---- 控制台真实路由（从 nginx 同源入口访问；不会修改业务数据） ----
python scripts/verify-web-routes.py http://127.0.0.1:8081  # 左侧菜单/登录页及全部打包资源；无需登录
$taskPassword = Read-Host '当前管理员口令' -AsSecureString
$taskPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($taskPassword)
try { $env:AGF_LIVE_PASSWORD = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($taskPointer) }
finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($taskPointer) }
python scripts/verify-console-paths.py http://127.0.0.1:8081 --read-only
# 需要同时核对内置演示记录时：
python scripts/verify-console-paths.py http://127.0.0.1:8081 --read-only --require-demo-data
Remove-Item Env:AGF_LIVE_PASSWORD
Remove-Variable taskPassword, taskPointer
```

`verify-web-routes.py` 会从当前左侧菜单读取路径，检查每个 SPA 地址和实际引用的 JS/CSS 分包，防止部署时遗漏页面资源；它不模拟点击或表单操作。`--require-demo-data` 会要求扫描、红队等内置演示记录可读；接入管理的日志源和数据源在管理员配置前保持空列表是正常状态。先在控制台填写连接目标、认证方式并执行连接测试，再开始真实数据采集。首次启动遇到强制改密时应在控制台完成，随后使用新口令运行只读检查。

---

## 9. 运维相关的真实缺口索引

以下项目均已在 `docs/pending-verification.docs.md` 中逐条登记，运维排障时请以该文件为准确认"是缺陷还是未实现"：

| 缺口 | 编号 |
|---|---|
| ~~HTTP API / 健康端点 `/healthz` / 指标 `/metrics` 未实现~~ **已闭环** | DOC-PV-001、DOC-PV-020、DOC-PV-021 |
| ~~`agf-server` / `agf-ingest` / `agf-scheduler` 二进制为脚手架~~ **已闭环** | DOC-PV-001、DOC-PV-003 |
| ~~`agfctl`（`genkey` / `migrate` / `db check-schema` / 备份恢复）未实现~~ **已闭环**（真库路径受 PV-001 约束） | DOC-PV-004 |
| ~~`rules/` 无 YAML 规则（只有生成器脚本）~~ **已闭环**（54 条） | DOC-PV-009 |
| ~~`scripts/gate.ps1`、`dev-up.ps1`、`coverage.ps1`、`backup.ps1`、`restore.ps1` 缺失~~ **已闭环**（全部在 `scripts/`） | DOC-PV-007、DOC-PV-008 |
| ~~冷归档 Parquet 未实现（当前 gzip NDJSON）~~ **已闭环**（默认列式 Parquet/SNAPPY，编码失败自动回落 gzip NDJSON） | DOC-PV-019 ✅ |
| ~~Kafka/Pulsar/MQTT/SNMP/JDBC/OTLP（入向接收）/OSS 拉取未实现~~ **已闭环**（Syslog TLS、Kafka、Pulsar 经 KoP、MQTT、SNMP Trap、JDBC、OTLP HTTP+gRPC、OSS 拉取均已实现；Pulsar 原生协议仍待；SNMP v3 `authPriv`（CBC-DES/CFB128-AES-128）与冷归档 Parquet 的 arrow 列式回灌**已实现**） | DOC-PV-011、PV-016 ✅ |
| **事件总线（发布侧）**不是 JetStream；`AGF_NATS_ENABLED=0` 不改变任何运行行为。**入向** JetStream 订阅是另一件事：已实现并装配（`AGF_INGEST_JETSTREAM_URL`，能力矩阵 `nats-jetstream` 行） | DOC-PV-029 |
| "语义缓存"实为 SHA-256 精确缓存（无 embedding） | DOC-PV-028 |
| `.env.example` 中大量变量在 Rust 中零引用（§10 全部 22 个 LLM 变量、§14 全部通知渠道、**新增的 email 变量**等） | DOC-PV-027 |
| ~~Helm Chart 已补齐但未实测渲染~~ **已闭环**（`helm lint` 0 failed / `helm template` 三套 values 渲染成功） | DOC-PV-006 |

> ✅ **运维脚本现状（已核对 `scripts/` 实有文件）**：
> **可用**：`env.ps1`（环境初始化）/ `lib.ps1`（公共库）/ `init-env.ps1`（生成 `.env`）/
> `selfcheck.ps1`（零依赖自检）/ `gen-fixtures.ps1`（合成夹具）/ `fetch-fixtures.ps1`（公开样本抓取）/
> `seed.ps1`（灌演示数据）/ `demo.ps1`（单机全链路演示）/ `gate.ps1`（门禁）/
> `dev-up.ps1`（起依赖）/ `coverage.ps1`（覆盖率）/ `backup.ps1` / `restore.ps1` /
> `parsers-stats.ps1` / `verify-console-paths.py`（控制台路径全覆盖收口）。
> **无缺失项**（DOC-PV-007/008 的 5 个脚本现已全部存在）。
>
> 排障时常用的两个离线诊断入口：
> ```powershell
> pwsh -File scripts/demo.ps1 -LocalOnly -WhatIf   # 打印 6 阶段全链路演示计划（不读数据、不探测后端）
> pwsh -File scripts/seed.ps1 -WhatIf              # 打印将要灌入的数据集与条数
> ```
