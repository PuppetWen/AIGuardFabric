# AIGuardFabric 架构设计

> 事实来源：`Cargo.toml`（workspace 成员与依赖）、`crates/*/Cargo.toml`（crate 间依赖）、
> `crates/*/src/lib.rs`（模块地图）、`deploy/sql/migration_parts/`、
> `docker-compose*.yml`、`deploy/docker/Dockerfile`、`deploy/docker/nginx.conf`、`apps/web/src/app/router.tsx`。
>
> ⚠️ **架构图描述的是设计意图与已落地的库结构**。`agf-api` 与 `apps/*`（`agf-server` / `agf-ingest` /
> `agf-scheduler`）**已落地**（端点与运行时行为经真实进程探测核对，见 §7）；`agf-cli` / `agf-correlate` /
> `agf-adapters` / `agf-agent` / `parsers/` **本轮由其它并行任务实现中**，图中相关边界标注为「🚧 实现中（本轮）」，
> 本文不对其下结论。逐项状态见 §7，缺口编号见
> [`docs/pending-verification.docs.md`](pending-verification.docs.md)。
>
> 📏 **规模数字的口径**：本文件的"行数"均为**本轮实测**——读取文件全文后统计 `\n` 字节数
> （不用 `Get-Content | Measure-Object -Line`：PowerShell 5.1 以 ANSI 解码 UTF-8 时会吞掉部分换行导致少算）。

---

## 1. 分层架构

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  展示层  apps/web（React 19 + Vite）                                          │
│  21 个页面 · TanStack Query · Zustand(2) · i18next(zh-CN/en-US) · AntV G6      │
│  API 不可达 → 自动演示降级（apps/web/src/api/demo/*，约 7.4k 行确定性数据）      │
└───────────────────────────────┬──────────────────────────────────────────────┘
                                │ REST /api/v1（控制台调用面已全覆盖）+ /ws
┌───────────────────────────────▼──────────────────────────────────────────────┐
│  接入层  agf-api 🟢(20,926 行) · apps/server 🟢(336) · apps/ingest 🟢(385) ·   │
│          apps/scheduler 🟢(421)                                              │
│  已落地：Axum 0.8 路由 · RFC 9457 problem+json · OpenAPI 3.1(utoipa, 75 路径) · │
│        三级限流(X-RateLimit-*) · Idempotency-Key · 长任务 task_id · 优雅停机   │
│  另：agf-ingest 的 receiver 提供 axum Router（Webhook / 采集器上行）            │
└───────────────────────────────┬──────────────────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────────────┐
│  运行时  agf-runtime 🟡修复中                                                  │
│  mcp_proxy · policy(Rego/CEL/结构化) · guard · blocklist · quota ·            │
│  approval · audit · signature                                                 │
└───────────────────────────────┬──────────────────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────────────┐
│  领域层（业务能力，已实现，纯逻辑 + 可注入存储）                                │
│  agf-asset  资产发现/指纹/拓扑/漂移/生命周期                                   │
│  agf-scan   规则引擎/加载器/正负样本/五大域/红队编排                            │
│  agf-aigw   大模型统一网关（厂商适配/转换/路由/缓存/计量/预筛/Mock）             │
│  agf-ingest 协议接入/解析引擎/AGF-ECS 归一化/回放/冷归档                        │
│  agf-auth   认证(Argon2id/JWT/TOTP/APIKey) 与授权(RBAC+ABAC)                   │
│  agf-correlate 🚧实现中（本轮）（关联/链路还原/SOAR-lite）                      │
└───────────────────────────────┬──────────────────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────────────┐
│  集成层  agf-alicloud（六适配器 + Mock + 自检） · agf-adapters 🚧实现中（本轮）  │
│         统一 agf-core::adapter::Adapter 契约 + 熔断/重试/死信                  │
└───────────────────────────────┬──────────────────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────────────┐
│  存储层  agf-storage                                                          │
│  PostgreSQL 16+TimescaleDB（RLS/迁移/Repo） · Redis（Lua 配额/缓存/锁/限流）    │
│  对象存储（S3/MinIO/OSS ← 本地目录 ← 内存，三级自动降级） · AES-256-GCM 字段加密 │
└───────────────────────────────┬──────────────────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────────────┐
│  领域内核  agf-core（36 个模块 / 16,758 行，零 I/O 依赖，可离线完整单测）        │
│  领域模型 · DomainError · UUIDv7/时间戳 · enums 共同语言 · 安全原语            │
│  (secret/redact) · 适配器契约 · 哈希链审计 · 配置解析与打码                     │
└──────────────────────────────────────────────────────────────────────────────┘
```

**分层依赖铁律**：`agf-core` 只依赖纯计算与序列化（无 DB / HTTP / MQ，见 `crates/agf-core/src/lib.rs:1-8`）；
`agf-storage` 只依赖 `agf-core`；领域 crate 依赖 `agf-core`（+ 按需 `agf-storage`）；
`agf-api` 是唯一同时依赖全部领域 crate 的聚合点；`agf-runtime` **刻意不依赖 `agf-aigw`**（见 `crates/agf-runtime/Cargo.toml` 注释：反向依赖会造成 crate 环）。

---

## 2. 17 个 workspace 成员

`Cargo.toml` 的 `members` 与 `default-members` 列出**完全相同的 17 项**（14 crate + 3 app）。

### 2.1 依赖关系图（实线 = `Cargo.toml` 中声明的真实依赖）

```mermaid
graph TD
    WEB["apps/web<br/>(React 控制台)"]
    API["crates/agf-api<br/>🟢 23 文件 / 20,926 行"]
    SRV["apps/server<br/>🟢 336 行"]
    INGB["apps/ingest<br/>🟢 385 行"]
    SCH["apps/scheduler<br/>🟢 421 行"]
    CLI["crates/agf-cli<br/>🚧 实现中（本轮）"]

    AUTH["crates/agf-auth"]
    ASSET["crates/agf-asset"]
    SCAN["crates/agf-scan"]
    AIGW["crates/agf-aigw"]
    ING["crates/agf-ingest"]
    CORR["crates/agf-correlate<br/>🚧 实现中（本轮）"]
    RT["crates/agf-runtime<br/>🟡 修复中"]
    ADPT["crates/agf-adapters<br/>🚧 实现中（本轮）"]
    ALI["crates/agf-alicloud"]
    AGENT["crates/agf-agent<br/>🚧 实现中（本轮）"]

    ST["crates/agf-storage"]
    CORE["crates/agf-core"]

    WEB -.->|HTTP /api/v1| API
    SRV --> API
    SRV --> AUTH
    SRV --> ASSET
    SRV --> SCAN
    SRV --> AIGW
    SRV --> ING
    SRV --> CORR
    SRV --> RT
    SRV --> ADPT
    SRV --> ALI
    INGB --> ING
    INGB --> ASSET
    SCH --> ASSET
    SCH --> SCAN
    SCH --> ING
    SCH --> CORR
    SCH --> ALI
    CLI --> AUTH
    CLI --> ASSET
    CLI --> SCAN
    CLI --> API
    CLI --> ALI
    CLI --> ADPT

    API --> AUTH
    API --> ASSET
    API --> SCAN
    API --> AIGW
    API --> ING
    API --> CORR
    API --> RT
    API --> ADPT
    API --> ALI

    AUTH --> ST
    ASSET --> ST
    SCAN --> ST
    AIGW --> ST
    ING --> ST
    ING --> ASSET
    CORR --> ST
    RT --> ST
    ADPT --> ST
    ALI --> ST
    AGENT --> CORE
    ST --> CORE
```

> **注**：`agf-runtime` **不依赖 `agf-aigw`**（`crates/agf-runtime/Cargo.toml` 的注释明确说明：南北向网关联动由 `agf-aigw` 侧实现，网关只通过 `agf_runtime::engine::RuntimeEngine` 的公开入口 `evaluate` / `intercept_*` / `complete_call` / `guard_report` 调用运行时防御）。但 `agf-aigw` 的 `Cargo.toml` 当前也**没有**声明 `agf-runtime` 依赖，因此这条联动在代码层尚不存在。

### 2.2 逐成员职责

| # | 成员 | 类型 | 源码规模 | 职责（取自 crate 文档与模块地图） |
|---|---|---|---|---|
| 1 | `crates/agf-core` | lib | 36 模块 / 16,758 行 | **领域内核**。领域模型、`DomainError`、UUIDv7/时间戳/分页、跨域枚举、多租户与身份模型、资产域模型、风险与治理域模型、日志告警与案件域模型、集成与平台能力模型、安全原语（`secret`/`redact`）、统一适配器契约、哈希链审计、配置解析与自动打码。**无 I/O 依赖**（模块数以 `lib.rs` 的 `pub mod` 声明数实测） |
| 2 | `crates/agf-storage` | lib | 7 模块 / 4,489 行 | **存储层**。`db`（连接池 + 内嵌迁移 + `TenantTransaction` 租户上下文事务）、`crypto`（AES-256-GCM 字段加密，AAD 绑定租户与记录 id）、`redis_store`（缓存 / Lua 原子三级配额 / 分布式锁 / 固定窗口限流）、`objectstore`（S3 / 本地 / 内存三实现 + 自动降级）、`repository`（7 个 Repo + `Store` 聚合 + `PlatformStats`）、`config`（`StorageConfig`） |
| 3 | `crates/agf-auth` | lib | 7 模块 / 2,493 行 | **认证与授权**。`password`（Argon2id + 口令策略 + 需要 rehash）、`claims`（JWT 访问/刷新令牌对、Bearer 提取、刷新指纹）、`mfa`（TOTP + 恢复码）、`api_key`（`agf_live_`/`agf_test_` 前缀、指纹、轮换）、`rbac`（角色→权限点 + ABAC 条件：部门/数据分级/来源网段 CIDR）、`service`（`AuthService`：登录/改密/刷新/登出，`AuthBackend` trait，`InMemoryAuthBackend`） |
| 4 | `crates/agf-asset` | lib | 6 模块 / 3,373 行 | **资产域**（§4.1）。`fingerprint`（去重键、类型推断、暴露面入参、内容哈希）、`topology`（由资产+依赖构图、可达性、外传路径、影响面）、`drift`（基线快照对比、日间 diff、未授权资产判定）、`discovery`（终端上报 / Git 扫描 / 网段扫描 / 手工 → 统一 `DiscoveredAsset`）、`service`（幂等入库、生命周期流转、盘点统计、快照与漂移；经 `AssetBackend` trait 与存储解耦） |
| 5 | `crates/agf-scan` | lib | 8 模块 / 5,898 行 | **风险治理与 AI 红队**（§4.2）。`detector`（把 `Detection` 编译成匹配器并执行：regex/keyword/keyword-all/entropy/encoding-bypass/ast/yara/semantic/composite）、`loader`（从目录递归加载 YAML 规则包，校验正负样本、去重、灰度、版本、`pack_fingerprint`）、`samples`（正负样本自动回归 + 20 条内置负样本基线）、`domains`（五大安全域专项检测器）、`engine`（`ScanEngine`：规则 + 域检测器 + 可选 LLM 二次研判）、`redteam`（用例库加载、`CampaignRunner` 编排、`RedteamSimulator` 离线模拟、报告与 finding 产出） |
| 6 | `crates/agf-aigw` | lib | 11 模块 / 11,088 行 | **大模型统一网关**（§4.4）。`wire`（canonical 协议，纯 serde）、`convert`（canonical ↔ OpenAI/Anthropic/Gemini 格式 + SSE 增量解析）、`provider`（`ProviderAdapter` 契约 + OpenAI 兼容族 / Anthropic / Gemini / Bedrock 四实现）、`router`（5 种路由策略 + 数据分级门禁 + 降级链）、`cache`（SHA-256 精确指纹缓存，内存/Redis）、`meter`（token/成本计量 + `BudgetGuard`）、`screen`（内容安全前置/后置过滤）、`gateway`（`AiGateway` 编排）、`mock`（`MockProvider`） |
| 7 | `crates/agf-ingest` | lib | 13 模块 / 11,168 行 | **统一日志与告警接入**（§4.5）。`syslog`（RFC3164/5424、TCP 分帧、TCP/UDP 监听）、`engine`（10 类解析引擎）、`template`（18 个内置厂商模板）、`registry`（模板注册表 + 优先级匹配 + 样本打分）、`normalize`（→ AGF-ECS `Event`）、`ai_parser`（无模板时的推断）、`pipeline`（去重→解析→归一化→脱敏→落库→投递；`Sink` 抽象）、`bus`（内存/Noop/NATS 发布）、`replay`（原始日志回放 + 差分报告）、`coldarchive`（列式 Parquet / NDJSON 冷归档 + 保留策略）、`receiver`（Webhook / 文件 tail / HTTP Pull / 采集器上行；各协议接收器见 `receiver_capability_matrix()`） |
| 8 | `crates/agf-correlate` | lib | 9 文件 / 9,118 行 | 🟢 **已实现**。跨源实体对齐、告警聚合降噪（`AlertAggregator`）、攻击链路还原、SOAR-lite 剧本（CEL 真求值）；**如实保留**：SLA 暂停窗口恒 0、聚合簇不落库、通知去重/限流状态在进程内（见 `docs/pending-verification.md` PV-030） |
| 9 | `crates/agf-runtime` | lib | 13 模块 / 12,154 行 | **运行时防御**（§4.3）。`mcp_proxy`（MCP 代理拦截点）、`policy` + `rego` + `cel`（策略引擎三形态）、`guard`（守卫）、`blocklist`（命令黑名单/工具白名单/域名出网）、`quota`（三级配额）、`approval`（人工审批）、`audit`（拦截审计）、`engine`（`RuntimeEngine` 公开入口）、`signature`（策略签名）。**该 crate 正在修复，行为细节见源码** |
| 10 | `crates/agf-adapters` | lib | 22 文件 / 8,300 行 | 🟢 **已实现**。`contract` / `registry` / `vendor` / `health` / `transport` / `settings` / `http` + `vendors/` **11 个厂商模块**，**全部具备真实传输**（通知 HTTP / `email` 真实 SMTP / 工单 REST 建单 / EDR 隔离下发 / Syslog UDP·TCP），并**按协议支持实现 `push`/`pull`/`sync`**（`jira`/`servicenow`/`zentao`/`edr` 三条全有，`slack` 有 `push`；其余如实登记 `Unsupported` + 原因，能力矩阵 `crates/agf-adapters/CAPABILITY-MATRIX.md` 为唯一事实源）。13 个 `AGF_<VENDOR>_ENABLED` 开关由 `agf-core/src/config.rs:570-587` 解析，但**适配器实现不读它们**（从 `AdapterConfig.settings` 取参） |
| 11 | `crates/agf-alicloud` | lib | 16 模块 / 12,369 行 | **阿里云六适配器**（§5）。`cms` / `apig` / `mse` / `privatelink` / `schedulerx3` / `agentteams` 六服务适配器、`signer`（RPC HMAC-SHA1 与 V3 ACS3-HMAC-SHA256）、`credential`（RAM Role/STS/AssumeRole/长期 AK 风险登记）、`endpoint`（公网 + PrivateLink 私网 endpoint 与地域映射）、`http`（`RpcClient`，Mock 模式下闸门关闭）、`mock`（六服务确定性 Mock + 描述符）、`selfcheck`（连通性/最小权限/配额余量 + RAM 策略 + Markdown 报表）、`registry`（`AliCloudRegistry` 按配置构建六适配器）、`deadletter`（离线缓存 + 死信 + 恢复重放） |
| 12 | `crates/agf-api` | lib | 23 文件 / 20,926 行 | 🟢 **HTTP / GraphQL / WebSocket API 宿主（已落地）**。Axum 0.8 路由（`routes/` 下 auth/assets/ai_assets/governance/soc/ingest/ecosystem/console/console_ops/platform 十个资源组）、RFC 9457 `problem+json`（`error.rs`）、三级限流 + 幂等 + 请求上下文中间件（`middleware.rs`）、认证主体 `Principal`（REST 与 GraphQL 共用同一 RBAC/ABAC 守卫）、`GET /ws`（事件面经 NATS `agf.ws.*`，NATS 不可用时退回进程内广播）、`/metrics`、`/healthz` `/readyz`、`GET /api/v1/openapi.json`（实测 **OpenAPI 3.1.0 / 120 条路径 / 17 个 schema / 声明 501 为 0**）。**资源读写已切到 PG 写后持久化**（`persistence.rs` 的 `PersistenceReport` 是唯一事实源），**501 端点 0 条**。**是唯一同时依赖全部领域 crate 的聚合点** |
| 13 | `crates/agf-auth` | — | 见 #3 | — |
| 14 | `crates/agf-agent` | lib | 16 文件 / 5,782 行 | 🟢 **已实现**。终端采集器：采集清单 / 上报协议 / 客户端 / 本地队列 / 自更新接口（115 测试）；Windows 侧真实采集，Linux/macOS 走接口 + TODO 锚点。**"免改造纳管真实实例"仍需本机存在真实安装**（PV-003/PV-005） |
| 15 | `crates/agf-cli` | bin `agfctl` + lib | 模块化源码 | 🟢 **已实现**。`migrate` / `db check-schema` / `backup` / `restore` / `genkey` / `rules verify`（54/54）/ `redteam verify`（220 用例）/ `airgap bundle` + `verify` / `version`；`db check-schema` 对表、租户 RLS 策略与运行角色失败关闭，100 项库单测通过（PV-004/PV-023） |
| 16 | `apps/server` | bin `agf-server` | **336 行** | 🟢 **已实现**。dotenvy 载入 `.env`、tracing（pretty/json）+ OTLP span 导出（`AGF_OTLP_ENDPOINT` 门控，未设置时不建导出器）、连库并执行内嵌迁移、引导管理员（`must_change_password=true`，**口令绝不打印**，随机口令写 `<data_dir>/seed/bootstrap-admin.txt` 0600）、挂载 `agf-api` 路由、Ctrl-C/SIGTERM 优雅关闭；子命令 `healthcheck --url` / `migrate` / `bootstrap-admin`。PG 不可达时降级**离线内存模式** |
| 17 | `apps/ingest` | bin `agf-ingest`（package 名 `agf-ingest-bin`） | **385 行** | 🟢 **已实现**。Webhook(8090) + Syslog TCP/UDP(5514) + **Syslog TLS(6514)** + **OTLP/HTTP(4318 可选，默认挂主端口 `/v1/logs`)** + **OTLP/gRPC(4317)** 装配，Kafka/KoP-Pulsar/MQTT/SNMP Trap/JDBC/对象存储拉取按环境变量启用、解析流水线启动、`/healthz` `/readyz`（含接收器能力矩阵与未实现子能力的 TODO 锚点）/`/metrics`（syslog/webhook 基础族 + 接收器四族 + `matched_by` + Kafka 分区/lag + MQTT 链路 + JDBC + SNMP USM + 冷归档）、`healthcheck --url`。**不监听 8091**；落库默认内存 Sink |
| 18 | `apps/scheduler` | bin `agf-scheduler` | **421 行** | 🟢 **已实现**。`/healthz` `/readyz`（degraded 并说明原因）/`/tasks`（实现态 + 6 个 TODO 任务）/`/metrics`（`agf_scheduler_task_runs_total` 等）、`healthcheck --url`、优雅关闭；**已实现 `rules-regression`（严格加载 `rules/` 跑正负样本）与 `redteam-cruise`（220 用例、离线模拟目标、报告落 `data/reports/*.md`）**。`AGF_SCHEDULER_BACKEND=schedulerx3` 时告警并退回本地 cron |

（编号 1–17 为 workspace 成员；`apps/web` 是第 18 个 workspace 成员之外的前端工程，由 `pnpm-workspace.yaml` 管理，不参与 `cargo`。）

### 2.3 关键领域 crate 的内部结构

```mermaid
graph LR
    subgraph CORE["agf-core（零 I/O）"]
        ENUMS["enums 共同语言"]
        ERR["error: DomainError"]
        IDS["ids/time/pagination"]
        SEC["secret / redact"]
        ADP["adapter 契约"]
        AUD["audit 哈希链"]
        CFG["config 解析+打码"]
        DOM["领域模型<br/>asset/agent/mcp/skill/model/<br/>credential/risk/rule/redteam/<br/>policy/quota/event/source/<br/>parser/alert/case/notify/<br/>cloud/report/topology"]
    end
    subgraph ST["agf-storage"]
        DB["db: 连接池+迁移+租户事务"]
        CRY["crypto: AES-256-GCM"]
        RDS["redis_store: Lua 配额/锁/限流"]
        OBJ["objectstore: S3/本地/内存"]
        REPO["repository: 7 Repo + Store"]
    end
    CORE --> ST
```

---

## 3. 数据流

### 3.1 日志与告警流：接入 → 解析 → 归一化 → 事件 → 关联 → 告警 → 案件

```mermaid
sequenceDiagram
    autonumber
    participant DEV as 设备/云平台<br/>(Syslog/Webhook/文件/HTTP Pull/采集器)
    participant RCV as agf-ingest::receiver
    participant SINK as Sink (SqlSink / InMemorySink)
    participant PIPE as pipeline::IngestPipeline
    participant REG as registry::ParserRegistry
    participant ENG as engine (10 类解析引擎)
    participant NRM as normalize → AGF-ECS Event
    participant BUS as bus::EventBus<br/>(内存/Noop/NATS 发布)
    participant CORR as agf-correlate 🚧
    participant ALR as AlertRepo::upsert_dedup
    participant CAS as CaseRepo

    DEV->>RCV: 原始载荷 (bytes, origin)
    RCV->>PIPE: ingest_raw(source, protocol, payload, origin)
    PIPE->>SINK: put_raw(RawLog)  原始载荷保真入库
    PIPE->>REG: 按 vendor/product/protocol 选模板 + 样本打分
    REG-->>PIPE: ParserDefinition（优先级最高者）
    PIPE->>ENG: parse_with(def, raw) → ParseOutcome
    ENG-->>PIPE: fields + extra + unmapped
    PIPE->>NRM: normalize(outcome, SourceMeta, raw_text, origin) → Event
    Note over NRM: raw_hash = SHA-256(raw_text)<br/>未映射字段进 Event::extra（绝不丢弃）
    PIPE->>PIPE: redact_event(event, mode) 凭据脱敏
    PIPE->>SINK: put_event(Event)
    PIPE->>SINK: mark_raw(parsed=true, event_id)
    PIPE->>BUS: publish(Event)
    Note over BUS: 投递失败仅计数告警<br/>不回滚已落库事件
    CORR-->>ALR: 🟢 关联/实体对齐（已交付）
    ALR->>ALR: 按 dedup_key 聚合去重 upsert
    ALR->>CAS: 告警 → 案件 → case_events → timelines
```

**各环节的可核实事实**：

| 环节 | 实现 | 关键细节 |
|---|---|---|
| 去重 | `IngestConfig::dedup_window_secs`（默认 300） | `Event::dedup_key()` = 源 + 事件时间 + `raw_hash` |
| 解析 | `agf-ingest/src/engine.rs`，13 个引擎全部已实现 | Grok 为**自研展开**（内置 41 条 pattern，未知 pattern 退化为 `\S+` 并告警，不失败）；JQ 用纯 Rust 的 `jaq`；`Cel` 是**派生字段求值**（模板 `derived` 段，`cel-interpreter`），不能作主抽取引擎；`Plugin` 走 **Rust 动态库插件**（`engine/plugin.rs`：`agf_plugin_descriptor_v1` 稳定 ABI + `abi_version` 门禁 + `AGF_INGEST_PLUGIN_TIMEOUT_MS` 超时；插件输出 AGF-ECS JSON → 扁平化 → 既有 `mapping`/归一化路径；**不参与样本打分**，超时只放弃结果、同进程调用无法中断） |
| 模板选择 | `ParserRegistry` | 优先级匹配 + `sample_match_score`（阈值 `MATCH_THRESHOLD = 0.5`） |
| 归一化 | `normalize.rs` | `event.raw` 保结构（JSON 保 JSON），`message` 空则用原始文本截断 2048 字符；两者都过映射，未识别路径落 `Event::extra` |
| 脱敏 | `pipeline::redact_event` | 模式 `RedactionMode::CredentialsOnly`（默认） |
| 落库 | `Sink` trait 两实现 | `SqlSink` 走 `EventRepo` + 直写 `raw_logs.parsed/event_id/parse_error`；`InMemorySink` 用于离线单测 |
| 总线 | `bus.rs` | **只有 3 个实现**：进程内有界队列 / `NoopEventBus` / `NatsEventBus`（**核心协议发布，非 JetStream**）。`NatsEventBus` 不在 `prelude` 中，当前无实例化调用方。**入向** JetStream 订阅在另一个模块（`jetstream/**`，已装配） |
| 回放 | `replay.rs` | 只回放 `parsed = false` 的原始日志；**不改不删既有事件**，新结果作为新事件写入，差分进 `ReplayReport::diffs`；`mark_parsed` 默认 true |
| 冷归档 | `coldarchive.rs` | 对象键 `agf-events/dt=YYYY-MM-DD/hour=HH/events-<uuid>-<seq>.ndjson.gz`；热 30 天 / 冷 365 天 / `max_batch = 10_000` |
| 关联 | 🟢 `agf-correlate` 已交付 | 跨源实体对齐、告警聚合（`AlertAggregator`：聚簇/去重/抑制/降噪率）、攻击链路还原、SOAR-lite 剧本引擎（CEL 真求值）。API 侧 `POST /api/v1/alerts/aggregate` **已接真实引擎**；表 `timelines`、`AssetRepo`/`FindingRepo` 已就绪。**如实保留**：SLA 暂停窗口恒 0（`TODO(correlate-sla-persist)`）、聚合簇不落库（`TODO(correlate-aggregate-persist)`） |
| 告警 | `AlertRepo::upsert_dedup` | 返回 `(告警 id, 是否新建)`；`ix_alerts_dedup` / `ix_alerts_sla` 索引支撑去重与 SLA 扫描 |
| 案件 | `agf-core/src/case.rs` + `CaseRepo` | 表 `cases` / `case_events` / `timelines`；`playbooks` / `playbook_runs` 支撑 SOAR-lite |

### 3.2 请求流：请求 → 网关 → 策略 → 拦截审计

```mermaid
sequenceDiagram
    autonumber
    participant AGT as 被管 Agent / 客户端
    participant PROXY as agf-runtime::mcp_proxy 🟡
    participant RTENG as agf-runtime::engine (RuntimeEngine)
    participant POL as 策略引擎<br/>policy + rego + cel
    participant BL as blocklist
    participant QT as quota（Redis Lua）
    participant APR as approval
    participant AUD as audit（policy_hits）
    participant GW as agf-aigw::AiGateway
    participant SCR as screen::ContentScreen
    participant RT as router::ModelRouter
    participant PROV as ProviderAdapter<br/>(OpenAI兼容/Anthropic/Gemini/Bedrock/Mock)
    participant MET as meter::Meter

    AGT->>PROXY: MCP 工具调用 / 模型请求
    PROXY->>RTENG: intercept_*(...)
    RTENG->>POL: evaluate(输入) → allow/deny/audit/quota/redact
    RTENG->>BL: 命令黑名单 / 工具白名单 / 域名出网
    RTENG->>QT: check_and_consume（租户→Agent→会话）
    alt 需要人工审批
        RTENG->>APR: 挂起并创建审批请求
    end
    alt deny
        RTENG-->>AGT: PolicyDenied（0 成本，不触达上游）
        RTENG->>AUD: record_hit(policy_hits)
    else allow / redact
        RTENG->>GW: 放行（经 RuntimeEngine 公开入口）
        GW->>SCR: screen_request → Allow / Redact / Block
        Note over SCR: Block → PolicyDenied，零成本拦截，不计费
        GW->>RT: select(RoutingContext) → 有序候选链
        Note over RT: 硬过滤：enabled / 租户 / accepts_data_class<br/>Restricted 强制 local_deployment
        GW->>PROV: complete() 或 stream()（沿途熔断+重试+降级链）
        PROV-->>GW: ChatResponse / StreamChunk
        GW->>SCR: screen_response → 后置过滤
        GW->>MET: record(usage...) → Meter（内存态）
        GW-->>AGT: GatewayResponse（含 cached / mocked / fallback_used / cost_micro）
    end
```

**网关编排的精确顺序**（`agf-aigw/src/gateway.rs`）：
`幂等/预算检查 → screen_request → router.select → 缓存查询 → 逐端点调用（熔断 + provider.complete）→ screen_response → meter.record → write_cache`。

**Mock 降级的三层判定（在发出任何网络请求之前）**：

1. `self.mock_mode == true`（显式 `.with_mock_mode(true)`，**覆盖环境变量**）；
2. `endpoint.provider == LlmProvider::Mock`；
3. `!self.credential_available(endpoint)`（`credential_ref` 为空或解析器返回 `None`）。

环境变量 `AGF_MOCK_MODE` 的真值判定：trim 后等于 `"1"`，或忽略大小写等于 `"true"` / `"yes"`。

**流式请求的差异**：`chat_stream` **不做缓存读取、不写缓存**（`is_cacheable` 对 `stream == true` 返回 false）；流末必补一个带 `usage` 的结束分片；后置过滤在累积完成后**一次性执行**（避免逐分片切碎多字节字符）。

### 3.3 资产流：发现 → 指纹归并 → 入库 → 拓扑 → 漂移

```mermaid
graph LR
    A1["终端 Agent 上报<br/>DiscoverySource::AgentReport"] --> B["DiscoveryBatch"]
    A2["Git 仓库扫描<br/>DiscoverySource::GitScan"] --> B
    A3["网段扫描<br/>DiscoverySource::NetworkScan"] --> B
    A4["手工登记<br/>DiscoverySource::Manual"] --> B
    A9["云 API / 被动流量 / Collector<br/>Sidecar / Import"] -.->|"⛔ 无生产代码路径"| B
    B --> C["DiscoveredAsset<br/>（只描述事实）"]
    C --> D["AssetService::ingest<br/>find_by_fingerprint 幂等"]
    D -->|命中| E["只刷新可观测字段<br/>保留人工维护的 owner/department/<br/>lifecycle/data_class"]
    D -->|未命中| F["新建 + change_for_new + snapshot"]
    E --> G["TopologyBuilder::build"]
    F --> G
    G --> H["Topology（节点+边）<br/>reachable_from / shortest_path /<br/>find_exfil_paths"]
    G --> I["TopologySummary<br/>shadow / high_exposure / exfil_path_count"]
    F --> J["DriftScanner::diff<br/>基线快照 + 日间 diff"]
    J --> K["AssetChange（Added/Removed/Modified）<br/>risky 判定 → domain = ToolAbuse"]
```

**发现来源的精确枚举**（`agf-core/src/enums.rs:236-272`，9 个变体）：
`AgentReport` · `NetworkScan` · `CloudApi` · `PassiveTraffic` · `Manual` · `GitScan` · `Collector` · `Sidecar` · `Import`。
**代码中实际有产出路径的只有 4 个**：`AgentReport`（`DiscoveryBatch::from_agent_report`）、`GitScan`（`GitScanner::scan_local`）、
`NetworkScan`（`NetworkScanner::probe/scan`）、`Manual`（调用方指定）。其余 5 个仅存在于枚举中。

**拓扑边类型**（`agf-core/src/topology.rs`，8 个）：`AgentUsesMcp` · `McpExposesTool` · `ToolAccessesData` · `CallsModel` ·
`PromptDrivesModel` · `RagFeedsContext` · `UsesCredential` · `DependsOn`；其中前 6 类中 `carries_data()` 为真的 4 类
（`ToolAccessesData` / `CallsModel` / `RagFeedsContext` / `UsesCredential`）参与数据外传路径判定。

---

## 4. 多租户隔离机制

**三层防御，数据库层是最后且最强的一道。**

### 4.1 第一层：数据库 RLS

```sql
-- deploy/sql/migration_parts/0001_init_01.sql:42-48
CREATE OR REPLACE FUNCTION agf_current_tenant() RETURNS uuid AS $$
BEGIN
    RETURN NULLIF(current_setting('agf.tenant_id', true), '')::uuid;
EXCEPTION WHEN OTHERS THEN
    RETURN NULL;
END;
$$ LANGUAGE plpgsql STABLE;

-- :1514-1522（对 50 张表循环执行）
ALTER TABLE %I ENABLE ROW LEVEL SECURITY;
CREATE POLICY p_%1$s_tenant ON %1$s
  USING (tenant_id = agf_current_tenant())
  WITH CHECK (tenant_id = agf_current_tenant());
```

| 事实 | 位置 |
|---|---|
| RLS 启用表清单 | 历史迁移及后续增量迁移共同覆盖；2026-09-25 真实库核对为 **80/80 张含 tenant_id 的表**，每表有租户策略。`agfctl db check-schema` 对未来新增表与运行角色做失败门禁 |
| 策略语义 | `USING` 管读、`WITH CHECK` 管写；两者都要求 `tenant_id = agf_current_tenant()` |
| 超级管理员旁路角色 | `agf_platform_admin NOLOGIN BYPASSRLS`（`:1540-1542`），**应用正常连接不使用该角色** |
| 平台级操作 | `Database::begin_platform()` 不开租户上下文；此时访问任何 RLS 表都返回空集——**有意为之的安全默认值**（`agf-storage/src/db.rs:140-149`） |

### 4.2 第二层：`agf.tenant_id` 会话变量

```rust
// crates/agf-storage/src/db.rs:129-138
pub async fn begin_tenant(&self, tenant: TenantId) -> DomainResult<TenantTransaction<'_>> {
    let mut tx = self.pool.begin().await?;
    // SET LOCAL 不接受绑定参数，用 set_config 既参数化又只作用于当前事务
    sqlx::query("SELECT set_config('agf.tenant_id', $1, true)")
        .bind(tenant.to_string())
        .execute(&mut *tx)
        .await?;
    Ok(TenantTransaction { tenant, tx })
}
```

| 设计要点 | 说明 |
|---|---|
| `SET LOCAL` 语义 | 只在事务内生效，事务结束自动清理，**避免连接复用导致租户串号** |
| 唯一入口 | `Store::with_tenant(tenant, f)` 是所有租户级读写的唯一入口：成功自动提交、失败自动回滚（`repository.rs:77`） |
| 参数化而非拼接 | 用 `set_config($1, true)` 而非字符串拼接 `SET LOCAL`，从根源避免注入 |

### 4.3 第三层：应用层显式校验

| 机制 | 位置 | 语义 |
|---|---|---|
| `TenantTransaction::assert_owned(table, id)` | `db.rs:334` | 断言资源属于当前租户，否则返回 `DomainError::TenantViolation`。**把"越权"从静默 404 提升为显式审计事件** |
| `TenantScoped` trait | `agf-core/src/ids.rs` | 领域实体统一暴露 `tenant_id()`（如 `AdapterConfig`、`DeadLetterEntry`、`AuditLog`） |
| 服务层租户参数 | 所有 Repo 方法首参为 `&mut TenantTransaction` 或 `TenantId` | 编译期强制传递租户上下文 |
| Redis 键前缀 | `RedisStore::key(&[...])` 前缀 `AGF_REDIS_PREFIX`（默认 `agf`） | 多租户共用一个 Redis 实例时的隔离手段 |
| 网关侧租户过滤 | `ModelRouter::exclude_reason` | 端点租户不匹配即排除（保留 `TenantId::default_tenant()` 的全局端点） |
| JWT 声明 | `agf-auth/src/claims.rs` | 访问令牌携带租户，API 层据此建立租户上下文 |

### 4.4 隔离强度分级

| 级别 | 配置 | 现状 |
|---|---|---|
| **逻辑隔离** | `tenants.isolation = 'logical'`（默认租户种子值，迁移 `:1551-1561`） | ✅ RLS + 会话变量 + 应用校验 |
| **物理隔离** | `AGF_TENANT_PHYSICAL_ISOLATION=0`（默认关闭） | 🟡 配置项已存在；**独立库/独立 schema 的落地代码未见**（`tenant_settings` 表与 `tenants.isolation` 字段已预留） |

---

## 5. 关键设计取舍

### 5.1 为什么用运行时 SQL 而不是 `sqlx::query!` 宏

`crates/agf-storage/src/db.rs:3-9` 与 `crates/agf-storage/src/lib.rs:18-20` 明确记录了这个取舍：

| 维度 | `query!` 宏（编译期校验） | 运行时 `query(...)`（**本项目选择**） |
|---|---|---|
| 构建前提 | 构建机必须持有可用 PostgreSQL 实例（或提交 `.sqlx` 离线缓存） | 只需源码与 `Cargo.lock` |
| 与"离线可编译、单目录自包含"的关系 | **冲突**：CI/新机器无法仅凭仓库完成编译 | 兼容 |
| 类型安全补偿 | 编译期 | ① `sqlx::migrate!` 内嵌 `deploy/sql/migrations/`（编译期只读文件，`db.rs:28`）② 运行期表结构自检 `Database::missing_tables(&REQUIRED_TABLES)`（`db.rs:178`）③ `map_sqlx_err` 把 PostgreSQL 错误码（`23505`/`23503`/`23502`/`23514`）映射为语义化 `DomainError`（`db.rs:412`） |
| 动态表名 | 不支持 | 支持，但强制走 `is_safe_identifier()` 白名单校验（仅 ASCII 字母数字下划线、≤63 字符、不以数字开头） |

### 5.2 为什么"纯 Rust JQ"

`agf-ingest` 的 JQ 解析引擎使用 `jaq-core` + `jaq-std` + `jaq-json`（纯 Rust 实现），而非调用外部 `jq` 二进制：

| 收益 | 说明 |
|---|---|
| 零外部依赖 | 符合 §0 铁律"需要新装的东西一律落在项目内"——不引入非 Cargo 管理的二进制 |
| 单二进制容器 | distroless 运行时镜像内没有 shell 与包管理器（`Dockerfile:78`），无法安装 `jq` |
| 离线可测 | 单测无需准备外部进程 |
| 代价 | 与上游 `jq` 的语义差异需自行承担（`jaq` 为兼容实现而非同一代码库） |

同一取舍也体现在 `agf-alicloud`：**不依赖阿里云官方 SDK 的联网客户端**，而是自行实现 RPC 与 V3 签名（`agf-alicloud/src/signer.rs`），
以此保证"Mock 模式绝不发起真实 HTTP"这条不变量能由单一闸门（`http::RpcClient::live`）守死。

### 5.3 字段加密的 AAD 绑定

```rust
// crates/agf-storage/src/crypto.rs:98-100
pub fn make_aad(tenant: &TenantId, record: &Id) -> String {
    format!("tenant:{tenant}|id:{record}")
}
```

| 设计 | 目的 | 测试证据 |
|---|---|---|
| AES-256-GCM + 12 字节随机 nonce | 认证加密，抗篡改 | `nonce_is_unique_per_encryption`、`tampered_ciphertext_is_rejected` |
| **AAD = `tenant:<租户>\|id:<记录 id>`** | **防"密文搬家"**：把 A 租户的密文复制到 B 租户记录上会解密失败 | `aad_mismatch_fails_authentication`（断言替换 AAD 后必然解密失败） |
| 密文与 16 字节 tag 分开存储（`tag_b64`） | 与其它后端统一；同时兼容"密文含 tag"的历史形态 | `legacy_tag_appended_format_is_supported` |
| `key_id` 参与解密校验 | 支持密钥轮换：密钥不匹配时提示"请先执行密钥轮换解密" | `key_id_mismatch_reports_rotation_required` |
| `SecretString` + `zeroize` | 明文 Drop 时清零 | `secrecy` / `zeroize` 依赖；`Debug` 打印 `<redacted 32 bytes>` |
| `rewrap(material, new_aad)` | AAD 变更（如凭据迁移到另一 id）时用同密钥重新加密 | `rewrap_changes_aad_and_keeps_plaintext` |

**冗余损失可接受性**：AAD 绑定意味着凭据不能跨记录复用密文，牺牲了一定的存储灵活性，换取"密文不可搬迁"这一强保证。

### 5.4 哈希链审计

```rust
// crates/agf-core/src/audit.rs:1-6
//! 防篡改设计：
//! - 每条记录计算 `entry_hash = SHA256(prev_hash ‖ 规范化载荷)`；
//! - `prev_hash` 指向同租户上一条记录，形成链；
//! - 定期生成链锚点（AuditChainAnchor）并对锚点做 HMAC 签名，
//!   即使攻击者改库并重算链路，也无法伪造锚点签名。
```

| 层次 | 机制 | 能防住什么 |
|---|---|---|
| 单条完整性 | `entry_hash = SHA256(prev_hash ‖ canonical_payload)` | 改单条记录的内容 |
| 链式衔接 | `prev_hash` ↔ 上一条 `entry_hash`；`GENESIS_HASH` = 64 个 `0` | 删除中间记录、插入伪造记录（`verify_chain` 报 `prev_gap`） |
| 锚点签名 | `AuditChainAnchor` + HMAC | **改库并重算整条链**（攻击者无签名密钥） |
| 写入侧 | `AuditRepo::append` 在租户事务内自动取链尾哈希并封存 | 并发写导致的链尾竞争（应在同一事务内串行） |

**为什么选择哈希链而非"只写不删"权限**：数据库超级用户总能改数据；哈希链把"改数据"变成"必须同时重算全链且伪造签名"，
把检测能力从"依赖权限配置"提升到"依赖密码学"。

### 5.5 其他取舍

| 取舍 | 选择 | 理由与证据 |
|---|---|---|
| Redis 不可用时的配额判定 | `fail_closed` 由调用方决定；`true` = **拒绝**（宁可少服务） | 配额是安全控制（`redis_store.rs:318-320`） |
| 分布式锁在 Redis 不可用时 | **返回错误**，而不是"假定加锁成功" | 避免多实例同时执行同一任务（`redis_store.rs:222-223`） |
| 数据库不可用时 | **拒绝启动**（唯一硬失败） | 平台没有数据库无法工作（`agf-storage/src/lib.rs:14`） |
| 对象存储不可用时 | 自动降级：S3 → 本地 `<data_dir>/objects` → 内存 | "平台永远可启动"承诺的一部分（`objectstore.rs:1-9`） |
| 语义缓存 | **SHA-256 精确指纹缓存**（非向量相似度） | 键 = `aigw:cache:{tenant}:{fingerprint}`；向量检索需本地 embedding 模型，`SemanticCacheEntry.embedding` 字段存在但 `agf-aigw` 从不读写（`cache.rs:7-9`） |
| 敏感配置打印 | `AppConfig` / `FieldCipher` 自定义 `Debug`，**全部打码** | 使 `tracing::info!(?config)` 安全（`config.rs:671-695`） |
| 不可豁免的安全底线 | ① 含 `side_effecting` 工具的请求不可缓存；② 数据分级不被端点接受的请求不可缓存；③ 内容预筛的 `Redact`/`Block` 不受 `allow_cache` 影响 | `cache.rs:142-160`、`screen.rs` 与 `lib.rs` 的"不可豁免的底线" |
| `panic` / `unwrap` / `expect` | workspace lint 全部 `deny` | `Cargo.toml:256-258`；`unsafe_code = "forbid"`（`:247`） |

---

## 6. 部署拓扑

### 6.1 单机 Docker Compose（默认与生产）

```mermaid
graph TB
    subgraph HOST["宿主机（Windows 开发机 / Linux 生产机）"]
        subgraph NET["docker 网络：agf-net（开发）/ agf-prod-net（生产）"]
            PG[("postgres<br/>timescale/timescaledb:latest-pg16<br/>:5432")]
            RD[("redis<br/>redis:7.4-alpine<br/>:6379")]
            NT[("nats<br/>nats:2.10-alpine<br/>JetStream :4222 / :8222")]
            MIO[("minio<br/>:9000 / :9001")]
            MI["minio-init<br/>（一次性建桶）"]
            CH[("clickhouse<br/>profile: clickhouse<br/>:8123")]
            GF["grafana<br/>profile: grafana<br/>:3000"]
            SRV["agf-server 🟢<br/>:8080 / :9100"]
            ING["agf-ingest 🟢<br/>:8090 / :5514 / :8091"]
            SCH["agf-scheduler 🟢<br/>:9101"]
            WEB["agf-web 🟢<br/>nginx-unprivileged :8080→宿主 8081"]
            BK["backup sidecar<br/>（仅 prod）"]
        end
        DATA["&lt;项目根&gt;/data/<br/>pg · redis · nats · clickhouse · minio<br/>evidence · seed · backup · grafana"]
    end
    USER["浏览器"] -->|":8081"| WEB
    WEB -->|"/api /ws /healthz 反代"| SRV
    SRV --> PG
    SRV --> RD
    SRV --> NT
    SRV --> MIO
    ING --> PG
    ING --> NT
    SCH --> PG
    SCH --> NT
    MI --> MIO
    GF --> SRV
    BK --> PG
    PG --> DATA
    RD --> DATA
    NT --> DATA
    MIO --> DATA
    CH --> DATA
    GF --> DATA
```

**compose 三件套的定位差异**：

| 文件 | 角色 | 关键差异 |
|---|---|---|
| `docker-compose.yml` | 全栈基线（含自建数据面） | 10 个服务 + 2 个 profile；日志 `20m×5`；`security_opt: no-new-privileges` |
| `docker-compose.dev.yml` | **只做减法**的覆盖文件 | 把 4 个应用服务归入 `profiles: ["full"]`、`minio-init` 归入 `["objects"]`，因此默认只起 `postgres`/`redis`/`nats`/`minio`；应用在宿主机上热重载 |
| `docker-compose.prod.yml` | 独立的生产编排 | ① **不自建** postgres/redis/clickhouse，连外部托管实例（`${AGF_PG_HOST:?}` 强制指定）；② 应用容器 `read_only: true` + `cap_drop: ALL` + `tmpfs /tmp` + `user 10001:10001` + 资源 `limits`；③ 日志 `50m×10`；④ 附 `backup` sidecar（每日 `pg_dump --format=custom --compress=6`，保留 7 份） |

### 6.2 Kubernetes / Helm

```mermaid
graph TB
    ING2["Ingress<br/>（TLS 终结 + PrivateLink 注解）"] --> WSVC["Service: agf-web<br/>:8080"]
    ING2 --> ASVC["Service: agf-server<br/>:8080 / :9100"]
    WSVC --> WDEP["Deployment: agf-web<br/>nginx-unprivileged"]
    ASVC --> ADEP["Deployment: agf-server<br/>uid 10001 · read_only · HPA · PDB"]
    ASVC --> IDEP["Deployment: agf-ingest<br/>:8090 / :5514"]
    ASVC --> SDEP["Deployment: agf-scheduler"]
    ADEP --> SEC["Secret（外置）<br/>DB/JWT/主密钥/云凭据"]
    ADEP --> EXTPG[("外部托管 PostgreSQL")]
    ADEP --> EXTRD[("外部托管 Redis")]
    ADEP --> EXTNAT[("外部 NATS / JetStream")]
    ADEP --> EXTS3[("对象存储")]
```

**当前状态：🟢 Chart 已完整，且 `helm lint` / `helm template` 已实测。** `deploy/helm/aiguardfabric/` 含：
`Chart.yaml`（`apiVersion: v2`、`version 0.1.0`、`appVersion "0.1.0"`、`kubeVersion ">=1.27.0-0"`、
注解 `aiguardfabric.io/run-as-uid: "10001"`）、`values.yaml` + `values-prod.yaml` + `values-airgap.yaml`、
`.helmignore`、`README.md`（10 个小节），以及 `templates/` 下 **25 个模板**：

| 类别 | 模板 |
|---|---|
| 应用 | `deployment-server.yaml`、`deployment-ingest.yaml`、`deployment-scheduler.yaml`、`deployment-web.yaml`、`services.yaml`、`configmap.yaml`、`secret.yaml`、`serviceaccount.yaml` |
| 入口与网络 | `ingress.yaml`、`networkpolicy.yaml`、`privatelink.yaml` |
| 高可用与治理 | `hpa.yaml`、`pdb.yaml`、`servicemonitor.yaml`、`pvc-evidence.yaml` |
| 可选内置数据面 | `postgresql.yaml`、`redis.yaml`、`nats.yaml`、`minio.yaml`、`clickhouse.yaml`、`grafana.yaml` |
| 辅助 | `_helpers.tpl`、`NOTES.txt`、`extra-manifests.yaml` |

`values.yaml` 顶层键：`global` / `image` / `imagePullSecrets` / `podSecurityContext` / `containerSecurityContext` /
`nodeSelector` / `tolerations` / `affinity` / `serviceAccount` / `config` / `extraConfig` / `secrets` / `volumes` /
`ports` / `server` / `ingest` / `scheduler` / `web` / `ingress` / `privateLink` / `hpa` / `pdb` / `networkPolicy` /
`serviceMonitor` / `postgresql` / `redis` / `nats` / `minio` / `clickhouse` / `grafana` / `extraManifests`。

**实测结论（PV-011）**：`helm lint` 与 `lint --strict` 均 **0 chart failed**；`helm template` 三套 values
（默认 / prod / airgap）全部渲染成功（1469 / 1835 / 2363 行，共 **26 个文档**：4 Deployment / 10 NetworkPolicy /
4 Service / 2 HPA / 3 PDB / 1 ConfigMap / 1 SA / 1 PVC），4 个 Deployment 均含 image + 存活/就绪探针。
helm v3.16.4 装在项目内 `tools/bin/helm.exe`（铁律 2）。
**负例已验证**：不提供密钥时 `helm template` **exit 1**（`agf.validateSecrets` 硬失败），"禁止明文默认密钥"确实会拦住部署。

### 6.3 容器镜像构建

`deploy/docker/Dockerfile` 的 6 个 stage：

| Stage | 基镜像 | 作用 |
|---|---|---|
| `planner` | `rust:1.97-slim` | `cargo-chef prepare` 生成 `recipe.json`（依赖层与源码层分离） |
| `builder` | `rust:1.97-slim` | `cargo chef cook --release` 编译依赖（缓存层）→ `cargo build --release --locked --bins` 产出 `agf-server` / `agf-ingest` / `agf-scheduler` / `agfctl` |
| `runtime-base` | `gcr.io/distroless/cc-debian12:nonroot` | 无 shell、无包管理器，最小攻击面；`USER 10001:10001` |
| `server` / `ingest` / `scheduler` | `runtime-base` | 各自 `ENTRYPOINT` + 复制 `deploy/sql/migrations` 与 `rules/` |
| `builder-web` | `node:24-slim` | `corepack prepare pnpm@11` + `pnpm install` + `pnpm run build` |
| `web` | `nginxinc/nginx-unprivileged:1.27-alpine` | 静态产物 + `nginx.conf`，监听 8080 |

> **注意**：`Dockerfile:95/100/106` 会 `COPY --from=builder /app/rules /app/rules`，而当前 `rules/` 下**没有任何 YAML 规则**（只有 `rules/_gen/*.py` 生成器）。

### 6.4 控制台反代（`deploy/docker/nginx.conf`）

| 配置 | 事实 |
|---|---|
| 上游 | `upstream agf_api { server agf-server:8080; keepalive 32; }` |
| 监听 | `8080`（非 root 变体 nginx） |
| 安全头 | `X-Content-Type-Options: nosniff`、`X-Frame-Options: DENY`、`Referrer-Policy`、`Permissions-Policy`、**CSP**（`default-src 'self'`、`object-src 'none'`、`frame-ancestors 'none'`） |
| `/api/` | `proxy_buffering off` + `proxy_read_timeout 300s`（**SSE / 大模型流式转发必须关缓冲**）；`client_max_body_size 32m` |
| `/ws` | `Upgrade`/`Connection: upgrade`，`proxy_read_timeout 3600s` |
| `/healthz` | 反代到 `agf_api/healthz`，`access_log off` |
| `/assets/` | `expires 1y` + `Cache-Control: public, immutable`（带 hash 的构建产物） |
| `/index.html` | `Cache-Control: no-store` |
| SPA 回退 | `try_files $uri $uri/ /index.html` |
| `server_tokens off` | 不暴露版本号 |

---

## 7. 当前实现状态与架构缺口

| 架构边界 | 状态 | 缺口 |
|---|---|---|
| 展示层 | 🟢 | 控制台的每个调用都与后端真实注册路由逐一比对并补齐（**35 条缺失端点 + 6 处形状错配**）；收口脚本 `scripts/verify-console-paths.py` 实测 **PASS 54 / FAIL 0**（PV-027/PV-028） |
| 接入层（HTTP API） | 🟢 | `agf-api` 已落地（`/healthz` `/readyz` `/metrics` `/graphql` `/ws` `/api/v1/openapi.json` 均已注册并实测可达）。**资源读写已切到 PG 写后持久化**：`assets`/`findings`/`policies`/`alerts`/`cases`/`case_events`/`audit_logs`/`api_keys` 走写后桥 + 启动水合（**`api_keys` 只落指纹/前缀/scope/租户/吊销状态，明文永不入库**；水合使 `agf-scheduler` 这类用长期服务 Key 的组件在 agf-server 重启后仍可校验），其余资源仍仅内存（`persistence.rs` 的 `PersistenceReport` 是唯一事实源，`/settings` 的 `persistence` 段与 `/readyz` 的 `checks.persistence` 实时投影）；**501 端点 0 条**；`/ws` 事件面默认经 NATS（`agf.ws.*`）跨副本互通、NATS 不可用时自动退回进程内广播；`utoipa-swagger-ui` 被注释掉（`TODO(api-openapi-swagger)`） |
| 接入层（协议接收器） | 🟢 部分 | Syslog/Webhook/文件/HTTP Pull/采集器上行已实现且**已由 `apps/ingest` 装配成进程**；**Syslog TLS（RFC5425）已接线**（`AGF_SYSLOG_TLS_PORT` 默认 6514 + `CERT`/`KEY`）；**Kafka、Pulsar（经 KoP）、MQTT、SNMP Trap、JDBC（PostgreSQL/MySQL/MSSQL/Oracle 四种方言，MSSQL 与 Oracle 均已真机验证）、OTLP（HTTP 三信号 logs+traces+metrics；gRPC 只有 `LogsService`）、NATS JetStream 入向订阅、CEL 派生字段、OSS-S3 拉取、Rust 动态库插件（`engine: plugin`，`AGF_INGEST_PLUGIN_DIR` 启动期装载，装载/失败清单进 `/readyz` notes）均已实现并装配**（`/readyz` 能力矩阵是**四态**：`ready`/`not-wired`/`not-implemented`/`mock`，前两者由 `declare_wired` 装配登记决定）；**仍未实现**：HTTP Push、journald、Pulsar 原生协议（KoP 之外的原生二进制协议为另一工作流）、gRPC 端口自身 TLS、gRPC 侧 TraceService/MetricsService（`/readyz` 的 TODO 锚点会如实列出）；**SNMP v3 `authPriv`（CBC-DES/CFB128-AES-128）与冷归档 Parquet 的 arrow 列式回灌已实现**（真机脚本 `tools/simulators/verify_snmp_authpriv.ps1`、`verify_archive_replay.ps1`；插件真机脚本 `verify_plugin_engine.ps1`）。**Oracle/MSSQL 拉取已真机验证**：Oracle `oracle://agf:***@127.0.0.1:11521/FREEPDB1`（PG `events` 的 `source_name='sql-pull'` 70→75(+5)→77(仅 +2)、游标 `"5"`→`"7"`）、MSSQL `mssql://sa:***@127.0.0.1:11433/agfaudit`；未覆盖项（REFCURSOR/对象/集合列按字符串兜底、Oracle 未加引号标识符折叠为大写、单连接句柄、OCI 阻塞 C 库、**构建期需 C 编译器**）见 `TODO ingest-jdbc-oracle-extras` |
| 运行时 | 🟡 | `agf-runtime` 修复中；`agf-aigw` ↔ `agf-runtime` 的联动在双方 `Cargo.toml` 中均未声明 |
| 领域层 | 🟢 | `agf-correlate` 已交付（跨源对齐 / 告警聚合 / 攻击链路还原 / SOAR-lite）；API 侧 `POST /alerts/aggregate` 已接真实引擎 |
| 集成层 | 🟢 | 阿里云六适配器完整（含 Mock）；`agf-adapters` **11 个适配器全部有真实传输**（含 `email` 的真实 SMTP 发送），并**按协议支持实现 `push`/`pull`/`sync`**（工单类 `jira`/`servicenow`/`zentao` + `edr` 三条全有、`slack` 有 `push`；其余 `Unsupported` 带客观原因，见 `crates/agf-adapters/CAPABILITY-MATRIX.md`） |
| 存储层 | 🟢 | 数据库不可用 = 拒绝启动（设计选择）；`agf-server` 在**未配置**数据库凭据时降级为离线内存模式 |
| 领域内核 | 🟢 | — |
| 二进制 | 🟢 | `agf-server`（含 `healthcheck`/`migrate`/`bootstrap-admin`）、`agf-ingest`、`agf-scheduler` **已实现并实测可跑**；`agfctl`（`agf-cli`）**已实现并实测**（`rules verify` 54/54、`redteam verify` 220 用例、`airgap bundle` 421 文件一致、`version` 构建期注入三元组/提交/时间） |
| 配置闭环 | 🟡 | `.env.example` 的 LLM 段（15 个上游 + 7 个策略项）与 `AGF_NATS_ENABLED/URL/STREAM` 在 Rust 中**零引用**；`AGF_RULES_DIR` / `AGF_REDTEAM_CASE_DIR` 的读取方随本轮 `agf-cli` / `agf-scheduler` 落地而变化（`apps/scheduler` 已按 `AGF_RULES_DIR` / `AGF_REDTEAM_DIR` 读取规则与用例库），完整清单见 [`docs/deployment.md`](deployment.md) §4 的「代码读取」列 |
| 计量闭环 | 🟡 | `Meter` 为纯内存态，`UsageRecord` 无落库消费者；进程重启即丢失 |
| 事件总线 | 🟡 | `NatsEventBus` 只有核心协议 `publish`，**不是 JetStream**；`NatsConfig` 解析后无消费者。**边界**：这是**发布**侧；**入向** JetStream 订阅是另一个模块（`agf-ingest/src/jetstream/**`），**已实现并装配**（`AGF_INGEST_JETSTREAM_URL`） |
| Helm | 🟢 | Chart 已完整（`values.yaml` + 25 个模板）；`helm lint`（含 `--strict`）**0 chart failed**、`helm template` 三套 values 全部渲染成功（PV-011） |
| 容器 healthcheck | 🟢 | `docker-compose.yml` 中 `agf-server` / `agf-ingest` / `agf-scheduler` 的 healthcheck **已从 `wget` 改为自带 `healthcheck --url` 子命令**（runtime 镜像是 distroless，无 `wget`）；`agf-web` 仍用 `wget`（nginx-unprivileged 有 wget）。**实测已闭环**：`docker compose up -d` 后 **8 个容器全部 healthy**（PV-001） |

> 逐条缺口（含阻塞原因、所需条件、已完成的替代验证）见 [`docs/pending-verification.docs.md`](pending-verification.docs.md)。

---

## 8. 相关文档

- 威胁建模与信任边界：[`docs/threat-model.md`](threat-model.md)
- 部署与运维：[`docs/deployment.md`](deployment.md) · [`docs/operations.md`](operations.md)
- 适配器契约：[`docs/adapter-spec.md`](adapter-spec.md)
- 里程碑与实现注记：[`docs/roadmap.md`](roadmap.md)
- 项目门面：[`README.md`](../README.md)
