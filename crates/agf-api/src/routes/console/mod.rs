//! 控制台端点：总览 / 搜索 / 拓扑 / 身份 / 设置 / 运行时 / 接入预览。
//!
//! ## 为什么有这一组端点
//!
//! `apps/web/src/api/client.ts` 里的控制台页面已经在调用这批路径（`/overview`、`/search`、
//! `/topology`、`/users`、`/tenants`、`/api-keys`、`/settings/password-policy`、
//! `/runtime/*`、`/agents/onboarding-plan`、`/ingest/replay`），但后端此前没有对应路由：
//! 请求 404 → `callApi` 判定为可降级失败 → 控制台永远显示"演示数据（后端未连接）"。
//! 本模块把这批端点补齐；GET 预览只读，明确的 POST 操作才修改业务状态。
//!
//! ## 契约来源（唯一权威）
//!
//! 字段名与响应形状**以控制台为准**：
//! `apps/web/src/api/client.ts` 的 `callApi<类型>` 决定形状（分页信封 / 裸数组 / 单对象），
//! `apps/web/src/types/domain.ts` 决定字段集合。JSON 键统一使用 **snake_case**：
//! 前端 `request()` 会对响应做 `camelizeDeep`（`page_size`→`pageSize`、`risk_score`→`riskScore`、
//! `display_name`→`displayName`），因此字段名按 domain.ts 的驼峰倒推成下划线即可。
//!
//! | 路径 | 形状 | 权限点 |
//! |---|---|---|
//! | `GET /overview` | 单对象 `DashboardOverview` | `assets:read` |
//! | `GET /search?q=` | **裸数组** `SearchHit[]` | 每种资源独立校验 `read` 权限 |
//! | `GET /topology` | 单对象 `TopologyGraph` | `assets:read` |
//! | `GET /users` | **裸数组** `User[]` | `platform:admin` |
//! | `POST /users` | 单对象 `User` | `platform:admin` |
//! | `PATCH /users/{id}` | 单对象 `User`（要求 `expected_version`） | `platform:admin` |
//! | `GET /tenants` | **裸数组** `Tenant[]` | `settings:read` |
//! | `GET /api-keys` | **裸数组** `ApiKey[]` | `settings:read` |
//! | `GET /settings/password-policy` | 单对象 `PasswordPolicy` | `settings:read` |
//! | `GET /runtime/blacklists` | **裸数组** `BlacklistEntry[]` | `policies:read` |
//! | `GET /runtime/events` | **裸数组** `InterceptEvent[]` | `policies:read` |
//! | `GET /runtime/intercept-points` | **裸数组** `InterceptPointStatus[]` | `policies:read` |
//! | `GET /runtime/quotas` | **裸数组** `QuotaUsage[]` | `quotas:read` |
//! | `GET`/`POST /agents/onboarding-plan` | 单对象 `OnboardingPlan` | `agents:read` |
//! | `GET /ingest/replay` | 单对象（只读原文预览） | `sources:write`（原文敏感） |
//! | `POST /ingest/replay` | 单对象（执行结果、解析统计与原文） | `sources:write` |
//!
//! 权限点全部取自既有 RBAC 组（`agf_core::rbac::Role::builtin_definitions`），不新造权限名；
//! 未认证 401、越权 403，错误体一律 RFC 9457 `application/problem+json`（[`ApiError`]）。
//!
//! ### 两处 HTTP 方法差异（以控制台为准，两种方法都注册）
//!
//! - `/agents/onboarding-plan`：控制台用 **POST** + JSON body `{agentId, mode}`（`client.ts:680`），
//!   任务书表格写的是 GET。为了让控制台与文档化调用都能用，路由**同时注册两种方法**：
//!   GET 从 query 取 `agent_id`/`kind`/`mode`，POST 从 body 取 `{agentId|agent_id, kind, mode}`。
//!   [`endpoint_specs`] 里记 **POST**（控制台实际调用的方法）。
//! - `/ingest/replay`：样例面板用 **GET** + `?sourceId=` 只读预览；执行面板用 **POST**
//!   + JSON body 明确触发回放。两种方法均登记在 [`endpoint_specs`]。
//!
//! ## 数据来源：真实统计 vs 中性默认值（逐条如实标注）
//!
//! **真实统计**（来自 `ApiStore` 台账 / 运行时引擎 / 认证服务 / 配置）：
//!
//! - `/overview`：`kpis.assets`（`platform_snapshot().assets`）、`kpis.openAlerts`
//!   （`alerts_active`）、`kpis.criticalFindings`（`findings_critical`）、
//!   `kpis.redteamSuccessRate`（`RedteamCampaign` 的 `succeeded_cases/executed_cases`）、
//!   `kpis.tokenSpend`（保留的真实模型计量微元 → CNY）、`domainDistribution`（资产按 `kind` 归域 +
//!   发现按 `domain` 归域，含 critical 计数）、`topRiskAssets`（台账按风险分倒序）、
//!   `recentAlerts`（告警表按 `last_seen_at` 倒序）、`adapterHealth`（阿里云适配器注册表：
//!   `id`/`name`/`mock`/`category` 真实）。
//! - `/search`：按资源权限检索当前租户的资产、发现、告警、案件、规则和红队用例。
//!   SQL 子串查询限时且限制每组结果数；精确 ID/名称优先，其余类别交错返回详情链接。
//! - `/topology`：节点来自资产台账（类型/风险分/影子/分级/名称真实），边来自
//!   `Asset.dependencies` 与 `Asset.attributes` 里的引用键（真实关系；无关系数据时只有节点、无边）。
//! - `/users`：认证后端里当前租户的完整账号目录，`email`/`mfa_enabled`/
//!   `must_change_password`/`status`/`last_login_at`/`role`（由 `roles_of` 映射）真实。
//! - `/tenants`：`id`（默认租户 UUID）、`quota_defaults.tenant_tokens_per_day`（租户级 Token/日配额）、
//!   `quota_defaults.max_concurrent_sessions`（并发配额）、`created_at`（配额创建时间）真实；
//!   `white_label.product_name` 取平台常量/`AGF_PRODUCT_NAME`，真实。
//! - `/api-keys`：`ApiStore::api_key_list` 的 `id`/`name`/`prefix`/`scopes`/`created_at`/
//!   `expires_at`/`last_used_at`/`revoked` 真实（**显式剔除 `key_fingerprint` 与 `allowed_cidrs`**，
//!   只暴露 domain.ts 声明的字段）。
//! - `/settings/password-policy`：`AuthService::policy()` 的 `min_length`/`require_classes`/
//!   `max_age_days`/`history_size`/`max_failures` 真实（即 `AGF_PASSWORD_MIN_LENGTH`、
//!   `AGF_LOGIN_MAX_FAILURES` 等配置的生效值）。
//! - `/runtime/blacklists`：`agf_runtime::blocklist::default_rules()` 的 `id`/`pattern`/
//!   `action`/`note`（命中原因为真实中文说明）真实。
//! - `/runtime/events`：运行时拦截审计链（`RuntimeEngine::audit()`，哈希链记录）——`ts`/`point`/
//!   `action`/`reason`/`payload_digest`（链上条目哈希）/`severity` 真实。
//!   行由**引擎自己**产生：演示环境（`AGF_SEED_FIXTURES=1`）在灌库阶段用
//!   `intercept_mcp_request` / `evaluate` + `record_decision` 跑过代表性载荷
//!   （见 `crate::seed::seed_runtime_interceptions`），因此链上会有若干条真实拦截；
//!   未开该开关（或不接代理流量）时是空数组（**空数组 + 200，不是 404**）。
//!   MCP 工具请求的 `tool_name` 来自原始帧；非工具请求及无法安全关联请求的响应保持 `null`。
//!   `policy_name` 对**黑名单命中**的行是 `"-"`——黑名单不是租户策略，没有策略名，
//!   命中的规则 id 在 `reason` 里（形如 `命中黑名单规则 cmd.curl-pipe-sh：…`）。
//! - `/runtime/intercept-points`：拦截点集合来自 `RuntimeEngine::config().required_intercept_points()`
//!   （真实配置），`blocked_24h` 来自**同一份**拦截审计链按点计数——与 `/runtime/events` 里
//!   判定为拦截的行数天然一致（同一数据源，不另算一遍；无拦截流量时为 0）。
//! - `/runtime/quotas`：与 `GET /quotas/snapshot` 同源（`quota_list` + `quota_usage`），
//!   `used`/`limit`/`scope`/`throttled`（= `is_exceeded`）真实。
//! - `/agents/onboarding-plan` uses a validated client origin or request Host/server config,
//!   validates optional agent membership, and generates commands for the selected OS.
//!
//! **中性默认值**（算不出就给空数组/0/false，绝不编造）：
//!
//! - `/overview`：`kpis[*].delta = null`、`kpis[*].sparkline = []`（平台未保留 KPI 历史序列，长期指标由
//!   Prometheus 承担）；`riskTrend` 每小时记录实际未结严重 + 高危发现数，不补启动零值，
//!   本实例周期保存并在重启恢复，多副本各持一份，
//!   长期序列仍由 Prometheus 承载（`TODO(api-console-history)` 的长期面）；`adapterHealth[*].uptime_percent = null`
//!   与 `health = "unknown"`（API 进程不主动探活云适配器，云侧健康由 `/alicloud/selfcheck` 承担）。
//! - `/topology`：`edges[*].calls_24h` 缺省 0（仅当资产 `attributes` 里带 `calls_24h` 时才有值）；
//!   `egressPaths` 只含"端点确实存在"的路径，无边时为 `[]`。
//! - `/users`：`role` 未命中内置角色表时回落 `viewer`；从未登录时 `last_login_at` 回落账号创建时间
//!   （domain.ts 不允许 null）。
//! - `/tenants`：`slug`/`name`/`plan`/`region` 取 `AGF_DEFAULT_TENANT_SLUG` 等环境变量，缺省
//!   `default`/`默认租户`/`enterprise`/`cn-hangzhou`；`quota_defaults.agent_tokens_per_hour` 与
//!   `session_tokens_per_turn` 缺省 0——**不把配置里的"每日/每会话"额度按不同粒度换算成
//!   "每小时/每轮"**（那会误导）；`white_label.logo_text`/`primary_color` 缺省 `AGF`/`#1677ff`。
//! - `/settings/password-policy`：`require_uppercase/lowercase/digit/symbol` 四个布尔**同取**
//!   `require_classes`——`agf_core::auth::PasswordPolicy` 的语义是"四类中至少三类"，而 domain.ts
//!   是逐类布尔，没有"至少三类"的表达能力；`mfa_enforced = false`（平台没有"租户级强制 MFA"开关，
//!   MFA 是账号级 `mfa_enabled`）。
//! - `/runtime/blacklists`：`hits_24h = 0`（`BlocklistStats` 没有对外读取接口，
//!   `TODO(api-console-blacklist-stats)`）；`updated_at` 取进程启动时间（规则无独立更新时间）；
//!   `scope` 恒 `tenant`（内置规则是平台级闸门，domain.ts 的 `QuotaScope` 没有"platform"取值）；
//!   **只输出 `command`/`domain` 两类**——内置的 13 条敏感路径 + 1 条工具 + 1 条哈希规则在
//!   domain.ts 的 `BlacklistEntry.kind` 里没有对应取值（宁可少输出，不改写类别）。
//! - `/runtime/events`：`latency_ms` 由审计链的实测微秒换算；没有测量值时为 0。
//!   `mcp_name = null`（链上只有工具名，没有 MCP 名）、`severity` 缺省 `info`、
//!   `action` 经 [`policy_action_frontend`] 映射（后端 10 个动作 → 前端 7 个，见函数文档）。
//! - `/runtime/intercept-points`：`throughput_per_min` 与 `p95_latency_ms` 都是**真实值**，
//!   同源于拦截审计链的**最近窗口**：吞吐 = 最近 60 秒落在该拦截点上的条目数
//!   （`THROUGHPUT_WINDOW_SECS`）；p95 = 最近 `crate::metrics::INTERCEPTION_P95_WINDOW_SECS`
//!   窗口内该点位的 `InterceptionRecord::latency_micros` 样本（各拦截入口真实测得的
//!   "进入处理 → 出决策"耗时）用**最近秩法**算出的分位数，微秒样本**向上取整**到毫秒
//!   （有样本即 ≥ 1ms、窗口内无样本严格为 0，不编造）。两个口径在 `/metrics` 上分别以
//!   `agf_runtime_interceptions_total{point,action}` 与
//!   `agf_runtime_interception_latency_p95_milliseconds{point}` 暴露（零流量时序列存在且为 0）；
//!   `enabled = false` + `mode = "bypass"` + `health = "unknown"`（**如实反映"API 进程内没有承载
//!   这些拦截点的代理进程"**，`last_error` 里写明由谁承担）；`version` 取平台版本
//!   `crate::VERSION`（拦截点组件自身没有独立版本号）；数组恒含 4 个前端已知拦截点，
//!   其中 `egress-proxy` 是**占位条目**（见 [`intercept_point_rows`]）。
//! - `/runtime/quotas`：`unit` 由配额维度推导（`concurrency`→`sessions`、`requests`/`cost`→`calls`、
//!   `tokens`→`tokens`）——domain.ts 的 `unit` 没有金额单位，`cost` 维度按 `calls` 呈现；
//!   `window_end` 统一取请求时刻（配额计数在存储侧滚动，窗口无需精确结束时间）；
//!   `scope_name` 优先取作用域对象的资产名，取不到时回落配额名。
//! - Onboarding plans validate target platform and published artifacts, generate manual steps,
//!   and leave downtime unknown. They do not deploy applications or inject probes.
//!
//! ## 明确的能力缺口（不改 `store.rs`/`state.rs`，如实返回）
//!
//! | 缺口 | 表现 | 需要的扩展 |
//! |---|---|---|
//! | 没有租户仓储 | `/tenants` 只返回默认租户（`00000000-0000-0000-0000-000000000001`） | `agf_storage` 租户仓储 / `TenantRepo` |
//! | 运行时黑名单无"当前规则集"读取接口 | `/runtime/blacklists` 用内置规则表（`default_rules()`）；热重载后的自定义规则集看不到，`TODO(api-console-blacklist-live-rules)` | `RuntimeEngine::blocklist_rules()` |
//! | ~~原始日志仓储（`Sink`）未装配~~ **已解决** | GET 从 `AppState.ingest_sink` 读取原文；POST 使用 `AppState.replay_parsers` 调真实 `Replayer`（主体在 [`crate::routes::ingest::replay_raw_logs`]） | 已装配（具体 Sink 由运行配置决定） |
//!
//! ## 降级铁律
//!
//! 数据为空时**返回 200 + `total: 0` / 空数组**，绝不 404：控制台用"接口存在但暂无数据"
//! 与"接口不存在"区分"真实空态"与"演示降级"。
//!
//! `TODO(api-console-history)`（长期序列：Prometheus 承载，进程内只保留小时级采样）、
//! `TODO(api-console-runtime-metrics)`（拦截点**时延**：审计链无耗时字段）、
//! `TODO(api-console-blacklist-stats)`、`TODO(api-console-blacklist-live-rules)`、
//! `TODO(api-ingest-replay-response-shape)`
//! （回放响应已从"未实现"变为"对象形状的报告 + 原文"，控制台 `client.ts` 声明的 `string[]`
//! 需与之对齐）。

use std::collections::{BTreeMap, BTreeSet};

use agf_core::asset::Asset;
use agf_core::enums::{
    AlertState, AssetKind, DataClass, DiscoverySource, InterceptPoint, LifecycleState, PolicyAction, QuotaDimension,
    QuotaScope, RiskDomain, Severity,
};
use agf_core::error::DomainError;
use agf_core::ids::{Id, TenantId};
use agf_core::quota::{Quota, QuotaWindow};
use agf_core::risk::FindingState;
use agf_core::time::Timestamp;
use agf_runtime::blocklist::{RuleAction, RuleKind, RuleRule};
use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::routing::get;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::error::{ApiError, ApiResult};
use crate::middleware::Principal;
use crate::query::ListQuery;
use crate::routes::platform::EndpointSpec;
use crate::state::AppState;

/// 搜索默认返回条数（与 `demo.searchAll(keyword, limit = 8)` 一致）。
pub(super) const SEARCH_DEFAULT_LIMIT: i64 = 8;

/// 搜索返回条数上限（防止单次请求拉全表）。
pub(super) const SEARCH_MAX_LIMIT: i64 = 50;

/// 拓扑路径枚举的最大深度（防止深图上的组合爆炸）。
pub(super) const TOPOLOGY_MAX_DEPTH: usize = 6;

/// 拓扑 `egressPaths` 的最大条数。
pub(super) const TOPOLOGY_MAX_PATHS: usize = 20;

/// `/runtime/intercept-points` 的吞吐窗口（秒）：窗口内链上条目数 = "条/分钟"。
pub(super) const THROUGHPUT_WINDOW_SECS: i64 = 60;

/// 控制台端点路由（`/api/v1` 前缀由 [`crate::routes::api_v1_router`] 的 `nest` 提供）。
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/overview", get(overview))
        .route("/search", get(search))
        .route("/search/natural", axum::routing::post(natural_search::natural_search))
        .route("/topology", get(topology))
        .route("/users", get(list_users).post(users::create_user))
        .route("/users/{id}", axum::routing::patch(users::update_user))
        .route("/tenants", get(list_tenants))
        .route("/settings/tenant", axum::routing::put(settings::tenant))
        .route("/settings/quotas", axum::routing::put(settings::quotas))
        .route("/api-keys", get(list_api_keys))
        .route("/settings/password-policy", get(password_policy).put(settings::password))
        .route("/runtime/blacklists", get(list_blacklists))
        .route("/runtime/events", get(list_runtime_events))
        .route("/runtime/intercept-points", get(list_intercept_points))
        .route("/runtime/quotas", get(list_runtime_quotas))
        // 控制台用 POST + body（client.ts:680），任务书要求 GET + query：两种都注册。
        .route("/agents/onboarding-plan", get(onboarding_plan_get).post(onboarding_plan_post))
        // 样例 GET 只预览；执行回放须显式 POST。
        .route("/ingest/replay", get(ingest_replay_get).post(ingest_replay_post))
}

/// 控制台端点清单（供 `platform::openapi_spec` 与覆盖对账使用）。
///
/// `path` 使用完整 `/api/v1/...` 路径，与全局 OpenAPI 清单一致。
/// `implemented` 与真实行为一致：GET 预览与 POST 回放分别登记。
#[must_use]
pub fn endpoint_specs() -> Vec<EndpointSpec> {
    use utoipa::openapi::path::HttpMethod::{Get, Patch, Post};
    vec![
        EndpointSpec {
            path: "/api/v1/overview",
            method: Get,
            id: "consoleOverview",
            summary: "控制台总览（KPI/趋势/域分布/TOP 资产/最近告警/适配器健康）",
            tag: "overview",
            implemented: true,
        },
        EndpointSpec {
            path: "/api/v1/search",
            method: Get,
            id: "consoleSearch",
            summary: "全局搜索（资产/发现/告警/规则/红队用例，裸数组）",
            tag: "search",
            implemented: true,
        },
        EndpointSpec {
            path: "/api/v1/search/natural",
            method: Post,
            id: "consoleNaturalSearch",
            summary: "Natural language to validated read-only query DSL with explicit Mock/demo metadata",
            tag: "search",
            implemented: true,
        },
        EndpointSpec {
            path: "/api/v1/topology",
            method: Get,
            id: "consoleTopology",
            summary: "资产拓扑图（节点+边+外传路径）",
            tag: "topology",
            implemented: true,
        },
        EndpointSpec {
            path: "/api/v1/users",
            method: Get,
            id: "consoleListUsers",
            summary: "当前租户的完整账号目录（裸数组）",
            tag: "identity",
            implemented: true,
        },
        EndpointSpec {
            path: "/api/v1/users",
            method: Post,
            id: "consoleCreateUser",
            summary: "创建租户账号与角色",
            tag: "identity",
            implemented: true,
        },
        EndpointSpec {
            path: "/api/v1/users/{id}",
            method: Patch,
            id: "consoleUpdateUser",
            summary: "按 expected_version 更新账号角色或状态；旧版本返回 409",
            tag: "identity",
            implemented: true,
        },
        EndpointSpec {
            path: "/api/v1/tenants",
            method: Get,
            id: "consoleListTenants",
            summary: "当前主体可查看的租户列表（裸数组）",
            tag: "identity",
            implemented: true,
        },
        EndpointSpec {
            path: "/api/v1/api-keys",
            method: Get,
            id: "consoleListApiKeys",
            summary: "API Key 列表（不含指纹与明文，裸数组）",
            tag: "settings",
            implemented: true,
        },
        EndpointSpec {
            path: "/api/v1/settings/password-policy",
            method: Get,
            id: "consolePasswordPolicy",
            summary: "生效的口令策略",
            tag: "settings",
            implemented: true,
        },
        EndpointSpec {
            path: "/api/v1/runtime/blacklists",
            method: Get,
            id: "consoleListBlacklists",
            summary: "运行时分级黑名单（内置规则表映射）",
            tag: "runtime",
            implemented: true,
        },
        EndpointSpec {
            path: "/api/v1/runtime/events",
            method: Get,
            id: "consoleListInterceptEvents",
            summary: "拦截事件流（运行时拦截审计链，裸数组）",
            tag: "runtime",
            implemented: true,
        },
        EndpointSpec {
            path: "/api/v1/runtime/intercept-points",
            method: Get,
            id: "consoleListInterceptPoints",
            summary: "拦截点状态（含未挂载点的如实标注）",
            tag: "runtime",
            implemented: true,
        },
        EndpointSpec {
            path: "/api/v1/runtime/quotas",
            method: Get,
            id: "consoleListRuntimeQuotas",
            summary: "配额用量（与 /quotas/snapshot 同源）",
            tag: "runtime",
            implemented: true,
        },
        EndpointSpec {
            path: "/api/v1/agents/onboarding-plan",
            method: Post,
            id: "consoleOnboardingPlan",
            summary: "免改造纳管计划（GET/POST 均可用；POST 为控制台用法）",
            tag: "agents",
            implemented: true,
        },
        EndpointSpec {
            path: "/api/v1/ingest/replay",
            method: Get,
            id: "consoleIngestReplay",
            summary: "只读预览指定日志源的未解析原文；不会生成事件或标记原文",
            tag: "ingest",
            implemented: true,
        },
        EndpointSpec {
            path: "/api/v1/ingest/replay",
            method: Post,
            id: "consoleIngestReplayExecute",
            summary: "显式回放原始日志：重新解析、保存新事件与差分报告",
            tag: "ingest",
            implemented: true,
        },
    ]
}

mod identity;
mod mapping;
mod onboarding;
mod onboarding_authority;
mod onboarding_commands;
mod onboarding_startup;
mod onboarding_targets;
mod onboarding_templates;
mod onboarding_types;
pub use onboarding_types::*;
mod natural_search;
mod overview;
mod runtime;
mod search;
mod search_topology;
mod settings;
mod users;
mod views;

#[cfg(test)]
mod tests;

pub use views::*;

use identity::*;
use mapping::*;
use onboarding::*;
use overview::*;
use runtime::*;
use search::search;
use search_topology::*;
