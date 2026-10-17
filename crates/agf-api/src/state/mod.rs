//! 应用状态：配置、数据层、认证/授权、规则包、红队用例库、解析器注册表、云适配器注册表。
//!
//! ## 外部目录加载与降级行为（`AGF_*_DIR`）
//!
//! | 目录 | 环境变量 | 容器默认 | 本机回退 | 缺失/加载失败时 |
//! |---|---|---|---|---|
//! | 规则库 | `AGF_RULES_DIR` | `/app/rules` | `<项目根>/rules` | 降级为内置最小规则集（每风险域 1 条）并写入 `notes` |
//! | 红队用例库 | `AGF_REDTEAM_DIR`（兼容 `AGF_REDTEAM_CASE_DIR`） | `/app/redteam` | `<项目根>/redteam` | 空用例库 + `warn` + `notes`，红队端点返回空库而不是 500 |
//! | 解析模板库 | `AGF_PARSERS_DIR` | `/app/parsers` | `<项目根>/parsers` | 保留 18 个内置模板 + `warn` + `notes`；坏模板由加载器计入 `invalid` 跳过 |
//! | 演示数据集 | `AGF_SEED_FIXTURES`（开关，默认**关闭**）/ `AGF_SEED_DIR` | `/app/data/seed` | `<项目根>/data/seed` | 开关关闭即不灌；目录缺失、数据集损坏、字段缺失只 `warn` + 计入 `SeedReport`（见 [`crate::seed`]），不影响启动。**开启时还会驱动真实组件**（[`RuntimeEngine`] 拦截 / `agf_aigw::Meter` 计量 / `agf_correlate::playbook` 执行），产出 `/runtime/events`、`/models/usage`、`/cases/{id}/soar-runs` 的数据 |
//!
//! 四条路径的加载/灌库失败**一律不返回错误、不退出进程**：`AppState::build` 只在数据库/口令策略等
//! 核心依赖不可用时失败，外部内容目录与演示数据的缺失属于可降级项，缺什么由 `/readyz` 的 `notes`
//! 与各资源端点的响应如实说明。
//!
//! ## 与 SOC 闭环相关的四件装配（本轮新增；数据来源与降级见各字段文档）
//!
//! | 字段 | 作用 | 外部依赖 |
//! |---|---|---|
//! | [`AppState::ingest_sink`] | 原始日志仓储，`GET`/`POST /api/v1/ingest/replay` 的真实回放入口 | 内存 Sink（与 `apps/ingest` 同款；重启即丢） |
//! | [`AppState::replay_parsers`] | 可变解析器注册表（回放要更新模板命中统计） | 与 `/parsers` 读路径同源加载，独立实例 |
//! | [`AppState::notifier`] | 通知派发器（跨请求共享的去重/限流/重试/审计） | 渠道全部为 `MockChannel`（不联网） |
//! | [`AppState::schedules`] | 报表周期调度登记表 | 进程内存；`cron` 只登记不执行 |
//!
//! ## 事件面（`/ws`）与 NATS 降级
//!
//! [`AppState::publish`] 写的是一层**统一事件面**：`AGF_NATS_ENABLED=1` 且 NATS 可达时经
//! [`crate::ws::NatsEventPlane`] 投递到 `agf.ws.<tenant>.<kind>`，并由订阅泵回灌本副本的
//! 进程内广播（多副本互通）；否则直接用进程内广播。**降级铁律**：
//!
//! - 装配由 [`AppState::attach_nats_events`] **显式触发**：`AppState::build` 不连任何外部依赖，
//!   保证离线单测与最小部署不被 NATS 拖住；
//! - NATS URL 非法/不可达/订阅失败：只 `warn` + 追加 `notes`（`GET /readyz` 可见）并退回
//!   进程内广播，**不返回错误、不阻断启动、不让 `/ws` 不可用**；
//! - 运行期单条事件投递失败（连接抖动/发布队列满/序列化失败）：该条退回进程内广播，
//!   计入 `agf_ws_local_fallback_total`；事件不丢（只是跨副本不可见）。
//!
//! ## 进程内 KPI 历史（`/overview` 的 `riskTrend`）
//!
//! [`RiskHistory`] 按小时滚动记录风险趋势采样，保证控制台曲线至少有**两个点**
//! （启动点 + 当前点）。它**只活在进程内**：重启即清空、多副本各自一份，长期趋势由
//! Prometheus（`agf_*` 指标 + Grafana）承载——这是如实标注的能力边界。

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use agf_aigw::Meter;
use agf_alicloud::registry::AliCloudRegistry;
use agf_auth::api_key::ApiKeyService;
use agf_auth::claims::TokenIssuer;
use agf_auth::rbac::Authorizer;
use agf_auth::service::{AuthBackend, AuthService, InMemoryAuthBackend};
use agf_core::auth::PasswordPolicy;
use agf_core::config::AppConfig;
use agf_core::constants::{API_KEY_PREFIX_LIVE, JWT_AUDIENCE, JWT_ISSUER};
use agf_core::enums::{IngestProtocol, PolicyAction, RiskDomain, RuleKind, Severity};
use agf_core::error::{DomainError, DomainResult};
use agf_core::event::RawLog;
use agf_core::ids::{Id, TenantId};
use agf_core::rbac::{Role, builtin};
use agf_core::report::{ReportFormat, ReportKind, ReportSchedule};
use agf_core::rule::{Detection, RuleDefinition, RuleSamples, RuleTarget};
use agf_core::time::Timestamp;
use agf_core::user::User;
use agf_correlate::notify::{DispatchConfig, NotificationDispatcher};
use agf_ingest::pipeline::{InMemorySink, Sink};
use agf_ingest::registry::ParserRegistry;
use agf_runtime::engine::{EngineConfig, RuntimeEngine};
use agf_scan::engine::ScanEngine;
use agf_scan::loader::{RulePack, RulePackLoader, RulesDir};
use agf_scan::redteam::CaseLibrary;
use tracing::{info, warn};

use crate::error::ApiError;
use crate::metrics::Metrics;
use crate::middleware::{IdempotencyStore, RateLimitTiers, RateLimiter};
use crate::persistence::PersistenceBridge;
use crate::store::ApiStore;
use crate::ws::NatsEventPlane;

/// 应用状态（axum `State`）。
#[derive(Debug, Clone)]
pub struct AppState {
    #[cfg(feature = "test-loopback-transport")]
    pub(crate) gateway_test_transport: Option<Arc<crate::gateway_settlement::loopback::Capability>>,
    #[cfg(feature = "test-loopback-transport")]
    pub(crate) redteam_multi_test_transport: Option<Arc<crate::routes::ecosystem::multi_target::TestCapability>>,
    /// 运行配置。
    pub config: Arc<AppConfig>,
    /// 数据层。
    pub store: Arc<ApiStore>,
    /// **写后（write-behind）持久化桥**（`None` = 离线内存模式，无数据库）。
    ///
    /// 有数据库时它负责：启动水合（PG → 内存读缓存）、消费 [`crate::persistence::PgWrite`]
    /// 写意图、以及 `queued/applied/failed/dropped` 计数与最近错误。口径见
    /// [`crate::persistence`] 模块文档：**PG 是持久层、内存是缓存、写入最终一致（非事务性双写）**。
    ///
    /// `/readyz` 与 `/settings` 的 notes 由 [`PersistenceBridge::report`] 在**启动期**生成
    /// （`routes/**` 只读 `state.notes`，本轮不改路由层）；运行期实时计数请读 `report()` 或日志。
    pub persistence: Option<Arc<PersistenceBridge>>,
    /// 运行模式。
    pub mode: ServiceMode,
    /// 降级/提示说明（写入启动日志并在 `/readyz`、`/settings` 暴露）。
    pub notes: Arc<Vec<String>>,
    /// 认证服务。
    pub auth: Arc<AuthService>,
    /// 认证后端：有数据库时同步事务提交；离线测试使用内存。
    pub auth_backend: Arc<dyn AuthBackend>,
    /// 同步提交的控制台配置（端点、接入、租户设置）。
    pub configurations: Arc<crate::config_store::ConfigStore>,
    /// 离线内存模式下把模型配置及其资产投影作为一次串行操作。
    pub(crate) model_asset_lock: Arc<tokio::sync::Mutex<()>>,
    /// Serializes the explicit offline automation mode; SQL also uses cross-instance record locks.
    pub(crate) soar_automation_lock: Arc<tokio::sync::Mutex<()>>,
    /// 模型连接池与过滤/计量编排器，配置变化后按租户自动重建。
    pub model_gateway: Arc<crate::model_gateway::GatewayRegistry>,
    /// 独立租户/配置版本的集成适配器，保留熔断与增量读取状态。
    pub integration_runtime: Arc<crate::integration_runtime::Registry>,
    pub privatelink_provisioning: std::sync::Arc<crate::privatelink_provisioning::Registry>,
    pub cloud_runtime: Arc<crate::cloud_runtime::Registry>,
    /// Explicit Nacos HTTPS transport; loopback tests require a typed server-side capability.
    pub mse_config_publication: Arc<crate::mse_config_publication::Registry>,
    /// Fixed APIG origin; a loopback origin requires a typed isolated test capability.
    pub apig_policy_publication: Arc<crate::apig_policy_publication::Registry>,
    /// Explicit trusted APIG content and model configuration transport capability.
    pub apig_configuration_publication: Arc<crate::apig_configuration_publication::Registry>,
    /// Safe Scheduler observations; isolated loopback providers require a typed server capability.
    pub scheduler_native_observation: Arc<crate::scheduler_native_observation::Registry>,
    /// Explicit CMS queue runtime capability; GET never sends or seeds.
    pub cms_queue: Arc<crate::cms_queue::Registry>,
    /// 授权器（RBAC + ABAC）。
    pub authorizer: Arc<Authorizer>,
    /// API Key 服务。
    pub api_keys: Arc<ApiKeyService>,
    /// 规则包。
    pub rules: Arc<RulePack>,
    pub rule_cache: Arc<crate::rule_store::RuleCache>,
    /// 红队用例库。
    pub redteam_cases: Arc<CaseLibrary>,
    /// 解析器注册表。
    pub parsers: Arc<ParserRegistry>,
    /// 阿里云适配器注册表（无凭据时全部为 Mock）。
    pub alicloud: Arc<AliCloudRegistry>,
    /// 运行时拦截引擎。
    pub runtime: Arc<RuntimeEngine>,
    /// 模型计量（`agf-aigw` 的真实计量链）。
    ///
    /// 为什么 `AppState` 要有它：`GET /api/v1/models/usage` 与 `/models/usage/aggregate`
    /// 读的就是 [`Meter::recent`]，此前 `AppState` 没有计量实例 ⇒ 两个端点恒 `total=0`。
    /// 记录由演示灌库（`AGF_SEED_FIXTURES=1`，见 [`crate::seed::seed_model_usage`]）驱动
    /// `MockProvider` + [`Meter::record`] 写入；**生产路径**是 `agf_aigw::AiGateway::chat`
    /// 内部的 `meter.record`（`TODO(api-models-metering)`：网关实例尚未装配进 `AppState`，
    /// 当前只有计量件，没有南北向网关本身）。
    pub meter: Arc<Meter>,
    /// 原始日志仓储（**回放**用）。
    ///
    /// `GET`/`POST /api/v1/ingest/replay` 走 `agf_ingest::replay::Replayer`，它需要一个
    /// 已装配的 [`Sink`]；此前 `AppState` 没有该字段 ⇒ 回放端点只能返回 501。
    /// 这里装的是 `agf_ingest::pipeline::InMemorySink`（与 `apps/ingest` 的默认落库同款）：
    /// 进程内、重启即丢，真实的 PostgreSQL 落库（`SqlSink`）由 `TODO(ingest-sql-sink)` 承接。
    pub ingest_sink: Arc<dyn Sink>,
    pub runtime_registry: Arc<crate::runtime_registry::Registry>,
    pub(crate) ingest_pipelines: Arc<crate::ingest_pipelines::Registry>,
    /// 回放用解析器注册表（**可变**）。
    ///
    /// 回放会调 [`ParserRegistry::match_raw`]（`&mut self`，会累加模板命中统计），
    /// 因此必须可写；[`AppState::parsers`] 保持 `Arc<ParserRegistry>` 只读形态，两者
    /// 由**同一次目录加载来源**分别构建（两份独立实例，启动时内容一致）。
    /// 已知差异：运行期对其中一份的改动不影响另一份（当前没有运行期模板写接口，见 `routes`）。
    pub replay_parsers: Arc<std::sync::Mutex<ParserRegistry>>,
    /// 通知派发器（进程内共享）。
    ///
    /// 共享的意义：`agf_correlate::notify::NotificationDispatcher` 的去重表、限流窗口与审计
    /// 都在实例内部，做成进程单例才能让「同一案件同一渠道只发一次」「窗口内限流」跨请求真实生效。
    /// **渠道全部是 `MockChannel`（不联网）**；真实渠道适配器见 `agf-adapters`（
    /// `TODO(correlate-notify-adapters)`）。
    pub notifier: Arc<tokio::sync::Mutex<NotificationDispatcher>>,
    /// 报表周期调度登记表（`GET`/`POST /api/v1/reports/schedules`）。
    pub schedules: Arc<ScheduleStore>,
    /// 扫描引擎。
    pub scan_engine: Arc<ScanEngine>,
    /// 指标。
    pub metrics: Arc<Metrics>,
    /// 限流器。
    pub limiter: Arc<RateLimiter>,
    /// 多副本部署要求 Redis 共享限流；缺失时拒绝业务请求并使就绪探针失败。
    pub shared_rate_limit_required: bool,
    /// 幂等键存储。
    pub idempotency: Arc<IdempotencyStore>,
    /// 事件广播（`/ws` 订阅 + 心跳）。
    ///
    /// NATS 事件面可用时，它由 [`NatsEventPlane`] 的订阅泵回灌；否则由 [`AppState::publish`]
    /// 直接写入（`AGF_NATS_ENABLED=0` 或 NATS 不可达的降级路径）。
    pub events: tokio::sync::broadcast::Sender<WsEvent>,
    /// `/ws` 的 NATS 事件面（`None` = 走进程内广播）。
    ///
    /// 由 [`AppState::attach_nats_events`] 显式装配：`AGF_NATS_ENABLED=1` 且连接成功才有值；
    /// 连接失败只写 `notes` 并保持 `None`（降级为进程内广播，见模块文档）。
    pub nats: Option<Arc<NatsEventPlane>>,
    /// 进程内小时级风险趋势历史（`/overview` 的 `riskTrend`；跨重启丢失，见 [`RiskHistory`]）。
    pub risk_history: Arc<RiskHistory>,
    /// 启动时间。
    pub started_at: Timestamp,
    /// 默认租户。
    pub default_tenant: TenantId,
    /// CORS 允许来源（配置驱动：`AGF_CORS_ALLOW_ORIGINS`）。
    pub cors_origins: Arc<Vec<String>>,
}

// `spawn_risk_history_persister` 内部按 `crate::state::env_u64` 取环境变量，故在父模块保留该名字。
use resources::env_u64;

use replay::*;
pub use resources::*;
pub use schedule::*;
pub use types::*;

mod app_ops;
mod build;
mod not_implemented;
mod replay;
mod resources;
mod schedule;
mod seed_persist;
mod types;
