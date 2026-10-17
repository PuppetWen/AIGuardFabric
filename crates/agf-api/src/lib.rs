//! # agf-api — AIGuardFabric HTTP / GraphQL / WebSocket API
//!
//! ## 分层
//!
//! | 模块 | 职责 |
//! |---|---|
//! | [`error`] | RFC 9457 `application/problem+json`（复用 `DomainError` 的 type/status/code） |
//! | [`state`] | `AppState` 装配：配置、数据层、认证/授权、规则包、红队库、解析器、云适配器 |
//! | [`store`] | 离线优先内存数据层（`ApiStore`，同时实现 `AssetBackend`） |
//! | [`middleware`] | 请求 id、tracing span、三级限流、幂等、认证主体提取（`Principal`） |
//! | [`query`] | 分页/排序/过滤/字段裁剪的统一解析 |
//! | [`metrics`] | Prometheus 指标（请求计数 / 时延直方图 / 拦截计数） |
//! | [`history`] | `/overview` KPI 历史（`riskTrend`）的本地持久化（JSON 原子写；装配由 `state` 侧接线） |
//! | [`routes`] | 各资源组路由（见 [`routes`] 模块文档） |
//! | [`graphql`] / [`ws`] | `POST /graphql` 与 `GET /ws` |
//!
//! ## 离线可测
//!
//! 测试用 `tower::ServiceExt::oneshot` 直接驱动 [`build_router`]：不监听端口、不联网、
//! 不依赖 PostgreSQL（资源全部落在 [`store::ApiStore`] 的进程内存）。
//!
//! ## 未实现面的表达方式
//!
//! 未实现能力一律返回 **501** 且带 `todo` 锚点，源码里必须存在同名 `TODO(...)` 注释：
//! `api-correlate-aggregate`、`api-alert-sla`、`api-alert-escalation`、`api-case-sla`、
//! `api-playbook-execute`、`api-notify-dispatch`、`api-report-schedule`、
//! `api-sources-persist`、`api-persistence`、`api-openapi-swagger`。

#![forbid(unsafe_code)]
// 测试用 assert!/panic!/unwrap() 表达不变量；生产代码的 panic 仍在 workspace 层被 deny。
#![cfg_attr(test, allow(clippy::panic, clippy::unwrap_used, clippy::expect_used))]
// `ApiError` 承载 `DomainError`（含多个 `String` 变体），其 Err 分支约 144 字节，超过
// clippy `result_large_err` 的 128 字节阈值。API 层有近百个返回 `Result<_, ApiError>`
// 的处理函数，把错误 Box 化会污染全部签名并削弱 `?` 与 `IntoResponse` 的可读性；
// 这里集中放行该**风格类** lint（错误类型尺寸不影响正确性），并保留其余 pedantic 检查。
#![allow(clippy::result_large_err)]

pub mod agentteams_audit;
pub(crate) mod agentteams_orchestration;
pub(crate) mod agentteams_role_mapping;
pub mod agentteams_task_handling;
pub mod alert_escalation;
pub mod apig_configuration_publication;
pub mod apig_policy_publication;
pub mod asset_inventory;
pub mod audit_anchor;
pub mod auth_policy;
pub mod auth_store;
pub mod cloud_credentials;
pub mod cloud_inventory;
pub mod cloud_inventory_views;
pub mod cloud_runtime;
pub mod cloud_status;
pub mod cloud_store;
pub mod config_store;
pub mod containment;
pub mod correlation;
pub mod error;
pub mod event_analysis;
pub mod event_delivery;
pub mod gateway_quota;
pub mod gateway_semantic;
pub(crate) mod gateway_semantic_profile;
pub(crate) mod gateway_settlement;
pub use gateway_settlement::{GatewayMaintenance, start_gateway_maintenance};
pub mod cms_queue;
pub mod graphql;
pub mod history;
pub(crate) mod ingest_pipelines;
pub mod integration_receipts;
pub mod integration_runtime;
pub mod integration_store;
pub mod mcp_gateway;
pub mod metrics;
pub mod mfa_store;
pub mod middleware;
pub mod model_gateway;
pub mod model_routes;
pub mod mse_config_publication;
pub mod mse_inventory;
pub mod notification_config;
pub mod notification_delivery;
mod notification_inbox;
pub mod notification_outbox;
pub mod parser_store;
pub mod persistence;
pub mod policy_store;
pub mod privatelink_inventory;
pub mod privatelink_provisioning;
mod probe_publication;
pub mod query;
pub mod quota_definitions;
pub mod report_artifact;
pub mod report_cron;
mod report_pdf;
pub mod report_service;
pub mod routes;
pub mod rule_store;
pub mod runtime_audit;
pub mod runtime_quota;
pub mod runtime_registry;
pub mod runtime_rules;
pub mod scheduler_native_observation;
pub mod security_analysis;
pub mod seed;
pub mod soar_automation;
pub mod soar_executor;
pub mod soar_workflow;
pub mod source_ingest;
pub mod source_store;
pub mod source_worker;
pub mod state;
pub mod store;
pub(crate) mod team_management;
pub mod tenant_directory;
pub mod worker_quota;
pub mod ws;

use agf_core::error::DomainError;
use agf_core::pagination::{Page, PageRequest};
use axum::Router;
use axum::http::{HeaderName, HeaderValue, Method, Uri, header};
use axum::routing::get;
use tower_http::cors::{Any, CorsLayer};

pub use error::{ApiError, ApiResult, ProblemDetails};
pub use metrics::Metrics;
pub use middleware::{Principal, RateLimitTier, RateLimitTiers};
pub use query::ListQuery;
pub use state::{AppState, BootstrapOutcome, ServiceMode, WsEvent};
pub use store::{ApiStore, ScanJob, ScanJobState};

/// 平台版本（编译期取自 Cargo 包版本）。
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// 内存列表 → [`Page`]（切片窗口 + 总数），供离线后端统一使用。
pub(crate) fn pagination_page<T>(items: Vec<T>, req: &PageRequest) -> Page<T> {
    let normalized = req.normalized();
    let total = i64::try_from(items.len()).unwrap_or(i64::MAX);
    let offset = usize::try_from(normalized.offset()).unwrap_or(0);
    let limit = usize::try_from(normalized.limit()).unwrap_or(usize::MAX);
    let window: Vec<T> = items.into_iter().skip(offset).take(limit).collect();
    Page::new(window, total, &normalized)
}

/// 组装完整路由器（含中间件与 CORS）。
pub fn build_router(state: AppState) -> Router {
    let prefix = state.config.server.api_prefix.clone();
    let cors = build_cors(&state.cors_origins);
    Router::new()
        .merge(routes::public_router())
        .merge(routes::gateway::compat_router())
        .nest(&prefix, routes::api_v1_router())
        .merge(graphql::router())
        .merge(ws::router())
        .route("/", get(root))
        .fallback(not_found)
        // 顺序：先加的在最内层。request_context 必须比 rate_limit 更外层，
        // 这样被限流的请求也会被计入指标并带上 X-Request-Id。
        .layer(axum::middleware::from_fn_with_state(state.clone(), middleware::idempotency))
        .layer(axum::middleware::from_fn_with_state(state.clone(), middleware::rate_limit))
        .layer(axum::middleware::from_fn_with_state(state.clone(), middleware::request_context))
        .layer(axum::middleware::from_fn(middleware::client_address::normalize))
        .layer(cors)
        .with_state(state)
}

/// Dedicated MCP listener: only transport routes and health checks, with the API's authentication and limits.
pub fn build_mcp_router(state: AppState) -> Router {
    let cors = build_cors(&state.cors_origins).allow_headers(tower_http::cors::AllowHeaders::mirror_request());
    Router::new()
        .nest(&state.config.server.api_prefix, routes::mcp_http::transport_router())
        .route("/healthz", get(routes::healthz))
        .layer(axum::middleware::from_fn_with_state(state.clone(), middleware::rate_limit))
        .layer(axum::middleware::from_fn_with_state(state.clone(), middleware::request_context))
        .layer(axum::middleware::from_fn(middleware::client_address::normalize))
        .layer(cors)
        .with_state(state)
}

/// Dedicated scrape listener: expose metrics and liveness without console APIs.
pub fn build_metrics_router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(routes::healthz))
        .route("/metrics", get(routes::render_metrics))
        .with_state(state)
}

/// 根路径：给出服务标识与关键端点（便于人工探活）。
async fn root() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "service": "AIGuardFabric",
        "product": agf_core::constants::PRODUCT_NAME_ZH,
        "version": VERSION,
        "endpoints": ["/healthz", "/readyz", "/metrics", "/api/v1", "/graphql", "/ws"],
    }))
}

/// 未匹配路由 → problem+json 404。
async fn not_found(uri: Uri) -> ApiError {
    ApiError::new(DomainError::NotFound { entity: "route", id: uri.path().to_string() })
}

/// CORS 层（配置驱动：`AGF_CORS_ALLOW_ORIGINS`，逗号分隔；生产未配置则不放行跨域）。
pub fn build_cors(origins: &[String]) -> CorsLayer {
    let layer = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::PATCH, Method::DELETE, Method::OPTIONS])
        .allow_headers([
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            header::ACCEPT,
            header::USER_AGENT,
            HeaderName::from_static("x-agf-key"),
            HeaderName::from_static("mcp-protocol-version"),
            HeaderName::from_static("mcp-method"),
            HeaderName::from_static("mcp-name"),
            HeaderName::from_static("mcp-session-id"),
            HeaderName::from_static("last-event-id"),
            HeaderName::from_static("x-agf-tenant"),
            HeaderName::from_static("x-agf-department"),
            // 采集器上行的 mTLS 身份头（由入口网关写入；浏览器侧本不该发，但 CORS 白名单
            // 必须与"端点接受的头部"一致，否则排查时会被浏览器预检拦掉）
            HeaderName::from_static("x-ssl-client-verify"),
            HeaderName::from_static("x-ssl-client-cert"),
            HeaderName::from_static("x-agf-client-cert-der"),
            HeaderName::from_static("idempotency-key"),
            HeaderName::from_static("x-request-id"),
        ])
        .expose_headers([
            HeaderName::from_static("x-request-id"),
            HeaderName::from_static("x-ratelimit-limit"),
            HeaderName::from_static("x-ratelimit-remaining"),
            HeaderName::from_static("x-ratelimit-reset"),
            HeaderName::from_static("idempotency-replayed"),
            HeaderName::from_static("retry-after"),
            HeaderName::from_static("mcp-session-id"),
            HeaderName::from_static("mcp-protocol-version"),
        ])
        .max_age(std::time::Duration::from_mins(10));
    if origins.iter().any(|o| o == "*") {
        return layer.allow_origin(Any);
    }
    let parsed: Vec<HeaderValue> = origins.iter().filter_map(|o| HeaderValue::from_str(o).ok()).collect();
    if parsed.is_empty() { layer } else { layer.allow_origin(parsed) }
}
