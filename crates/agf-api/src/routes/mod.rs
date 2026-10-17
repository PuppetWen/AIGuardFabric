//! 路由装配。
//!
//! 分组与提示词 §11 的资源组一一对应：
//! - [`auth`]：登录状态机（首登强制改密、刷新、登出、当前用户）；
//! - [`assets`]：资产台账 + 风险发现；
//! - [`ai_assets`]：AI 资产只读资源组 `agents` / `mcps` / `skills` / `models`（§4.11）；
//! - [`governance`]：规则库 + 扫描 + 策略；
//! - [`soc`]：告警 + 案件 + 配额；
//! - [`ingest`]：日志接入源 + 解析器（含能力矩阵）；
//! - [`ecosystem`]：红队 + 集成适配器 + 阿里云自检；
//! - [`console`]：控制台专用只读端点（总览/搜索/拓扑/身份/设置/运行时拦截点）；
//! - [`console_ops`]：控制台其余缺口（模型网关用量与路由、SOC 动作、生态与路径别名）；
//! - [`platform`]：审计链 + 报表 + 设置 + OpenAPI。

pub mod ai_assets;
pub mod alert_escalation;
pub mod asset_deletion;
pub mod asset_edr;
pub mod asset_iam;
pub mod asset_metadata;
pub mod assets;
mod assets_view;
pub mod auth;
pub mod cloud_config;
pub mod correlation;
pub mod downloads;
pub mod gateway;
pub mod integrations_config;
pub mod mcp_http;
pub mod mfa;
pub mod notifications;
pub mod runtime_control;
pub mod runtime_process;
pub mod sso;
pub mod tenants;
// 控制台只读端点（总览/搜索/拓扑/身份/设置/运行时，见 `console.rs` 模块文档）。
pub mod console;
pub mod console_ops;
pub mod ecosystem;
pub mod governance;
pub mod ingest;
pub mod platform;
pub mod soc;

use std::collections::BTreeMap;

use agf_core::error::DomainError;
use agf_core::ids::Id;
use axum::Json;
use axum::Router;
use axum::extract::{FromRequest, Request, State};
use axum::routing::get;
use serde::de::DeserializeOwned;

use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

/// 公共（无需认证）路由器：存活/就绪/指标。
pub fn public_router() -> Router<AppState> {
    Router::new()
        .merge(downloads::router())
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/metrics", get(render_metrics))
        .route("/openapi.json", get(platform::openapi_spec))
}

/// `/api/v1` 路由器。
pub fn api_v1_router() -> Router<AppState> {
    Router::new()
        .merge(auth::router())
        .merge(crate::audit_anchor::routes::router())
        .merge(sso::router())
        .merge(tenants::router())
        .merge(mfa::router())
        .merge(notifications::router())
        .merge(alert_escalation::router())
        .merge(integrations_config::router())
        .merge(cloud_config::router())
        .merge(crate::agentteams_audit::routes::router())
        .merge(crate::agentteams_orchestration::router())
        .merge(crate::agentteams_role_mapping::router())
        .merge(crate::agentteams_task_handling::router())
        .merge(crate::mse_inventory::router())
        .merge(crate::mse_config_publication::router())
        .merge(crate::apig_policy_publication::router())
        .merge(crate::apig_configuration_publication::router())
        .merge(crate::scheduler_native_observation::router())
        .merge(crate::cms_queue::router())
        .merge(crate::privatelink_inventory::router())
        .merge(crate::privatelink_provisioning::router())
        .merge(crate::worker_quota::routes::router())
        .merge(crate::team_management::router())
        .merge(correlation::router())
        .merge(runtime_control::router())
        .merge(runtime_process::router())
        .merge(mcp_http::router())
        .merge(gateway::router())
        .merge(crate::gateway_semantic_profile::router())
        .merge(crate::gateway_settlement::router())
        .merge(assets::router())
        .merge(ai_assets::router())
        .merge(governance::router())
        .merge(soc::router())
        .merge(ingest::router())
        .merge(ecosystem::router())
        .merge(console::router())
        .merge(console_ops::router())
        .merge(platform::router())
}

/// 存活探针：**不检查任何依赖**（数据库/Redis 挂了也返回 200）。
pub async fn healthz(State(state): State<AppState>) -> Json<serde_json::Value> {
    let uptime = agf_core::time::Timestamp::now().since_secs(&state.started_at).max(0);
    Json(serde_json::json!({
        "status": "ok",
        "service": "agf-server",
        "version": crate::VERSION,
        "mode": state.mode.as_str(),
        "uptime_secs": uptime,
    }))
}

/// 就绪探针：数据库/Redis 为**可选**依赖；未配置时按离线模式返回 ready 并标注 degraded。
///
/// # Errors
/// 已配置数据库但不可达时返回 503。
pub async fn readyz(State(state): State<AppState>) -> ApiResult<Json<serde_json::Value>> {
    let mut checks: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    let mut degraded = false;

    match state.store.database() {
        Some(store) => match store.health().await {
            Ok(health) => {
                checks.insert("database".to_string(), serde_json::json!({"status": "ok", "configured": true}));
                degraded |= !health.redis || !health.objects;
                checks.insert(
                    "redis".to_string(),
                    serde_json::json!({"status": if health.redis { "ok" } else { "degraded" }, "configured": health.redis}),
                );
                checks.insert(
                    "objects".to_string(),
                    serde_json::json!({
                        "status": if health.objects { "ok" } else { "degraded" },
                        "backend": health.object_backend,
                    }),
                );
            }
            Err(e) => {
                state.metrics.set_ready(false);
                return Err(ApiError::new(DomainError::DependencyUnavailable {
                    dependency: "postgres".to_string(),
                    cause: format!("就绪探测失败: {e}"),
                }));
            }
        },
        None => {
            degraded = true;
            checks.insert(
                "database".to_string(),
                serde_json::json!({"status": "offline", "configured": false, "note": "未配置数据库，运行在离线内存模式"}),
            );
        }
    }
    checks.entry("redis".to_string()).or_insert_with(|| {
        serde_json::json!({
            "status": "offline",
            "configured": false,
            "note": "Redis 为可选依赖：未配置时缓存与配额降级为进程内存",
        })
    });
    if state.shared_rate_limit_required && checks.get("redis").and_then(|value| value["status"].as_str()) != Some("ok")
    {
        state.metrics.set_ready(false);
        return Err(ApiError::new(DomainError::DependencyUnavailable {
            dependency: "redis".into(),
            cause: "多副本共享限流所需的 Redis 不可用".into(),
        }));
    }
    checks.insert("rules".to_string(), serde_json::json!({"status": "ok", "loaded": state.rules.len()}));
    // 红队用例库与解析模板库来自外部目录（`AGF_REDTEAM_DIR` / `AGF_PARSERS_DIR`）：
    // 缺失时进程照常就绪，但这里如实标注 `degraded` 与原因，便于运维一眼看出"缺什么"。
    let redteam_cases = state.redteam_cases.cases().len();
    checks.insert(
        "redteam".to_string(),
        serde_json::json!({
            "status": if redteam_cases > 0 { "ok" } else { "degraded" },
            "cases": redteam_cases,
            "note": if redteam_cases > 0 { "" } else { "用例库为空：AGF_REDTEAM_DIR 指向的目录不存在或没有可加载用例" },
        }),
    );
    let parser_stats = state.parsers.stats();
    checks.insert(
        "parsers".to_string(),
        serde_json::json!({
            "status": if parser_stats.loaded > 0 { "ok" } else { "degraded" },
            "total": state.parsers.all().len(),
            "loaded": parser_stats.loaded,
            "builtin": parser_stats.builtin,
            "invalid": parser_stats.invalid,
            "note": if parser_stats.loaded > 0 { "" } else { "目录模板未加载：AGF_PARSERS_DIR 指向的目录不存在或全部校验失败，当前只有内置模板" },
        }),
    );
    // 写后持久化：**每次请求现算**（`PersistenceBridge::report()`），不是启动期快照。
    // 失败/丢弃非 0 ⇒ PG 侧与内存层已经不一致，按 `degraded` 如实暴露并给 note。
    match state.persistence.as_ref().map(|bridge| bridge.report()) {
        Some(report) => {
            let lossy = report.failed > 0 || report.dropped > 0;
            degraded |= lossy;
            checks.insert(
                "persistence".to_string(),
                serde_json::json!({
                    "status": if lossy { "degraded" } else { "ok" },
                    "mode": "write-behind",
                    "durable": report.durable,
                    "memory_only": report.memory_only,
                    "queued": report.queued,
                    "applied": report.applied,
                    "failed": report.failed,
                    "dropped": report.dropped,
                    "depth": report.pending,
                    "id_remapped": report.id_remapped,
                    "queue_capacity": report.queue_capacity,
                    "note": if lossy {
                        format!(
                            "写后持久化有损：落库失败 {} 条 / 队列满丢弃 {} 条——PG 侧与内存层已不一致，\
                             详见 /settings 的 persistence.recent_errors 与 warn 日志",
                            report.failed, report.dropped
                        )
                    } else {
                        "写后（write-behind）持久化：PG 为持久层、内存为读缓存，写入最终一致（非事务性双写）"
                            .to_string()
                    },
                }),
            );
        }
        None => {
            checks.insert(
                "persistence".to_string(),
                serde_json::json!({
                    "status": "offline",
                    "mode": "memory-only",
                    "note": "离线内存模式：无写后持久化桥（PersistenceBridge），所有资源只落进程内存（重启即丢）",
                }),
            );
        }
    }

    // 阿里云适配器的 TLS 放松策略必须显式可见（**绝不静默弱化校验**）。
    // `readyz_notes()` 只在确实放松（`custom-ca` / `insecure-skip-verify`）时产出条目，
    // 默认（`verify-chain`）为空 ⇒ 不产生噪音。
    let mut notes: Vec<String> = state.notes.as_ref().clone();
    for report in &state.alicloud.self_check_suite().reports {
        notes.extend(report.readyz_notes());
    }

    state.metrics.set_ready(true);
    Ok(Json(serde_json::json!({
        "status": "ready",
        "mode": state.mode.as_str(),
        "degraded": degraded,
        "checks": checks,
        "notes": notes,
    })))
}

/// Prometheus 文本指标。
pub async fn render_metrics(State(state): State<AppState>) -> axum::response::Response {
    use axum::response::IntoResponse;
    ([(axum::http::header::CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8")], state.metrics.render())
        .into_response()
}

/// 统一解析路径中的 UUID（失败返回 problem+json 400）。
///
/// # Errors
/// 路径参数不是 UUID。
pub fn parse_id(raw: &str, entity: &'static str) -> Result<Id, ApiError> {
    Id::parse(raw).map_err(|e| ApiError::new(DomainError::Validation(format!("{entity} id 非法: {e}"))))
}

/// 统一 JSON 请求体提取器（拒绝时也返回 problem+json，而不是 axum 的默认纯文本）。
#[derive(Debug, Clone, Copy)]
pub struct ApiJson<T>(pub T);

impl<S, T> FromRequest<S> for ApiJson<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let axum::Json(value) = axum::Json::<T>::from_request(req, state)
            .await
            .map_err(|e| ApiError::new(DomainError::Validation(format!("请求体解析失败: {e}"))))?;
        Ok(Self(value))
    }
}

/// 统一的"未实现端点"响应构造（501 + TODO 锚点）。
///
/// # Errors
/// 恒返回 501。
pub fn todo_endpoint(anchor: &'static str, what: &str) -> Result<Json<serde_json::Value>, ApiError> {
    Err(AppState::not_implemented(anchor, what))
}

mod finding_filters;
mod finding_views;
