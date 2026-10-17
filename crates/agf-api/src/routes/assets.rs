//! 资产与风险发现路由。

use agf_asset::discovery::{DiscoveredAsset, DiscoveryBatch};
use agf_asset::service::LifecycleTransition;
use agf_core::audit::{AuditAction, AuditOutcome, AuditTarget};
use agf_core::enums::{AssetKind, DataClass, DiscoverySource, LifecycleState};
use agf_core::error::DomainError;
use agf_core::risk::FindingState;
use axum::Json;
use axum::Router;
use axum::extract::{Path, State};
use axum::routing::{get, post};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::error::{ApiError, ApiResult};
use crate::middleware::Principal;
use crate::query::ListQuery;
use crate::routes::{ApiJson, parse_id};
use crate::state::AppState;

/// 资产与发现路由。
pub fn router() -> Router<AppState> {
    Router::new()
        .merge(crate::asset_inventory::router())
        .merge(super::asset_edr::router())
        .merge(super::asset_iam::router())
        .route("/assets", get(list_assets))
        .route("/assets/stats", get(asset_stats))
        .route("/assets/discovery", post(ingest_discovery))
        .route("/assets/drift", post(compute_drift))
        .route(
            "/assets/{id}",
            get(get_asset).patch(super::asset_metadata::update).delete(super::asset_deletion::remove),
        )
        .route("/assets/{id}/transition", post(transition_asset))
        .route("/findings", get(list_findings))
        .route("/findings/stats", get(finding_stats))
        .route("/findings/{id}", get(get_finding))
        .route("/findings/{id}/state", post(set_finding_state))
}

/// 资产列表（`GET /api/v1/assets`）：支持 `page`/`page_size`/`sort`/`fields`/`q` 与
/// `kind`、`lifecycle`、`min_exposure` 过滤。
///
/// # Errors
/// 过滤参数非法或存储错误。
pub async fn list_assets(
    State(state): State<AppState>,
    principal: Principal,
    query: ListQuery,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "assets", "read")?;
    let filters = crate::store::AssetSelection::from_query(&query)?;
    let page = state.store.asset_page_durable(principal.tenant, &query.to_page_request(), filters).await?;
    Ok(Json(super::assets_view::page(&state, &principal, &query, &page).await?))
}

/// 资产详情（含变更台账）。
///
/// # Errors
/// 资产不存在或 id 非法。
pub async fn get_asset(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "assets", "read")?;
    let asset_id = parse_id(&id, "asset")?;
    let Some(asset) = state.store.asset_get_durable(principal.tenant, asset_id).await? else {
        return Err(ApiError::new(DomainError::NotFound { entity: "asset", id: id.clone() }));
    };
    let changes = state.store.asset_changes_durable(principal.tenant, asset_id, 100).await?;
    let governance = serde_json::json!({"can_write": principal.require(&state,"assets","write").is_ok(),
        "lifecycle":asset.lifecycle,"allowed_next":asset.lifecycle.allowed_next(),"updated_at":asset.updated_at,
        "owner":asset.owner,"department":asset.department,"data_class":asset.data_class});
    let content_observation = serde_json::json!({"sha256":asset.attributes.get("content_sha256"),
        "status":asset.attributes.get("content_hash_status"),"received_at":asset.attributes.get("content_hash_observed_at")});
    let package_observation = serde_json::json!({"current":asset.attributes.get("skill_package"),
        "received_at":asset.attributes.get("skill_package_received_at"),
        "last_verified":asset.attributes.get("skill_package_last_verified"),
        "last_verified_at":asset.attributes.get("skill_package_last_verified_at")});
    let asset = super::assets_view::detail(&state, &principal, &asset).await?;
    Ok(Json(serde_json::json!({ "asset": asset, "changes": changes, "governance":governance,
        "content_observation":content_observation,"package_observation":package_observation })))
}

/// 盘点统计（`GET /api/v1/assets/stats`）。
///
/// # Errors
/// 权限不足或存储错误。
pub async fn asset_stats(State(state): State<AppState>, principal: Principal) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "assets", "read")?;
    let inventory = state.store.asset_stats_durable(principal.tenant).await?;
    let platform = state.store.platform_snapshot_durable(principal.tenant).await?;
    Ok(Json(serde_json::json!({ "inventory": inventory, "platform": platform })))
}

/// 发现批次导入 Body。
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
pub struct DiscoveryBody {
    /// 发现来源（默认 `agent-report`）。
    #[serde(default)]
    pub source: Option<String>,
    /// 发现项。
    pub assets: Vec<DiscoveryItem>,
    /// 采集侧告警。
    #[serde(default)]
    pub warnings: Vec<String>,
    /// 批次耗时（毫秒）。
    #[serde(default)]
    pub elapsed_ms: u64,
}

/// 单个发现项。
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
pub struct DiscoveryItem {
    /// Optional SHA-256 of observed Skill/Prompt content, never the content itself.
    #[serde(default)]
    pub content_sha256: Option<String>,
    /// 资产类型（`agent`/`mcp-server`/`skill`/…）。
    pub kind: String,
    /// 名称。
    pub name: String,
    /// 稳定指纹（同一资产多次上报必须一致）。
    pub fingerprint: String,
    /// 端点。
    #[serde(default)]
    pub endpoint: Option<String>,
    /// 厂商。
    #[serde(default)]
    pub vendor: Option<String>,
    /// 版本。
    #[serde(default)]
    pub version: Option<String>,
    /// 归属人。
    #[serde(default)]
    pub owner: Option<String>,
    /// 部门。
    #[serde(default)]
    pub department: Option<String>,
    /// 暴露面评分。
    #[serde(default)]
    pub exposure_score: Option<u8>,
    /// 是否含明文凭据。
    #[serde(default)]
    pub has_plaintext_secret: Option<bool>,
}

/// 发现批次导入（`POST /api/v1/assets/discovery`，幂等：按指纹归并）。
///
/// # Errors
/// 请求体非法或存储错误。
pub async fn ingest_discovery(
    State(state): State<AppState>,
    principal: Principal,
    ApiJson(body): ApiJson<DiscoveryBody>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "assets", "write")?;
    let source = match body.source.as_deref() {
        Some(raw) => parse_discovery_source(raw)?,
        None => DiscoverySource::AgentReport,
    };
    let tenant = principal.tenant;
    let mut batch = DiscoveryBatch::new(tenant, source);
    batch.warnings = body.warnings;
    batch.elapsed_ms = body.elapsed_ms;
    for item in &body.assets {
        let kind = AssetKind::parse(&item.kind).map_err(|e| ApiError::new(DomainError::Validation(e)))?;
        let mut discovered = DiscoveredAsset::new(kind, item.name.clone(), item.fingerprint.clone(), source);
        if let Some(hash) = &item.content_sha256 {
            if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(ApiError::new(DomainError::Validation(
                    "content_sha256 must contain 64 hexadecimal digits".into(),
                )));
            }
            discovered.attributes["content_sha256"] = serde_json::json!(hash.to_ascii_lowercase());
            discovered.attributes["content_hash_status"] = serde_json::json!("verified");
            discovered.attributes["content_hash_observed_at"] = serde_json::json!(agf_core::time::Timestamp::now());
        }
        discovered.endpoint = item.endpoint.clone();
        discovered.vendor = item.vendor.clone();
        discovered.version = item.version.clone();
        discovered.owner = item.owner.clone();
        discovered.department = item.department.clone();
        discovered.exposure_score = item.exposure_score.unwrap_or(0).min(100);
        discovered.has_plaintext_secret = item.has_plaintext_secret.unwrap_or(false);
        // `agf_asset::discovery::to_asset` 不搬运 `has_plaintext_secret`（`Asset` 没有该字段），
        // 而 `InventoryStats::from_assets` 与 AI 资产视图都按 `attributes.has_plaintext_secret` 读，
        // 因此在这里落进扩展属性，避免"导入时报了明文凭据、台账里查不到"。
        if let Some(present) = item.has_plaintext_secret {
            discovered.attributes["has_plaintext_secret"] = serde_json::json!(present);
        }
        discovered.evidence_ref = format!("batch:{}", batch.assets.len() + 1);
        batch.assets.push(discovered);
    }
    let audit = AppState::audit_entry(
        tenant,
        AuditAction::Create,
        AuditOutcome::Success,
        AppState::audit_actor(&principal, "assets-discovery"),
        AuditTarget::new("asset-batch", None, Some(source.as_str().to_string())),
        "",
    );
    let stats = state.store.asset_ingest_audited_durable(tenant, &batch, audit).await?;
    if stats.created > 0 {
        state.publish(crate::state::WsEvent {
            kind: "asset".to_string(),
            tenant_id: tenant,
            at: agf_core::time::Timestamp::now(),
            payload: serde_json::json!({"created": stats.created, "updated": stats.updated}),
        });
    }
    Ok(Json(serde_json::json!({ "source": source.as_str(), "stats": stats })))
}

/// 即时比较首次观测基线，不重复追加变更台账（`POST /api/v1/assets/drift`）。
///
/// # Errors
/// 权限不足或存储错误。
pub async fn compute_drift(
    State(state): State<AppState>,
    principal: Principal,
    ApiJson(body): ApiJson<DriftBody>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "assets", "write")?;
    let (count, report) = state.store.asset_drift_durable(principal.tenant, body.baseline_date.as_deref()).await?;
    Ok(Json(serde_json::json!({
        "snapshot_count": count,
        "report": serde_json::to_value(&report)?,
        "needs_attention": report.summary.needs_attention(),
        "comparison_mode": "first-observation",
        "daily_inventory_url": "/api/v1/assets/inventory",
    })))
}

/// 漂移计算 Body。
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
pub struct DriftBody {
    /// 基线日期（`YYYY-MM-DD`，缺省为昨天）。
    #[serde(default)]
    pub baseline_date: Option<String>,
}

/// 生命周期流转 Body。
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
pub struct TransitionBody {
    /// 目标状态。
    pub to: String,
    /// 旧客户端兼容字段；实际操作人取当前认证身份。
    #[serde(default)]
    pub actor: String,
    /// 编辑表单读取的更新时间；不匹配时拒绝覆盖新数据。
    #[serde(default)]
    #[schema(value_type = Option<String>)]
    pub expected_updated_at: Option<agf_core::time::Timestamp>,
    /// 评审说明。
    #[serde(default)]
    pub note: String,
    /// 数据分级（流转到生产必填）。
    #[serde(default)]
    pub data_class: Option<String>,
    /// 归属人（流转到生产必填）。
    #[serde(default)]
    pub owner: Option<String>,
    /// 部门。
    #[serde(default)]
    pub department: Option<String>,
}

/// 资产生命周期流转（`POST /api/v1/assets/{id}/transition`）。
///
/// # Errors
/// 非法流转或缺少生产评审字段。
pub async fn transition_asset(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<String>,
    ApiJson(body): ApiJson<TransitionBody>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "assets", "write")?;
    if body.note.len() > 2000
        || body.owner.as_ref().is_some_and(|value| value.len() > 256)
        || body.department.as_ref().is_some_and(|value| value.len() > 256)
    {
        return Err(ApiError::new(DomainError::Validation("评审说明最多 2000 字节，负责人及部门最多 256 字节".into())));
    }
    let asset_id = parse_id(&id, "asset")?;
    let to = parse_lifecycle(&body.to)?;
    let mut transition = LifecycleTransition::new(asset_id, to, principal.display(), body.note);
    transition.data_class = match body.data_class.as_deref() {
        Some(raw) => Some(parse_data_class(raw)?),
        None => None,
    };
    transition.owner = body.owner;
    transition.department = body.department;
    let audit = AppState::audit_entry(
        principal.tenant,
        AuditAction::Update,
        AuditOutcome::Success,
        AppState::audit_actor(&principal, "asset-transition"),
        AuditTarget::new("asset", Some(asset_id.to_string()), None),
        &format!("生命周期流转到 {}", to.as_str()),
    );
    let asset =
        state.store.asset_transition_durable(principal.tenant, &transition, body.expected_updated_at, audit).await?;
    Ok(Json(serde_json::json!({ "asset": asset, "state": to.as_str() })))
}

pub use super::finding_views::{get_finding, list_findings};

/// 发现统计（按域 / 按等级）。
///
/// # Errors
/// 权限不足或存储错误。
pub async fn finding_stats(State(state): State<AppState>, principal: Principal) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "findings", "read")?;
    let findings = state.store.finding_list_all_durable(principal.tenant).await?;
    let mut by_domain: std::collections::BTreeMap<String, i64> = std::collections::BTreeMap::new();
    let mut by_severity: std::collections::BTreeMap<String, i64> = std::collections::BTreeMap::new();
    let mut by_state: std::collections::BTreeMap<String, i64> = std::collections::BTreeMap::new();
    for f in &findings {
        *by_domain.entry(f.domain.as_str().to_string()).or_insert(0) += 1;
        *by_severity.entry(f.severity.as_str().to_string()).or_insert(0) += 1;
        *by_state.entry(f.state.as_str().to_string()).or_insert(0) += 1;
    }
    Ok(Json(serde_json::json!({
        "total": findings.len(),
        "by_domain": by_domain,
        "by_severity": by_severity,
        "by_state": by_state,
    })))
}

/// 发现状态流转 Body。
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
pub struct FindingStateBody {
    /// 目标状态（`pending`/`code-reviewed`/`verified`/`false-positive`/`fixed`）。
    pub state: String,
    /// 复核注记。
    #[serde(default)]
    pub verify_note: Option<String>,
    /// 证据等级（`unknown`/`partial`/`confirmed`/`impact`）。
    #[serde(default)]
    pub evidence_level: Option<String>,
}

/// 发现状态流转（`POST /api/v1/findings/{id}/state`）。
///
/// # Errors
/// 状态非法或发现不存在。
pub async fn set_finding_state(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<String>,
    ApiJson(body): ApiJson<FindingStateBody>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "findings", "write")?;
    let finding_id = parse_id(&id, "finding")?;
    let target = parse_finding_state(&body.state)?;
    let level = match body.evidence_level.as_deref() {
        Some(raw) => Some(parse_evidence_level(raw)?),
        None => None,
    };
    let finding =
        state.store.finding_set_state_durable(principal.tenant, finding_id, target, body.verify_note, level).await?;
    state
        .audit(
            principal.tenant,
            AuditAction::Update,
            AuditOutcome::Success,
            AppState::audit_actor(&principal, "finding-state"),
            AuditTarget::new("finding", Some(finding_id.to_string()), Some(finding.title.clone())),
            &format!("状态流转到 {}", target.as_str()),
        )
        .await?;
    Ok(Json(serde_json::json!({ "finding": finding })))
}

// ---------------------------------------------------------------- 解析助手

/// 解析生命周期状态。
///
/// # Errors
/// 未知状态名。
pub fn parse_lifecycle(raw: &str) -> Result<LifecycleState, ApiError> {
    match raw.trim().to_ascii_lowercase().replace('_', "-").as_str() {
        "requested" => Ok(LifecycleState::Requested),
        "under-review" => Ok(LifecycleState::UnderReview),
        "trial" => Ok(LifecycleState::Trial),
        "production" => Ok(LifecycleState::Production),
        "changing" => Ok(LifecycleState::Changing),
        "archived" => Ok(LifecycleState::Archived),
        "rejected" => Ok(LifecycleState::Rejected),
        other => Err(ApiError::new(DomainError::Validation(format!("未知生命周期状态: {other}")))),
    }
}

/// 解析数据分级。
///
/// # Errors
/// 未知分级名。
pub fn parse_data_class(raw: &str) -> Result<DataClass, ApiError> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "public" => Ok(DataClass::Public),
        "internal" => Ok(DataClass::Internal),
        "confidential" => Ok(DataClass::Confidential),
        "restricted" => Ok(DataClass::Restricted),
        other => Err(ApiError::new(DomainError::Validation(format!("未知数据分级: {other}")))),
    }
}

/// 解析发现来源。
///
/// # Errors
/// 未知来源名。
pub fn parse_discovery_source(raw: &str) -> Result<DiscoverySource, ApiError> {
    match raw.trim().to_ascii_lowercase().replace('_', "-").as_str() {
        "agent-report" => Ok(DiscoverySource::AgentReport),
        "network-scan" => Ok(DiscoverySource::NetworkScan),
        "cloud-api" => Ok(DiscoverySource::CloudApi),
        "passive-traffic" => Ok(DiscoverySource::PassiveTraffic),
        "manual" => Ok(DiscoverySource::Manual),
        "git-scan" => Ok(DiscoverySource::GitScan),
        "collector" => Ok(DiscoverySource::Collector),
        "sidecar" => Ok(DiscoverySource::Sidecar),
        "import" => Ok(DiscoverySource::Import),
        other => Err(ApiError::new(DomainError::Validation(format!("未知发现来源: {other}")))),
    }
}

/// 解析发现状态。
///
/// # Errors
/// 未知状态名。
pub fn parse_finding_state(raw: &str) -> Result<FindingState, ApiError> {
    match raw.trim().to_ascii_lowercase().replace('_', "-").as_str() {
        "pending" => Ok(FindingState::Pending),
        "code-reviewed" => Ok(FindingState::CodeReviewed),
        "verified" => Ok(FindingState::Verified),
        "false-positive" => Ok(FindingState::FalsePositive),
        "fixed" => Ok(FindingState::Fixed),
        other => Err(ApiError::new(DomainError::Validation(format!("未知发现状态: {other}")))),
    }
}

/// 解析证据等级。
///
/// # Errors
/// 未知等级名。
pub fn parse_evidence_level(raw: &str) -> Result<agf_core::enums::EvidenceLevel, ApiError> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "unknown" => Ok(agf_core::enums::EvidenceLevel::Unknown),
        "partial" => Ok(agf_core::enums::EvidenceLevel::Partial),
        "confirmed" => Ok(agf_core::enums::EvidenceLevel::Confirmed),
        "impact" => Ok(agf_core::enums::EvidenceLevel::Impact),
        other => Err(ApiError::new(DomainError::Validation(format!("未知证据等级: {other}")))),
    }
}
