//! 配额端点：列表 / 快照 / 新建或更新。

use super::*;

// ===========================================================================
// 配额
// ===========================================================================

/// 配额列表（`GET /api/v1/quotas`）。
///
/// # Errors
/// 权限不足。
pub async fn list_quotas(
    State(state): State<AppState>,
    principal: Principal,
    query: ListQuery,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "quotas", "read")?;
    let usage = crate::runtime_quota::usage(&state, principal.tenant).await?;
    let quotas = crate::quota_definitions::list_versioned(&state, principal.tenant).await?;
    let entries: Vec<serde_json::Value> = quotas
        .iter()
        .map(|row| {
            let q = &row.quota;
            let used = usage.get(&q.id).copied().unwrap_or(0);
            serde_json::json!({
                "quota": row,
                "used": used,
                "remaining": q.remaining(used),
                "usage_ratio": q.usage_ratio(used),
                "exceeded": q.is_exceeded(used),
                "soft_breached": q.is_soft_breached(used),
            })
        })
        .collect();
    let page = query.paginate_vec(
        &entries,
        |v| v.get("quota").and_then(|q| q.get("name")).and_then(|n| n.as_str()).unwrap_or("").to_string(),
        |v| v.get("quota").and_then(|q| q.get("name")).and_then(|n| n.as_str()).unwrap_or("").to_string(),
    );
    Ok(Json(query.render_page(&page)?))
}

/// 配额快照（`GET /api/v1/quotas/snapshot`）。
///
/// # Errors
/// 权限不足。
pub async fn quota_snapshot(State(state): State<AppState>, principal: Principal) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "quotas", "read")?;
    let usage = crate::runtime_quota::usage(&state, principal.tenant).await?;
    let quotas = crate::quota_definitions::list(&state, principal.tenant).await?;
    let mut by_dimension: std::collections::BTreeMap<String, serde_json::Value> = std::collections::BTreeMap::new();
    for quota in &quotas {
        let used = usage.get(&quota.id).copied().unwrap_or(0);
        by_dimension.insert(
            quota.dimension.as_str().to_string(),
            serde_json::json!({
                "scope": quota.scope.as_str(),
                "window": quota.window.as_str(),
                "limit": quota.limit,
                "used": used,
                "remaining": quota.remaining(used),
                "ratio": quota.usage_ratio(used),
                "on_exceed": quota.on_exceed.as_str(),
                "enabled": quota.enabled,
            }),
        );
    }
    Ok(Json(serde_json::json!({
        "tenant_id": principal.tenant,
        "at": Timestamp::now(),
        "dimensions": by_dimension,
        "request_rate_per_min": state.config.quota.tenant_req_per_min,
    })))
}

/// 配额 Body。
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
pub struct QuotaBody {
    /// 名称（同租户唯一）。
    pub name: String,
    /// 当前配置版本；编辑必填，新建可填 0。过期版本返回 409。
    #[serde(default)]
    pub expected_version: Option<u64>,
    /// 作用域：`tenant`/`agent`/`session`。
    #[serde(default)]
    pub scope: Option<String>,
    /// 可选 Agent 资产；只允许 agent 作用域，省略表示分别应用于所有 Agent。
    #[serde(default)]
    #[schema(value_type = Option<String>, format = Uuid)]
    pub target_id: Option<Id>,
    /// 维度：`tokens`/`requests`/`concurrency`/`cost`。
    pub dimension: String,
    /// 时间窗：`minute`/`hour`/`day`/`month`/`session`/`total`。
    #[serde(default)]
    pub window: Option<String>,
    /// 上限。
    pub limit: i64,
    /// 软阈值（默认上限的 80%）。
    #[serde(default)]
    pub soft_threshold: Option<i64>,
    /// 超限动作（默认 `deny`）。
    #[serde(default)]
    pub action: Option<String>,
    /// 是否启用。
    #[serde(default = "default_true")]
    pub enabled: bool,
}

const fn default_true() -> bool {
    true
}

const fn default_soft_threshold(limit: i64) -> i64 {
    limit / 5 * 4 + limit % 5 * 4 / 5
}

/// 新增/更新配额（`POST /api/v1/quotas`）。
///
/// # Errors
/// 参数非法。
pub async fn upsert_quota(
    State(state): State<AppState>,
    principal: Principal,
    ApiJson(body): ApiJson<QuotaBody>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "quotas", "write")?;
    if body.name.trim().is_empty()
        || body.name.len() > 128
        || body.limit < 0
        || body.soft_threshold.is_some_and(|value| value < 0 || value > body.limit)
    {
        return Err(DomainError::Validation("配额名称不能为空，数值不能为负，软阈值不能超过上限".into()).into());
    }
    let scope = match body.scope.as_deref() {
        Some(raw) => parse_quota_scope(raw)?,
        None => QuotaScope::Tenant,
    };
    if let Some(target) = body.target_id {
        if scope != QuotaScope::Agent {
            return Err(DomainError::Validation("target_id 只用于 Agent 作用域配额".into()).into());
        }
        if state
            .store
            .asset_get_durable(principal.tenant, target)
            .await?
            .is_none_or(|asset| asset.kind != agf_core::enums::AssetKind::Agent || !asset.is_live())
        {
            return Err(DomainError::Validation("配额目标须为当前租户中有效的 Agent 资产".into()).into());
        }
    }
    let dimension = parse_quota_dimension(&body.dimension)?;
    let window = match body.window.as_deref() {
        Some(raw) => QuotaWindow::parse(raw).map_err(|e| ApiError::new(DomainError::Validation(e)))?,
        None => QuotaWindow::Day,
    };
    let action = match body.action.as_deref() {
        Some(raw) => PolicyAction::parse(raw).map_err(|e| ApiError::new(DomainError::Validation(e)))?,
        None => PolicyAction::Deny,
    };
    let now = Timestamp::now();
    let soft_threshold = body.soft_threshold.unwrap_or_else(|| default_soft_threshold(body.limit));
    if !matches!(
        action,
        PolicyAction::Deny | PolicyAction::Throttle | PolicyAction::Quota | PolicyAction::Audit | PolicyAction::Allow
    ) {
        return Err(
            DomainError::Validation("配额超限动作支持拒绝、限速或仅审计；模型降级请配置运行时策略".into()).into()
        );
    }
    let mut audit = AppState::audit_entry(
        principal.tenant,
        AuditAction::Configure,
        AuditOutcome::Success,
        AppState::audit_actor(&principal, "quota-configuration"),
        AuditTarget::new("quota", None, Some(body.name.clone())),
        "按版本保存运行时配额配置",
    );
    audit.after = Some(serde_json::json!({
        "name": body.name, "scope": scope, "dimension": dimension, "window": window,
        "limit": body.limit, "soft_threshold": soft_threshold,
        "on_exceed": action, "enabled": body.enabled, "target_id": body.target_id, "expected_version": body.expected_version,
    }));
    let quota = Quota {
        id: Id::new(),
        tenant_id: principal.tenant,
        name: body.name,
        scope,
        dimension,
        window,
        limit: body.limit,
        soft_threshold,
        on_exceed: action,
        enabled: body.enabled,
        target_id: body.target_id,
        created_at: now,
        updated_at: now,
    };
    let saved =
        crate::quota_definitions::save_audited(&state, principal.tenant, quota, body.expected_version, audit).await?;
    Ok(Json(serde_json::json!({ "quota": saved })))
}
