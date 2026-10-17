//! 告警端点：列表 / 创建 / 详情 / 状态流转。

use super::*;
use agf_core::enums::RiskDomain;

// ===========================================================================
// 告警
// ===========================================================================

/// 告警列表（`GET /api/v1/alerts`）。
///
/// # Errors
/// 过滤参数非法。
pub async fn list_alerts(
    State(state): State<AppState>,
    principal: Principal,
    query: ListQuery,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "alerts", "read")?;
    if query.sort_by.as_deref().is_some_and(|sort| {
        !["severity", "dedup_count", "sla_due_at", "title", "first_seen_at", "last_seen_at", "created_at", "updated_at"]
            .contains(&sort)
    }) {
        return Err(DomainError::Validation("不支持的告警排序字段".into()).into());
    }
    let filter = agf_storage::repository::AlertFilter {
        states: query.filter_many("state").iter().map(|s| parse_alert_state(s)).collect::<ApiResult<_>>()?,
        severities: query
            .filter_many("severity")
            .iter()
            .map(|s| Severity::parse(s).map_err(|e| DomainError::Validation(e).into()))
            .collect::<ApiResult<_>>()?,
        domains: query
            .filter_many("domain")
            .iter()
            .map(|s| RiskDomain::parse(s).map_err(|e| DomainError::Validation(e).into()))
            .collect::<ApiResult<_>>()?,
        active_only: query.filter_bool("active")?.unwrap_or(false),
    };
    let page = state.store.alert_page_durable(principal.tenant, &query, filter).await?;
    let mut value = query.render_page(&page)?;
    value["can_write"] = serde_json::json!(principal.require(&state, "alerts", "write").is_ok());
    Ok(Json(value))
}

/// 告警创建 Body。
///
/// 说明：生产环境中告警由告警聚合链路（`TODO(api-correlate-aggregate)`）产生；
/// 该端点是**显式登记**入口（人工研判/外部系统回填），并按 `dedup_key` 做活动态合并，
/// 保证"发现 → 告警 → 案件"链路在聚合未实现时仍可端到端走通。
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
pub struct AlertBody {
    /// 标题。
    pub title: String,
    /// 描述。
    #[serde(default)]
    pub description: String,
    /// 严重等级（默认 `medium`）。
    #[serde(default)]
    pub severity: Option<String>,
    /// 风险域。
    #[serde(default)]
    pub domain: Option<String>,
    /// 关联资产。
    #[serde(default)]
    pub asset_ids: Vec<String>,
    /// 关联发现。
    #[serde(default)]
    pub finding_ids: Vec<String>,
    /// 去重键（缺省由标题+等级推导；活动态同键告警会合并计数）。
    #[serde(default)]
    pub dedup_key: Option<String>,
}

/// 创建/合并告警（`POST /api/v1/alerts`）。
///
/// # Errors
/// 参数非法或状态非法。
pub async fn create_alert(
    State(state): State<AppState>,
    principal: Principal,
    ApiJson(body): ApiJson<AlertBody>,
) -> ApiResult<(axum::http::StatusCode, Json<serde_json::Value>)> {
    principal.require(&state, "alerts", "write")?;
    if body.title.trim().is_empty() {
        return Err(ApiError::new(DomainError::Validation("title 不能为空".to_string())));
    }
    let severity = match body.severity.as_deref() {
        Some(raw) => Severity::parse(raw).map_err(|e| ApiError::new(DomainError::Validation(e)))?,
        None => Severity::Medium,
    };
    let domain = match body.domain.as_deref() {
        Some(raw) => {
            Some(agf_core::enums::RiskDomain::parse(raw).map_err(|e| ApiError::new(DomainError::Validation(e)))?)
        }
        None => None,
    };
    let asset_ids = body.asset_ids.iter().map(|a| parse_id(a, "asset")).collect::<Result<Vec<_>, _>>()?;
    let finding_ids = body.finding_ids.iter().map(|a| parse_id(a, "finding")).collect::<Result<Vec<_>, _>>()?;
    let dedup_key =
        body.dedup_key.unwrap_or_else(|| format!("manual:{}:{}", severity.as_str(), body.title.trim().to_lowercase()));
    let (alert, created) = state
        .store
        .alert_upsert_durable(crate::persistence::AlertWrite {
            tenant: principal.tenant,
            memory_id: Id::new(),
            dedup_key,
            title: body.title.trim().into(),
            description: body.description,
            severity,
            domain,
            asset_ids,
            finding_ids,
            sla_due_at: Some(Timestamp::now().offset_secs(agf_core::alert::Alert::sla_secs(severity))),
        })
        .await?;
    let id = alert.id;
    state
        .audit(
            principal.tenant,
            AuditAction::Create,
            AuditOutcome::Success,
            AppState::audit_actor(&principal, "alert-create"),
            AuditTarget::new("alert", Some(id.to_string()), Some(body.title.clone())),
            if created { "登记告警" } else { "合并到既有活动告警" },
        )
        .await?;
    state.publish(crate::state::WsEvent {
        kind: "alert".to_string(),
        tenant_id: principal.tenant,
        at: Timestamp::now(),
        payload: serde_json::json!({ "alert_id": id, "created": created, "severity": severity.as_str() }),
    });
    Ok((
        axum::http::StatusCode::CREATED,
        Json(serde_json::json!({ "alert_id": id, "created": created, "alert": alert })),
    ))
}

/// 告警详情（`GET /api/v1/alerts/{id}`）。
///
/// # Errors
/// 告警不存在。
pub async fn get_alert(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "alerts", "read")?;
    let alert_id = parse_id(&id, "alert")?;
    let Some(alert) = state.store.alert_get_durable(principal.tenant, alert_id).await? else {
        return Err(ApiError::new(DomainError::NotFound { entity: "alert", id: id.clone() }));
    };
    let now = Timestamp::now();
    let mut remaining = alert.sla_remaining_secs(now);
    if let Some(secs) = remaining.as_mut() {
        *secs = (*secs).max(0);
    }
    Ok(Json(serde_json::json!({
        "alert": alert,
        "active": alert.is_active(),
        "sla_remaining_secs": remaining,
    })))
}

/// 告警状态流转 Body。
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
pub struct AlertStateBody {
    /// 目标状态：`open`/`acknowledged`/`suppressed`/`escalated`/`closed`。
    pub state: String,
    /// 指派人。
    #[serde(default)]
    pub assignee: Option<String>,
}

/// 告警状态流转（`POST /api/v1/alerts/{id}/state`）。
///
/// # Errors
/// 告警不存在或状态非法。
pub async fn set_alert_state(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<String>,
    ApiJson(body): ApiJson<AlertStateBody>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "alerts", "write")?;
    let alert_id = parse_id(&id, "alert")?;
    let target = parse_alert_state(&body.state)?;
    let alert = state.store.alert_set_state_durable(principal.tenant, alert_id, target, body.assignee).await?;
    state
        .audit(
            principal.tenant,
            AuditAction::Update,
            AuditOutcome::Success,
            AppState::audit_actor(&principal, "alert-state"),
            AuditTarget::new("alert", Some(alert_id.to_string()), Some(alert.title.clone())),
            &format!("告警状态流转到 {}", target.as_str()),
        )
        .await?;
    Ok(Json(serde_json::json!({ "alert": alert })))
}
