//! 策略路由：增删改查、临时与单条求值、热重载，以及策略与求值上下文构建。

use super::*;
use axum::{extract::RawQuery, http::HeaderMap};

// ===========================================================================
// 策略
// ===========================================================================

/// 策略列表（`GET /api/v1/policies`）。
///
/// # Errors
/// 权限不足。
pub async fn list_policies(
    State(state): State<AppState>,
    principal: Principal,
    query: ListQuery,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "policies", "read")?;
    let mut policies = crate::policy_store::list(&state, principal.tenant).await?;
    if let Some(enabled) = query.filter_bool("enabled")? {
        policies.retain(|p| p.enabled == enabled);
    }
    if let Some(action) = query.filter("action") {
        policies.retain(|p| p.action.as_str() == action);
    }
    let page = query.paginate_vec(
        &policies,
        |p| format!("{} {} {}", p.name, p.description, p.action.as_str()),
        |p| p.name.clone(),
    );
    Ok(Json(query.render_page(&page)?))
}

/// 策略详情（`GET /api/v1/policies/{id}`）。
///
/// # Errors
/// 策略不存在。
pub async fn get_policy(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "policies", "read")?;
    let policy_id = parse_id(&id, "policy")?;
    let Some(policy) = crate::policy_store::get(&state, principal.tenant, policy_id).await? else {
        return Err(ApiError::new(DomainError::NotFound { entity: "policy", id }));
    };
    Ok(Json(serde_json::json!({ "policy": policy })))
}

/// 策略 Body。
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyBody {
    /// Management CAS: create accepts absent/zero; update requires the positive current revision.
    #[serde(default)]
    pub expected_version: Option<u64>,
    /// 名称（同租户唯一；创建同名返回冲突）。
    pub name: String,
    /// 描述。
    #[serde(default)]
    pub description: String,
    /// 策略语言（`rego`/`cel`/`structured`，默认 `structured`）。
    #[serde(default)]
    pub language: Option<String>,
    /// 策略源码。
    #[serde(default)]
    pub source: String,
    /// 结构化条件（`structured` 语言时生效）。
    #[serde(default)]
    pub structured: StructuredCondition,
    /// 动作（默认 `audit`）。
    #[serde(default)]
    pub action: Option<String>,
    /// 优先级（越小越先匹配，默认 100）。
    #[serde(default)]
    pub priority: Option<u32>,
    /// 生效拦截点。
    #[serde(default)]
    pub intercept_points: Vec<String>,
    /// 限定 Agent。
    #[serde(default)]
    pub scope_agent_ids: Vec<String>,
    /// 限定部门。
    #[serde(default)]
    pub scope_departments: Vec<String>,
    /// 是否启用（默认 true）。
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// 是否只观察不拦截。
    #[serde(default)]
    pub dry_run: bool,
    pub quota_id: Option<Id>,
    pub degrade_endpoint_id: Option<Id>,
}

const fn default_true() -> bool {
    true
}

/// 创建新策略（`POST /api/v1/policies`）；同名创建返回冲突。
///
/// # Errors
/// 参数非法。
pub async fn create_policy(
    State(state): State<AppState>,
    principal: Principal,
    headers: HeaderMap,
    ApiJson(body): ApiJson<PolicyBody>,
) -> ApiResult<(axum::http::StatusCode, Json<serde_json::Value>)> {
    principal.require(&state, "policies", "write")?;
    let submitted_at = Timestamp::now();
    let lease = crate::policy_store::AccessLease::capture(&state, &principal, &headers)?;
    if body.expected_version.is_some_and(|version| version != 0) {
        return Err(
            DomainError::Validation("创建策略 expected_version 只能省略或为0；同名策略须读取后更新".into()).into()
        );
    }
    let policy = build_policy(&principal, body)?;
    let saved = crate::policy_store::create_audited(&state, &principal, policy, submitted_at, lease).await?;
    Ok((axum::http::StatusCode::CREATED, Json(serde_json::json!({"policy":saved}))))
}

/// Update a policy with the version explicitly reviewed by this caller. Its name is immutable.
///
/// # Errors
/// Missing version, stale draft, invalid dependencies, permission or atomic commit failure.
pub async fn update_policy(
    State(state): State<AppState>,
    principal: Principal,
    headers: HeaderMap,
    Path(id): Path<String>,
    ApiJson(body): ApiJson<PolicyBody>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "policies", "write")?;
    let submitted_at = Timestamp::now();
    let lease = crate::policy_store::AccessLease::capture(&state, &principal, &headers)?;
    let expected = expected_version(body.expected_version)?;
    let mut policy = build_policy(&principal, body)?;
    policy.id = parse_id(&id, "policy")?;
    let saved = crate::policy_store::update_audited(&state, &principal, policy, expected, submitted_at, lease).await?;
    Ok(Json(serde_json::json!({"policy":saved})))
}

/// Soft-delete exactly the reviewed revision; history remains available for explicit restoration.
///
/// # Errors
/// Missing/invalid query version, stale revision, permission or atomic commit failure.
pub async fn delete_policy(
    State(state): State<AppState>,
    principal: Principal,
    headers: HeaderMap,
    Path(id): Path<String>,
    RawQuery(raw): RawQuery,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "policies", "delete")?;
    let submitted_at = Timestamp::now();
    let lease = crate::policy_store::AccessLease::capture(&state, &principal, &headers)?;
    let fields = url::form_urlencoded::parse(raw.as_deref().unwrap_or_default().as_bytes()).collect::<Vec<_>>();
    if fields.len() != 1 || fields[0].0 != "expected_version" {
        return Err(DomainError::Validation("删除策略查询必须只提供 expected_version 正整数".into()).into());
    }
    let expected =
        fields[0].1.parse::<u64>().map_err(|_| DomainError::Validation("expected_version 必须是正整数".into()))?;
    let expected = expected_version(Some(expected))?;
    let policy_id = parse_id(&id, "policy")?;
    crate::policy_store::delete_audited(&state, &principal, policy_id, expected, submitted_at, lease).await?;
    Ok(Json(serde_json::json!({"deleted":policy_id})))
}

pub(super) fn expected_version(value: Option<u64>) -> ApiResult<u64> {
    value.filter(|version| *version > 0).ok_or_else(|| {
        DomainError::Validation("修改策略必须提供当前 expected_version 正整数；请先读取策略".into()).into()
    })
}

/// 策略求值上下文 Body。
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DryRunBody {
    /// 拦截点（`mcp-proxy`/`ai-gateway`/`process-hook`/`collector`，默认 `mcp-proxy`）。
    #[serde(default)]
    pub intercept_point: Option<String>,
    /// 会话 id。
    #[serde(default)]
    pub session_id: Option<String>,
    /// Agent id。
    #[serde(default)]
    pub agent_id: Option<String>,
    /// 部门（ABAC）。
    #[serde(default)]
    pub department: Option<String>,
    /// 工具名。
    #[serde(default)]
    pub tool_name: Option<String>,
    /// 文件路径。
    #[serde(default)]
    pub path: Option<String>,
    /// 目标域名。
    #[serde(default)]
    pub domain: Option<String>,
    /// 待执行命令。
    #[serde(default)]
    pub command: Option<String>,
    /// 载荷。
    #[serde(default)]
    pub payload: serde_json::Value,
    /// 数据分级。
    #[serde(default)]
    pub data_class: Option<String>,
    /// 关联风险域。
    #[serde(default)]
    pub risk_domains: Vec<String>,
    /// 最高严重等级。
    #[serde(default)]
    pub max_severity: Option<String>,
}

/// 临时求值（`POST /api/v1/policies/dry-run`）：对当前已加载策略执行一次判定。
///
/// # Errors
/// 参数非法或求值失败。
pub async fn dry_run_adhoc(
    State(state): State<AppState>,
    principal: Principal,
    ApiJson(body): ApiJson<DryRunBody>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "policies", "read")?;
    let context = build_policy_context(&principal, &body)?;
    let runtime = state.runtime_registry.get(&state, principal.tenant).await?;
    let decision = runtime.evaluate(context).await?;
    state.record_interception(principal.tenant, decision.action, decision.policy_name.as_deref().unwrap_or("-"));
    Ok(Json(serde_json::json!({
        "decision": decision,
        "blocking": decision.is_blocking(),
        "needs_redaction": decision.needs_redaction(),
        "needs_approval": decision.needs_approval(),
    })))
}

/// 单条策略求值（`POST /api/v1/policies/{id}/dry-run`）：仅加载该策略后判定。
///
/// # Errors
/// 策略不存在或求值失败。
pub async fn dry_run_policy(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<String>,
    ApiJson(body): ApiJson<DryRunBody>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "policies", "read")?;
    let policy_id = parse_id(&id, "policy")?;
    let Some(policy) = crate::policy_store::get(&state, principal.tenant, policy_id).await? else {
        return Err(ApiError::new(DomainError::NotFound { entity: "policy", id: id.clone() }));
    };
    let context = build_policy_context(&principal, &body)?;
    let engine = RuntimeEngine::in_memory(vec![policy], Vec::new(), EngineConfig::default())?;
    let decision = engine.evaluate(context).await?;
    Ok(Json(serde_json::json!({
        "policy_id": policy_id,
        "decision": decision,
        "blocking": decision.is_blocking(),
    })))
}

/// 热重载策略（`POST /api/v1/policies/reload`）。
///
/// # Errors
/// 策略源码非法。
pub async fn reload_policies(
    State(state): State<AppState>,
    principal: Principal,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "policies", "write")?;
    let policies = crate::policy_store::list(&state, principal.tenant).await?;
    let runtime = state.runtime_registry.get(&state, principal.tenant).await?;
    let loaded = runtime.policy_count().await;
    state
        .audit(
            principal.tenant,
            AuditAction::Configure,
            AuditOutcome::Success,
            AppState::audit_actor(&principal, "policy-reload"),
            AuditTarget::new("runtime-engine", None, Some("policies".to_string())),
            &format!("热重载策略 {loaded} 条"),
        )
        .await?;
    state.publish(crate::state::WsEvent {
        kind: "policy".to_string(),
        tenant_id: principal.tenant,
        at: Timestamp::now(),
        payload: serde_json::json!({ "reloaded": loaded }),
    });
    Ok(Json(serde_json::json!({ "reloaded": loaded, "total": policies.len() })))
}

fn build_policy(principal: &Principal, body: PolicyBody) -> Result<Policy, ApiError> {
    let language = match body.language.as_deref() {
        Some(raw) => PolicyLanguage::parse(raw).map_err(|e| ApiError::new(DomainError::Validation(e)))?,
        None => PolicyLanguage::Structured,
    };
    let action = match body.action.as_deref() {
        Some(raw) => PolicyAction::parse(raw).map_err(|e| ApiError::new(DomainError::Validation(e)))?,
        None => PolicyAction::Audit,
    };
    if body.name.trim().is_empty() || body.name.len() > 128 || body.source.len() > 65536 {
        return Err(DomainError::Validation("策略名称不能为空且不超过 128 字节；源码不超过 64 KiB".into()).into());
    }
    let now = Timestamp::now();
    Ok(Policy {
        id: Id::new(),
        tenant_id: principal.tenant,
        name: body.name,
        description: body.description,
        language,
        source: body.source,
        structured: body.structured,
        action,
        priority: body.priority.unwrap_or(100),
        intercept_points: body
            .intercept_points
            .iter()
            .map(|p| parse_intercept_point(p))
            .collect::<Result<Vec<_>, _>>()?,
        scope_agent_ids: body.scope_agent_ids.iter().map(|a| parse_id(a, "agent")).collect::<Result<Vec<_>, _>>()?,
        scope_departments: body.scope_departments,
        enabled: body.enabled,
        dry_run: body.dry_run,
        quota_id: body.quota_id,
        degrade_endpoint_id: body.degrade_endpoint_id,
        content_hash: String::new(),
        signature: String::new(),
        version: 1,
        created_at: now,
        updated_at: now,
        deleted_at: None,
    })
}

fn build_policy_context(principal: &Principal, body: &DryRunBody) -> Result<PolicyContext, ApiError> {
    let intercept_point = match body.intercept_point.as_deref() {
        Some(raw) => parse_intercept_point(raw)?,
        None => InterceptPoint::McpProxy,
    };
    let data_class = match body.data_class.as_deref() {
        Some(raw) => crate::routes::assets::parse_data_class(raw)?,
        None => DataClass::Internal,
    };
    let max_severity = match body.max_severity.as_deref() {
        Some(raw) => Some(Severity::parse(raw).map_err(|e| ApiError::new(DomainError::Validation(e)))?),
        None => None,
    };
    let mut risk_domains = Vec::new();
    for raw in &body.risk_domains {
        risk_domains.push(RiskDomain::parse(raw).map_err(|e| ApiError::new(DomainError::Validation(e)))?);
    }
    let payload_bytes = u64::try_from(serde_json::to_string(&body.payload).map_or(0, |s| s.len())).unwrap_or(0);
    Ok(PolicyContext {
        tenant_id: principal.tenant,
        session_id: body.session_id.clone().unwrap_or_else(|| "dry-run".to_string()),
        agent_id: match body.agent_id.as_deref() {
            Some(raw) => Some(parse_id(raw, "agent")?),
            None => None,
        },
        department: body.department.clone().or_else(|| principal.department.clone()),
        intercept_point,
        tool_name: body.tool_name.clone(),
        path: body.path.clone(),
        domain: body.domain.clone(),
        command: body.command.clone(),
        payload: body.payload.clone(),
        payload_bytes,
        risk_domains,
        max_severity,
        data_class,
        now: Timestamp::now(),
    })
}

/// 解析拦截点。
///
/// # Errors
/// 未知拦截点。
pub fn parse_intercept_point(raw: &str) -> Result<InterceptPoint, ApiError> {
    match raw.trim().to_ascii_lowercase().replace('_', "-").as_str() {
        "mcp-proxy" => Ok(InterceptPoint::McpProxy),
        "ai-gateway" => Ok(InterceptPoint::AiGateway),
        "process-hook" => Ok(InterceptPoint::ProcessHook),
        "collector" => Ok(InterceptPoint::Collector),
        other => Err(ApiError::new(DomainError::Validation(format!("未知拦截点: {other}")))),
    }
}

/// 占位：未实现端点（保留以便集中登记 TODO 锚点）。
///
/// # Errors
/// 恒 501。
pub async fn unimplemented_probe() -> Result<Json<serde_json::Value>, ApiError> {
    todo_endpoint("api-governance-todo", "治理域未实现端点占位")
}
