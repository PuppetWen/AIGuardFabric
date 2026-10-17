//! 设置端点：配置快照 / API Key 列表与创建。

use super::*;

/// 吊销指定租户的 API Key，重复请求保持幂等。
pub async fn revoke_api_key(
    State(state): State<AppState>,
    principal: Principal,
    Path(raw): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "settings", "admin")?;
    let id = parse_id(&raw, "api-key")?;
    let audit = AppState::audit_entry(
        principal.tenant,
        AuditAction::Grant,
        AuditOutcome::Success,
        AppState::audit_actor(&principal, "api-key-revoke"),
        AuditTarget::new("api-key", Some(id.to_string()), None),
        "吊销 API Key",
    );
    state.store.api_key_revoke_audited(principal.tenant, id, audit).await?;
    Ok(Json(serde_json::json!({"id": id, "revoked": true})))
}

// ===========================================================================
// 设置
// ===========================================================================

/// 配置快照（`GET /api/v1/settings`，敏感值一律掩码）。
///
/// # Errors
/// 权限不足。
pub async fn settings_snapshot(
    State(state): State<AppState>,
    principal: Principal,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "settings", "read")?;
    let config = &state.config;
    let mask = agf_core::secret::mask_default;
    Ok(Json(serde_json::json!({
        "service": {
            "name": "agf-server",
            "version": crate::VERSION,
            "mode": state.mode.as_str(),
            "mock_mode": config.mock_mode,
            "degrade_on_missing": config.degrade_on_missing,
        },
        "server": {
            "host": config.server.host,
            "port": config.server.port,
            "api_prefix": config.server.api_prefix,
            "max_body_bytes": config.server.max_body_bytes,
            "metrics_port": config.server.metrics_port,
            "ingest_port": config.server.ingest_port,
            "syslog_tcp_port": config.server.syslog_tcp_port,
            "mcp_proxy_port": config.server.mcp_proxy_port,
        },
        "database": {
            "host": config.database.host,
            "port": config.database.port,
            "database": config.database.database,
            "user": config.database.user,
            "password": mask(&config.database.password),
            "dsn": config.database.masked_dsn(),
            "pool_max": config.database.pool_max,
            "pool_min": config.database.pool_min,
        },
        "redis": { "url": config.redis.masked_url(), "key_prefix": config.redis.key_prefix },
        "nats": { "enabled": config.nats.enabled, "url": config.nats.url, "stream": config.nats.stream },
        "clickhouse": { "enabled": config.clickhouse.enabled, "url": config.clickhouse.url, "database": config.clickhouse.database },
        "s3": {
            "endpoint": config.s3.endpoint,
            "region": config.s3.region,
            "bucket": config.s3.bucket,
            "access_key": mask(&config.s3.access_key),
            "secret_key": mask(&config.s3.secret_key),
            "force_path_style": config.s3.force_path_style,
        },
        "security": {
            "jwt_secret": mask(&config.security.jwt_secret),
            "jwt_issuer": config.security.jwt_issuer,
            "jwt_access_ttl_secs": config.security.jwt_access_ttl_secs,
            "jwt_refresh_ttl_secs": config.security.jwt_refresh_ttl_secs,
            "master_key": mask(&config.security.master_key_b64),
            "kms_backend": config.security.kms_backend,
            "bootstrap_admin_user": config.security.bootstrap_admin_user,
            "force_password_change": config.security.force_password_change,
            "password_min_length": config.security.password_min_length,
            "login_max_failures": config.security.login_max_failures,
            "login_lockout_secs": config.security.login_lockout_secs,
            "fingerprint_salt": mask(&config.security.fingerprint_salt),
        },
        "quota": serde_json::to_value(&config.quota)?,
        "observability": serde_json::to_value(&config.observability)?,
        "device_adapters": config.device_adapters,
        "cors_origins": state.cors_origins.as_ref(),
        "resources": {
            "rules_loaded": state.rules.len(),
            "redteam_cases": state.redteam_cases.cases().len(),
            "parsers": state.parsers.all().len(),
            "alicloud_services": state.alicloud.records().len(),
        },
        "persistence": persistence_section(&state),
        "notes": state.notes.as_ref(),
    })))
}

/// `/settings` 的 `persistence` 段：**由 `PersistenceReport` 动态生成**（不写死两份清单）。
///
/// 唯一事实源是 `crates/agf-api/src/persistence.rs` 的
/// [`crate::persistence::PersistenceReport`]：已落 PG 的资源（`DURABLE_RESOURCES`）、
/// 无仓储仅内存的资源（`MEMORY_ONLY_RESOURCES`）与写队列实时计数都由 `report()` 现算。
///
/// 离线模式（`AppState.persistence == None`）**没有**写后桥，因此如实报告"没有任何资源落 PG"：
/// `durable` 为空，`memory_only` 是全部资源（两个常量清单的并集）。
fn persistence_section(state: &AppState) -> serde_json::Value {
    use crate::persistence::{DURABLE_RESOURCES, MEMORY_ONLY_RESOURCES, PersistenceReport};

    let Some(bridge) = state.persistence.as_ref() else {
        let mut memory_only: Vec<&str> =
            DURABLE_RESOURCES.iter().chain(MEMORY_ONLY_RESOURCES.iter()).copied().collect();
        memory_only.sort_unstable();
        memory_only.dedup();
        return serde_json::json!({
            "mode": state.mode.as_str(),
            "enabled": false,
            "durable": Vec::<String>::new(),
            "memory_only": memory_only,
            "note": "离线内存模式：无写后持久化桥（PersistenceBridge），所有资源只落进程内存（重启即丢）",
        });
    };
    let report = bridge.report();
    serde_json::json!({
        "mode": state.mode.as_str(),
        "enabled": true,
        "durable": report.durable,
        "memory_only": report.memory_only,
        "hydrate": report.hydrate,
        "queued": report.queued,
        "applied": report.applied,
        "failed": report.failed,
        "dropped": report.dropped,
        "id_remapped": report.id_remapped,
        "pending": report.pending,
        "queue_capacity": report.queue_capacity,
        "recent_errors": report.recent_errors,
        "note": PersistenceReport::consistency_line(),
    })
}

/// API Key 列表（`GET /api/v1/settings/api-keys`，**永不返回明文**）。
///
/// # Errors
/// 权限不足。
pub async fn list_api_keys(State(state): State<AppState>, principal: Principal) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "settings", "admin")?;
    let keys = state.store.api_key_list_durable(principal.tenant).await?;
    Ok(Json(serde_json::json!({ "items": keys, "total": keys.len() })))
}

/// API Key 创建 Body。
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
pub struct ApiKeyBody {
    /// Optional authenticated Agent identity, used by runtime controls and Agent quotas.
    #[serde(default, alias = "boundAgentId")]
    #[schema(value_type = Option<String>)]
    pub bound_agent_id: Option<Id>,
    /// 名称。
    pub name: String,
    /// 直接授予的权限点（支持 `assets:*` 与 `*`）。
    #[serde(default)]
    pub scopes: Vec<String>,
    /// 有效期（秒；缺省为永不过期）。
    #[serde(default)]
    pub expires_in_secs: Option<i64>,
    /// 来源 CIDR 白名单。
    #[serde(default)]
    pub allowed_cidrs: Vec<String>,
}

/// 创建 API Key（`POST /api/v1/settings/api-keys`，**明文只返回一次**）。
///
/// # Errors
/// 参数非法。
pub async fn create_api_key(
    State(state): State<AppState>,
    principal: Principal,
    ApiJson(body): ApiJson<ApiKeyBody>,
) -> ApiResult<(axum::http::StatusCode, Json<serde_json::Value>)> {
    principal.require(&state, "settings", "admin")?;
    if body.name.trim().is_empty() || body.name.len() > 128 {
        return Err(ApiError::new(DomainError::Validation("name 不能为空".to_string())));
    }
    let now = Timestamp::now();
    if body.scopes.is_empty()
        || body.scopes.iter().any(|scope| {
            let (group, action) = scope.split_once(':').unwrap_or((scope, "*"));
            scope == "*" && !principal.superadmin || principal.require(&state, group, action).is_err()
        })
    {
        return Err(DomainError::Forbidden("必须指定当前账号拥有的权限范围".into()).into());
    }
    if body.expires_in_secs.is_some_and(|seconds| !(1..=315_360_000).contains(&seconds)) {
        return Err(DomainError::Validation("有效期必须为 1 秒至 3650 天".into()).into());
    }
    if let Some(id) = body.bound_agent_id {
        if state
            .store
            .asset_get_durable(principal.tenant, id)
            .await?
            .is_none_or(|asset| asset.kind != agf_core::enums::AssetKind::Agent)
        {
            return Err(DomainError::Validation("绑定目标须为当前租户的 Agent 资产".into()).into());
        }
    }
    let mut request = ApiKeyIssueRequest::named(principal.tenant, body.name.clone(), now);
    request.scopes = body.scopes.iter().map(|s| agf_core::rbac::Permission::from_raw(s.clone())).collect();
    request.expires_at = body.expires_in_secs.map(|secs| now.offset_secs(secs.max(0)));
    request.allowed_cidrs = body.allowed_cidrs;
    request.bound_agent_id = body.bound_agent_id;
    let issued = state.api_keys.issue(request);
    let audit = AppState::audit_entry(
        principal.tenant,
        AuditAction::Grant,
        AuditOutcome::Success,
        AppState::audit_actor(&principal, "api-key-issue"),
        AuditTarget::new("api-key", Some(issued.record.id.to_string()), Some(issued.record.name.clone())),
        "签发 API Key（明文仅在本次响应中返回）",
    );
    state.store.api_key_create_audited(&issued.record, audit).await?;
    Ok((
        axum::http::StatusCode::CREATED,
        Json(serde_json::json!({
            "api_key": issued.record,
            "plaintext": issued.plaintext,
            "warning": "明文密钥只返回一次，请立即保存；服务端只保存指纹",
        })),
    ))
}
