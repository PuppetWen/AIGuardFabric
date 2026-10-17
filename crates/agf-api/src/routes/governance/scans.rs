//! 扫描任务路由：发起/查询/列表/取消，以及扫描目标形态解析。

use super::*;

// ===========================================================================
// 扫描
// ===========================================================================

/// 扫描请求 Body。
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
pub struct ScanBody {
    /// 任务名。
    #[serde(default)]
    pub job_name: Option<String>,
    /// 扫描目标。
    pub targets: Vec<ScanTargetBody>,
    /// 是否启用 LLM 研判（离线 Mock 模式返回规则等价结论）。
    #[serde(default)]
    pub use_llm_judge: bool,
    /// 限定扫描域（留空按目标形态推导）。
    #[serde(default)]
    pub domains: Vec<String>,
    /// 是否同步等待扫描完成（默认 true；false 时立即返回 `task_id` 供轮询）。
    #[serde(default = "default_wait")]
    pub wait: bool,
}

const fn default_wait() -> bool {
    true
}

/// 扫描目标 Body。
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
pub struct ScanTargetBody {
    /// 目标标识。
    pub label: String,
    /// 目标形态：`prompt`/`log-payload`/`document`/`tool-arguments`/`model-output`/`mcp-response`/`config`。
    pub kind: String,
    /// 文本内容。
    pub text: String,
    /// 关联资产 id。
    #[serde(default)]
    pub asset_id: Option<String>,
    /// 数据分级。
    #[serde(default)]
    pub data_class: Option<String>,
}

/// 发起扫描（`POST /api/v1/scans`）：返回 `task_id`。
///
/// # Errors
/// 目标为空或参数非法。
pub async fn create_scan(
    State(state): State<AppState>,
    principal: Principal,
    ApiJson(body): ApiJson<ScanBody>,
) -> ApiResult<(axum::http::StatusCode, Json<serde_json::Value>)> {
    principal.require(&state, "scans", "execute")?;
    super::scan_execution::validate(&body)?;
    if body.use_llm_judge {
        principal.require(&state, "models", "write")?;
    }
    let tenant = principal.tenant;
    let now = Timestamp::now();
    let job_name = body.job_name.clone().unwrap_or_else(|| format!("scan-{}", now.unix_secs()));

    let mut request = ScanRequest::new(job_name.clone());
    request.use_llm_judge = body.use_llm_judge;
    for raw in &body.domains {
        request.domains.push(RiskDomain::parse(raw).map_err(|e| ApiError::new(DomainError::Validation(e)))?);
    }
    for raw in &body.targets {
        let kind = parse_scan_target_kind(&raw.kind)?;
        let mut target = ScanTarget::new(raw.label.clone(), kind, raw.text.clone());
        if let Some(dc) = raw.data_class.as_deref() {
            target = target.with_data_class(crate::routes::assets::parse_data_class(dc)?);
        }
        if let Some(asset_id) = raw.asset_id.as_deref() {
            principal.require(&state, "assets", "read")?;
            let id = parse_id(asset_id, "asset")?;
            let asset = state
                .store
                .asset_get_durable(tenant, id)
                .await?
                .ok_or_else(|| ApiError::new(DomainError::NotFound { entity: "asset", id: asset_id.into() }))?;
            target.data_class = target.data_class.max(asset.data_class);
            target = target.with_asset(id);
        }
        request = request.with_target(target);
    }

    let rules = crate::rule_store::pack(&state, tenant).await?;
    let job = ScanJob {
        id: Id::new(),
        tenant_id: tenant,
        name: job_name,
        state: ScanJobState::Queued,
        targets: request.targets.len(),
        domains: request.domains.iter().map(|d| d.as_str().to_string()).collect(),
        progress: 0,
        use_llm_judge: request.use_llm_judge,
        rule_hits: std::collections::BTreeMap::new(),
        finding_count: 0,
        risk_score: None,
        finding_ids: Vec::new(),
        llm_mocked: None,
        judgement_count: 0,
        judgement_failures: 0,
        max_severity: Severity::Info.as_str().to_string(),
        summary: String::new(),
        elapsed_ms: 0,
        error: None,
        requested_by: principal.display(),
        created_at: now,
        started_at: None,
        finished_at: None,
    };
    let task_id = job.id;
    let engine = super::scan_judge::engine(&state, &principal, task_id, &request);
    state.store.scan_insert_durable(&job).await?;

    if body.wait {
        let finished = super::scan_execution::execute(&state, rules, &engine, tenant, task_id, &request).await?;
        Ok((axum::http::StatusCode::OK, Json(serde_json::json!({ "task_id": task_id, "job": finished }))))
    } else {
        let spawned = state.clone();
        tokio::spawn(async move {
            match super::scan_execution::execute(&spawned, rules, &engine, tenant, task_id, &request).await {
                Ok(job) => tracing::info!(task_id = %job.id, findings = job.finding_count, "异步扫描完成"),
                Err(e) => tracing::warn!(task_id = %task_id, error = %e, "异步扫描失败"),
            }
        });
        Ok((
            axum::http::StatusCode::ACCEPTED,
            Json(serde_json::json!({ "task_id": task_id, "job": job, "poll": format!("/api/v1/scans/{task_id}") })),
        ))
    }
}

/// 查询扫描任务状态（`GET /api/v1/scans/{task_id}`）。
///
/// # Errors
/// 任务不存在。
pub async fn get_scan(
    State(state): State<AppState>,
    principal: Principal,
    Path(task_id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "scans", "read")?;
    let id = parse_id(&task_id, "scan-job")?;
    let Some(job) = state.store.scan_get_durable(principal.tenant, id).await? else {
        return Err(ApiError::new(DomainError::NotFound { entity: "scan-job", id: task_id }));
    };
    Ok(Json(serde_json::json!({ "job": job, "terminal": job.state.is_terminal() })))
}

/// 扫描任务列表（`GET /api/v1/scans`）。
///
/// # Errors
/// 权限不足。
pub async fn list_scans(
    State(state): State<AppState>,
    principal: Principal,
    query: ListQuery,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "scans", "read")?;
    let page = state.store.scan_page_durable(principal.tenant, &query).await?;
    Ok(Json(query.render_page(&page)?))
}

/// 取消扫描任务（`POST /api/v1/scans/{task_id}/cancel`）。
///
/// # Errors
/// 任务不存在或已处于终态。
pub async fn cancel_scan(
    State(state): State<AppState>,
    principal: Principal,
    Path(task_id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "scans", "execute")?;
    let id = parse_id(&task_id, "scan-job")?;
    let job = state.store.scan_transition_durable(principal.tenant, id, ScanJobState::Cancelled, None).await?;
    Ok(Json(serde_json::json!({ "job": job })))
}

/// 解析扫描目标形态。
///
/// # Errors
/// 未知形态。
pub fn parse_scan_target_kind(raw: &str) -> Result<ScanTargetKind, ApiError> {
    match raw.trim().to_ascii_lowercase().replace('_', "-").as_str() {
        "prompt" => Ok(ScanTargetKind::Prompt),
        "log-payload" | "event-payload" => Ok(ScanTargetKind::LogPayload),
        "document" => Ok(ScanTargetKind::Document),
        "tool-arguments" => Ok(ScanTargetKind::ToolArguments),
        "tool-result" => Ok(ScanTargetKind::ToolResult),
        "mcp-request" => Ok(ScanTargetKind::McpRequest),
        "model-output" => Ok(ScanTargetKind::ModelOutput),
        "mcp-response" => Ok(ScanTargetKind::McpResponse),
        "config" => Ok(ScanTargetKind::Config),
        "file-content" => Ok(ScanTargetKind::FileContent),
        "tool-definition" => Ok(ScanTargetKind::ToolDefinition),
        other => Err(ApiError::new(DomainError::Validation(format!("未知扫描目标形态: {other}")))),
    }
}
