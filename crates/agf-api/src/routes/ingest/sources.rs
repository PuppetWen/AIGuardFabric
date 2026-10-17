//! 接入源与解析器路由（自 `routes/ingest.rs` 拆出，逻辑未变）。

use super::*;

/// 接入面条目（对外投影，避免暴露内部结构细节）。
#[derive(Debug, Clone, Serialize)]
pub struct SourceView {
    /// 源标识（协议文本形式）。
    pub id: String,
    /// 接收器名。
    pub receiver: String,
    /// 协议。
    pub protocol: String,
    /// 实现状态。
    pub status: String,
    /// 说明。
    pub note: String,
    /// TODO 锚点（未实现时）。
    pub todo: Option<String>,
    /// 是否支持 Mock 回放。
    pub mock_replay: bool,
    /// 监听地址（仅 push 类协议）。
    pub listener: Option<String>,
}

fn source_views(state: &AppState) -> Vec<SourceView> {
    let bind = &state.config.server.host;
    receiver_capability_matrix()
        .into_iter()
        .map(|descriptor| {
            let listener = listener_for(&descriptor, bind, state);
            SourceView {
                id: descriptor.protocol.as_str().to_string(),
                receiver: descriptor.name,
                protocol: descriptor.protocol.as_str().to_string(),
                status: descriptor.status.as_str().to_string(),
                note: descriptor.note,
                todo: descriptor.todo,
                mock_replay: descriptor.mock_replay,
                listener,
            }
        })
        .collect()
}

fn listener_for(descriptor: &ReceiverDescriptor, bind: &str, state: &AppState) -> Option<String> {
    // 用 `as_str()` 分派而不是穷举枚举：协议集合会随 `agf-ingest` 扩展，
    // 这里只对"平台主动监听"的协议给出地址，其余返回 `None`。
    let port = match descriptor.protocol.as_str() {
        "syslog" => Some(state.config.server.syslog_tcp_port),
        "webhook" | "http-push" => Some(state.config.server.ingest_port),
        "mcp" => Some(state.config.server.mcp_proxy_port),
        _ => None,
    };
    port.map(|p| format!("{bind}:{p}"))
}

/// 接收器能力矩阵（`GET /api/v1/sources/capabilities`）。
///
/// # Errors
/// 权限不足。
pub async fn source_capabilities(
    State(state): State<AppState>,
    principal: Principal,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "sources", "read")?;
    let descriptors = receiver_capability_matrix();
    let ready = descriptors.iter().filter(|d| d.status.as_str() == "ready").count();
    let not_implemented = descriptors.iter().filter(|d| d.status.as_str() == "not-implemented").count();
    Ok(Json(serde_json::json!({
        "matrix": serde_json::to_value(&descriptors)?,
        "summary": { "total": descriptors.len(), "ready": ready, "not_implemented": not_implemented },
        "listeners": source_views(&state),
    })))
}

fn parser_view(parser: &agf_core::parser::Parser) -> serde_json::Value {
    serde_json::json!({
        "id": parser.id,
        "tenant_id": parser.tenant_id,
        "key": parser.definition.key,
        "name": parser.definition.name,
        "vendor": parser.definition.vendor,
        "product": parser.definition.product,
        "engine": parser.definition.engine.as_str(),
        "protocols": parser.definition.protocols.iter().map(IngestProtocol::as_str).collect::<Vec<_>>(),
        "version": parser.definition.version,
        "builtin": parser.definition.builtin,
        "ai_inferred": parser.definition.ai_inferred,
        "description": parser.definition.description,
        "pattern": parser.definition.pattern,
        "required_fields": parser.definition.required_fields,
        "derived_fields": parser.definition.derived.keys().collect::<Vec<_>>(),
        "sample_fixture": parser.definition.sample_fixture,
        "enabled": parser.enabled,
        "priority": parser.priority,
        "content_hash": parser.content_hash,
        "success_count": parser.success_count,
        "failure_count": parser.failure_count,
        "success_rate": parser.success_rate(),
        "last_used_at": parser.last_used_at,
        "created_at": parser.created_at,
        "updated_at": parser.updated_at,
    })
}

/// 解析器列表（`GET /api/v1/parsers`）。
///
/// # Errors
/// 权限不足。
pub async fn list_parsers(
    State(state): State<AppState>,
    principal: Principal,
    query: ListQuery,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "parsers", "read")?;
    let protocol = match query.filter("protocol") {
        Some(raw) => Some(parse_ingest_protocol(raw)?),
        None => None,
    };
    let registry = crate::parser_store::registry(&state, principal.tenant).await?;
    let handle = state.ingest_pipelines.get(principal.tenant, state.ingest_sink.clone(), &registry)?;
    let entries = handle.pipeline.with_registry(|live| live.all().to_vec())?;
    let parsers: Vec<serde_json::Value> = entries
        .iter()
        .filter(|p| protocol.is_none_or(|want| p.definition.protocols.contains(&want)))
        .filter(|p| query.filter("vendor").is_none_or(|v| p.definition.vendor.eq_ignore_ascii_case(v)))
        .filter(|p| query.filter("product").is_none_or(|v| p.definition.product.eq_ignore_ascii_case(v)))
        .filter(|p| query.filter("engine").is_none_or(|e| p.definition.engine.as_str() == e))
        .map(|p| {
            let mut value = parser_view(p);
            value["editable"] = serde_json::json!(state.parsers.find_id(p.id).is_none());
            value
        })
        .collect();
    let page = query.paginate_vec(
        &parsers,
        |v| {
            format!(
                "{} {} {} {}",
                v.get("key").and_then(|x| x.as_str()).unwrap_or_default(),
                v.get("name").and_then(|x| x.as_str()).unwrap_or_default(),
                v.get("vendor").and_then(|x| x.as_str()).unwrap_or_default(),
                v.get("product").and_then(|x| x.as_str()).unwrap_or_default()
            )
        },
        |v| v.get("key").and_then(|x| x.as_str()).unwrap_or_default().to_string(),
    );
    Ok(Json(query.render_page(&page)?))
}

/// 解析器统计（`GET /api/v1/parsers/stats`）。
///
/// # Errors
/// 权限不足。
pub async fn parser_stats(State(state): State<AppState>, principal: Principal) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "parsers", "read")?;
    let registry = crate::parser_store::registry(&state, principal.tenant).await?;
    let handle = state.ingest_pipelines.get(principal.tenant, state.ingest_sink.clone(), &registry)?;
    let stats = handle.pipeline.registry_stats()?;
    let attention = handle
        .pipeline
        .with_registry(|r| r.needs_attention(0.9, 10).iter().map(|p| p.definition.key.clone()).collect::<Vec<_>>())?;
    Ok(Json(serde_json::json!({
        "stats": serde_json::to_value(&stats)?,
        "invalid_templates": serde_json::to_value(state.parsers.invalid_templates())?,
        "needs_attention": attention,
        "scope": "current-server-process",
    })))
}

/// 解析引擎支持矩阵（`GET /api/v1/parsers/engine-matrix`）。
///
/// # Errors
/// 权限不足。
pub async fn engine_matrix(State(state): State<AppState>, principal: Principal) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "parsers", "read")?;
    let matrix = engine_support_matrix();
    let supported = matrix.iter().filter(|(_, v)| !v.starts_with("未实现")).count();
    Ok(Json(serde_json::json!({
        "matrix": serde_json::to_value(&matrix)?,
        "summary": { "total": matrix.len(), "supported": supported },
    })))
}

/// 解析器详情（`GET /api/v1/parsers/{id}`，支持 UUID 或模板 key）。
///
/// # Errors
/// 解析器不存在。
pub async fn get_parser(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "parsers", "read")?;
    let parser = crate::parser_store::find(&state, principal.tenant, &id).await?;
    Ok(Json(serde_json::json!({
        "parser": parser_view(&parser),
        "validation_error": parser.definition.validate().err(),
    })))
}

/// 解析接入协议名。
///
/// # Errors
/// 未知协议。
pub fn parse_ingest_protocol(raw: &str) -> Result<IngestProtocol, ApiError> {
    let wanted = raw.trim().to_ascii_lowercase().replace('_', "-");
    IngestProtocol::all()
        .into_iter()
        .find(|p| p.as_str() == wanted)
        .ok_or_else(|| ApiError::new(DomainError::Validation(format!("未知接入协议: {raw}"))))
}
