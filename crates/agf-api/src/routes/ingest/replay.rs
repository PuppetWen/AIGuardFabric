//! 原始日志只读预览与显式回放，按日志源过滤。

use super::*;

// ===========================================================================
// GET 仅预览原文；POST 才重新解析并写入事件（§4.5）。
// ===========================================================================

/// 预览/回放请求（`GET` 走 query；`POST` 走 JSON body）。
///
/// `source_id` 必填（保持既有契约）：它可以是 `RawLog.origin`（如 `demo-src-wazuh-json`），
/// 也可以是 `RawLog.source_id` 的 UUID 文本。`limit` 缺省 1000，**必须为正**。
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ReplayRequest {
    /// 日志源标识（必填）。同时接受控制台的驼峰写法 `sourceId`。
    #[serde(default, alias = "sourceId")]
    pub source_id: Option<String>,
    /// 回放条数上限。
    #[serde(default)]
    pub limit: Option<i64>,
}

/// 单次扫描的原始日志条数上限（防御性：源过滤发生在取数之后，必须先取到足够多的候选）。
const REPLAY_SCAN_CAP: i64 = 100_000;

/// 源过滤包装：只让**指定日志源**的未解析原始日志进入回放引擎。
///
/// 为什么需要它：`agf_ingest::replay::Replayer` 的入参只有 `limit`，按"租户 + 未解析"取数；
/// 而本端点的契约是"回放某个日志源"。包装器把 `unparsed_raw` 收窄到该源，其余方法**原样透传**
/// （标记已解析、写事件、读事件都必须落到同一个真实仓储上，否则回放会产生"只在包装器里存在"的假事件）。
#[derive(Debug)]
struct SourceScopedSink {
    inner: Arc<dyn Sink>,
    source_id: String,
}

/// 该原始日志是否属于本次回放的日志源（`origin` 或 `source_id` 文本匹配，大小写不敏感）。
fn raw_matches_source(raw: &RawLog, source_id: &str) -> bool {
    raw.origin.eq_ignore_ascii_case(source_id) || raw.source_id.to_string().eq_ignore_ascii_case(source_id)
}

fn validated_request(request: &ReplayRequest) -> ApiResult<(&str, i64)> {
    let Some(source_id) = request.source_id.as_deref().map(str::trim).filter(|v| !v.is_empty()) else {
        return Err(DomainError::Validation("source_id（或 sourceId）不能为空：必须指定日志源".into()).into());
    };
    let limit = request.limit.unwrap_or(1_000);
    if limit <= 0 {
        return Err(DomainError::Validation(format!("limit 必须为正整数，收到 {limit}")).into());
    }
    Ok((source_id, limit))
}

struct RawPreview {
    rows: Vec<serde_json::Value>,
    total: usize,
    matched_by: &'static str,
}

async fn load_raw_preview(state: &AppState, tenant: TenantId, source_id: &str, limit: i64) -> ApiResult<RawPreview> {
    let candidates = state.ingest_sink.unparsed_raw(tenant, REPLAY_SCAN_CAP).await?;
    let matched: Vec<RawLog> = candidates.into_iter().filter(|raw| raw_matches_source(raw, source_id)).collect();
    let matched_by = matched
        .first()
        .map(|raw| if raw.origin.eq_ignore_ascii_case(source_id) { "origin" } else { "source_id" })
        .unwrap_or("none");
    let rows = matched
        .iter()
        .take(usize::try_from(limit).unwrap_or(usize::MAX))
        .map(|raw| match decode_payload(raw) {
            Ok(payload) => serde_json::json!({
                "id":raw.id,"source_id":raw.source_id,"origin":raw.origin,
                "protocol":raw.protocol.as_str(),"bytes":raw.bytes,
                "received_at":raw.received_at,"payload":payload,
            }),
            Err(error) => serde_json::json!({
                "id":raw.id,"source_id":raw.source_id,"origin":raw.origin,
                "protocol":raw.protocol.as_str(),"bytes":raw.bytes,
                "received_at":raw.received_at,"payload":serde_json::Value::Null,
                "decode_error":error.to_string(),
            }),
        })
        .collect();
    Ok(RawPreview { rows, total: matched.len(), matched_by })
}

#[async_trait]
impl Sink for SourceScopedSink {
    fn backend(&self) -> &'static str {
        self.inner.backend()
    }

    async fn put_raw(&self, raw: &RawLog) -> DomainResult<()> {
        self.inner.put_raw(raw).await
    }

    async fn mark_raw(
        &self,
        tenant: TenantId,
        raw_id: Id,
        parsed: bool,
        event_id: Option<Id>,
        error: Option<&str>,
    ) -> DomainResult<()> {
        self.inner.mark_raw(tenant, raw_id, parsed, event_id, error).await
    }

    async fn put_event(&self, event: &Event) -> DomainResult<()> {
        self.inner.put_event(event).await
    }

    async fn put_events(&self, events: &[Event]) -> DomainResult<usize> {
        self.inner.put_events(events).await
    }

    async fn get_event(&self, tenant: TenantId, id: Id) -> DomainResult<Option<Event>> {
        self.inner.get_event(tenant, id).await
    }

    async fn unparsed_raw(&self, tenant: TenantId, limit: i64) -> DomainResult<Vec<RawLog>> {
        let candidates = self.inner.unparsed_raw(tenant, REPLAY_SCAN_CAP).await?;
        let mut matched: Vec<RawLog> =
            candidates.into_iter().filter(|raw| raw_matches_source(raw, &self.source_id)).collect();
        let limit = usize::try_from(limit.max(0)).unwrap_or(usize::MAX);
        matched.truncate(limit);
        Ok(matched)
    }

    async fn event_count(&self, tenant: TenantId) -> DomainResult<u64> {
        self.inner.event_count(tenant).await
    }

    async fn raw_count(&self, tenant: TenantId) -> DomainResult<u64> {
        self.inner.raw_count(tenant).await
    }
}

/// 显式回放主体（仅 `POST /api/v1/ingest/replay`）。
///
/// ## 真实在哪里
/// - 取数：`AppState.ingest_sink`（`agf_ingest::pipeline::InMemorySink`）里 `parsed=false` 的原始日志，
///   经 [`SourceScopedSink`] 收窄到指定源；
/// - 解析：`AppState.replay_parsers`（当前解析器注册表）→ `ParserRegistry::match_raw`；
/// - 回放：`agf_ingest::replay::Replayer::replay`（新事件按 `(tenant,time,id)` 追加写入、
///   原始日志标记为已解析、与既有事件逐字段差分）；
/// - 响应里的 `raw_logs` 是回放前取到的**原文**（base64 解码后），`parser_used` / `diffs` /
///   `failures` 全部来自引擎返回的 `ReplayReport`。GET 只读取同一批原文，不执行回放。
///
/// ## 降级
/// - 该源没有未解析原始日志 ⇒ 200 + `replayed = 0`（不伪造条数），`notes` 说明原因；
/// - 单条解析失败 ⇒ 引擎计入 `failures`，其余照常回放（不是整体失败）；
/// - 原始日志 `payload_b64` 非法 ⇒ 计入 `failures`，并出现在 `raw_logs[].decode_error`。
///
/// ## 响应形状
/// POST 返回回放报告和原文；控制台明确执行操作的 `SourceReplay` 读取这些字段。
///
/// # Errors
/// 权限不足（`sources:write`）、`source_id` 缺失/为空（400）、`limit` 非正（400）、
/// 仓储读失败或事件写失败。
pub async fn replay_raw_logs(
    state: &AppState,
    principal: &Principal,
    request: &ReplayRequest,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(state, "sources", "write")?;
    let (source_id, limit) = validated_request(request)?;
    // 回放会把原文标记为已解析，必须先取得控制台所需的预览快照。
    let preview = load_raw_preview(state, principal.tenant, source_id, limit).await?;
    let matched_total = preview.total;
    let matched_by = preview.matched_by;
    let raw_logs = preview.rows;

    let scoped = SourceScopedSink { inner: Arc::clone(&state.ingest_sink), source_id: source_id.to_string() };
    let configured = match Id::parse(source_id) {
        Ok(id) => state
            .configurations
            .get::<crate::source_store::Record>(principal.tenant, crate::source_store::KIND, id)
            .await?
            .and_then(|row| row.source),
        Err(_) => None,
    };
    let parsers = crate::parser_store::registry(state, principal.tenant).await?;
    if configured.as_ref().and_then(|s| s.parser_id).is_some_and(|id| parsers.find_id(id).is_none_or(|p| !p.enabled)) {
        return Err(DomainError::PreconditionFailed("日志源绑定的模板已删除或停用，请重新选择解析器".into()).into());
    }
    let parser_key = configured
        .as_ref()
        .and_then(|source| source.parser_id)
        .and_then(|id| parsers.find_id(id))
        .map(|parser| parser.definition.key.clone());
    let registry =
        if configured.is_some() { Arc::new(std::sync::Mutex::new(parsers)) } else { Arc::clone(&state.replay_parsers) };
    let replayer = Replayer::plain(
        Arc::new(scoped),
        registry,
        ReplayConfig { limit, mark_parsed: true, emit_to_bus: false, tenant: principal.tenant },
    )
    .with_parser_key(parser_key);
    let report = replayer.replay(limit).await.map_err(ApiError::new)?;

    let mut notes: Vec<String> = vec![
        "回放走 agf_ingest::replay::Replayer：重新解析 → 追加新事件 → 标记原始日志已解析 → 与既有事件差分".to_string(),
        format!("日志仓储：{}", state.ingest_sink.backend()),
    ];
    if matched_total == 0 {
        notes.push(format!("日志源 {source_id} 没有未解析的原始日志（该源可能从未接入，或历史原始日志都已解析过）"));
    } else if matched_total > usize::try_from(limit).unwrap_or(usize::MAX) {
        notes.push(format!("该源未解析原始日志共 {matched_total} 条，本次按 limit={limit} 回放前 {limit} 条"));
    }

    state
        .audit(
            principal.tenant,
            agf_core::audit::AuditAction::Execute,
            agf_core::audit::AuditOutcome::Success,
            AppState::audit_actor(principal, "ingest-replay"),
            agf_core::audit::AuditTarget::new("raw-log", Some(source_id.to_string()), None),
            &format!(
                "原始日志回放：源 {source_id}，检查 {} 条、新解析 {} 条、失败 {} 条",
                report.replayed, report.newly_parsed, report.failed
            ),
        )
        .await?;

    Ok(Json(serde_json::json!({
        "source_id": source_id,
        "matched_by": matched_by,
        "limit": limit,
        "replayed": report.replayed,
        "newly_parsed": report.newly_parsed,
        "failed": report.failed,
        "is_noop": report.is_noop(),
        "unparsed_total_for_source": matched_total,
        "parser_used": report.parser_used,
        "diffs": report.diffs,
        "failures": report.failures,
        "elapsed_micros": report.elapsed_micros,
        "raw_logs": raw_logs,
        "report": report,
        "notes": notes,
    })))
}

/// 原始日志只读预览（`GET /api/v1/ingest/replay`）。
///
/// # Errors
/// 权限不足、缺少日志源、limit 无效或仓储读取失败。
pub async fn replay_get(
    State(state): State<AppState>,
    principal: Principal,
    query: ListQuery,
) -> ApiResult<Json<serde_json::Value>> {
    let request = ReplayRequest {
        source_id: query.filter("source_id").or_else(|| query.filter("sourceId")).map(ToString::to_string),
        limit: query.filter_i64("limit")?,
    };
    // 原始载荷可能含凭据或个人信息；沿用原路由的 sources:write 权限边界。
    principal.require(&state, "sources", "write")?;
    let (source_id, limit) = validated_request(&request)?;
    let preview = load_raw_preview(&state, principal.tenant, source_id, limit).await?;
    let note = if preview.total == 0 {
        format!("日志源 {source_id} 没有未解析的原始日志")
    } else {
        format!("该源还有 {} 条未解析原文；只有 POST 才会重新解析并写入事件", preview.total)
    };
    Ok(Json(serde_json::json!({
        "source_id":source_id,"matched_by":preview.matched_by,"limit":limit,
        "preview_only":true,"replayed":0,"newly_parsed":0,"failed":0,
        "is_noop":true,"unparsed_total_for_source":preview.total,
        "parser_used":{},"diffs":[],"failures":[],"elapsed_micros":0,
        "raw_logs":preview.rows,"report":serde_json::Value::Null,
        "notes":["GET 仅预览未解析的原文，不执行回放，也不修改日志或事件",note],
    })))
}

/// 执行回放（`POST /api/v1/ingest/replay`，body 版）。
///
/// # Errors
/// 同 [`replay_raw_logs`]。
pub async fn replay_post(
    State(state): State<AppState>,
    principal: Principal,
    crate::routes::ApiJson(body): crate::routes::ApiJson<ReplayRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    replay_raw_logs(&state, &principal, &body).await
}
