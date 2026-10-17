//! Webhook 接收器：Bearer 鉴权（常量时间比较）、载荷拆分、HTTP 路由与响应构造。

use super::*;

/// Webhook 通道的解析命中统计。
///
/// **为什么单列**：webhook **不进** `agf_ingest_syslog_frames_total` / `parse_failures`，
/// 而响应体里的 `accepted` 只表示"该条没有处理错误"。若不单独统计，
/// "webhook 通道解析命中率"在任何地方都不可观测（模拟器实测缺口，见
/// `tools/simulators/README.md` 第 7 节第 5 条）。
#[derive(Debug, Default)]
pub struct WebhookCounters {
    matched: AtomicU64,
    unmatched: AtomicU64,
}

impl WebhookCounters {
    /// 命中模板的条数。
    #[must_use]
    pub fn matched(&self) -> u64 {
        self.matched.load(Ordering::Relaxed)
    }

    /// 未命中任何模板的条数（**缺失就是缺失**，不并入 matched）。
    #[must_use]
    pub fn unmatched(&self) -> u64 {
        self.unmatched.load(Ordering::Relaxed)
    }

    /// 按一批结果累加。
    fn record(&self, outcomes: &[IngestOutcome]) {
        let matched = outcomes.iter().filter(|o| o.matched).count();
        let total = outcomes.len();
        self.matched.fetch_add(u64::try_from(matched).unwrap_or(u64::MAX), Ordering::Relaxed);
        self.unmatched.fetch_add(u64::try_from(total.saturating_sub(matched)).unwrap_or(u64::MAX), Ordering::Relaxed);
    }
}

/// Webhook（HTTP 推送）接收器。
#[derive(Debug)]
pub struct WebhookReceiver {
    pipeline: Arc<IngestPipeline>,
    source: LogSource,
    path: String,
    token: Option<String>,
    max_batch: usize,
    counters: Arc<WebhookCounters>,
}

impl WebhookReceiver {
    /// 构造（`path` 形如 `/ingest/webhook`）。
    #[must_use]
    pub fn new(pipeline: Arc<IngestPipeline>, source: LogSource, path: &str) -> Self {
        Self {
            pipeline,
            source,
            path: path.to_string(),
            token: None,
            max_batch: 256,
            counters: Arc::new(WebhookCounters::default()),
        }
    }

    /// 解析命中/未命中累计（供 `/metrics` 与自检读取）。
    #[must_use]
    pub fn counters(&self) -> &WebhookCounters {
        &self.counters
    }

    /// 设置 Bearer 令牌（未设置表示**不鉴权**，仅允许内网/已由前置网关鉴权的场景）。
    #[must_use]
    pub fn with_token(mut self, token: impl Into<String>) -> Self {
        self.token = Some(token.into());
        self
    }

    /// 设置单次请求最大条数。
    #[must_use]
    pub const fn with_max_batch(mut self, max_batch: usize) -> Self {
        self.max_batch = max_batch;
        self
    }

    /// 挂载路径。
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// 已配置的令牌（**仅用于测试与排障判断，不要在日志里打印**）。
    #[must_use]
    pub fn token(&self) -> Option<&str> {
        self.token.as_deref()
    }

    /// 流水线。
    #[must_use]
    pub fn pipeline(&self) -> &Arc<IngestPipeline> {
        &self.pipeline
    }

    /// 日志源。
    #[must_use]
    pub const fn source(&self) -> &LogSource {
        &self.source
    }

    /// 校验 Bearer 令牌（纯函数；未配置令牌时返回 `true`）。
    #[must_use]
    pub fn verify_bearer(&self, presented: Option<&str>) -> bool {
        let Some(expected) = &self.token else {
            return true;
        };
        let Some(presented) = presented else {
            return false;
        };
        let presented =
            presented.strip_prefix("Bearer ").or_else(|| presented.strip_prefix("bearer ")).unwrap_or(presented);
        constant_time_eq(expected.as_bytes(), presented.trim().as_bytes())
    }

    /// 鉴权判定（未配置令牌时允许，但会在描述里标注风险）。
    ///
    /// # Errors
    /// 令牌缺失或不匹配 ⇒ [`DomainError::Unauthenticated`]。
    pub fn authorize(&self, presented: Option<&str>) -> DomainResult<()> {
        if self.verify_bearer(presented) {
            Ok(())
        } else {
            Err(DomainError::Unauthenticated("Webhook Bearer 令牌缺失或不匹配".to_string()))
        }
    }

    /// 把请求体拆成多条载荷：JSON 数组 → 逐元素；NDJSON → 逐行；否则视为单条。
    #[must_use]
    pub fn split_payloads(body: &[u8], max_batch: usize) -> Vec<Vec<u8>> {
        let text = String::from_utf8_lossy(body);
        let trimmed = text.trim();
        if trimmed.is_empty() {
            return Vec::new();
        }
        if let Some(items) = crate::payload::json_array_records(body, crate::payload::ArrayStrings::Decode) {
            // String elements retain the existing decoded-content contract for syslog.
            return items.into_iter().take(max_batch).collect();
        }
        if trimmed.starts_with('{') && !trimmed.contains('\n') {
            return vec![body.to_vec()];
        }
        // Pretty JSON keeps the existing line-framing contract; LF/CRLF stays in each record.
        crate::payload::line_records(body).take(max_batch).map(<[u8]>::to_vec).collect()
    }

    /// 执行接入（供 handler 与测试复用）。
    ///
    /// # Errors
    /// 鉴权失败、空请求体或落库失败。
    pub async fn ingest(&self, body: &[u8], origin: &str) -> DomainResult<Vec<IngestOutcome>> {
        let payloads = Self::split_payloads(body, self.max_batch);
        if payloads.is_empty() {
            return Err(DomainError::Validation("Webhook 请求体为空".to_string()));
        }
        let items: Vec<(Vec<u8>, String)> = payloads.into_iter().map(|p| (p, origin.to_string())).collect();
        let outcomes = self.pipeline.ingest_batch(&self.source, IngestProtocol::Webhook, &items).await?;
        // 命中/未命中如实累计（响应体与 /metrics 都读它）
        self.counters.record(&outcomes);
        Ok(outcomes)
    }

    /// 一批结果的响应统计（落库 / 命中 / 未命中 / 各模板命中数）。
    ///
    /// 三个口径**必须分开报**，否则 webhook 通道的解析命中率不可观测：
    /// - `accepted` = `persisted`（已保真落库的条数，**含未命中模板的载荷**）；
    /// - `matched` = 命中模板的条数；
    /// - `unmatched` = 未命中任何模板的条数（**缺失就是缺失**，不并入 accepted）。
    #[must_use]
    pub fn outcome_summary(outcomes: &[IngestOutcome]) -> Value {
        let matched = outcomes.iter().filter(|o| o.matched).count();
        let mut parsers: BTreeMap<String, usize> = BTreeMap::new();
        for outcome in outcomes.iter().filter(|o| o.matched) {
            if let Some(key) = &outcome.parser_key {
                *parsers.entry(key.clone()).or_insert(0) += 1;
            }
        }
        serde_json::json!({
            "accepted": outcomes.iter().filter(|o| o.persisted).count(),
            "total": outcomes.len(),
            "matched": matched,
            "unmatched": outcomes.len().saturating_sub(matched),
            "parsers": parsers,
        })
    }
}

/// 常量时间比较（避免令牌逐字节试探的时序侧信道）。
#[must_use]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0_u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[async_trait]
impl Receiver for WebhookReceiver {
    fn protocol(&self) -> IngestProtocol {
        IngestProtocol::Webhook
    }

    fn describe(&self) -> ReceiverDescriptor {
        let note = if self.token.is_some() {
            "axum HTTP handler，Bearer 鉴权 + JSON/NDJSON 拆包".to_string()
        } else {
            "axum HTTP handler；**未配置令牌**，仅限内网或前置网关已鉴权场景".to_string()
        };
        ReceiverDescriptor {
            name: "webhook".to_string(),
            protocol: IngestProtocol::Webhook,
            status: ReceiverStatus::Ready,
            note,
            todo: None,
            mock_replay: false,
        }
    }

    async fn start(&self, _pipeline: Arc<IngestPipeline>, _source: LogSource) -> DomainResult<()> {
        // HTTP 服务由 agf-runtime 统一托管；本接收器只提供 handler 与路由。
        debug!(path = %self.path, "Webhook 接收器由运行时挂载路由");
        Ok(())
    }

    async fn poll_once(&self, _pipeline: Arc<IngestPipeline>, _source: LogSource, _max: usize) -> DomainResult<usize> {
        Err(DomainError::NotImplemented("Webhook 为推送型接收器，无轮询语义；请调用 handle/router".to_string()))
    }
}

/// 构造 Webhook 路由（`POST <path>`）。
#[must_use = "路由构造后必须挂载到服务上，直接丢弃等于没有接入点"]
pub fn webhook_router(receiver: Arc<WebhookReceiver>) -> Router {
    let path = receiver.path().to_string();
    Router::new().route(&path, post(handle_webhook)).with_state(receiver)
}

/// axum handler。
async fn handle_webhook(State(receiver): State<Arc<WebhookReceiver>>, headers: HeaderMap, body: Bytes) -> Response {
    let presented = headers.get(axum::http::header::AUTHORIZATION).and_then(|v| v.to_str().ok());
    if let Err(e) = receiver.authorize(presented) {
        return (StatusCode::from_u16(e.status_code()).unwrap_or(StatusCode::UNAUTHORIZED), Json(problem(&e)))
            .into_response();
    }
    let origin = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()).unwrap_or("webhook").to_string();
    match receiver.ingest(&body, &origin).await {
        Ok(outcomes) => {
            let deduped = outcomes.iter().filter(|o| o.deduped).count();
            let mut summary = WebhookReceiver::outcome_summary(&outcomes);
            if let Some(map) = summary.as_object_mut() {
                // 纯增量字段：既有调用方读 accepted/total 的语义不变
                map.insert("deduped".to_string(), Value::from(deduped));
                map.insert(
                    "event_ids".to_string(),
                    Value::from(
                        outcomes.iter().filter_map(|o| o.event_id).map(|id| id.to_string()).collect::<Vec<_>>(),
                    ),
                );
            }
            (StatusCode::ACCEPTED, Json(summary)).into_response()
        }
        Err(e) => (StatusCode::from_u16(e.status_code()).unwrap_or(StatusCode::BAD_REQUEST), Json(problem(&e)))
            .into_response(),
    }
}

/// RFC 9457 风格的错误体。
fn problem(error: &DomainError) -> Value {
    serde_json::json!({
        "type": error.problem_type(),
        "title": error.code(),
        "detail": error.to_string(),
        "status": error.status_code(),
    })
}

// ---------------------------------------------------------------------------
// 文件采集（tail）
// ---------------------------------------------------------------------------
