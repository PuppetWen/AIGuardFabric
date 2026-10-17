//! HTTP Pull 接收器：可注入取数抽象 `HttpFetcher`（`reqwest` 实现）与增量拉取。

use super::*;

/// HTTP 取数抽象（真实实现用 `reqwest`；测试可注入离线实现）。
#[async_trait]
pub trait HttpFetcher: Send + Sync + std::fmt::Debug {
    /// 拉取一个 URL。
    ///
    /// # Errors
    /// 网络失败、非 2xx 或响应体过大。
    async fn fetch(&self, url: &str, headers: &BTreeMap<String, String>) -> DomainResult<Vec<u8>>;
}

/// 基于 `reqwest` 的取数实现（真实出网）。
#[derive(Debug)]
pub struct ReqwestFetcher {
    pub(super) client: reqwest::Client,
    pub(super) max_bytes: usize,
}

impl ReqwestFetcher {
    /// 构造（默认 30s 超时 / 64 MiB 上限）。
    ///
    /// # Errors
    /// TLS 后端初始化失败。
    pub fn new() -> DomainResult<Self> {
        Self::with_limits(30, 64 * 1024 * 1024)
    }

    /// 自定义超时与体积上限。
    ///
    /// # Errors
    /// HTTP 客户端构造失败。
    pub fn with_limits(timeout_secs: u64, max_bytes: usize) -> DomainResult<Self> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(timeout_secs.max(1)))
            .build()
            .map_err(|e| DomainError::Config(format!("构造 HTTP 客户端失败: {e}")))?;
        Ok(Self { client, max_bytes })
    }
}

#[async_trait]
impl HttpFetcher for ReqwestFetcher {
    async fn fetch(&self, url: &str, headers: &BTreeMap<String, String>) -> DomainResult<Vec<u8>> {
        let mut request = self.client.get(url);
        for (k, v) in headers {
            request = request.header(k, v);
        }
        let response = request.send().await.map_err(|e| DomainError::DependencyUnavailable {
            dependency: "http-pull".to_string(),
            cause: format!("请求 {url} 失败: {e}"),
        })?;
        let status = response.status();
        if !status.is_success() {
            return Err(DomainError::DependencyUnavailable {
                dependency: "http-pull".to_string(),
                cause: format!("{url} 返回 {status}"),
            });
        }
        let bytes = response.bytes().await.map_err(|e| DomainError::Internal(format!("读取响应体失败: {e}")))?;
        if bytes.len() > self.max_bytes {
            return Err(DomainError::Validation(format!("响应体 {} 字节超过上限 {}", bytes.len(), self.max_bytes)));
        }
        Ok(bytes.to_vec())
    }
}

/// HTTP 拉取接收器（增量拉取 + 游标）。
#[derive(Debug)]
pub struct HttpPullReceiver {
    endpoint: String,
    headers: BTreeMap<String, String>,
    fetcher: Arc<dyn HttpFetcher>,
    cursor: Mutex<Option<String>>,
    max_batch: usize,
}

impl HttpPullReceiver {
    /// 构造。
    #[must_use]
    pub fn new(endpoint: impl Into<String>, headers: BTreeMap<String, String>, fetcher: Arc<dyn HttpFetcher>) -> Self {
        Self { endpoint: endpoint.into(), headers, fetcher, cursor: Mutex::new(None), max_batch: 1_000 }
    }

    /// 由日志源构造（需要 `connection.endpoint`）。
    ///
    /// # Errors
    /// 未配置端点。
    pub fn from_source(source: &LogSource, fetcher: Arc<dyn HttpFetcher>) -> DomainResult<Self> {
        let endpoint = source
            .connection
            .endpoint
            .clone()
            .ok_or_else(|| DomainError::Config("HTTP 拉取需要 connection.endpoint".to_string()))?;
        let mut headers = source.connection.headers.clone();
        if let Some(cursor) = &source.connection.cursor_value {
            headers.insert("x-agf-cursor".to_string(), cursor.clone());
        }
        Ok(Self::new(endpoint, headers, fetcher))
    }

    /// 端点。
    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// 当前游标。
    #[must_use]
    pub fn cursor(&self) -> Option<String> {
        self.cursor.lock().ok().and_then(|c| c.clone())
    }

    /// 更新游标。
    pub fn set_cursor(&self, value: Option<String>) {
        if let Ok(mut cursor) = self.cursor.lock() {
            *cursor = value;
        }
    }

    /// 拆分响应体为多条记录（NDJSON 优先，其次 JSON 数组，最后整包视为一条）。
    #[must_use]
    pub fn split_records(body: &[u8], max_batch: usize) -> Vec<Vec<u8>> {
        let text = String::from_utf8_lossy(body);
        let trimmed = text.trim();
        if trimmed.is_empty() {
            return Vec::new();
        }
        if let Some(items) = crate::payload::json_array_records(body, crate::payload::ArrayStrings::Preserve) {
            return items.into_iter().take(max_batch).collect();
        }
        let lines: Vec<Vec<u8>> = crate::payload::line_records(body).take(max_batch).map(<[u8]>::to_vec).collect();
        if lines.len() <= 1 { vec![body.to_vec()] } else { lines }
    }
}

#[async_trait]
impl Receiver for HttpPullReceiver {
    fn protocol(&self) -> IngestProtocol {
        IngestProtocol::HttpPull
    }

    fn describe(&self) -> ReceiverDescriptor {
        ReceiverDescriptor {
            name: "http-pull".to_string(),
            protocol: IngestProtocol::HttpPull,
            status: ReceiverStatus::Ready,
            note: format!("增量拉取 {}（x-agf-cursor 游标，游标值取自 connection.cursor_value）", self.endpoint),
            todo: None,
            mock_replay: false,
        }
    }

    async fn start(&self, pipeline: Arc<IngestPipeline>, source: LogSource) -> DomainResult<()> {
        let interval = u64::try_from(source.poll_interval_secs.unwrap_or(60).max(5)).unwrap_or(60);
        loop {
            let _ = self.poll_once(Arc::clone(&pipeline), source.clone(), self.max_batch).await?;
            tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
        }
    }

    async fn poll_once(&self, pipeline: Arc<IngestPipeline>, source: LogSource, max: usize) -> DomainResult<usize> {
        let body = self.fetcher.fetch(&self.endpoint, &self.headers).await?;
        let records = Self::split_records(&body, max.min(self.max_batch));
        if records.is_empty() {
            return Ok(0);
        }
        let items: Vec<(Vec<u8>, String)> = records.into_iter().map(|r| (r, self.endpoint.clone())).collect();
        let outcomes = pipeline.ingest_batch(&source, IngestProtocol::HttpPull, &items).await?;
        Ok(outcomes.iter().filter(|o| o.persisted).count())
    }
}

// ---------------------------------------------------------------------------
// Mock 回放通道 + 未实现协议
// ---------------------------------------------------------------------------
