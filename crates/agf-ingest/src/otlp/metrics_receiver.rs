//! OTLP/HTTP metrics 接收器与路由（`POST /v1/metrics`）。
//!
//! 与 [`super::metrics_signal`] 的解析/归一化配套：本文件只管"接收入口 → 流水线 → OTLP 响应"。

use std::sync::Arc;

use agf_core::enums::IngestProtocol;
use agf_core::error::{DomainError, DomainResult};
use agf_core::source::LogSource;
use async_trait::async_trait;
use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::Response;
use axum::routing::post;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tracing::{debug, warn};

use crate::metrics::ReceiverCounters;
use crate::pipeline::IngestPipeline;
use crate::receiver::{Receiver, ReceiverDescriptor, ReceiverStatus, effective_status};

use super::metrics_signal::{OTLP_METRICS_PATH, parse_metrics};

/// 一次 metrics 导出的接入结果（渲染为 `partialSuccess.rejectedDataPoints`）。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OtlpMetricsReport {
    /// 解析出的 data point 数。
    pub received: usize,
    /// 已落库事件数。
    pub persisted: usize,
    /// 命中模板数。
    pub matched: usize,
    /// 未命中模板数。
    pub unmatched: usize,
    /// 被拒绝（编码错误 / 超限）的 data point 数。
    pub rejected: usize,
    /// 拒绝原因（OTLP `partialSuccess.errorMessage`）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
}

impl OtlpMetricsReport {
    /// OTLP/HTTP 响应体（成功且无拒绝时为空 `{}`）。
    #[must_use]
    pub fn to_response(&self) -> Value {
        if self.rejected == 0 {
            return Value::Object(Map::new());
        }
        serde_json::json!({
            "partialSuccess": {
                "rejectedDataPoints": self.rejected,
                "errorMessage": self.error_message.clone().unwrap_or_else(|| "部分 data point 未能接入".to_string()),
            }
        })
    }
}

/// OTLP/HTTP metrics 接收器。
#[derive(Debug)]
pub struct OtlpMetricsReceiver {
    pipeline: Arc<IngestPipeline>,
    source: LogSource,
    max_records: usize,
    max_decompressed_bytes: usize,
    counters: Arc<ReceiverCounters>,
}

impl OtlpMetricsReceiver {
    /// 构造（默认单请求 10_000 条、解压上限 64 MiB）。
    #[must_use]
    pub fn new(pipeline: Arc<IngestPipeline>, source: LogSource) -> Self {
        Self {
            pipeline,
            source,
            max_records: 10_000,
            max_decompressed_bytes: 64 * 1024 * 1024,
            counters: Arc::new(ReceiverCounters::new()),
        }
    }

    /// 注入共享计数器（`/metrics` 用）。
    #[must_use]
    pub fn with_counters(mut self, counters: Arc<ReceiverCounters>) -> Self {
        self.counters = counters;
        self
    }

    /// 单请求最大 data point 数。
    #[must_use]
    pub const fn with_max_records(mut self, max_records: usize) -> Self {
        self.max_records = max_records;
        self
    }

    /// 计数器。
    #[must_use]
    pub fn counters(&self) -> &Arc<ReceiverCounters> {
        &self.counters
    }

    /// 日志源。
    #[must_use]
    pub const fn source(&self) -> &LogSource {
        &self.source
    }

    /// 处理一次 OTLP/HTTP metrics 导出请求（含 gzip 解压与编码分派）。
    ///
    /// # Errors
    /// 体积超限、gzip 失败或编码不受支持。
    pub async fn ingest_metrics(&self, headers: &HeaderMap, body: &[u8]) -> DomainResult<OtlpMetricsReport> {
        self.ingest_metrics_from(headers, body, crate::pipeline::TransportPeer::default()).await
    }

    /// Export with the actual connection attributes, never payload-supplied origins.
    ///
    /// # Errors
    /// Invalid payload, source access denied, or persistence failure.
    pub async fn ingest_metrics_from(
        &self,
        headers: &HeaderMap,
        body: &[u8],
        peer: crate::pipeline::TransportPeer,
    ) -> DomainResult<OtlpMetricsReport> {
        let raw =
            if super::is_gzip(headers) { super::gunzip(body, self.max_decompressed_bytes)? } else { body.to_vec() };
        let content_type = headers.get(axum::http::header::CONTENT_TYPE).and_then(|v| v.to_str().ok());
        let mut report = OtlpMetricsReport::default();
        let points = match parse_metrics(&raw, content_type) {
            Ok(points) => points,
            // 编码不受支持属调用方错误（OTLP 规范要求 4xx），显式失败而非假装部分成功
            Err(e @ DomainError::Validation(_)) => return Err(e),
            Err(e) => {
                self.counters.add_received(1);
                self.counters.add_dropped(1);
                warn!(error = %e, "OTLP metrics 请求体解码失败（整包拒绝）");
                return Err(e);
            }
        };
        report.received = points.len();
        let over = points.len().saturating_sub(self.max_records);
        if over > 0 {
            report.rejected += over;
            report.error_message = Some(format!("超过单请求上限 {}，{over} 条被拒绝", self.max_records));
        }
        let accepted: Vec<(Vec<u8>, String)> =
            points.iter().take(self.max_records).map(|p| (p.to_payload(), p.origin())).collect();
        let outcomes = self.pipeline.ingest_batch_from(&self.source, IngestProtocol::Otlp, &accepted, peer).await?;
        crate::otlp::http_response::count_rejections(&outcomes, &mut report.rejected, &mut report.error_message);
        report.persisted = outcomes.iter().filter(|o| o.persisted).count();
        report.matched = outcomes.iter().filter(|o| o.matched).count();
        report.unmatched = outcomes.len().saturating_sub(report.matched);
        self.counters.add_received(u64::try_from(points.len()).unwrap_or(u64::MAX));
        self.counters.record_outcomes(&outcomes);
        debug!(received = report.received, persisted = report.persisted, "OTLP metrics 已接入");
        Ok(report)
    }
}

#[async_trait]
impl Receiver for OtlpMetricsReceiver {
    fn protocol(&self) -> IngestProtocol {
        IngestProtocol::Otlp
    }

    fn describe(&self) -> ReceiverDescriptor {
        ReceiverDescriptor {
            name: "otlp-metrics".to_string(),
            protocol: IngestProtocol::Otlp,
            // **装配事实**决定状态：路由没被 merge 进进程 ⇒ `not-wired`，绝不谎报 `ready`
            status: effective_status(ReceiverStatus::Ready, "otlp-metrics"),
            note: format!(
                "OTLP/HTTP POST {OTLP_METRICS_PATH}：JSON + Protobuf 双编码，支持 Content-Encoding: gzip；\
                 Gauge/Sum/Histogram/ExponentialHistogram/Summary 的 data point 归一化为 event.category='metric'\
                 的载荷（单请求上限 {} 条）",
                self.max_records
            ),
            todo: None,
            mock_replay: false,
        }
    }

    async fn start(&self, _pipeline: Arc<IngestPipeline>, _source: LogSource) -> DomainResult<()> {
        debug!(path = OTLP_METRICS_PATH, "OTLP metrics 接收器由运行时挂载路由");
        Ok(())
    }

    async fn poll_once(&self, _pipeline: Arc<IngestPipeline>, _source: LogSource, _max: usize) -> DomainResult<usize> {
        Err(DomainError::NotImplemented("OTLP 为推送型接收器，无轮询语义；请调用 ingest_metrics/router".to_string()))
    }
}

/// 构造 OTLP metrics 路由（`POST /v1/metrics`）。
#[must_use = "路由构造后必须挂载到服务上，直接丢弃等于没有接入点"]
pub fn metrics_router(receiver: Arc<OtlpMetricsReceiver>) -> Router {
    Router::new().route(OTLP_METRICS_PATH, post(handle_otlp_metrics)).with_state(receiver)
}

/// axum handler：OTLP/HTTP metrics 导出。
async fn handle_otlp_metrics(
    State(receiver): State<Arc<OtlpMetricsReceiver>>,
    peer: Option<axum::Extension<axum::extract::ConnectInfo<std::net::SocketAddr>>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let peer = crate::pipeline::TransportPeer { ip: peer.map(|p| p.0.0.ip()), mutual_tls: false };
    match receiver.ingest_metrics_from(&headers, &body, peer).await {
        Ok(report) => crate::otlp::http_response::success(&headers, report.to_response()),
        Err(error) => crate::otlp::http_response::error(&headers, &error),
    }
}
