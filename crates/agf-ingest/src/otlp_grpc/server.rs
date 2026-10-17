//! 服务端：`LogsService/Export` 实现、`OtlpGrpcServer`（tonic 承载 + 优雅停机）与监听地址解析。

use super::*;
use crate::otlp::{OtlpMetricsReceiver, OtlpTracesReceiver};
use opentelemetry_proto::tonic::collector::{
    metrics::v1::metrics_service_server::MetricsServiceServer, trace::v1::trace_service_server::TraceServiceServer,
};

/// `LogsService/Export` 实现：一次 gRPC 请求 = 一次既有 OTLP 接入（同 receiver、同 pipeline）。
#[derive(Debug)]
pub struct OtlpGrpcLogsService {
    receiver: Arc<OtlpLogsReceiver>,
}

impl OtlpGrpcLogsService {
    /// 构造。
    #[must_use]
    pub fn new(receiver: Arc<OtlpLogsReceiver>) -> Self {
        Self { receiver }
    }

    /// 底层接收器（`/stats`、测试断言用）。
    #[must_use]
    pub fn receiver(&self) -> &Arc<OtlpLogsReceiver> {
        &self.receiver
    }
}

#[tonic::async_trait]
impl LogsService for OtlpGrpcLogsService {
    async fn export(
        &self,
        request: Request<ExportLogsServiceRequest>,
    ) -> Result<Response<ExportLogsServiceResponse>, Status> {
        let peer = super::signals::transport_peer(&request);
        let inner = request.into_inner();
        let json = request_to_json(&inner).map_err(|e| crate::otlp::http_response::grpc_error(&e))?;
        match self.receiver.ingest_logs_from(&json_headers(), &json, peer).await {
            Ok(report) => {
                debug!(
                    received = report.received,
                    persisted = report.persisted,
                    matched = report.matched,
                    rejected = report.rejected,
                    "OTLP/gRPC 导出已接入"
                );
                Ok(Response::new(report_to_response(&report)))
            }
            // 调用方错误（编码不受支持等）：gRPC 用 INVALID_ARGUMENT 显式失败，
            // 绝不当成"收下了"——否则 exporter 会丢数据。
            Err(e) => {
                warn!(error = %e, "OTLP/gRPC 导出请求被拒绝");
                Err(crate::otlp::http_response::grpc_error(&e))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 服务端
// ---------------------------------------------------------------------------

/// 已绑定的 OTLP/gRPC 服务端。
///
/// **先绑定再服务**：绑定失败（端口占用/地址非法）立刻返回错误，调用方只 `warn` 并写进
/// `/readyz` 的 notes，进程与其余接收器完全不受影响；绑定成功则 [`Self::local_addr`]
/// 给出**内核实际分配的地址**（`127.0.0.1:0` 也能如实汇报）。
///
/// **端口自身的 TLS/mTLS** 在 [`Self::from_listener`] 就定案（[`OtlpGrpcTlsState`]）：
/// 证书齐备且 PEM 合法才启用；配置错误时返回错误并释放监听器。[`Self::tls_mode`] 给出
/// 本进程**实际生效**的形态，`/readyz` 与能力矩阵据此如实标注。
#[derive(Debug)]
pub struct OtlpGrpcServer {
    listener: TcpListener,
    service: Arc<OtlpGrpcLogsService>,
    max_message_bytes: usize,
    tls: OtlpGrpcTlsState,
    traces: Option<Arc<OtlpTracesReceiver>>,
    metrics: Option<Arc<OtlpMetricsReceiver>>,
}

impl OtlpGrpcServer {
    /// 绑定并装配（`listen` 形如 `0.0.0.0:4317`；`127.0.0.1:0` 由内核选口，单测与
    /// "端口不固定"的部署都用它）。
    ///
    /// # Errors
    /// 地址非法或绑定失败。
    pub async fn bind(listen: &str, config: &OtlpGrpcConfig, receiver: Arc<OtlpLogsReceiver>) -> DomainResult<Self> {
        let addr = parse_listen(listen)?;
        let listener = TcpListener::bind(addr).await.map_err(|e| DomainError::DependencyUnavailable {
            dependency: "otlp-grpc".to_string(),
            cause: format!("绑定 {listen} 失败: {e}"),
        })?;
        Self::from_listener(listener, config, receiver)
    }

    /// 用**已绑定**的监听器装配（`agf-ingest` 的运行时用它先绑定、再把真实地址写进 `/readyz`）。
    ///
    /// # Errors
    /// Requested TLS cannot be configured. The supplied listener is closed on failure.
    pub fn from_listener(
        listener: TcpListener,
        config: &OtlpGrpcConfig,
        receiver: Arc<OtlpLogsReceiver>,
    ) -> DomainResult<Self> {
        let tls = OtlpGrpcTlsState::from_config(&config.tls)?;
        Ok(Self {
            listener,
            service: Arc::new(OtlpGrpcLogsService::new(receiver)),
            max_message_bytes: config.max_message_bytes,
            tls,
            traces: None,
            metrics: None,
        })
    }

    /// Attach the trace and metric pipelines before serving the shared gRPC port.
    #[must_use]
    pub fn with_signals(mut self, traces: Arc<OtlpTracesReceiver>, metrics: Arc<OtlpMetricsReceiver>) -> Self {
        self.traces = Some(traces);
        self.metrics = Some(metrics);
        self
    }

    /// 本进程**实际生效**的端口传输形态（明文 / 单向 TLS / mTLS）。
    #[must_use]
    pub const fn tls_mode(&self) -> OtlpGrpcTlsMode {
        self.tls.mode
    }

    /// TLS 诊断信息。成功构造的服务不会因配置错误降级为明文。
    #[must_use]
    pub fn tls_degraded(&self) -> Option<&str> {
        self.tls.degraded.as_deref()
    }

    /// 内核实际监听的地址（绑定失败时不会有本对象，因此这里**不含 Option 语义**）。
    ///
    /// # Errors
    /// 极端情况下 `getsockname` 失败（套接字已被关闭）。
    pub fn local_addr(&self) -> DomainResult<SocketAddr> {
        self.listener.local_addr().map_err(|e| DomainError::DependencyUnavailable {
            dependency: "otlp-grpc".to_string(),
            cause: format!("读取本地监听地址失败: {e}"),
        })
    }

    /// 服务直到进程结束（或传输层致命错误）。
    ///
    /// 单个连接的 accept 错误只 `warn` + 短暂停顿后继续（不会因为一次 `EMFILE` 就整体退出）。
    ///
    /// # Errors
    /// tonic 服务端致命错误（例如监听套接字被关闭），或 TLS 装配在服务阶段意外失败。
    pub async fn serve(self) -> DomainResult<()> {
        let addr = self.local_addr()?;
        let Self { listener, service, max_message_bytes, tls, traces, metrics } = self;
        info!(
            addr = %addr,
            transport = tls.mode.as_str(),
            "OTLP/gRPC 服务监听中（HTTP/2，接受 gzip）"
        );
        let incoming = incoming_stream(listener);
        let mut builder = Server::builder();
        if let Some(tls_config) = tls.config {
            builder = builder.tls_config(tls_config).map_err(|e| DomainError::DependencyUnavailable {
                dependency: "otlp-grpc".to_string(),
                cause: format!("TLS 服务端配置失败: {e}"),
            })?;
        }
        builder
            .add_service(
                LogsServiceServer::from_arc(service)
                    .accept_compressed(CompressionEncoding::Gzip)
                    .max_decoding_message_size(max_message_bytes),
            )
            .add_service(
                TraceServiceServer::new(super::signals::TraceService(traces))
                    .accept_compressed(CompressionEncoding::Gzip)
                    .max_decoding_message_size(max_message_bytes),
            )
            .add_service(
                MetricsServiceServer::new(super::signals::MetricsService(metrics))
                    .accept_compressed(CompressionEncoding::Gzip)
                    .max_decoding_message_size(max_message_bytes),
            )
            .serve_with_incoming(incoming)
            .await
            .map_err(|e| DomainError::DependencyUnavailable {
                dependency: "otlp-grpc".to_string(),
                cause: format!("gRPC 服务端退出: {e}"),
            })
    }
}

/// 解析 `IP:PORT` 形式的监听地址（纯函数，单测直接覆盖）。
///
/// # Errors
/// 地址不是合法的 `IP:PORT`。
pub fn parse_listen(listen: &str) -> DomainResult<SocketAddr> {
    listen
        .parse::<SocketAddr>()
        .map_err(|e| DomainError::Config(format!("{ENV_LISTEN}={listen:?} 不是合法的 IP:PORT: {e}")))
}

/// `TcpListener` → tonic 需要的连接流。
///
/// 手工用 `futures::stream::unfold` 构造（不引入 `tokio-stream` 的 `net` 特性：
/// workspace 只开了 `sync`）；accept 出错时只 `warn` + 短暂停顿后**继续**监听，
/// 绝不因为一次 `EMFILE` 就让整个 gRPC 端口静默消失。
fn incoming_stream(listener: TcpListener) -> impl futures::Stream<Item = std::io::Result<TcpStream>> {
    futures::stream::unfold(listener, |listener| async move {
        loop {
            match listener.accept().await {
                Ok((stream, _peer)) => return Some((Ok(stream), listener)),
                Err(e) => {
                    warn!(error = %e, "OTLP/gRPC accept 失败（继续监听）");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        }
    })
}
