//! OTLP 装配段（由 `spawn_extra_receivers.rs` 按块拆分，纯搬移、逻辑不变）。
//!
//! 覆盖两条传输：OTLP/HTTP 三信号（logs + traces + metrics）与 OTLP/gRPC(4317)。
use super::*;

impl ExtraReceiverCtx<'_> {
    /// ---- OTLP/HTTP 三信号（logs + traces + metrics）----
    ///
    /// 三信号共用同一份 proto/JSON/gzip/上限保护，**路由由 `otlp::signal_router` 一次性挂载**：
    /// 装配完成后立刻 `declare_wired` 登记，能力矩阵才允许把 `otlp-traces`/`otlp-metrics`
    /// 报成 `ready`（未登记时是 `not-wired`，绝不出现"ready 但 /v1/traces 返回 404"）。
    pub(super) async fn otlp_http(
        &mut self,
    ) -> (Option<Arc<OtlpLogsReceiver>>, Option<Arc<OtlpTracesReceiver>>, Option<Arc<OtlpMetricsReceiver>>) {
        let source_identity = self.identity.clone();
        let pipeline = self.pipeline;
        let metrics = self.metrics;
        let listeners = &mut *self.listeners;
        let (otlp, otlp_traces, otlp_metrics) = if env_or("AGF_INGEST_OTLP_ENABLED", "1") == "0" {
            listeners.note("OTLP 按配置关闭（AGF_INGEST_OTLP_ENABLED=0）".to_string());
            (None, None, None)
        } else {
            let logs_source = ingest_source(&source_identity, IngestProtocol::Otlp, "otlp");
            let traces_source = ingest_source(&source_identity, IngestProtocol::Otlp, "otlp-traces");
            let metrics_source = ingest_source(&source_identity, IngestProtocol::Otlp, "otlp-metrics");
            // 单请求上限（三信号共用）：超出部分按 `partialSuccess.rejected*` **如实**回填
            let max_records = env_num("AGF_INGEST_OTLP_MAX_RECORDS", 10_000_usize).max(1);
            let logs = Arc::new(
                OtlpLogsReceiver::new(Arc::clone(pipeline), logs_source)
                    .with_max_records(max_records)
                    .with_counters(metrics.counters("otlp")),
            );
            let traces = Arc::new(
                OtlpTracesReceiver::new(Arc::clone(pipeline), traces_source)
                    .with_max_records(max_records)
                    .with_counters(metrics.counters("otlp-traces")),
            );
            let api_metrics = Arc::new(
                OtlpMetricsReceiver::new(Arc::clone(pipeline), metrics_source)
                    .with_max_records(max_records)
                    .with_counters(metrics.counters("otlp-metrics")),
            );
            tracing::info!(
                max_records,
                "OTLP/HTTP 三信号端点就绪：POST /v1/logs + /v1/traces + /v1/metrics\
                 （JSON + Protobuf，支持 gzip）"
            );
            (Some(logs), Some(traces), Some(api_metrics))
        };

        // OTLP 专用监听（可选）：多数 exporter 默认发往 4318；三信号都挂，否则 traces/metrics 会 404
        if otlp.is_some() || otlp_traces.is_some() || otlp_metrics.is_some() {
            let listen = env_or("AGF_OTLP_HTTP_LISTEN", "");
            if !listen.is_empty() {
                match tokio::net::TcpListener::bind(&listen).await {
                    Ok(listener) => {
                        let (app, mounted) = signal_router(
                            otlp.as_ref().map(Arc::clone),
                            otlp_traces.as_ref().map(Arc::clone),
                            otlp_metrics.as_ref().map(Arc::clone),
                        );
                        tokio::spawn(async move {
                            if let Err(e) = axum::serve(listener, app).await {
                                tracing::warn!(error = %e, "OTLP 专用监听异常退出（主 HTTP 端口的 /v1/* 仍可用）");
                            }
                        });
                        tracing::info!("OTLP/HTTP 专用监听 {listen}（挂载 {mounted:?}）");
                        listeners.otlp_http = Some(listen);
                    }
                    Err(e) => {
                        tracing::warn!(addr = %listen, error = %e, "OTLP 专用监听绑定失败（主 HTTP 端口的 /v1/* 仍可用）");
                        listeners.note(format!("OTLP 专用监听 {listen} 未启用：绑定失败（{e}）"));
                    }
                }
            }
        }

        (otlp, otlp_traces, otlp_metrics)
    }

    /// === OTLP/gRPC(4317)：官方 LogsService/Export 服务端（独立块）===
    ///
    /// 复用既有 OTLP 接收器：gRPC 请求先按 OTLP/JSON 序列化，再走 `OtlpLogsReceiver::ingest_logs`
    /// （同一份字段映射 + 同一条 pipeline），只有传输层不同——计数按 `receiver="otlp-grpc"`
    /// 单独统计，便于区分"哪个入口在收数"。
    /// 绑定失败 / 地址非法一律只 warn + 写进 `/readyz` 的 notes，绝不影响进程启动。
    pub(super) async fn otlp_grpc(&mut self) {
        let source_identity = self.identity.clone();
        let pipeline = self.pipeline;
        let metrics = self.metrics;
        let listeners = &mut *self.listeners;
        {
            use agf_ingest::otlp_grpc::{OtlpGrpcConfig, OtlpGrpcServer};

            let config = OtlpGrpcConfig::from_env();
            if !config.enabled {
                listeners.note("OTLP/gRPC 按配置关闭（AGF_INGEST_OTLP_GRPC_ENABLED=0）".to_string());
            } else {
                let grpc_source = ingest_source(&source_identity, IngestProtocol::Otlp, "otlp-grpc");
                let grpc_receiver = Arc::new(
                    OtlpLogsReceiver::new(Arc::clone(pipeline), grpc_source)
                        .with_max_records(config.max_records)
                        .with_counters(metrics.counters("otlp-grpc")),
                );
                match OtlpGrpcServer::bind(&config.listen, &config, grpc_receiver).await {
                    Ok(server) => {
                        let traces = Arc::new(
                            OtlpTracesReceiver::new(
                                Arc::clone(pipeline),
                                ingest_source(&source_identity, IngestProtocol::Otlp, "otlp-grpc-traces"),
                            )
                            .with_max_records(config.max_records)
                            .with_counters(metrics.counters("otlp-grpc-traces")),
                        );
                        let api_metrics = Arc::new(
                            OtlpMetricsReceiver::new(
                                Arc::clone(pipeline),
                                ingest_source(&source_identity, IngestProtocol::Otlp, "otlp-grpc-metrics"),
                            )
                            .with_max_records(config.max_records)
                            .with_counters(metrics.counters("otlp-grpc-metrics")),
                        );
                        let server = server.with_signals(traces, api_metrics);
                        for receiver in ["otlp-grpc", "otlp-grpc-traces", "otlp-grpc-metrics"] {
                            declare_wired(receiver, true);
                        }
                        let bound = match server.local_addr() {
                            Ok(addr) => addr.to_string(),
                            Err(e) => {
                                tracing::warn!(error = %e, "OTLP/gRPC 监听地址读取失败（按配置回退展示）");
                                config.listen.clone()
                            }
                        };
                        let notes = Arc::clone(&listeners.notes);
                        tokio::spawn(async move {
                            let result = server.serve().await;
                            for receiver in ["otlp-grpc", "otlp-grpc-traces", "otlp-grpc-metrics"] {
                                declare_wired(receiver, false);
                            }
                            if let Err(e) = result {
                                tracing::warn!(error = %e, "OTLP/gRPC 服务退出（其它接收器不受影响）");
                                push_note(&notes, format!("OTLP/gRPC 服务退出：{e}"));
                            }
                        });
                        tracing::info!(
                            "OTLP/gRPC 三信号服务就绪：{bound}（Logs/Trace/MetricsService，HTTP/2，接受 gzip）"
                        );
                        listeners.otlp_grpc = Some(bound.clone());
                        listeners.note(format!("OTLP/gRPC 已监听 {bound}（{}）", config.describe()));
                    }
                    Err(e) => {
                        tracing::warn!(listen = %config.listen, error = %e, "OTLP/gRPC 未启用（绑定失败，其余能力不受影响）");
                        listeners.note(format!("OTLP/gRPC 未启用：{e}"));
                    }
                }
            }
        }
    }
}
