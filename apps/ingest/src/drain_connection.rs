//! 由 `main.rs` 拆分：`drain_connection` 等 6 个函数（纯搬移，逻辑不变）。
use super::*;
use agf_ingest::receiver::wiring_snapshot;

/// 在**一条连接的生命周期内**持续收帧：循环 `read_batch()` 直到 EOF、空闲超时或分帧失步。
///
/// 这里刻意不设"每连接帧数上限"——历史缺陷正是把单次调用上限当成了每连接上限，
/// 导致第 65 帧起静默丢弃（`tools/simulators/README.md` 第 7 节第 6 条）。
/// 丢弃（畸形帧 / 超长帧 / 关闭时的半帧）一律计数并告警，绝不静默。
pub(crate) async fn drain_connection<S>(
    mut conn: agf_ingest::syslog::SyslogConnection<S>,
    pipeline: Arc<IngestPipeline>,
    stats: Arc<Stats>,
    source: LogSource,
) where
    S: tokio::io::AsyncRead + Unpin + Send,
{
    let origin = conn.peer().to_string();
    let peer = conn.transport_peer();
    let mut frames_total = 0_u64;
    loop {
        let batch = match conn.read_batch().await {
            Ok(batch) => batch,
            Err(e) => {
                tracing::warn!(peer = %origin, error = %e, "syslog 连接读取失败，断开该连接");
                break;
            }
        };
        for frame in batch.frames {
            frames_total += 1;
            stats.syslog_frames.fetch_add(1, Ordering::Relaxed);
            match pipeline.ingest_raw_from(&source, IngestProtocol::Syslog, &frame, &origin, peer).await {
                Ok(outcome) => {
                    // 与 UDP 通道同一口径：未命中模板计入 parse_failures（否则该通道不可观测）
                    if !outcome.matched {
                        stats.parse_failures.fetch_add(1, Ordering::Relaxed);
                    }
                }
                Err(e) => tracing::warn!(error = %e, "syslog 帧接入失败（已丢弃并告警）"),
            }
        }
        if batch.dropped > 0 {
            stats.syslog_frames_dropped.fetch_add(u64::try_from(batch.dropped).unwrap_or(u64::MAX), Ordering::Relaxed);
            tracing::warn!(
                peer = %origin,
                dropped = batch.dropped,
                frames_received = frames_total,
                "syslog 分帧丢弃（已计入 agf_ingest_syslog_frames_dropped_total），断开该连接"
            );
            break;
        }
        if batch.eof {
            break;
        }
        if batch.idle_timeout {
            tracing::debug!(peer = %origin, frames = frames_total, "syslog 连接空闲超时，关闭该连接");
            break;
        }
    }
}

/// 健康检查（存活）：不查外部依赖。
pub(crate) async fn healthz() -> impl IntoResponse {
    axum::Json(serde_json::json!({
        "status": "ok",
        "service": "agf-ingest",
        "version": agf_ingest::VERSION,
        "check": "liveness",
    }))
}

/// 就绪检查：列出可用的接入能力（未实现协议如实标注）+ **本进程真实监听状态**。
///
/// 能力矩阵是**四态**：`ready`（已实现 + 已装配）/ `not-wired`（已实现但本进程未装配）/
/// `not-implemented`（代码层面就没有）/ `mock`。`wiring` 给出装配登记表的原始快照，
/// 供"矩阵状态与实际装配是否一致"对账（防"ready 但路由没挂"）。
pub(crate) async fn readyz(listeners: Arc<ListenerState>) -> impl IntoResponse {
    let matrix = agf_ingest::receiver::receiver_capability_matrix();
    let count = |status: agf_ingest::receiver::ReceiverStatus| matrix.iter().filter(|d| d.status == status).count();
    let ready = count(agf_ingest::receiver::ReceiverStatus::Ready);
    let not_wired = matrix
        .iter()
        .filter(|d| d.status == agf_ingest::receiver::ReceiverStatus::NotWired)
        .map(|d| d.name.clone())
        .collect::<Vec<_>>();
    let sink_backend = listeners.sink.clone();
    let sink_text = if sink_backend == "sql" {
        "PostgreSQL（raw_logs 保真层 + events 归一化层，租户 RLS 事务）"
    } else {
        "内存 Sink（TODO(ingest-sql-sink)：进程重启即丢）"
    };
    axum::Json(serde_json::json!({
        "status": "ready",
        // `degraded` 保守取真（未配置/未启用的接收器在 `notes` 里逐条列出）；
        // 但 `reason`/`sink` 必须**反映实际落库后端**，不许硬编码"内存 Sink"。
        "degraded": true,
        "sink": sink_backend,
        "reason": format!(
            "事件落库为 {sink_text}；事件总线只有核心协议 publish，**不是** JetStream（PV-013）——\
             注意这与**入向** JetStream 订阅（`AGF_INGEST_JETSTREAM_URL`）是两件事"
        ),
        "receivers_total": matrix.len(),
        "receivers_ready": ready,
        // **已实现但本进程未装配**的模块名（这一格是本轮新增的第四态；为空才算全装配）
        "receivers_not_wired": not_wired,
        "receivers_not_implemented": count(agf_ingest::receiver::ReceiverStatus::NotImplemented),
        // 装配登记表原始快照：装配点报到什么，这里就是什么（能力矩阵按它折算状态）
        "wiring": wiring_snapshot(),
        // 能力矩阵是"代码支持什么 + 本进程装配了什么"，listeners 是"本进程真的起了什么"——两者都如实给出。
        "listeners": {
            "http": listeners.http,
            "syslog-udp": listeners.syslog_udp,
            "syslog-tcp": listeners.syslog_tcp,
            "syslog-tls": listeners.syslog_tls,
            "otlp-http": listeners.otlp_http,
            "otlp-grpc": listeners.otlp_grpc,
            "nats-jetstream": listeners.nats_jetstream,
            "snmp-trap": listeners.snmp_trap,
        },
        "notes": listeners.note_snapshot(),
        "capabilities": matrix
            .iter()
            .map(|d| {
                serde_json::json!({
                    "name": d.name,
                    "protocol": d.protocol.as_str(),
                    "status": d.status.as_str(),
                    "note": d.note,
                    "todo": d.todo,
                    "mock_replay": d.mock_replay,
                })
            })
            .collect::<Vec<_>>(),
    }))
}

/// 运行态统计（`/stats`）：流水线统计 + **每个接收器的四类计数** + 监听器状态
/// + **Kafka/KoP 每个分区的 offset/lag/失败状态**。
///
/// 端到端验证与运维排障都靠它——`/metrics` 是给 Prometheus 的，`/stats` 是给人/给测试的。
pub(crate) async fn stats_json(
    pipeline: Arc<IngestPipeline>,
    metrics: SharedMetrics,
    listeners: Arc<ListenerState>,
    kafka: Arc<Vec<KafkaSeries>>,
) -> impl IntoResponse {
    axum::Json(serde_json::json!({
        "pipeline": pipeline.stats(),
        // **实际落库后端**（`memory` / `sql`）：与 `/readyz` 的 `sink` 同源（`build_sink` 的注释
        // 早就声称 `/stats` 有这一格，但此前代码里根本没有 ⇒ 本轮补上，口径变成可核对的事实）
        "sink": listeners.sink.clone(),
        "receivers": metrics.snapshot(),
        "listeners": {
            "http": listeners.http,
            "syslog-udp": listeners.syslog_udp,
            "syslog-tcp": listeners.syslog_tcp,
            "syslog-tls": listeners.syslog_tls,
            "otlp-http": listeners.otlp_http,
            "otlp-grpc": listeners.otlp_grpc,
            "nats-jetstream": listeners.nats_jetstream,
            "snmp-trap": listeners.snmp_trap,
        },
        // 装配登记表：`/stats` 与 `/readyz` 同源，避免两处口径漂移
        "wiring": wiring_snapshot(),
        // 逐分区状态：offset（本地游标）/ lag（高水位−游标）/ 累计条数 / 连续失败次数 / 最近失败原因
        "kafka_partitions": kafka
            .iter()
            .map(|series| serde_json::json!({
                "receiver": series.receiver,
                "topic": series.topic,
                "partitions": series.stats.snapshot(),
                "lag_total": series.stats.lag_total(),
                "records_consumed_total": series.stats.records_consumed_total(),
                "deduped_total": series.stats.deduped_total(),
                "skipped_total": series.stats.skipped_total(),
                "reconnects_total": series.stats.reconnects_total(),
                "reconnect_backoff_seconds": series.stats.reconnect_backoff().as_secs_f64(),
            }))
            .collect::<Vec<_>>(),
        "notes": listeners.note_snapshot(),
    }))
}

/// Prometheus 文本指标。
pub(crate) fn metrics_text(
    stats: &Stats,
    webhook: &agf_ingest::receiver::WebhookCounters,
    metrics: &MetricsRegistry,
    kafka: &[KafkaSeries],
) -> (StatusCode, [(String, String); 1], String) {
    let frames = stats.syslog_frames.load(Ordering::Relaxed);
    let failures = stats.parse_failures.load(Ordering::Relaxed);
    let dropped = stats.syslog_frames_dropped.load(Ordering::Relaxed);
    let rejected = stats.syslog_connections_rejected.load(Ordering::Relaxed);
    let webhook_matched = webhook.matched();
    let webhook_unmatched = webhook.unmatched();
    let body = format!(
        "# HELP agf_ingest_syslog_frames_total 已接收的 syslog 帧数\n\
         # TYPE agf_ingest_syslog_frames_total counter\n\
         agf_ingest_syslog_frames_total {frames}\n\
         # HELP agf_ingest_parse_failures_total 未命中任何模板的报文数（syslog 通道）\n\
         # TYPE agf_ingest_parse_failures_total counter\n\
         agf_ingest_parse_failures_total {failures}\n\
         # HELP agf_ingest_syslog_frames_dropped_total 分帧层丢弃的 syslog 帧数（畸形/超长/关闭时半帧）\n\
         # TYPE agf_ingest_syslog_frames_dropped_total counter\n\
         agf_ingest_syslog_frames_dropped_total {dropped}\n\
         # HELP agf_ingest_syslog_connections_rejected_total 因并发连接上限被拒绝的连接数\n\
         # TYPE agf_ingest_syslog_connections_rejected_total counter\n\
         agf_ingest_syslog_connections_rejected_total {rejected}\n\
         # HELP agf_ingest_webhook_matched_total webhook 通道命中模板的条数\n\
         # TYPE agf_ingest_webhook_matched_total counter\n\
         agf_ingest_webhook_matched_total {webhook_matched}\n\
         # HELP agf_ingest_webhook_unmatched_total webhook 通道未命中任何模板的条数\n\
         # TYPE agf_ingest_webhook_unmatched_total counter\n\
         agf_ingest_webhook_unmatched_total {webhook_unmatched}\n"
    );
    // 每个协议接收器的四类计数（收到/命中/解析失败/丢弃）由统一登记表渲染
    let receivers = metrics.prometheus();
    // Kafka/KoP 分区级指标：offset / lag / 拉取失败 / 重连 / 去重 / 跳过
    let partitions = kafka_prometheus(kafka);
    // === MQTT 链路指标：错误按 TLS/鉴权/网络/协议/其他 分类 + 退避重连次数 ===
    let mqtt_link = agf_ingest::mqtt::link_prometheus();
    // === 三族协议专属计数器（与 `mqtt_link` 同一套路：模块提供进程级渲染入口）===
    // 1) SQL（"JDBC"）拉取：拉取条数 / 丢弃 / 轮次 / 失败 / 游标推进
    let jdbc = agf_ingest::jdbc::pull_prometheus();
    // 2) SNMP v3 USM：6 类认证失败（usmStats）+ 认证通过 / 免认证通过 / Report 收到
    let snmp_usm = agf_ingest::snmp::usm_prometheus();
    // 3) 冷归档：对象数 / 字节数 / 事件数 / 回落次数 / Parquet 对象数
    let coldarchive = agf_ingest::coldarchive::archive_metrics().prometheus();
    // 三族都**无条件**拼接：未配置对应接收器时以全零序列出现（不是"有数据才出现"）。
    (
        StatusCode::OK,
        [("content-type".to_string(), "text/plain; version=0.0.4".to_string())],
        format!("{body}{receivers}{partitions}{mqtt_link}{jdbc}{snmp_usm}{coldarchive}"),
    )
}

/// Ctrl-C / SIGTERM 优雅关闭。
pub(crate) async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(e) = tokio::signal::ctrl_c().await {
            tracing::warn!(error = %e, "无法监听 Ctrl-C");
        }
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(e) => tracing::warn!(error = %e, "无法监听 SIGTERM"),
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
    tracing::info!("收到关闭信号，等待在途请求结束…");
}
