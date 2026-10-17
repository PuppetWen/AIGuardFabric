//! 由 `main.rs` 拆分：`serve` 函数（纯搬移，逻辑不变）。
use super::*;
use agf_ingest::receiver::{WebhookReceiver, declare_wired, webhook_router};

/// 启动接入服务。
pub(crate) async fn serve() -> anyhow::Result<()> {
    // .env 可选：容器里由 compose 注入环境变量，本机开发时读文件
    let _ = dotenvy::dotenv();

    let filter = env_or("RUST_LOG", "info");
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(filter))
        .with_target(false)
        .try_init();

    // Validate identity before opening listeners or connecting to external sources.
    let source_identity = SourceIdentity::from_env()?;
    tracing::info!(tenant = %source_identity.tenant, instance = %source_identity.instance, "Native receiver identity configured");
    let host = env_or("AGF_INGEST_HOST", "0.0.0.0");
    let port = env_or("AGF_INGEST_PORT", "8090");
    let syslog_tcp = env_or("AGF_SYSLOG_TCP_PORT", "5514");
    let syslog_udp = env_or("AGF_SYSLOG_UDP_PORT", "5514");
    let syslog_tls = env_or("AGF_SYSLOG_TLS_PORT", "6514");
    let tls_cert_path = env_or("AGF_SYSLOG_TLS_CERT", "");
    let tls_key_path = env_or("AGF_SYSLOG_TLS_KEY", "");
    let tls_client_ca_path = env_or("AGF_SYSLOG_TLS_CLIENT_CA", "");
    let tcp_idle_secs: u64 = env_or("AGF_SYSLOG_TCP_IDLE_TIMEOUT_SECS", "60").parse().unwrap_or(60);
    let max_connections: usize = env_or("AGF_SYSLOG_MAX_CONNECTIONS", "128").parse().unwrap_or(128);
    let token = std::env::var("AGF_WEBHOOK_TOKEN").unwrap_or_default();

    let stats = Arc::new(Stats::default());
    // 接收器统一指标（收到 / 命中 / 解析失败 / 丢弃）：/metrics 与 /stats 都读它
    let metrics: SharedMetrics = Arc::new(MetricsRegistry::new());
    // 落库目标：默认内存 Sink（重启即丢）；`AGF_INGEST_SQL_SINK=1` 时走 PostgreSQL
    // （`raw_logs` + `events` 表），使"事件真的落库了"可以用 SQL 直接核对。
    let sink = build_sink().await?;
    if sink.queues_events() {
        if let Some(store) = sink.database() {
            tokio::spawn(crate::event_delivery::run_loop(store, source_identity.tenant));
        }
    }
    let bus = Arc::new(InMemoryEventBus::new(1024));
    let mut registry = ParserRegistry::with_builtins();
    // 厂商模板库：AGF_PARSERS_DIR 优先，容器内默认 /app/parsers，本机回退 <项目根>/parsers。
    // 加载失败**不让进程崩溃**：只 warn 并继续用内置模板（§4.5 "永远可启动"）。
    let root = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let parsers_dir = resolve_dir("AGF_PARSERS_DIR", "parsers", &root);
    match registry.load_dir(&parsers_dir) {
        Ok(loaded) => {
            let registry_stats = registry.stats();
            tracing::info!(
                dir = %parsers_dir.display(),
                loaded,
                builtin = registry_stats.builtin,
                invalid = registry_stats.invalid,
                total = registry.all().len(),
                "厂商解析模板库已加载（parsers/）"
            );
            if registry_stats.invalid > 0 {
                for bad in registry.invalid_templates() {
                    tracing::warn!(
                        origin = %bad.origin,
                        key = %bad.key,
                        reason = %bad.reason,
                        "解析模板被拒绝（该模板不进入匹配集，其余模板照常工作）"
                    );
                }
            }
        }
        Err(e) => tracing::warn!(
            dir = %parsers_dir.display(),
            error = %e,
            "模板库目录加载失败：仅使用内置模板，进程继续（可用 AGF_PARSERS_DIR 指定目录）"
        ),
    }
    let parser_count = registry.all().len();
    let source_control = sink
        .database()
        .map(|database| Arc::new(agf_ingest::pipeline::NativeSourceControl::new(Some(database), registry.clone())));
    let pipeline = IngestPipeline::new(
        registry,
        Arc::clone(&sink) as Arc<dyn Sink>,
        Arc::clone(&bus) as Arc<dyn EventBus>,
        IngestConfig::default(),
    );
    let pipeline = Arc::new(match source_control {
        Some(control) => pipeline.with_source_control(control),
        None => pipeline,
    });
    tracing::info!("接入流水线就绪：解析模板 {parser_count} 个；事件落库={} Sink", sink.backend());

    // 落库后端**如实登记**：`/readyz` 的 `sink`/`reason` 与 `/stats` 的 `sink` 都读它，
    // 因此"实际用的是内存 Sink 还是 PostgreSQL"在观测面上不可能写错。
    let mut listeners = ListenerState { sink: sink.backend().to_string(), ..ListenerState::default() };
    listeners.note(format!(
        "固定租户 {}；接收器实例 {}；日志源 ID 在重启后保持稳定",
        source_identity.tenant, source_identity.instance
    ));
    // TCP/TLS 并发连接上限：无上限时单个客户端可用连接数耗尽内存（老实现是"串行一次一条"，
    // 这里既换成并发又不放弃边界）。超出即拒绝并 warn + 计入 /metrics。
    let conn_slots = Arc::new(tokio::sync::Semaphore::new(max_connections.max(1)));

    // Syslog UDP
    let udp_addr = format!("{host}:{syslog_udp}");
    match SyslogUdpListener::bind(&udp_addr).await {
        Ok(listener) => {
            let pipeline = Arc::clone(&pipeline);
            let stats = Arc::clone(&stats);
            let source = ingest_source(&source_identity, IngestProtocol::Syslog, "syslog-udp");
            tokio::spawn(async move {
                loop {
                    match listener.recv_datagram(1_048_576, 1_000).await {
                        Ok((bytes, peer)) => {
                            let origin = peer.to_string();
                            stats.syslog_frames.fetch_add(1, Ordering::Relaxed);
                            match pipeline
                                .ingest_raw_from(
                                    &source,
                                    IngestProtocol::Syslog,
                                    &bytes,
                                    &origin,
                                    agf_ingest::pipeline::TransportPeer { ip: Some(peer.ip()), mutual_tls: false },
                                )
                                .await
                            {
                                Ok(outcome) => {
                                    if !outcome.matched {
                                        stats.parse_failures.fetch_add(1, Ordering::Relaxed);
                                    }
                                }
                                Err(e) => {
                                    tracing::warn!(error = %e, "UDP 报文接入失败（已丢弃并计数）");
                                }
                            }
                        }
                        Err(e) => {
                            // 接收超时是正常路径（用于让出调度），只在其它错误时告警
                            let text = e.to_string();
                            if !text.contains("超时") && !text.contains("timeout") {
                                tracing::warn!(error = %e, "syslog UDP 接收异常");
                            }
                        }
                    }
                }
            });
            tracing::info!("Syslog UDP 监听 {udp_addr}");
            listeners.syslog_udp = Some(udp_addr);
        }
        Err(e) => {
            tracing::warn!(
                addr = %udp_addr,
                error = %e,
                "Syslog UDP 绑定失败（该协议不可用，其余能力不受影响）"
            );
            listeners.note(format!("Syslog UDP 未启用：绑定 {udp_addr} 失败（{e}）"));
        }
    }

    // Syslog TCP：**连接生命周期内持续收帧**。
    //
    // 老实现 `accept_frames(1_048_576, 64)` 把"每次调用最多 64 帧"当成了"每连接最多 64 帧"，
    // 第 65 帧起随连接一起静默丢弃（不报错、不计 parse_failures）。现在：
    // 每条连接一个任务，循环 `read_batch()` 直到 EOF / 空闲超时 / 分帧失步；
    // 丢弃一律计入 `agf_ingest_syslog_frames_dropped_total` 并 warn。
    let tcp_addr = format!("{host}:{syslog_tcp}");
    match SyslogTcpListener::bind(&tcp_addr).await {
        Ok(listener) => {
            let pipeline = Arc::clone(&pipeline);
            let stats = Arc::clone(&stats);
            let slots = Arc::clone(&conn_slots);
            let source = ingest_source(&source_identity, IngestProtocol::Syslog, "syslog-tcp");
            let idle = std::time::Duration::from_secs(tcp_idle_secs.max(1));
            tokio::spawn(async move {
                loop {
                    let accepted = listener.accept_connection(1_048_576, 64, idle).await;
                    let (conn, peer) = match accepted {
                        Ok(pair) => pair,
                        Err(e) => {
                            tracing::warn!(error = %e, "syslog TCP 接收异常");
                            continue;
                        }
                    };
                    let Ok(permit) = Arc::clone(&slots).try_acquire_owned() else {
                        stats.syslog_connections_rejected.fetch_add(1, Ordering::Relaxed);
                        tracing::warn!(%peer, "syslog TCP 并发连接已达上限，拒绝该连接（见 AGF_SYSLOG_MAX_CONNECTIONS）");
                        continue;
                    };
                    let pipeline = Arc::clone(&pipeline);
                    let stats = Arc::clone(&stats);
                    let source = source.clone();
                    tokio::spawn(async move {
                        let _permit = permit;
                        drain_connection(conn, pipeline, stats, source).await;
                    });
                }
            });
            tracing::info!("Syslog TCP 监听 {tcp_addr}（连接生命周期内持续收帧，空闲超时 {tcp_idle_secs}s）");
            listeners.syslog_tcp = Some(tcp_addr);
        }
        Err(e) => {
            tracing::warn!(addr = %tcp_addr, error = %e, "Syslog TCP 绑定失败（该协议不可用）");
            listeners.note(format!("Syslog TCP 未启用：绑定 {tcp_addr} 失败（{e}）"));
        }
    }

    // Syslog TLS（RFC5425）：证书/密钥缺失或非法时**只 warn 不启用**，绝不让进程起不来。
    if syslog_tls == "0" {
        tracing::info!("AGF_SYSLOG_TLS_PORT=0：Syslog TLS（RFC5425）按配置关闭");
        listeners.note("Syslog TLS 按配置关闭（AGF_SYSLOG_TLS_PORT=0）".to_string());
    } else if tls_cert_path.is_empty() || tls_key_path.is_empty() {
        tracing::warn!(
            "未配置 AGF_SYSLOG_TLS_CERT / AGF_SYSLOG_TLS_KEY：Syslog TLS（RFC5425）不启用（其余能力不受影响）"
        );
        listeners.note("Syslog TLS 未启用：未配置 AGF_SYSLOG_TLS_CERT / AGF_SYSLOG_TLS_KEY".to_string());
    } else {
        match (std::fs::read(&tls_cert_path), std::fs::read(&tls_key_path)) {
            (Ok(cert_pem), Ok(key_pem)) => {
                let tls_addr = format!("{host}:{syslog_tls}");
                let configured = async {
                    let client_ca = if tls_client_ca_path.is_empty() {
                        None
                    } else {
                        Some(std::fs::read(&tls_client_ca_path).map_err(|error| {
                            agf_core::error::DomainError::Config(format!("Cannot read Syslog client CA: {error}"))
                        })?)
                    };
                    SyslogTlsListener::bind_with_client_ca(&tls_addr, &cert_pem, &key_pem, client_ca.as_deref()).await
                }
                .await;
                match configured {
                    Ok(listener) => {
                        let pipeline = Arc::clone(&pipeline);
                        let stats = Arc::clone(&stats);
                        let slots = Arc::clone(&conn_slots);
                        let source = ingest_source(&source_identity, IngestProtocol::Syslog, "syslog-tls");
                        let idle = std::time::Duration::from_secs(tcp_idle_secs.max(1));
                        tokio::spawn(async move {
                            loop {
                                let handshake = match listener.accept_handshake().await {
                                    Ok(handshake) => handshake,
                                    // 握手失败只影响该连接（扫描器/错误客户端属常态），不退出监听循环
                                    Err(e) => {
                                        tracing::warn!(error = %e, "syslog TLS 连接异常（握手失败不影响监听）");
                                        continue;
                                    }
                                };
                                let Ok(permit) = Arc::clone(&slots).try_acquire_owned() else {
                                    stats.syslog_connections_rejected.fetch_add(1, Ordering::Relaxed);
                                    tracing::warn!("syslog TLS 并发连接已达上限，拒绝该连接");
                                    continue;
                                };
                                let pipeline = Arc::clone(&pipeline);
                                let stats = Arc::clone(&stats);
                                let source = source.clone();
                                tokio::spawn(async move {
                                    let _permit = permit;
                                    match handshake.complete(1_048_576, 64, idle).await {
                                        Ok((conn, _)) => drain_connection(conn, pipeline, stats, source).await,
                                        Err(error) => tracing::warn!(%error, "Syslog TLS handshake rejected"),
                                    }
                                });
                            }
                        });
                        tracing::info!("Syslog TLS（RFC5425）监听 {tls_addr}（证书 {tls_cert_path}）");
                        listeners.syslog_tls = Some(tls_addr);
                    }
                    Err(e) => {
                        tracing::warn!(
                            cert = %tls_cert_path,
                            error = %e,
                            "Syslog TLS 启用失败（证书/密钥非法或端口占用）：该协议不可用，其余能力不受影响"
                        );
                        listeners.note(format!("Syslog TLS 未启用：{e}"));
                    }
                }
            }
            (cert, key) => {
                let detail = match (cert, key) {
                    (Err(e), _) => format!("读取证书 {tls_cert_path} 失败：{e}"),
                    (_, Err(e)) => format!("读取私钥 {tls_key_path} 失败：{e}"),
                    _ => "证书/密钥读取失败".to_string(),
                };
                tracing::warn!(error = %detail, "Syslog TLS 启用失败：该协议不可用，其余能力不受影响");
                listeners.note(format!("Syslog TLS 未启用：{detail}"));
            }
        }
    }

    // 新增协议接收器（OTLP/对象存储/JDBC/MQTT/SNMP/Kafka/Pulsar-KoP）：未配置 = 不启用，
    // 配置错误或连接失败 = 只 warn（进程照常启动，其余接收器不受影响）。
    // Kafka/KoP 的停机信号在这里先建好：SIGINT/SIGTERM 时用它让接收器**先刷新游标再退出**。
    let kafka_shutdown = KafkaShutdown::new();
    let extra = spawn_extra_receivers(&pipeline, &metrics, &mut listeners, &kafka_shutdown, &source_identity).await;
    let ExtraReceivers { otlp: otlp_receiver, otlp_traces, otlp_metrics, kafka_series, kafka_tasks } = extra;
    let kafka_series = Arc::new(kafka_series);

    // HTTP：webhook 接入 + 健康检查 + 指标
    let webhook_source = ingest_source(&source_identity, IngestProtocol::Webhook, "webhook");
    let mut receiver = WebhookReceiver::new(Arc::clone(&pipeline), webhook_source, "/ingest/webhook");
    if token.is_empty() {
        tracing::warn!("未配置 AGF_WEBHOOK_TOKEN：Webhook 不校验鉴权（仅限内网或前置网关已鉴权）");
    } else {
        receiver = receiver.with_token(token);
        tracing::info!("Webhook Bearer 鉴权已启用");
    }

    let addr = format!("{host}:{port}");
    listeners.http = Some(addr.clone());
    let metrics_stats = Arc::clone(&stats);
    let metrics_registry = Arc::clone(&metrics);
    let stats_metrics = Arc::clone(&metrics);
    let stats_pipeline = Arc::clone(&pipeline);
    let stats_listeners = Arc::new(listeners);
    let readyz_listeners = Arc::clone(&stats_listeners);
    // Kafka/KoP 的分区指标（offset/lag/失败/重连）与四族计数器一起暴露
    let metrics_kafka = Arc::clone(&kafka_series);
    let stats_kafka = Arc::clone(&kafka_series);
    // webhook 通道的解析命中统计：webhook 不进 syslog 计数，必须单独暴露
    // （否则"webhook 解析命中率"在任何指标上都不可观测）。
    let webhook = Arc::new(receiver);
    let metrics_webhook = Arc::clone(&webhook);
    let mut app: Router = webhook_router(webhook)
        .merge(Router::new().route("/healthz", get(healthz)).route(
            "/readyz",
            get(move || {
                let listeners = Arc::clone(&readyz_listeners);
                async move { readyz(listeners).await }
            }),
        ))
        .route(
            "/metrics",
            get(move || {
                let stats = Arc::clone(&metrics_stats);
                let webhook = Arc::clone(&metrics_webhook);
                let registry = Arc::clone(&metrics_registry);
                let kafka = Arc::clone(&metrics_kafka);
                async move { metrics_text(&stats, webhook.counters(), &registry, &kafka) }
            }),
        )
        .route(
            "/stats",
            get(move || {
                let pipeline = Arc::clone(&stats_pipeline);
                let registry = Arc::clone(&stats_metrics);
                let listeners = Arc::clone(&stats_listeners);
                let kafka = Arc::clone(&stats_kafka);
                async move { stats_json(pipeline, registry, listeners, kafka).await }
            }),
        )
        .layer(tower_http::trace::TraceLayer::new_for_http());
    // OTLP/HTTP **三信号**端点与 webhook 同端口暴露（专用端口见 AGF_OTLP_HTTP_LISTEN）。
    //
    // **唯一装配点**：走 `otlp::signal_router`，因此"路由构造函数存在"与"路由真的挂上"
    // 是同一件事；挂上之后立刻 `declare_wired`，能力矩阵才把 otlp-traces/otlp-metrics
    // 报成 `ready`（未挂上是 `not-wired`）。
    let (otlp_app, mounted_otlp) = signal_router(otlp_receiver, otlp_traces, otlp_metrics);
    for module in &mounted_otlp {
        declare_wired(module, true);
    }
    app = app.merge(otlp_app);
    tracing::info!(mounted = ?mounted_otlp, "OTLP/HTTP 三信号路由已挂载到主 HTTP 端口");

    let listener = TcpListener::bind(&addr).await.with_context(|| format!("HTTP 监听 {addr} 失败"))?;
    tracing::info!("HTTP 接入监听 http://{addr}/ingest/webhook（/v1/logs、healthz/readyz/metrics/stats 同端口）");

    axum::serve(listener, app.into_make_service_with_connect_info::<std::net::SocketAddr>())
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("HTTP 服务异常退出")?;

    // 停机顺序：先广播停机信号（Kafka/KoP 接收器**立即跳出等待并刷新游标落盘**），
    // 再等消费任务结束（有超时上限：绝不让退出路径挂住）。
    kafka_shutdown.trigger();
    if !kafka_tasks.is_empty() {
        tracing::info!(tasks = kafka_tasks.len(), "已广播停机信号：等待 Kafka/KoP 接收器刷新游标…");
    }
    let mut joined = 0_usize;
    for (index, task) in kafka_tasks.into_iter().enumerate() {
        match tokio::time::timeout(std::time::Duration::from_secs(5), task).await {
            Ok(Ok(())) => joined += 1,
            Ok(Err(e)) => tracing::warn!(task = index, error = %e, "Kafka/KoP 消费任务异常结束"),
            Err(_) => tracing::warn!(task = index, "Kafka/KoP 消费任务 5s 内未退出（游标仍为最后一批成功位置，不丢）"),
        }
    }
    if joined > 0 {
        tracing::info!(joined, "Kafka/KoP 消费任务已退出（游标已刷新）");
    }

    tracing::info!(
        "已优雅退出：syslog 帧 {}、解析失败 {}、分帧丢弃 {}、拒绝连接 {}；接收器计数 {:?}",
        stats.syslog_frames.load(Ordering::Relaxed),
        stats.parse_failures.load(Ordering::Relaxed),
        stats.syslog_frames_dropped.load(Ordering::Relaxed),
        stats.syslog_connections_rejected.load(Ordering::Relaxed),
        metrics.snapshot()
    );
    Ok(())
}
