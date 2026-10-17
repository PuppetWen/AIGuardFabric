//! 流式订阅接收器装配段（由 `spawn_extra_receivers.rs` 按块拆分，纯搬移、逻辑不变）。
//!
//! 覆盖 Kafka、Pulsar（**经 KoP 复用 Kafka 接收器**）与 NATS JetStream 入向订阅。
use super::*;

impl ExtraReceiverCtx<'_> {
    /// ---- Kafka ----
    pub(super) async fn kafka(&mut self) {
        let source_identity = self.identity.clone();
        let pipeline = self.pipeline;
        let metrics = self.metrics;
        let shutdown = self.shutdown;
        let listeners = &mut *self.listeners;
        let kafka_series = &mut self.kafka_series;
        let kafka_tasks = &mut self.kafka_tasks;
        let kafka_brokers = env_or("AGF_INGEST_KAFKA_BROKERS", "");
        let kafka_topic = env_or("AGF_INGEST_KAFKA_TOPIC", "");
        if kafka_brokers.is_empty() || kafka_topic.is_empty() {
            listeners.note("Kafka 未启用：需同时配置 AGF_INGEST_KAFKA_BROKERS 与 AGF_INGEST_KAFKA_TOPIC".to_string());
        } else {
            match parse_brokers(&kafka_brokers) {
                Ok(brokers) => {
                    let mut config = KafkaPullConfig {
                        brokers,
                        topic: kafka_topic.clone(),
                        consumer_id: env_or("AGF_INGEST_KAFKA_GROUP_ID", "agf-ingest"),
                        sasl: kafka_sasl_from_env(),
                        tls: kafka_tls_from_env(),
                        ..KafkaPullConfig::default()
                    };
                    apply_kafka_tuning(&mut config, "AGF_INGEST_KAFKA", "data/ingest/kafka-cursor.json");
                    let start_from = config.start_from;
                    let security = agf_ingest::kafka::KafkaSecurity::from_config(&config);
                    let counters = metrics.counters("kafka");
                    let stats = Arc::new(KafkaStats::new());
                    let shutdown_rx = shutdown.handle();
                    let pipeline = Arc::clone(pipeline);
                    let notes = Arc::clone(&listeners.notes);
                    tracing::info!(
                        topic = %kafka_topic,
                        start_from = start_from.as_str(),
                        security = %security.describe(),
                        group_id = %std::env::var("AGF_INGEST_KAFKA_GROUP_ID").unwrap_or_default(),
                        cursor = %config.cursor_path.as_deref().map_or_else(|| "-".to_string(), |p| p.display().to_string()),
                        "Kafka 消费接收器已配置（纯 Rust 客户端；配了 GROUP_ID 走消费者组协议，否则走本地游标；连接在后台建立）"
                    );
                    let series = KafkaSeries {
                        receiver: "kafka".to_string(),
                        topic: kafka_topic.clone(),
                        stats: Arc::clone(&stats),
                    };
                    // 连接必须在后台：broker 不可达时 rskafka 会**一直退避重试**，
                    // 若放在启动路径上会让 HTTP 端口永远起不来（实测踩过，见答复的降级验证）。
                    kafka_tasks.push(tokio::spawn(async move {
                        // **配了 AGF_INGEST_KAFKA_GROUP_ID 走消费者组协议；未配置走本地游标**
                        // （唯一的判定点：`agf_ingest::kafka::connect_kafka_source`）
                        let connected = tokio::time::timeout(
                            std::time::Duration::from_secs(10),
                            agf_ingest::kafka::connect_kafka_source(&config, "agf-ingest", "AGF_INGEST_KAFKA"),
                        )
                        .await;
                        match connected {
                            Ok(Ok(source)) => {
                                let receiver = KafkaReceiver::new(source, config)
                                    .with_counters(counters)
                                    .with_stats(Arc::clone(&stats))
                                    .with_shutdown(shutdown_rx);
                                let source = ingest_source(&source_identity, IngestProtocol::Kafka, "kafka");
                                if let Err(e) = receiver.start(pipeline, source).await {
                                    tracing::warn!(error = %e, "Kafka 消费任务退出");
                                }
                            }
                            Ok(Err(e)) => {
                                tracing::warn!(error = %e, "Kafka 连接失败，该接收器未启用（其余能力不受影响）");
                                push_note(&notes, format!("Kafka 未启用：{e}"));
                            }
                            Err(_) => {
                                tracing::warn!("Kafka 连接超时（10s），该接收器未启用（其余能力不受影响）");
                                push_note(&notes, "Kafka 未启用：连接超时（10s）");
                            }
                        }
                    }));
                    kafka_series.push(series);
                }
                Err(e) => {
                    tracing::warn!(error = %e, "Kafka broker 列表非法");
                    listeners.note(format!("Kafka 未启用：{e}"));
                }
            }
        }
    }

    /// ---- Pulsar（**经 KoP 复用 Kafka 接收器**；Pulsar 原生协议未实现） ----
    pub(super) async fn pulsar(&mut self) {
        let source_identity = self.identity.clone();
        // **原生优先**（本轮新增的唯一改动）：配了 `AGF_INGEST_PULSAR_URL` 就不同时起 KoP，
        // 否则同一订阅会被两条通道各消费一半（Shared）或因 ConsumerBusy 反复重连（Exclusive）。
        // 既有 KoP 部署不设该变量 ⇒ 行为与本轮之前**逐字节一致**。
        let native_url = env_or("AGF_INGEST_PULSAR_URL", "");
        if !native_url.trim().is_empty() {
            tracing::info!(
                native = %native_url,
                "Pulsar：已配置 AGF_INGEST_PULSAR_URL ⇒ 走**原生二进制协议**，KoP（Kafka 协议）段按优先规则跳过"
            );
            self.listeners.note("Pulsar 走原生二进制协议（AGF_INGEST_PULSAR_URL 优先）；KoP 段未启动".to_string());
            return;
        }
        let pipeline = self.pipeline;
        let metrics = self.metrics;
        let shutdown = self.shutdown;
        let listeners = &mut *self.listeners;
        let kafka_series = &mut self.kafka_series;
        let kafka_tasks = &mut self.kafka_tasks;
        let pulsar_url = env_or("AGF_INGEST_PULSAR_SERVICE_URL", "");
        let pulsar_topic = env_or("AGF_INGEST_PULSAR_TOPIC", "");
        if pulsar_url.is_empty() || pulsar_topic.is_empty() {
            listeners.note(
                "Pulsar 未启用：需配置 AGF_INGEST_PULSAR_SERVICE_URL（KoP 的 Kafka 协议监听，如 kafka://host:9092）与 AGF_INGEST_PULSAR_TOPIC；Pulsar 原生协议（binary/WebSocket）未实现"
                    .to_string(),
            );
            tracing::warn!(
                "Pulsar 未启用：未配置 AGF_INGEST_PULSAR_SERVICE_URL/AGF_INGEST_PULSAR_TOPIC（原生协议未实现；已实现路径是经 KoP 复用 Kafka 接收器）"
            );
        } else {
            let pulsar_tls_insecure = env_flag("AGF_INGEST_PULSAR_TLS_INSECURE_SKIP_VERIFY");
            if pulsar_tls_insecure {
                tracing::warn!(
                    "Pulsar KoP TLS：AGF_INGEST_PULSAR_TLS_INSECURE_SKIP_VERIFY=1 —— 证书链校验被关闭，仅可用于排障"
                );
            }
            let source = source_with(&source_identity, IngestProtocol::Pulsar, "pulsar", |connection| {
                connection.endpoint = Some(pulsar_url.clone());
                connection.topic = Some(pulsar_topic.clone());
                connection
                    .headers
                    .insert("subscription".to_string(), env_or("AGF_INGEST_PULSAR_SUBSCRIPTION", "agf-ingest"));
                // KoP 的 SASL/PLAIN：username 默认取 token 的 sub（授权角色），password = `token:<jwt>`
                // （**不落日志**；两者都由 PulsarReceiver 从 token 推导，见 kop_plain_username/password）
                if let Some(token) = env_secret("AGF_INGEST_PULSAR_TOKEN") {
                    connection.headers.insert("token".to_string(), token);
                }
                if let Some(username) = env_secret("AGF_INGEST_PULSAR_SASL_USERNAME") {
                    connection.headers.insert("sasl.username".to_string(), username);
                }
                if env_flag("AGF_INGEST_PULSAR_TLS") {
                    connection.headers.insert("tls".to_string(), "1".to_string());
                }
                for (header, env) in [
                    ("tls.ca", "AGF_INGEST_PULSAR_TLS_CA"),
                    ("tls.cert", "AGF_INGEST_PULSAR_TLS_CERT"),
                    ("tls.key", "AGF_INGEST_PULSAR_TLS_KEY"),
                ] {
                    if let Some(path) = env_secret(env) {
                        connection.headers.insert(header.to_string(), path);
                    }
                }
                if pulsar_tls_insecure {
                    connection.headers.insert("tls.insecure".to_string(), "1".to_string());
                }
                if let Some(start_from) = env_secret("AGF_INGEST_PULSAR_START_FROM") {
                    connection.headers.insert("start.from".to_string(), start_from);
                }
                if let Some(namespace) = env_secret("AGF_INGEST_PULSAR_TENANT_NAMESPACE") {
                    connection.headers.insert("tenant.namespace".to_string(), namespace);
                }
            });
            match PulsarReceiver::from_source(&source) {
                Ok(mut receiver) => {
                    // Pulsar 与 Kafka 共用同一份运维旋钮（前缀不同），游标文件独立（默认 pulsar-cursor.json）
                    receiver.tune(|config| {
                        apply_kafka_tuning(config, "AGF_INGEST_PULSAR", "data/ingest/pulsar-cursor.json");
                        // === 多副本分区分配（本轮新增锚点，独立成段） ===
                        // rskafka 无消费者组 ⇒ 并行消费由本接收器自己做分片：
                        //   * 只配 INSTANCE_ID/INSTANCE_COUNT ⇒ 静态取模 `p % instance_count`（不接管）；
                        //   * 再配 LEASE_DIR（**所有同订阅名副本必须看到同一目录**）⇒ 心跳租约 + 故障接管，
                        //     租约到期后死者的分区重分片到存活副本，并从磁盘分片游标继续（不丢不重）。
                        // 一个都不配 ⇒ 完全保持单副本行为（消费全部分区），与历史版本逐字节一致。
                        config.instance_id = env_secret("AGF_INGEST_PULSAR_INSTANCE_ID")
                            .and_then(|value| value.trim().parse::<u32>().ok());
                        config.instance_count = env_secret("AGF_INGEST_PULSAR_INSTANCE_COUNT")
                            .and_then(|value| value.trim().parse::<u32>().ok())
                            .unwrap_or(1)
                            .max(1);
                        if let Some(dir) = env_secret("AGF_INGEST_PULSAR_LEASE_DIR") {
                            config.lease_dir = Some(std::path::PathBuf::from(dir));
                        }
                        if let Some(ttl) = env_secret("AGF_INGEST_PULSAR_LEASE_TTL_MS")
                            .and_then(|value| value.trim().parse::<u64>().ok())
                        {
                            config.lease_ttl_ms = ttl.max(1);
                        }
                        // 启动静默期：等同伴的心跳到齐再认领分区（等价于 Kafka 的
                        // group.initial.rebalance.delay.ms）。0 = 不等待。
                        if let Some(settle) = env_secret("AGF_INGEST_PULSAR_ASSIGN_SETTLE_MS")
                            .and_then(|value| value.trim().parse::<u64>().ok())
                        {
                            config.assign_settle_ms = settle;
                        }
                        tracing::info!(
                            instance_id = config.instance_id.unwrap_or(0),
                            instance_count = config.instance_count,
                            lease_dir = %config.lease_dir.as_deref().map_or_else(|| "-".to_string(), |dir| dir.display().to_string()),
                            lease_ttl_ms = config.lease_ttl_ms,
                            assign_settle_ms = config.assign_settle_ms,
                            "Pulsar（KoP）多副本分区分配：静态取模 +（配了 LEASE_DIR 时）心跳租约接管；未配置 ⇒ 单副本消费全部分区"
                        );
                    });
                    let stats = Arc::new(KafkaStats::new());
                    let topic_label = receiver.topic.clone();
                    let subscription = receiver.subscription.clone();
                    let namespace = receiver.tenant_namespace.clone();
                    let receiver = Arc::new(
                        receiver
                            .with_counters(metrics.counters("pulsar"))
                            .with_stats(Arc::clone(&stats))
                            .with_shutdown(shutdown.handle()),
                    );
                    tracing::info!(
                        kop = %pulsar_url,
                        kafka_topic = %topic_label,
                        subscription = %subscription,
                        tenant_namespace = namespace.as_deref().unwrap_or("-"),
                        "Pulsar 接收器已启用：**经 KoP（Kafka on Pulsar）复用 Kafka 接收器**；Pulsar 原生协议未实现（连接在后台建立）"
                    );
                    kafka_series.push(KafkaSeries { receiver: "pulsar".to_string(), topic: topic_label, stats });
                    let pipeline = Arc::clone(pipeline);
                    kafka_tasks.push(tokio::spawn(async move {
                        if let Err(e) = receiver.start(pipeline, source).await {
                            tracing::warn!(error = %e, "Pulsar（KoP）消费任务退出");
                        }
                    }));
                }
                Err(e) => {
                    tracing::warn!(error = %e, "Pulsar 未启用（配置非法，其余能力不受影响）");
                    listeners.note(format!("Pulsar 未启用：{e}"));
                }
            }
        }
    }

    /// ---- Pulsar **原生二进制协议**（`AGF_INGEST_PULSAR_URL`；与上面的 KoP 行**并存**） ----
    ///
    /// **两条路径的分工与优先级**（[`agf_ingest::pulsar::pulsar_route`]）：
    ///
    /// * 配了 `AGF_INGEST_PULSAR_URL`（`pulsar://host:6650` / `pulsar+ssl://host:6651`）⇒ 走
    ///   **原生 binary protocol**（本段），消息由 `agf_ingest::pulsar::PulsarNativeReceiver` 直接
    ///   在 Pulsar 协议上消费；
    /// * 只配了 `AGF_INGEST_PULSAR_SERVICE_URL`（KoP 的 **Kafka 协议**监听）⇒ 由上面的
    ///   `pulsar()` 段按 KoP 复用 `KafkaReceiver`（**行为一字不改**）；
    /// * 两条都配 ⇒ **原生优先**，KoP 不同时启动（避免同一订阅被两条通道各消费一半）。
    ///
    /// 失败语义与其它接收器一致：未配置 ⇒ 只写 `/readyz` 的 note；配置非法/连接失败 ⇒ 只 `warn`，
    /// 进程照常启动（连接与重连都在后台任务里，退避重连不阻塞 HTTP 监听）。
    pub(super) async fn pulsar_native(&mut self) {
        let source_identity = self.identity.clone();
        let pipeline = self.pipeline;
        let metrics = self.metrics;
        let shutdown = self.shutdown;
        let listeners = &mut *self.listeners;
        let kafka_tasks = &mut self.kafka_tasks;
        let native_url = env_or("AGF_INGEST_PULSAR_URL", "");
        let kop_url = env_or("AGF_INGEST_PULSAR_SERVICE_URL", "");
        let route = pulsar_route(Some(&native_url), Some(&kop_url));
        if route != PulsarRoute::Native {
            listeners.note(format!(
                "Pulsar 原生协议未装配：未配置 AGF_INGEST_PULSAR_URL（pulsar://host:6650）；\
                 当前路由 = {}（native URL 优先，其次 AGF_INGEST_PULSAR_SERVICE_URL 的 KoP）",
                route.as_str()
            ));
            return;
        }
        if !kop_url.trim().is_empty() {
            tracing::info!(
                kop = %kop_url,
                native = %native_url,
                "Pulsar：原生 URL 与 KoP 地址同时配置 ⇒ **原生优先**，KoP 段不启动（避免同订阅双通道消费）"
            );
        }
        match PulsarNativeConfig::from_env() {
            Ok(config) => {
                let stats = Arc::new(PulsarNativeStats::new());
                let receiver = Arc::new(
                    PulsarNativeReceiver::new(config.clone())
                        .with_counters(metrics.counters("pulsar-native"))
                        .with_stats(Arc::clone(&stats))
                        .with_shutdown(shutdown.handle()),
                );
                tracing::info!(
                    config = %config.describe(),
                    token_auth = config.token.is_some(),
                    tls = config.tls,
                    "Pulsar **原生二进制协议**消费者已装配（与 KoP 路径并存；连接在后台建立）"
                );
                listeners.note(format!(
                    "Pulsar 原生二进制协议已装配：{}（真 ACK；`pulsar-admin topics stats` 的 msgBacklog 应归零）",
                    config.describe()
                ));
                let pipeline = Arc::clone(pipeline);
                let source = ingest_source(&source_identity, IngestProtocol::Pulsar, "pulsar-native");
                let notes = Arc::clone(&listeners.notes);
                kafka_tasks.push(tokio::spawn(async move {
                    if let Err(e) = receiver.run(pipeline, source).await {
                        tracing::warn!(error = %e, "Pulsar 原生消费任务退出（其余能力不受影响）");
                        push_note(&notes, format!("Pulsar 原生消费任务退出：{e}"));
                    }
                }));
            }
            Err(e) => {
                tracing::warn!(error = %e, "Pulsar 原生未启用（配置非法，其余能力不受影响）");
                listeners.note(format!("Pulsar 原生未启用：{e}"));
            }
        }
    }

    /// ---- NATS JetStream 入向订阅（**与事件总线无关**） ----
    ///
    /// 与 `crate::bus` 的 `NatsEventBus`（核心协议 publish，非 JetStream）是两件事：
    /// 这里是"从 NATS 把日志收进来"。名字只由 `AGF_INGEST_JETSTREAM_IDENTITY` 决定
    /// （**不用**每次启动新生成的 `LogSource::id`），否则重启后 durable 名字一变，
    /// "中断重启不丢"就不成立。
    ///
    /// 连接用**有界超时**（5s，与 SQL Sink 的降级口径一致）：连不上只 warn + 写进 /readyz 的
    /// notes，**不登记装配** ⇒ 能力矩阵如实显示 `not-wired`（而不是"声称 ready 却收不到数"）。
    pub(super) async fn jetstream(&mut self) {
        let source_identity = self.identity.clone();
        let pipeline = self.pipeline;
        let metrics = self.metrics;
        let listeners = &mut *self.listeners;
        let kafka_tasks = &mut self.kafka_tasks;
        let jetstream_url = env_or("AGF_INGEST_JETSTREAM_URL", "");
        if jetstream_url.is_empty() {
            listeners.note(
                "NATS JetStream 入向订阅未启用：未配置 AGF_INGEST_JETSTREAM_URL\
                 （注意：这与事件总线 `AGF_NATS_URL` 是两件事——后者是发布，不是收数）"
                    .to_string(),
            );
        } else {
            match parse_nats_urls(&jetstream_url) {
                Err(e) => {
                    tracing::warn!(error = %e, "NATS JetStream 未启用：地址列表非法");
                    listeners.note(format!("NATS JetStream 未启用：{e}"));
                }
                Ok(urls) => {
                    let identity = env_or("AGF_INGEST_JETSTREAM_IDENTITY", "default");
                    let subject = env_or("AGF_INGEST_JETSTREAM_SUBJECT", &format!("agf.ingest.{identity}"));
                    let mode = if env_or("AGF_INGEST_JETSTREAM_MODE", "pull").eq_ignore_ascii_case("push") {
                        JetMode::Push
                    } else {
                        JetMode::Pull
                    };
                    let batch = env_num("AGF_INGEST_JETSTREAM_BATCH", agf_ingest::jetstream::DEFAULT_BATCH_SIZE).max(1);
                    let stream_plan = StreamPlan::for_identity(&identity, &subject);
                    let mut consumer_plan = ConsumerPlan::for_identity(&identity, mode, &subject, batch);
                    consumer_plan.ack_wait_secs = env_num("AGF_INGEST_JETSTREAM_ACK_WAIT_SECS", 30_u64).max(1);
                    consumer_plan.max_deliver = env_num("AGF_INGEST_JETSTREAM_MAX_DELIVER", 8_i64);
                    let source = source_with(&source_identity, IngestProtocol::Nats, "nats-jetstream", |connection| {
                        connection.endpoint = Some(jetstream_url.clone());
                        connection.topic = Some(subject.clone());
                    });
                    let counters = metrics.counters("nats-jetstream");
                    let notes = Arc::clone(&listeners.notes);
                    // 连接 + provision 有界（5s）：失败 ⇒ 不登记装配，能力矩阵显示 not-wired
                    let connected = tokio::time::timeout(
                        std::time::Duration::from_secs(5),
                        AsyncNatsJetStream::connect(urls.clone()),
                    )
                    .await;
                    match connected {
                        Ok(Ok(source_impl)) => {
                            let receiver = Arc::new(
                                JetStreamReceiver::new(
                                    Arc::clone(pipeline),
                                    source,
                                    stream_plan.clone(),
                                    consumer_plan.clone(),
                                    Arc::new(source_impl),
                                )
                                .with_counters(counters),
                            );
                            match receiver.provision().await {
                                Ok(state) => {
                                    tracing::info!(
                                        nats = %jetstream_url,
                                        stream = %stream_plan.name,
                                        durable = %consumer_plan.durable_name,
                                        mode = mode.as_str(),
                                        batch,
                                        ack_wait_secs = consumer_plan.ack_wait_secs,
                                        messages = state.messages,
                                        "NATS JetStream 入向订阅已装配（durable 幂等 provision：stream `{}` 现有消息 {} 条）",
                                        stream_plan.name,
                                        state.messages
                                    );
                                    // 装配事实登记（成功 provision 之后才登记 ⇒ 矩阵才允许 ready）
                                    declare_wired("nats-jetstream", true);
                                    listeners.nats_jetstream = Some(format!("{jetstream_url}（pull/push 订阅）"));
                                    listeners.note(format!(
                                        "NATS JetStream 入向订阅已装配：stream={} durable={} mode={} subject={}（显式应答 ack/nak/term）",
                                        stream_plan.name,
                                        consumer_plan.durable_name,
                                        mode.as_str(),
                                        subject
                                    ));
                                    let notes_for_task = Arc::clone(&notes);
                                    kafka_tasks.push(tokio::spawn(async move {
                                        if let Err(e) = receiver.run().await {
                                            tracing::warn!(error = %e, "NATS JetStream 订阅任务退出");
                                            push_note(&notes_for_task, format!("NATS JetStream 订阅任务退出：{e}"));
                                        }
                                    }));
                                }
                                Err(e) => {
                                    tracing::warn!(error = %e, "NATS JetStream provision 失败，该接收器未启用（其余能力不受影响）");
                                    push_note(&notes, format!("NATS JetStream 未启用：provision 失败（{e}）"));
                                }
                            }
                        }
                        Ok(Err(e)) => {
                            tracing::warn!(error = %e, "NATS JetStream 连接失败，该接收器未启用（其余能力不受影响）");
                            push_note(&notes, format!("NATS JetStream 未启用：连接失败（{e}）"));
                        }
                        Err(_) => {
                            tracing::warn!(url = %jetstream_url, "NATS JetStream 连接超时（5s），该接收器未启用");
                            push_note(&notes, "NATS JetStream 未启用：连接超时（5s）");
                        }
                    }
                }
            }
        }
    }
}
