//! Pulsar 接收器：**经 KoP（Kafka on Pulsar）复用 Kafka 取数内核**；未配置 KoP 时不启用（能力矩阵如实标注）。

use super::*;

// Pulsar 经 KoP 复用 Kafka 接收器：这里只用"取数内核"的公开类型，不复制任何消费逻辑。
/// Pulsar 原生协议的 TODO 锚点（**一字不差地写清**"经 KoP 复用"与"原生协议未实现"）。
///
/// 绝不允许把它改写成"Pulsar 原生协议已支持"：KoP 是 **Kafka 协议兼容层**，
/// 消息走的是 Kafka wire protocol，落库协议标签为 `pulsar` 只是**来源标注**。
pub const PULSAR_NATIVE_TODO: &str = "TODO ingest-pulsar-native：Pulsar 原生协议（binary protocol / WebSocket）未实现；当前**经 KoP（Kafka on Pulsar）复用 Kafka 接收器**";

/// Pulsar 接收器（**经 KoP 复用 Kafka 接收器**）。
///
/// ## 实现方式（如实）
///
/// Pulsar 的 KoP（Kafka on Pulsar）协议处理器把 Pulsar topic 暴露成 **Kafka 协议**监听，
/// 因此本接收器**不重复实现取数内核**：
///
/// ```text
/// Pulsar broker (KoP 监听 :9092)  ──Kafka wire protocol──▶  crate::kafka::KafkaReceiver
///                                                              │  多分区独立游标 / SASL / TLS /
///                                                              │  退避重连 / offset+lag 指标 / 优雅停机
///                                                              ▼
///                                                       流水线（协议标签 = pulsar）
/// ```
///
/// * `AGF_INGEST_PULSAR_SERVICE_URL` → KoP 的 **Kafka 协议监听**（`kafka://host:9092` 或 `host:9092`）；
/// * `AGF_INGEST_PULSAR_TOPIC` → Kafka 侧 topic 名（`persistent://public/default/x` 取末段 `x`）；
/// * `AGF_INGEST_PULSAR_SUBSCRIPTION` → **本地游标命名空间 + client id**（rskafka 无消费者组，
///   **不**提交 offset 到 broker，语义不等价于 Pulsar/Kafka 的订阅或消费者组）；
/// * `AGF_INGEST_PULSAR_TOKEN` → KoP 的 **SASL/PLAIN**：`username` 为角色占位（KoP 仅在
///   proxyRoles 语义下使用），**password 必须是 `<authMethod>:<authData>`**（`token:<Pulsar token>`）。
///   裸 token 会被 KoP 以 `Authentication failed: password not specified` 拒绝——
///   见 [`kop_plain_password`] 的实测说明；凭据**只从环境变量取**，绝不进日志/指标/响应体；
/// * `AGF_INGEST_PULSAR_TLS`（+ `..._TLS_CA` / `..._TLS_CERT` / `..._TLS_KEY`）→ TLS（默认校验证书链）；
/// * `AGF_INGEST_PULSAR_TENANT_NAMESPACE` → 仅用于日志/指标标注（Kafka 侧 topic 名不含它）。
///
/// ## 多副本并行消费（无消费者组时的替代方案，实测已验）
///
/// `rskafka` 没有 JoinGroup/SyncGroup/Heartbeat，KoP 侧的消费者组协议**本客户端用不了**，
/// 因此并行消费由本接收器自己做**分区归属**（见 [`crate::kafka::PartitionOwnership`]）：
///
/// * `AGF_INGEST_PULSAR_INSTANCE_ID` / `..._INSTANCE_COUNT`：静态分片 `owner(p) = live[p % live.len()]`
///   （未配置 ⇒ 单副本消费全部分区，与历史行为一致）；
/// * `AGF_INGEST_PULSAR_LEASE_DIR`：**所有同订阅名副本必须看到同一个目录** ⇒ 升级为
///   **心跳租约 + 故障接管**（判死即重分片；接管者从共享目录里的**分区分片游标**继续，不丢不重）；
/// * `AGF_INGEST_PULSAR_LEASE_TTL_MS`（默认 15000）：判活窗口 = **接管时间上界**的主要项
///   （实测 ttl 6s + interval 2s ⇒ 接管 7.2s 完成）；
/// * `AGF_INGEST_PULSAR_ASSIGN_SETTLE_MS`（默认 3000）：**启动静默期**，等价于 Kafka 的
///   `group.initial.rebalance.delay.ms`。没有它时"先启动的副本会先把全部分区端走"，
///   与随后启动的同伴形成**重叠消费窗口**（实测踩过）；
/// * 归属与归零都可见：`/stats` 的 `kafka_partitions.*.owned/owner_instance/live_instances`，
///   `/metrics` 的 `agf_ingest_kafka_partition_owned` / `_partition_takeovers_total` /
///   `_instance_info{...,settling=...}`。
///
/// **语义边界（如实）**：没有 broker 侧 generation fence ⇒ 副本增减的瞬时重分片存在
/// ≤1 个轮询间隔的重叠窗口，由流水线的**内容去重**兜住（at-least-once + 去重）；
/// 接管路径（对端租约到期后才认领）没有该窗口。
///
/// ## KoP 侧实测坑（部署前必读）
///
/// * **Kafka 客户端版本上限**：KoP v3.1.1.1 最高只支持 `ApiVersions` **v3**，
///   而 Kafka **3.9.0+** 的客户端首包就发 v4；KoP 不返回 `UNSUPPORTED_VERSION` 而是
///   **直接关连接**（`UnsupportedVersionException` 在 KoP 侧抛出），客户端表现为
///   反复 `Bootstrap broker disconnected` → `Topic not present in metadata after 60000 ms`。
///   ⇒ 用 **≤ 3.8.x** 的 Kafka 客户端（本仓库 rskafka 0.6 本身走低版本协议，不受影响）。
/// * **默认幂等的生产者写不进去**：Kafka 3.x 的生产者默认 `enable.idempotence=true`，
///   会走事务协调器；KoP 需要 **`kafkaTransactionCoordinatorEnabled=true`**
///   （KoP 自己的开关，与 Pulsar 的 `transactionCoordinatorEnabled` 是两个键），
///   否则 broker 侧报 `Broker has disabled transaction coordinator`。
/// * **SASL username 是"租户选择器"，不是角色**：角色来自 token 的 `sub`。
///   默认 `username = token.sub` 只有在"角色名 == 租户名"时才对。开
///   `authorizationEnabled=true` 并用 ACL 受限角色 token 时，必须显式把
///   `AGF_INGEST_PULSAR_SASL_USERNAME` 设成**租户名**（如 `agf-ingest`），
///   否则 KoP 会拿角色名当租户名去查（`User is not allowed to access this tenant`）。
/// * **KoP 的 Kafka TLS 不复用 broker 的 PEM 配置**：它只读自己的 `kopSsl*` 键并交给
///   Jetty 的 `KeyStore.getInstance()` ⇒ 必须提供 **PKCS12/JKS** 密钥库
///   （`kopSslKeystoreLocation` / `kopSslKeystorePassword`），`kopSslKeystoreType=PEM` 不可用；
///   另外默认 `kopSslEnabledProtocols` 缺 TLSv1.3，建议显式补上。
/// * **变体部署必须覆盖 `kafkaAdvertisedListeners`**：KoP 在元数据里返回 advertised 地址，
///   客户端随后直连它；只改端口映射而不改 advertised 会被指回旧端口（连接被拒）。
///
/// ## 未实现（如实）
///
/// * **Pulsar 原生协议**（binary protocol `pulsar://` / WebSocket / `pulsar-client`）**未实现**：
///   需要 libpulsar C++ 绑定或 WebSocket 客户端，本 crate 不引入 C 工具链依赖；
///   因此指向 `pulsar://host:6650` 的配置会被**显式拒绝**（不静默降级、不假装可用）；
/// * **Pulsar 订阅类型**（Exclusive/Shared/Failover/Key_Shared）、死信队列、多 topic 订阅、
///   消息级 ack、`non-persistent` topic：KoP 路径下均不可用（Kafka 协议没有这些语义）；
/// * **未配置 KoP 地址时**：能力矩阵显示 `not-implemented`（不假装 ready），
///   仅保留配置模型 + [`MockReceiver`] 离线回放通道。
#[derive(Debug)]
pub struct PulsarReceiver {
    /// KoP 的 Kafka 协议地址（未配置 = `None`）。
    pub service_url: Option<String>,
    /// Kafka 侧 topic 名（Pulsar topic 末段）。
    pub topic: String,
    /// 订阅名（映射为本地游标命名空间 + client id）。
    pub subscription: String,
    /// tenant/namespace（仅日志/指标标注）。
    pub tenant_namespace: Option<String>,
    /// 经 KoP 映射出的 Kafka 拉取配置（`None` = 未配置 KoP 地址）。
    pub config: Option<KafkaPullConfig>,
    /// 离线回放通道（未配置 KoP 地址时可用；配置了就**不是**主通道）。
    pub mock: MockReceiver,
    /// 注入的 Kafka 源（单测用；`None` = 启动时按 config 真实连接 KoP）。
    injected: Option<Arc<dyn KafkaSource>>,
    /// 复用出的 Kafka 接收器（首次取数/启动时建立，之后共享）。
    receiver: Mutex<Option<Arc<KafkaReceiver>>>,
    /// 注入给内层 Kafka 接收器的共享计数器（`/metrics` 的 `pulsar` 标签）。
    counters: Option<Arc<crate::metrics::ReceiverCounters>>,
    /// 注入给内层 Kafka 接收器的分区指标登记。
    stats: Option<Arc<KafkaStats>>,
    /// 停机信号（SIGINT/SIGTERM 时刷新内层游标）。
    shutdown: Option<tokio::sync::watch::Receiver<bool>>,
}

impl PulsarReceiver {
    /// 由日志源配置构造（**纯配置映射，不发起任何网络连接**）。
    ///
    /// `connection.endpoint` = `AGF_INGEST_PULSAR_SERVICE_URL`（KoP 的 Kafka 协议监听），
    /// 其余参数走 `connection.headers`：`subscription` / `token` / `tls` / `tls.ca` /
    /// `tls.cert` / `tls.key` / `tls.insecure` / `start.from` / `tenant.namespace`。
    ///
    /// # Errors
    /// 缺 topic；或 endpoint 指向 **Pulsar 原生协议端口**（`pulsar://host:6650`）等非法 KoP 地址。
    pub fn from_source(source: &LogSource) -> DomainResult<Self> {
        let topic_raw = source
            .connection
            .topic
            .clone()
            .filter(|t| !t.trim().is_empty())
            .ok_or_else(|| DomainError::Config("Pulsar 需要 connection.topic".to_string()))?;
        let headers = &source.connection.headers;
        let subscription = headers.get("subscription").cloned().unwrap_or_else(|| "agf-ingest".to_string());
        let mock = MockReceiver::new(IngestProtocol::Pulsar, "pulsar", PULSAR_NATIVE_TODO);
        let endpoint = source.connection.endpoint.clone().filter(|e| !e.trim().is_empty());

        // 未配置 KoP 地址：只保留配置模型 + Mock 回放（能力矩阵显示 not-implemented，不假装 ready）
        let Some(endpoint) = endpoint else {
            let (topic, namespace) = kop_topic_name(&topic_raw);
            return Ok(Self {
                service_url: None,
                topic,
                subscription,
                tenant_namespace: headers.get("tenant.namespace").cloned().or(namespace),
                config: None,
                mock,
                injected: None,
                receiver: Mutex::new(None),
                counters: None,
                stats: None,
                shutdown: None,
            });
        };

        if topic_raw.trim_start().to_ascii_lowercase().starts_with("non-persistent://") {
            return Err(DomainError::Config(format!(
                "Pulsar non-persistent topic（{topic_raw}）经 KoP 不受支持：KoP 只映射 persistent topic（Kafka 协议无此语义）"
            )));
        }
        let kop = parse_kop_endpoint(&endpoint)?;
        if !kop.note.is_empty() {
            warn!(endpoint = %endpoint, note = %kop.note, "Pulsar：KoP 端点写法提示");
        }
        let (topic, namespace) = kop_topic_name(&topic_raw);
        let tenant_namespace = headers.get("tenant.namespace").cloned().or(namespace);

        // 鉴权：KoP 的 SASL/PLAIN —— username 必须是**被授权的角色**（实测；见 kop_plain_username），
        // password 必须是 Pulsar 的 `<authMethod>:<authData>` 形式（见 kop_plain_password）
        let sasl = headers.get("token").map(|token| {
            let username = headers.get("sasl.username").cloned().unwrap_or_else(|| kop_plain_username(token));
            KafkaSaslConfig::new(KafkaSaslMechanism::Plain, username, kop_plain_password(token))
        });
        // TLS：默认关闭；开启后默认校验链；跳过校验只在显式开关下
        let tls = (headers.get("tls").map(String::as_str) == Some("1")).then(|| KafkaTlsConfig {
            ca_pem: headers.get("tls.ca").filter(|p| !p.trim().is_empty()).map(PathBuf::from),
            client_cert_pem: headers.get("tls.cert").filter(|p| !p.trim().is_empty()).map(PathBuf::from),
            client_key_pem: headers.get("tls.key").filter(|p| !p.trim().is_empty()).map(PathBuf::from),
            insecure_skip_verify: headers.get("tls.insecure").map(String::as_str) == Some("1"),
        });
        let start_from = headers.get("start.from").and_then(|v| crate::kafka::KafkaStartFrom::parse(v));
        let config = KafkaPullConfig {
            brokers: kop.brokers,
            topic: topic.clone(),
            consumer_id: subscription.clone(),
            namespace: Some(subscription.clone()),
            protocol: IngestProtocol::Pulsar,
            receiver_name: "pulsar".to_string(),
            origin_scheme: "pulsar".to_string(),
            sasl,
            tls,
            start_from: start_from.unwrap_or_default(),
            ..KafkaPullConfig::default()
        };
        Ok(Self {
            service_url: Some(endpoint),
            topic,
            subscription,
            tenant_namespace,
            config: Some(config),
            mock,
            injected: None,
            receiver: Mutex::new(None),
            counters: None,
            stats: None,
            shutdown: None,
        })
    }

    /// 注入 Kafka 源（单测用：**测试不连真实 Pulsar/KoP**）。
    #[must_use]
    pub fn with_kafka_source(mut self, source: Arc<dyn KafkaSource>) -> Self {
        self.injected = Some(source);
        self
    }

    /// 注入共享计数器（`/metrics` 的 `pulsar` 标签）。
    #[must_use]
    pub fn with_counters(mut self, counters: Arc<crate::metrics::ReceiverCounters>) -> Self {
        self.counters = Some(counters);
        self
    }

    /// 注入分区指标登记（`/metrics` 的 offset/lag 与 `/stats` 的逐分区状态）。
    #[must_use]
    pub fn with_stats(mut self, stats: Arc<KafkaStats>) -> Self {
        self.stats = Some(stats);
        self
    }

    /// 注入停机信号（SIGINT/SIGTERM 时刷新内层游标）。
    #[must_use]
    pub fn with_shutdown(mut self, shutdown: tokio::sync::watch::Receiver<bool>) -> Self {
        self.shutdown = Some(shutdown);
        self
    }

    /// 是否已配置 KoP（Kafka 协议）地址。
    #[must_use]
    pub fn kop_enabled(&self) -> bool {
        self.config.is_some()
    }

    /// 覆盖内层 Kafka 拉取配置（运维旋钮：起始位置 / 单轮上限 / 退避 / 游标文件…）。
    ///
    /// 未配置 KoP 地址时为 no-op；内层接收器已建立后再调用只 warn（改动不追溯生效）。
    pub fn tune(&mut self, tune: impl FnOnce(&mut KafkaPullConfig)) {
        let Some(config) = self.config.as_mut() else {
            return;
        };
        tune(config);
        let built = self.receiver.lock().map(|guard| guard.is_some()).unwrap_or(false);
        if built {
            warn!("Pulsar：内层 Kafka 接收器已建立，本次 tune() 的改动不会生效（应在 start/poll_once 之前调用）");
        }
    }

    /// 取（必要时建立）内层 Kafka 接收器：**KoP 复用点**。
    ///
    /// # Errors
    /// 未配置 KoP 地址，或连接 KoP/SASL/TLS 失败。
    pub async fn kafka_receiver(&self) -> DomainResult<Arc<KafkaReceiver>> {
        if let Some(existing) = self.receiver.lock().ok().and_then(|guard| guard.clone()) {
            return Ok(existing);
        }
        let config = self.config.clone().ok_or_else(|| DomainError::NotImplemented(PULSAR_NATIVE_TODO.to_string()))?;
        let source: Arc<dyn KafkaSource> = match &self.injected {
            Some(injected) => Arc::clone(injected),
            None => {
                let security = KafkaSecurity::from_config(&config);
                tracing::info!(
                    kop = %self.service_url.as_deref().unwrap_or("-"),
                    topic = %config.topic,
                    subscription = %self.subscription,
                    tenant_namespace = self.tenant_namespace.as_deref().unwrap_or("-"),
                    security = %security.describe(),
                    "Pulsar 经 KoP 复用 Kafka 接收器（Kafka 协议消费 persistent topic）"
                );
                Arc::new(RskafkaSource::connect(config.brokers.clone(), &config.client_id(), &security).await?)
            }
        };
        let mut receiver = KafkaReceiver::new(source, config);
        if let Some(counters) = &self.counters {
            receiver = receiver.with_counters(Arc::clone(counters));
        }
        if let Some(stats) = &self.stats {
            receiver = receiver.with_stats(Arc::clone(stats));
        }
        if let Some(shutdown) = &self.shutdown {
            receiver = receiver.with_shutdown(shutdown.clone());
        }
        let receiver = Arc::new(receiver);
        if let Ok(mut guard) = self.receiver.lock() {
            *guard = Some(Arc::clone(&receiver));
        }
        Ok(receiver)
    }

    /// 已建立的内层 Kafka 接收器（尚未取数时为 `None`）。
    #[must_use]
    pub fn reused_kafka(&self) -> Option<Arc<KafkaReceiver>> {
        self.receiver.lock().ok().and_then(|guard| guard.clone())
    }
}

#[async_trait]
impl Receiver for PulsarReceiver {
    fn protocol(&self) -> IngestProtocol {
        IngestProtocol::Pulsar
    }

    fn describe(&self) -> ReceiverDescriptor {
        let Some(config) = &self.config else {
            // 未配置 KoP 地址 ⇒ 如实显示"未启用"（不假装 ready）；离线回放通道条数一并给出
            let mut descriptor = self.mock.descriptor();
            descriptor.note = format!(
                "未启用：未配置 KoP（Kafka on Pulsar）地址；Pulsar 原生协议未实现。\
                 仅提供配置模型 + Mock 回放（{} 条离线样本）",
                self.mock.len()
            );
            descriptor.todo = Some(PULSAR_NATIVE_TODO.to_string());
            return descriptor;
        };
        let security = KafkaSecurity::from_config(config).describe();
        ReceiverDescriptor {
            name: "pulsar".to_string(),
            protocol: IngestProtocol::Pulsar,
            status: ReceiverStatus::Ready,
            note: format!(
                "**经 KoP（Kafka on Pulsar）复用 Kafka 接收器**；Pulsar 原生协议未实现。\
                 KoP 的 Kafka 协议监听：{}（topic `{}`，订阅 `{}` → 本地游标命名空间，tenant/namespace {}）；\
                 取数内核与 Kafka 接收器完全一致（全分区独立游标 + 至少一次 + 退避重连 + offset/lag 指标）；安全：{}",
                self.service_url.as_deref().unwrap_or("-"),
                config.topic,
                self.subscription,
                self.tenant_namespace.as_deref().unwrap_or("-"),
                security
            ),
            todo: Some(PULSAR_NATIVE_TODO.to_string()),
            mock_replay: false,
        }
    }

    async fn start(&self, pipeline: Arc<IngestPipeline>, source: LogSource) -> DomainResult<()> {
        let receiver = self.kafka_receiver().await?;
        receiver.start(pipeline, source).await
    }

    async fn poll_once(&self, pipeline: Arc<IngestPipeline>, source: LogSource, max: usize) -> DomainResult<usize> {
        if self.config.is_none() {
            // 未配置 KoP 地址：保留离线回放通道（链路可用，但**不是**真实 Pulsar 取数）
            return self.mock.replay_all(&pipeline, &source, max).await;
        }
        let receiver = self.kafka_receiver().await?;
        receiver.poll_once(pipeline, source, max).await
    }

    async fn stop(&self) -> DomainResult<()> {
        if let Some(receiver) = self.reused_kafka() {
            receiver.stop().await?;
        }
        Ok(())
    }
}
