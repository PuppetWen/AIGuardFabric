//! MQTT 接收器：`MqttIngestReport`、`MqttReceiver`（取数/拆分/落库）与 `Receiver` trait 实现。

// ---------------------------------------------------------------------------
// 接收器
// ---------------------------------------------------------------------------

use super::*;

/// 单条消息的接入结果。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MqttIngestReport {
    /// 拆出的记录数。
    pub records: usize,
    /// 落库事件数。
    pub persisted: usize,
}

/// MQTT 订阅接收器。
#[derive(Debug)]
pub struct MqttReceiver {
    pipeline: Arc<IngestPipeline>,
    source: LogSource,
    topic: String,
    qos: u8,
    subscription: Arc<dyn MqttSubscription>,
    max_records: usize,
    counters: Arc<ReceiverCounters>,
    /// 订阅计划（含共享订阅信息；启用阶段即校验）。
    plan: SubscribePlan,
    /// 协议版本 + v5 专有特性（`/readyz` 如实标注用）。
    protocol: MqttProtocolConfig,
}

impl MqttReceiver {
    /// 构造。
    #[must_use]
    pub fn new(
        pipeline: Arc<IngestPipeline>,
        source: LogSource,
        topic: impl Into<String>,
        qos: u8,
        subscription: Arc<dyn MqttSubscription>,
    ) -> Self {
        let topic = topic.into();
        let plan = plan_subscribe(&topic, qos.min(2)).unwrap_or_else(|_| SubscribePlan {
            topic: topic.clone(),
            shared: None,
            qos: qos.min(2),
        });
        Self {
            pipeline,
            source,
            topic,
            qos: qos.min(2),
            subscription,
            max_records: 1_000,
            counters: Arc::new(ReceiverCounters::new()),
            plan,
            protocol: MqttProtocolConfig::default(),
        }
    }

    /// 注入协议配置（版本 + v5 特性）。
    #[must_use]
    pub fn with_protocol(mut self, protocol: MqttProtocolConfig) -> Self {
        self.protocol = protocol;
        self
    }

    /// 协议配置。
    #[must_use]
    pub const fn protocol_config(&self) -> &MqttProtocolConfig {
        &self.protocol
    }

    /// 由日志源 + 订阅实现构造（`connection.endpoint` / `connection.topic` / `headers[qos]`）。
    ///
    /// TLS / 遗嘱 / 退避 / **协议版本与 v5 特性** 这几类**加固项**由环境变量注入
    /// （`AGF_INGEST_MQTT_TLS*`、`AGF_INGEST_MQTT_WILL_*`、`AGF_INGEST_MQTT_RECONNECT_*`、
    /// `AGF_INGEST_MQTT_PROTOCOL_VERSION` + v5 专有项），
    /// 连接级参数（broker/主题/QoS/客户端 id/凭据）仍走 `connection.*`。
    ///
    /// # Errors
    /// 未配置 broker 或主题；`qos` 非法；TLS 配置非法/PEM 不可读；共享订阅语法非法；
    /// **版本与 v5 专有配置不自洽**（3.1.1 上配了 v5 字段）。
    pub fn from_source(pipeline: Arc<IngestPipeline>, source: &LogSource) -> DomainResult<Self> {
        let endpoint = source
            .connection
            .endpoint
            .clone()
            .ok_or_else(|| DomainError::Config("MQTT 需要 connection.endpoint（broker）".to_string()))?;
        let topic = source
            .connection
            .topic
            .clone()
            .filter(|t| !t.trim().is_empty())
            .ok_or_else(|| DomainError::Config("MQTT 需要 connection.topic".to_string()))?;
        let parsed = parse_endpoint(&endpoint)?;
        let qos = match source.connection.headers.get("qos") {
            Some(text) => {
                text.trim().parse::<u8>().map_err(|e| DomainError::Config(format!("MQTT qos {text:?} 非法: {e}")))?
            }
            None => 1,
        };
        if qos > 2 {
            return Err(DomainError::Config(format!("MQTT qos {qos} 超出范围（0/1/2）")));
        }
        // 版本/特性自洽性：3.1.1 上配 v5 专有项 ⇒ 明确报错（由调用方写进 /readyz notes）
        let protocol = MqttProtocolConfig::from_env();
        protocol.validate()?;
        let client_id =
            source.connection.headers.get("client.id").cloned().unwrap_or_else(|| format!("agf-ingest-{}", source.id));

        // TLS 材料（`mqtts://`/`wss://` 自动启用；`ws://` + TLS 材料是矛盾配置，由 options() 报错）
        let tls_config = MqttTlsConfig::from_env().for_scheme(&parsed);
        let material = if tls_config.enabled { Some(tls_config.load()?) } else { None };
        let will = MqttWill::from_env();
        let backoff = BackoffPolicy::from_env();

        let subscription: Arc<dyn MqttSubscription> = if protocol.version.is_v5() {
            let mut v5 =
                RumqttV5Subscription::new(parsed.clone(), client_id).with_v5(protocol.v5.clone()).with_backoff(backoff);
            if let (Some(username), Some(password)) =
                (source.connection.headers.get("username"), source.connection.headers.get("password"))
            {
                v5 = v5.with_credentials(username.clone(), password.clone());
            }
            if let Some(material) = material.clone() {
                v5 = v5.with_tls(material);
            }
            if let Some(will) = will {
                v5 = v5.with_will(will);
            }
            Arc::new(v5)
        } else {
            let mut v3 = RumqttSubscription::new(parsed, client_id)
                .with_clean_start(protocol.v5.clean_start)
                .with_backoff(backoff);
            if let (Some(username), Some(password)) =
                (source.connection.headers.get("username"), source.connection.headers.get("password"))
            {
                v3 = v3.with_credentials(username.clone(), password.clone());
            }
            if let Some(material) = material {
                v3 = v3.with_tls(material);
            }
            if let Some(will) = will {
                v3 = v3.with_will(will);
            }
            Arc::new(v3)
        };
        Ok(Self::new(pipeline, source.clone(), topic, qos, subscription).with_protocol(protocol))
    }

    /// 注入共享计数器。
    #[must_use]
    pub fn with_counters(mut self, counters: Arc<ReceiverCounters>) -> Self {
        self.counters = counters;
        self
    }

    /// 主题。
    #[must_use]
    pub fn topic(&self) -> &str {
        &self.topic
    }

    /// QoS。
    #[must_use]
    pub const fn qos(&self) -> u8 {
        self.qos
    }

    /// 订阅计划（共享订阅信息）。
    #[must_use]
    pub const fn plan(&self) -> &SubscribePlan {
        &self.plan
    }

    /// 计数器。
    #[must_use]
    pub fn counters(&self) -> &Arc<ReceiverCounters> {
        &self.counters
    }

    /// 接入一条消息。
    ///
    /// # Errors
    /// 落库失败（拆分/解析失败按既有口径计数，不返回错误）。
    pub async fn ingest_message(&self, message: &MqttMessage) -> DomainResult<MqttIngestReport> {
        self.counters.add_received(1);
        let records = HttpPullReceiver::split_records(&message.payload, self.max_records);
        if records.is_empty() {
            debug!(topic = %message.topic, "MQTT 载荷为空，跳过");
            return Ok(MqttIngestReport::default());
        }
        // v5 属性（用户属性/内容类型/topic alias…）以查询串随 origin 透传 ⇒ 落事件 extra 的 log.origin；
        // v5 连接额外带上 qos/retain（RetainAsPublished 的真实效果必须可被外部观测）
        let broker = self.subscription.describe();
        let origin =
            if self.protocol.version.is_v5() { message.origin_with_facts(&broker) } else { message.origin(&broker) };
        let items: Vec<(Vec<u8>, String)> = records.into_iter().map(|r| (r, origin.clone())).collect();
        let outcomes = self.pipeline.ingest_batch(&self.source, IngestProtocol::Mqtt, &items).await?;
        let persisted = outcomes.iter().filter(|o| o.persisted).count();
        self.counters.record_outcomes(&outcomes);
        Ok(MqttIngestReport { records: items.len(), persisted })
    }

    /// 运行订阅循环（消费订阅通道直到通道关闭）。
    ///
    /// # Errors
    /// 订阅失败（主题非法/客户端构造失败/PEM 不可读）。
    pub async fn run(&self) -> DomainResult<()> {
        let mut receiver = self.subscription.subscribe(&self.topic, self.qos).await?;
        while let Some(message) = receiver.recv().await {
            if let Err(e) = self.ingest_message(&message).await {
                warn!(topic = %message.topic, error = %e, "MQTT 消息接入失败（已丢弃并计数）");
                self.counters.add_dropped(1);
            }
        }
        warn!(topic = %self.topic, "MQTT 订阅通道关闭，接收器退出（broker 侧可能已断开）");
        Ok(())
    }
}

#[async_trait]
impl Receiver for MqttReceiver {
    fn protocol(&self) -> IngestProtocol {
        IngestProtocol::Mqtt
    }

    fn describe(&self) -> ReceiverDescriptor {
        let shared = match &self.plan.shared {
            Some(shared) => format!("，共享订阅 group={} filter={}", shared.group, shared.filter),
            None => String::new(),
        };
        ReceiverDescriptor {
            name: "mqtt".to_string(),
            protocol: IngestProtocol::Mqtt,
            status: ReceiverStatus::Ready,
            note: format!(
                "MQTT 订阅 {}，主题 `{}`，QoS {}{shared}；{}（载荷按 JSON 数组/NDJSON/单条拆分后归一化）",
                self.subscription.describe(),
                self.topic,
                self.qos,
                self.protocol.describe()
            ),
            todo: Some(
                "TODO ingest-mqtt-v5-auth：MQTT 5 AUTH 增强认证未接线（只用 username/password）；\
                 TODO ingest-mqtt-v5-properties-extra：v5 用户属性随 origin 透传（事件 extra 的 log.origin），\
                 未写入独立的 Event::extra 键（IngestPipeline 无逐条元数据通道）"
                    .to_string(),
            ),
            mock_replay: false,
        }
    }

    async fn start(&self, _pipeline: Arc<IngestPipeline>, _source: LogSource) -> DomainResult<()> {
        self.run().await
    }

    async fn poll_once(&self, _pipeline: Arc<IngestPipeline>, _source: LogSource, _max: usize) -> DomainResult<usize> {
        Err(DomainError::NotImplemented(
            "MQTT 为推送型（订阅）接收器，无轮询语义；请调用 run/ingest_message".to_string(),
        ))
    }
}
