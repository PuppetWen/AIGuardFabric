//! 订阅抽象 `MqttSubscription` 与 `rumqttc` 真实实现 `RumqttSubscription`（QoS 0/1/2、共享订阅、TLS）。

// ---------------------------------------------------------------------------
// 订阅抽象
// ---------------------------------------------------------------------------

use super::*;

/// MQTT 订阅抽象：真实实现走 `rumqttc`；测试注入内存实现（**测试不依赖 docker**）。
#[async_trait]
pub trait MqttSubscription: Send + Sync + std::fmt::Debug {
    /// 订阅主题并返回消息接收端（broker 不可达时**不报错**：由后台任务退避重连）。
    ///
    /// # Errors
    /// 主题非法或客户端构造失败。
    async fn subscribe(&self, topic: &str, qos: u8) -> DomainResult<mpsc::Receiver<MqttMessage>>;

    /// 描述（`/readyz` 与日志用）。
    fn describe(&self) -> String;
}

/// `rumqttc` 真实实现（MQTT 3.1.1：TLS / **WebSocket** / 遗嘱 / 共享订阅 / 退避重连）。
#[derive(Clone)]
pub struct RumqttSubscription {
    endpoint: MqttEndpoint,
    client_id: String,
    username: Option<String>,
    password: Option<String>,
    keep_alive_secs: u64,
    channel_capacity: usize,
    tls: Option<MqttTlsMaterial>,
    will: Option<MqttWill>,
    backoff: BackoffPolicy,
    /// clean session（`AGF_INGEST_MQTT_CLEAN_START`；默认真 = 既有行为）。
    clean_start: bool,
    counters: Arc<MqttLinkCounters>,
}

impl std::fmt::Debug for RumqttSubscription {
    /// 刻意手写：`password` 与 TLS 私钥**绝不**出现在调试输出里。
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RumqttSubscription")
            .field("endpoint", &self.endpoint)
            .field("client_id", &self.client_id)
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .field("keep_alive_secs", &self.keep_alive_secs)
            .field("channel_capacity", &self.channel_capacity)
            .field("tls", &self.tls)
            .field("will", &self.will)
            .field("backoff", &self.backoff)
            .field("clean_start", &self.clean_start)
            .field("counters", &self.counters.snapshot())
            .finish()
    }
}

impl RumqttSubscription {
    /// 构造（匿名、明文 TCP）。
    #[must_use]
    pub fn new(endpoint: MqttEndpoint, client_id: impl Into<String>) -> Self {
        Self {
            endpoint,
            client_id: client_id.into(),
            username: None,
            password: None,
            keep_alive_secs: 30,
            channel_capacity: 1024,
            tls: None,
            will: None,
            backoff: BackoffPolicy::default(),
            clean_start: true,
            counters: link_counters(),
        }
    }

    /// 设置用户名/口令。
    #[must_use]
    pub fn with_credentials(mut self, username: impl Into<String>, password: impl Into<String>) -> Self {
        self.username = Some(username.into());
        self.password = Some(password.into());
        self
    }

    /// 启用 TLS（材料已读取好 PEM）。
    #[must_use]
    pub fn with_tls(mut self, material: MqttTlsMaterial) -> Self {
        self.tls = Some(material);
        self
    }

    /// 注册遗嘱消息。
    #[must_use]
    pub fn with_will(mut self, will: MqttWill) -> Self {
        self.will = Some(will);
        self
    }

    /// 退避策略。
    #[must_use]
    pub fn with_backoff(mut self, backoff: BackoffPolicy) -> Self {
        self.backoff = backoff;
        self
    }

    /// clean session（`AGF_INGEST_MQTT_CLEAN_START`；v3.1.1 的等价字段）。
    #[must_use]
    pub const fn with_clean_start(mut self, clean_start: bool) -> Self {
        self.clean_start = clean_start;
        self
    }

    /// 是否 clean session。
    #[must_use]
    pub const fn clean_start(&self) -> bool {
        self.clean_start
    }

    /// 注入链路计数器（测试用；默认进程内单例）。
    #[must_use]
    pub fn with_link_counters(mut self, counters: Arc<MqttLinkCounters>) -> Self {
        self.counters = counters;
        self
    }

    /// 客户端 id。
    #[must_use]
    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    /// 是否启用 TLS。
    #[must_use]
    pub const fn tls_enabled(&self) -> bool {
        self.tls.is_some()
    }

    /// 遗嘱配置。
    #[must_use]
    pub const fn will(&self) -> Option<&MqttWill> {
        self.will.as_ref()
    }

    /// 组装 `MqttOptions`（**可离线单测**：不发起任何网络连接）。
    ///
    /// # Errors
    /// 端点声明 TLS 却没有 TLS 材料（**绝不静默降级为明文连接**）、`ws://` 却开了 TLS
    /// （scheme 与传输层矛盾），或 TLS 材料装配失败（PEM 非法）。
    pub fn options(&self) -> DomainResult<MqttOptions> {
        if self.endpoint.tls && self.tls.is_none() {
            return Err(DomainError::Config(format!(
                "MQTT broker 用 {}:// 声明了 TLS，但没有装配 TLS 材料：请配置 {ENV_TLS} / {ENV_TLS_CA}；\
                 绝不静默降级为明文连接",
                self.endpoint.scheme()
            )));
        }
        if self.endpoint.websocket && !self.endpoint.tls && self.tls.is_some() {
            return Err(DomainError::Config(
                "MQTT：ws:// 是**明文** WebSocket，却配置了 TLS 材料（{ENV_TLS}=1 或证书）；\
                 请改用 wss://（scheme 与传输层必须一致，绝不静默改写）"
                    .to_string(),
            ));
        }
        // WebSocket 端点必须把**完整 URL** 交给 rumqttc（它会直接当请求 URI 解析）
        let mut options = MqttOptions::new(self.client_id.clone(), self.endpoint.broker_address(), self.endpoint.port);
        options.set_keep_alive(Duration::from_secs(self.keep_alive_secs.max(5)));
        options.set_clean_session(self.clean_start);
        options.set_max_packet_size(1024 * 1024, 1024 * 1024);
        if let (Some(username), Some(password)) = (&self.username, &self.password) {
            options.set_credentials(username.clone(), password.clone());
        }
        match (&self.tls, self.endpoint.websocket) {
            (None, false) => {}
            (None, true) => {
                options.set_transport(Transport::Ws);
            }
            (Some(material), true) => {
                options.set_transport(Transport::Wss(TlsConfiguration::Rustls(material.rustls_config()?)));
            }
            (Some(material), false) => {
                options.set_transport(material.transport()?);
            }
        }
        if let Some(will) = &self.will {
            options.set_last_will(will.to_last_will());
        }
        Ok(options)
    }
}

#[async_trait]
impl MqttSubscription for RumqttSubscription {
    async fn subscribe(&self, topic: &str, qos: u8) -> DomainResult<mpsc::Receiver<MqttMessage>> {
        let plan = plan_subscribe(topic, qos)?;
        let options = self.options()?;
        let (client, mut eventloop) = AsyncClient::new(options, self.channel_capacity.max(16));
        // 订阅请求进入本地队列即可返回；真正的 CONNACK/SUBACK 在后台任务里驱动
        client.subscribe(plan.topic.clone(), qos_from_u8(plan.qos)).await.map_err(|e| {
            DomainError::DependencyUnavailable {
                dependency: "mqtt".to_string(),
                cause: format!("提交订阅请求失败: {e}"),
            }
        })?;
        let (sender, receiver) = mpsc::channel(self.channel_capacity.max(16));
        let label = self.describe();
        let topic_label = plan.topic.clone();
        let shared = plan.shared.clone();
        let will_label = self.will.as_ref().map(MqttWill::describe);
        let mut backoff = self.backoff.clone();
        let counters = Arc::clone(&self.counters);
        tokio::spawn(async move {
            loop {
                match eventloop.poll().await {
                    Ok(Event::Incoming(Packet::Publish(publish))) => {
                        backoff.reset();
                        let message = MqttMessage::new(
                            publish.topic.clone(),
                            publish.payload.to_vec(),
                            qos_to_u8(publish.qos),
                            publish.retain,
                        );
                        if sender.send(message).await.is_err() {
                            debug!(broker = %label, "MQTT 接收端已关闭，订阅任务退出");
                            break;
                        }
                    }
                    Ok(Event::Incoming(Packet::ConnAck(_))) => {
                        backoff.reset();
                        info!(
                            broker = %label,
                            topic = %topic_label,
                            shared_group = ?shared.as_ref().map(|s| s.group.as_str()),
                            will = ?will_label,
                            "MQTT 已连接并订阅"
                        );
                    }
                    Ok(_) => {}
                    Err(e) => {
                        // 连接失败只 warn + 退避重连：绝不因此让接入进程失败
                        let kind = classify_link_error(&e.to_string());
                        counters.record_error(kind);
                        counters.record_reconnect();
                        let delay = backoff.next_delay();
                        warn!(
                            broker = %label,
                            error = %e,
                            kind = kind.as_str(),
                            backoff_secs = delay.as_secs(),
                            next_secs = backoff.current_secs(),
                            "MQTT 连接异常，退避重连"
                        );
                        tokio::time::sleep(delay).await;
                    }
                }
            }
        });
        Ok(receiver)
    }

    fn describe(&self) -> String {
        let tls = match &self.tls {
            Some(_) => "，TLS 开启",
            None => "",
        };
        let will = match &self.will {
            Some(will) => format!("，遗嘱 {}", will.topic),
            None => String::new(),
        };
        // scheme 已含 ws/wss 区分；TCP 路径保持既有 `mqtt://host:port` 形状
        format!(
            "{}://{}:{} (client_id={}{tls}{will})",
            self.endpoint.scheme(),
            self.endpoint.host,
            self.endpoint.port,
            self.client_id
        )
    }
}

// ---------------------------------------------------------------------------
// 接收器
// ---------------------------------------------------------------------------
