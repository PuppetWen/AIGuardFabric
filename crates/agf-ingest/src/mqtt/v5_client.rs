//! MQTT 5 订阅实现 [`RumqttV5Subscription`]：`rumqttc::v5` 客户端 + WebSocket/TLS 传输 +
//! 会话过期/Clean Start/Topic Alias/Receive Maximum/订阅选项/用户属性。
//!
//! 与 MQTT 3.1.1 的 [`RumqttSubscription`] **共用**同一个 [`MqttSubscription`] 抽象与
//! 接收/解析流水线（`MqttReceiver` 只认 `MqttMessage`）：版本只决定"用哪个客户端库 + 下发哪些
//! 协议字段"，落库路径一条都不变。
//!
//! ## 为什么 v5 单独一个客户端
//!
//! `rumqttc` 的 v5 支持是**独立模块**（`rumqttc::v5::{AsyncClient, EventLoop, MqttOptions,
//! Packet}`，与 v4 的类型不通用）。因此这里单独实现订阅任务——但**降级口径一致**：
//! broker 不可达只 `warn` + 指数退避重连，错误按 [`MqttLinkError`] 分类计数，
//! 绝不让接入进程失败。

// ---------------------------------------------------------------------------
// MQTT 5 订阅
// ---------------------------------------------------------------------------

use super::*;

use rumqttc::v5::mqttbytes::v5::{ConnAckProperties, Filter, Packet as V5Packet, PublishProperties, RetainForwardRule};
use rumqttc::v5::{AsyncClient as V5AsyncClient, Event as V5Event, EventLoop as V5EventLoop, MqttOptions as V5Options};

/// MQTT 5 订阅实现（TLS / WebSocket / 遗嘱 / 退避重连 / v5 专有特性）。
#[derive(Clone)]
pub struct RumqttV5Subscription {
    endpoint: MqttEndpoint,
    client_id: String,
    username: Option<String>,
    password: Option<String>,
    keep_alive_secs: u64,
    channel_capacity: usize,
    tls: Option<MqttTlsMaterial>,
    will: Option<MqttWill>,
    backoff: BackoffPolicy,
    v5: MqttV5Config,
    counters: Arc<MqttLinkCounters>,
}

impl std::fmt::Debug for RumqttV5Subscription {
    /// 刻意手写：`password` 与 TLS 私钥**绝不**出现在调试输出里。
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RumqttV5Subscription")
            .field("endpoint", &self.endpoint)
            .field("client_id", &self.client_id)
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .field("keep_alive_secs", &self.keep_alive_secs)
            .field("channel_capacity", &self.channel_capacity)
            .field("tls", &self.tls)
            .field("will", &self.will)
            .field("backoff", &self.backoff)
            .field("v5", &self.v5)
            .field("counters", &self.counters.snapshot())
            .finish()
    }
}

impl RumqttV5Subscription {
    /// 构造（匿名、明文 TCP、v5 默认特性）。
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
            v5: MqttV5Config::default(),
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

    /// v5 专有特性。
    #[must_use]
    pub fn with_v5(mut self, v5: MqttV5Config) -> Self {
        self.v5 = v5;
        self
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

    /// v5 特性配置。
    #[must_use]
    pub const fn v5(&self) -> &MqttV5Config {
        &self.v5
    }

    /// 端点。
    #[must_use]
    pub const fn endpoint(&self) -> &MqttEndpoint {
        &self.endpoint
    }

    /// 组装 v5 `MqttOptions`（**可离线单测**：不发起任何网络连接）。
    ///
    /// # Errors
    /// 端点声明 TLS 却没有 TLS 材料（**绝不静默降级为明文**）、`ws://` 却开了 TLS
    /// （scheme 与传输层矛盾）、或 TLS 材料装配失败（PEM 非法）。
    pub fn options(&self) -> DomainResult<V5Options> {
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
        let mut options = V5Options::new(self.client_id.clone(), self.endpoint.broker_address(), self.endpoint.port);
        options.set_keep_alive(Duration::from_secs(self.keep_alive_secs.max(5)));
        // Clean Start（v5）：默认 true ⇒ 与既有 v3.1.1 的 clean_session=true 行为一致
        options.set_clean_start(self.v5.clean_start);
        options.set_max_packet_size(Some(1024 * 1024));
        if let Some(secs) = self.v5.session_expiry_secs {
            options.set_session_expiry_interval(Some(secs));
        }
        if self.v5.topic_alias_max > 0 {
            // 声明我方接受的入站别名上限；broker 只允许在该范围内用别名
            options.set_topic_alias_max(Some(self.v5.topic_alias_max));
        }
        if let Some(max) = self.v5.receive_maximum {
            options.set_receive_maximum(Some(max));
        }
        if !self.v5.user_properties.is_empty() {
            options.set_user_properties(self.v5.user_properties.clone());
        }
        if let (Some(username), Some(password)) = (&self.username, &self.password) {
            options.set_credentials(username.clone(), password.clone());
        }
        options.set_transport(self.transport()?);
        if let Some(will) = &self.will {
            options.set_last_will(will.to_last_will_v5());
        }
        Ok(options)
    }

    /// 传输层：TCP / TLS / **WebSocket** / **WSS**（`rumqttc` 的 `Transport` 在 v4/v5 之间共用）。
    fn transport(&self) -> DomainResult<Transport> {
        match (&self.tls, self.endpoint.websocket) {
            (None, false) => Ok(Transport::Tcp),
            (None, true) => Ok(Transport::Ws),
            (Some(material), true) => Ok(Transport::Wss(TlsConfiguration::Rustls(material.rustls_config()?))),
            (Some(material), false) => Ok(material.transport()?),
        }
    }

    /// 订阅过滤器（**v5 订阅选项**在这里下发：NoLocal / RetainAsPublished / RetainHandling）。
    #[must_use]
    pub fn filter(&self, topic: &str, qos: u8) -> Filter {
        Filter {
            path: topic.to_string(),
            qos: qos_from_u8_v5(qos),
            nolocal: self.v5.subscribe.no_local,
            preserve_retain: self.v5.subscribe.retain_as_published,
            retain_forward_rule: retain_forward_rule(self.v5.subscribe.retain_handling),
        }
    }
}

/// Retain Handling → `rumqttc::v5` 的 `RetainForwardRule`。
#[must_use]
pub const fn retain_forward_rule(handling: RetainHandling) -> RetainForwardRule {
    match handling {
        RetainHandling::OnEverySubscribe => RetainForwardRule::OnEverySubscribe,
        RetainHandling::OnNewSubscribe => RetainForwardRule::OnNewSubscribe,
        RetainHandling::Never => RetainForwardRule::Never,
    }
}

/// v5 `PublishProperties` → 我们自己的属性模型（**保真**：用户属性/内容类型/关联数据都带上）。
#[must_use]
pub fn properties_from_v5(properties: &Option<PublishProperties>) -> MqttMessageProperties {
    let Some(properties) = properties else { return MqttMessageProperties::default() };
    MqttMessageProperties {
        topic_alias: properties.topic_alias,
        message_expiry_interval: properties.message_expiry_interval,
        content_type: properties.content_type.clone(),
        response_topic: properties.response_topic.clone(),
        correlation_data: properties
            .correlation_data
            .as_ref()
            .map(|data| base64::Engine::encode(&base64::engine::general_purpose::STANDARD, data)),
        payload_format_indicator: properties.payload_format_indicator,
        subscription_identifiers: properties.subscription_identifiers.clone(),
        user_properties: properties.user_properties.clone(),
    }
}

/// CONNACK 属性的如实描述（`/readyz`/日志用；broker 侧的流控与会话能力一眼可见）。
#[must_use]
pub fn describe_connack(properties: &Option<ConnAckProperties>) -> String {
    let Some(properties) = properties else { return "broker 未下发 CONNACK 属性".to_string() };
    format!(
        "broker: 会话过期={:?}s，ReceiveMaximum={:?}，TopicAliasMax={:?}，最大QoS={:?}，\
         保留消息可用={:?}，共享订阅可用={:?}，最大包={:?}",
        properties.session_expiry_interval,
        properties.receive_max,
        properties.topic_alias_max,
        properties.max_qos,
        properties.retain_available,
        properties.shared_subscription_available,
        properties.max_packet_size,
    )
}

#[async_trait]
impl MqttSubscription for RumqttV5Subscription {
    async fn subscribe(&self, topic: &str, qos: u8) -> DomainResult<mpsc::Receiver<MqttMessage>> {
        let plan = plan_subscribe(topic, qos)?;
        let options = self.options()?;
        let (client, eventloop) = V5AsyncClient::new(options, self.channel_capacity.max(16));
        // 订阅请求进入本地队列即可返回；真正的 CONNACK/SUBACK 在后台任务里驱动
        client.subscribe_many(vec![self.filter(&plan.topic, plan.qos)]).await.map_err(|e| {
            DomainError::DependencyUnavailable {
                dependency: "mqtt".to_string(),
                cause: format!("提交 MQTT 5 订阅请求失败: {e}"),
            }
        })?;
        let (sender, receiver) = mpsc::channel(self.channel_capacity.max(16));
        let label = self.describe();
        let topic_label = plan.topic.clone();
        let shared = plan.shared.clone();
        let will_label = self.will.as_ref().map(MqttWill::describe);
        let v5_label = self.v5.describe();
        spawn_v5_pump(V5Pump {
            eventloop,
            sender,
            label,
            topic_label,
            shared_group: shared.as_ref().map(|s| s.group.clone()),
            will_label,
            v5_label,
            counters: Arc::clone(&self.counters),
            backoff: self.backoff.clone(),
            // 每个连接一份别名表（MQTT 5 规范：别名只在连接内有效）
            aliases: TopicAliasTable::new(self.v5.topic_alias_max),
        });
        Ok(receiver)
    }

    fn describe(&self) -> String {
        let tls = if self.tls.is_some() { "，TLS 开启" } else { "" };
        let will = match &self.will {
            Some(will) => format!("，遗嘱 {}", will.topic),
            None => String::new(),
        };
        format!(
            "{}://{}:{} (client_id={}，MQTT 5{tls}{will})",
            self.endpoint.scheme(),
            self.endpoint.host,
            self.endpoint.port,
            self.client_id
        )
    }
}

/// 事件泵的输入（单独一个结构体只是为了不把 8 个参数塞进函数签名）。
struct V5Pump {
    eventloop: V5EventLoop,
    sender: mpsc::Sender<MqttMessage>,
    label: String,
    topic_label: String,
    shared_group: Option<String>,
    will_label: Option<String>,
    v5_label: String,
    counters: Arc<MqttLinkCounters>,
    backoff: BackoffPolicy,
    aliases: TopicAliasTable,
}

/// 后台事件泵：PUBLISH → 别名解析 → 消息通道；连接异常 → 分类计数 + 退避重连。
fn spawn_v5_pump(pump: V5Pump) {
    let V5Pump {
        mut eventloop,
        sender,
        label,
        topic_label,
        shared_group,
        will_label,
        v5_label,
        counters,
        mut backoff,
        mut aliases,
    } = pump;
    tokio::spawn(async move {
        loop {
            match eventloop.poll().await {
                Ok(V5Event::Incoming(V5Packet::Publish(publish))) => {
                    backoff.reset();
                    let properties = properties_from_v5(&publish.properties);
                    let raw_topic = String::from_utf8_lossy(&publish.topic).to_string();
                    let resolved = match aliases.resolve(&raw_topic, properties.topic_alias) {
                        Ok(topic) => topic,
                        Err(e) => {
                            // 协议错误：丢弃该条并如实告警（**绝不猜主题**）
                            warn!(
                                broker = %label,
                                kind = e.as_str(),
                                alias = ?properties.topic_alias,
                                "MQTT 5 topic alias 解析失败，丢弃该条 PUBLISH"
                            );
                            counters.record_error(MqttLinkError::Protocol);
                            continue;
                        }
                    };
                    if let Some(alias) = properties.topic_alias {
                        // 正向证据：broker 真的用了别名（登记/复用）；没有这条日志 = 对端没启用出站别名
                        debug!(
                            broker = %label,
                            alias,
                            topic = %resolved,
                            registered = aliases.len(),
                            "MQTT 5 入站 topic alias 已解析"
                        );
                    }
                    let message =
                        MqttMessage::new(resolved, publish.payload.to_vec(), qos_to_u8_v5(publish.qos), publish.retain)
                            .with_properties(properties);
                    if sender.send(message).await.is_err() {
                        debug!(broker = %label, "MQTT 接收端已关闭，订阅任务退出");
                        break;
                    }
                }
                Ok(V5Event::Incoming(V5Packet::ConnAck(connack))) => {
                    backoff.reset();
                    info!(
                        broker = %label,
                        topic = %topic_label,
                        session_present = connack.session_present,
                        shared_group = ?shared_group,
                        will = ?will_label,
                        v5 = %v5_label,
                        connack = %describe_connack(&connack.properties),
                        "MQTT 5 已连接并订阅"
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
                        "MQTT 5 连接异常，退避重连"
                    );
                    tokio::time::sleep(delay).await;
                }
            }
        }
    });
}
