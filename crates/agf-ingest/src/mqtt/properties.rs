//! MQTT 5 入站 **Properties** 与 **Topic Alias** 解析：属性保真携带、别名表按规范校验。
//!
//! ## Topic Alias（MQTT 5 §3.3.2.3.4）
//!
//! broker 可以把"重复出现的长主题"压成一个整数别名：首个 PUBLISH 带 `topic + alias`，
//! 之后只带 `alias`（topic 为空）。本模块的 [`TopicAliasTable`] 就是这条会话的状态机：
//!
//! | 入站形态 | 处理 |
//! |---|---|
//! | 有 topic、无 alias | 原样使用 |
//! | 有 topic、有 alias | 登记 `alias → topic`，并使用该 topic |
//! | 无 topic、有 alias（**已登记**） | 用别名映射出的 topic |
//! | 无 topic、有 alias（未登记/越界/为 0） | **协议错误** ⇒ 丢弃该条并 `warn`（不猜主题） |
//!
//! `topic_alias_maximum` 由我方在 CONNECT 时声明（`AGF_INGEST_MQTT_TOPIC_ALIAS_MAX`）；
//! 未声明（默认 0）时**任何** alias 都是越界——`rumqttc` 不会替我们兜底。
//!
//! ## 属性透传
//!
//! [`MqttMessageProperties`] 完整保留 v5 PUBLISH 的属性（用户属性 / 内容类型 / 关联数据…）。
//! 其中**用户属性等会以查询串形式随 `origin` 透传**（见 [`MqttMessageProperties::to_origin_query`]），
//! 从而落在事件的 `extra["log.origin"]` 与 `raw_logs.origin` 上——不需要改动
//! `IngestPipeline`（它按 `(payload, origin)` 接入，没有逐条元数据通道）。

use super::*;

/// v5 入站 PUBLISH 的属性（v3.1.1 恒为默认空值）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MqttMessageProperties {
    /// topic alias（原始值；`MqttMessage::topic` 已是解析后的真实主题）。
    pub topic_alias: Option<u16>,
    /// 消息过期间隔（秒）。
    pub message_expiry_interval: Option<u32>,
    /// 内容类型（如 `application/json`）。
    pub content_type: Option<String>,
    /// 响应主题。
    pub response_topic: Option<String>,
    /// 关联数据（**base64**：原始是二进制）。
    pub correlation_data: Option<String>,
    /// 载荷格式指示（0=未指定字节，1=UTF-8）。
    pub payload_format_indicator: Option<u8>,
    /// 订阅标识符（broker 按订阅回填）。
    pub subscription_identifiers: Vec<usize>,
    /// 用户属性（`k=v` 列表，保序）。
    pub user_properties: Vec<(String, String)>,
}

impl MqttMessageProperties {
    /// 是否完全没有属性（v3.1.1 或"v5 但 broker 没带属性"）。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.topic_alias.is_none()
            && self.message_expiry_interval.is_none()
            && self.content_type.is_none()
            && self.response_topic.is_none()
            && self.correlation_data.is_none()
            && self.payload_format_indicator.is_none()
            && self.subscription_identifiers.is_empty()
            && self.user_properties.is_empty()
    }

    /// 透传查询串（`None` = 没有任何属性，保持既有 `origin` 形状不变）。
    ///
    /// 形如 `agf.mqtt.topic_alias=3&agf.mqtt.content_type=application%2Fjson&agf.mqtt.up.k=v`
    /// （用户属性前缀 `agf.mqtt.up.`，键值都做百分号转义，避免 `&`/`=` 注入）。
    #[must_use]
    pub fn to_origin_query(&self) -> Option<String> {
        if self.is_empty() {
            return None;
        }
        let mut parts: Vec<String> = Vec::new();
        if let Some(alias) = self.topic_alias {
            parts.push(format!("agf.mqtt.topic_alias={alias}"));
        }
        if let Some(expiry) = self.message_expiry_interval {
            parts.push(format!("agf.mqtt.message_expiry_interval={expiry}"));
        }
        if let Some(format) = self.payload_format_indicator {
            parts.push(format!("agf.mqtt.payload_format_indicator={format}"));
        }
        if let Some(content_type) = &self.content_type {
            parts.push(format!("agf.mqtt.content_type={}", percent_encode(content_type)));
        }
        if let Some(response_topic) = &self.response_topic {
            parts.push(format!("agf.mqtt.response_topic={}", percent_encode(response_topic)));
        }
        if let Some(correlation) = &self.correlation_data {
            parts.push(format!("agf.mqtt.correlation_data={}", percent_encode(correlation)));
        }
        for id in &self.subscription_identifiers {
            parts.push(format!("agf.mqtt.subscription_identifier={id}"));
        }
        for (key, value) in &self.user_properties {
            parts.push(format!("agf.mqtt.up.{k}={v}", k = percent_encode(key), v = percent_encode(value)));
        }
        Some(parts.join("&"))
    }

    /// 人读描述（日志用；**截断**，避免一条消息刷爆日志）。
    #[must_use]
    pub fn describe(&self) -> String {
        if self.is_empty() {
            return "无属性（v3.1.1 或无属性 v5 PUBLISH）".to_string();
        }
        let mut parts: Vec<String> = Vec::new();
        if let Some(alias) = self.topic_alias {
            parts.push(format!("topic_alias={alias}"));
        }
        if let Some(content_type) = &self.content_type {
            parts.push(format!("content_type={content_type}"));
        }
        if !self.user_properties.is_empty() {
            parts.push(format!("user_properties={}", self.user_properties.len()));
        }
        if !self.subscription_identifiers.is_empty() {
            parts.push(format!("subscription_ids={:?}", self.subscription_identifiers));
        }
        parts.join("，")
    }
}

/// 查询串转义（RFC3986 unreserved 之外一律 `%XX`）。
fn percent_encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => out.push(char::from(*byte)),
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

/// Topic Alias 解析失败（都是**协议错误**，调用方丢弃该条并如实计数/告警）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TopicAliasError {
    /// 别名 0 或超出我方声明的 `topic_alias_maximum`。
    OutOfRange { alias: u16, max: u16 },
    /// topic 为空且别名**未登记**（我方无从得知真实主题，绝不猜）。
    Unknown(u16),
    /// topic 为空且没有别名（畸形 PUBLISH）。
    MissingTopic,
}

impl TopicAliasError {
    /// 稳定短标识（日志/指标标签用）。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OutOfRange { .. } => "alias_out_of_range",
            Self::Unknown(_) => "unknown_alias",
            Self::MissingTopic => "missing_topic",
        }
    }
}

impl std::fmt::Display for TopicAliasError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OutOfRange { alias, max } => {
                write!(f, "topic alias {alias} 越界（我方声明的 topic_alias_maximum={max}）")
            }
            Self::Unknown(alias) => write!(f, "topic alias {alias} 未登记（broker 未先发带主题的 PUBLISH）"),
            Self::MissingTopic => write!(f, "PUBLISH 既无主题也无 topic alias"),
        }
    }
}

/// 入站 topic alias 表（**每条连接一份**，MQTT 5 规范要求别名在连接内有效）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TopicAliasTable {
    max: u16,
    entries: BTreeMap<u16, String>,
}

impl TopicAliasTable {
    /// 构造（`max` = 我方在 CONNECT 里声明的 `topic_alias_maximum`；0 ⇒ 不接受任何别名）。
    #[must_use]
    pub fn new(max: u16) -> Self {
        Self { max, entries: BTreeMap::new() }
    }

    /// 我方声明的上限。
    #[must_use]
    pub const fn max(&self) -> u16 {
        self.max
    }

    /// 已登记的别名数。
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// 是否没有登记任何别名。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// 按规范解析一条入站 PUBLISH 的 (topic, alias)，返回**真实主题**。
    ///
    /// # Errors
    /// 见 [`TopicAliasError`]（越界/未登记/无主题）。
    pub fn resolve(&mut self, topic: &str, alias: Option<u16>) -> Result<String, TopicAliasError> {
        let topic = topic.trim();
        match alias {
            None => {
                if topic.is_empty() {
                    return Err(TopicAliasError::MissingTopic);
                }
                Ok(topic.to_string())
            }
            Some(0) => Err(TopicAliasError::OutOfRange { alias: 0, max: self.max }),
            Some(alias) if alias > self.max => Err(TopicAliasError::OutOfRange { alias, max: self.max }),
            Some(alias) if !topic.is_empty() => {
                self.entries.insert(alias, topic.to_string());
                Ok(topic.to_string())
            }
            Some(alias) => self.entries.get(&alias).cloned().ok_or(TopicAliasError::Unknown(alias)),
        }
    }
}
