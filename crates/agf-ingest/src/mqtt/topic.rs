//! 协议无关的消息/端点模型与主题语义：broker 端点解析、QoS 映射、通配主题与共享订阅（`$share/`）校验、订阅计划。

// ---------------------------------------------------------------------------
// 协议无关的消息与端点
// ---------------------------------------------------------------------------

use super::*;

/// 协议无关的 MQTT 消息（便于单测注入，不需要 broker）。
///
/// `properties` 是 **MQTT 5 专有**的入站属性（topic alias / 用户属性 / 内容类型…）；
/// MQTT 3.1.1 连接上恒为默认空值（v3 的 PUBLISH 没有这些字段）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MqttMessage {
    /// 主题（**已解析 topic alias**：v5 的"仅别名 PUBLISH"到这里已经是真实主题）。
    pub topic: String,
    /// 载荷。
    pub payload: Vec<u8>,
    /// QoS（0/1/2）。
    pub qos: u8,
    /// retain 标志。
    pub retain: bool,
    /// v5 入站属性（v3.1.1 恒为空）。
    pub properties: MqttMessageProperties,
}

impl MqttMessage {
    /// 构造（v3.1.1 语义：无 v5 属性）。
    #[must_use]
    pub fn new(topic: impl Into<String>, payload: Vec<u8>, qos: u8, retain: bool) -> Self {
        Self { topic: topic.into(), payload, qos, retain, properties: MqttMessageProperties::default() }
    }

    /// 带上 v5 属性（v5 订阅任务用）。
    #[must_use]
    pub fn with_properties(mut self, properties: MqttMessageProperties) -> Self {
        self.properties = properties;
        self
    }

    /// 透传给流水线的 `origin`（含 v5 属性查询串，属性会落在事件的 `extra["log.origin"]`）。
    #[must_use]
    pub fn origin(&self, broker: &str) -> String {
        match self.properties.to_origin_query() {
            Some(query) => format!("mqtt://{broker}/{}?{query}", self.topic),
            None => format!("mqtt://{broker}/{}", self.topic),
        }
    }

    /// **MQTT 5 连接**上用的 `origin`：除属性外，额外带上消息级的 `qos` / `retain`。
    ///
    /// 存在的理由：v5 的订阅选项 `RetainAsPublished` 会**改变入站 RETAIN 标志**
    /// （0 ⇒ broker 把 RETAIN 置 0 后再转发），而 `IngestPipeline` 只有 `(payload, origin)`
    /// 一条元数据通道——不写进 origin 就等于"这个选项生效了没有"无法在真机上被外部观测。
    /// v5 才走本方法，因此 v3.1.1 的 origin 形状（与历史逐字节一致）不受影响。
    #[must_use]
    pub fn origin_with_facts(&self, broker: &str) -> String {
        let mut parts: Vec<String> = Vec::new();
        if let Some(query) = self.properties.to_origin_query() {
            parts.push(query);
        }
        parts.push(format!("agf.mqtt.qos={}", self.qos));
        parts.push(format!("agf.mqtt.retain={}", self.retain));
        format!("mqtt://{broker}/{}?{}", self.topic, parts.join("&"))
    }
}

/// broker 端点解析结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MqttEndpoint {
    /// 主机。
    pub host: String,
    /// 端口。
    pub port: u16,
    /// 是否声明了 TLS（`mqtts://` / `wss://` / `ssl://` / `tls://`）——**已接线**，见 [`MqttTlsConfig`]。
    pub tls: bool,
    /// 是否 MQTT over **WebSocket**（`ws://` / `wss://`）——**已接线**（传输层选 `Transport::Ws/Wss`）。
    pub websocket: bool,
    /// WebSocket 路径（`ws://host:9001/mqtt` ⇒ `/mqtt`；非 WS 端点为空串）。
    pub path: String,
}

impl MqttEndpoint {
    /// scheme 文本（`mqtt` / `mqtts` / `ws` / `wss`）。
    #[must_use]
    pub const fn scheme(&self) -> &'static str {
        match (self.websocket, self.tls) {
            (true, true) => "wss",
            (true, false) => "ws",
            (false, true) => "mqtts",
            (false, false) => "mqtt",
        }
    }

    /// 交给 `rumqttc` 的 broker 地址。
    ///
    /// TCP/TLS 走 `host` + 独立端口字段；**WebSocket 必须是完整 URL**——`rumqttc` 的
    /// `Transport::Ws/Wss` 会把 `broker_addr` 直接当 WebSocket 请求 URI 解析
    /// （其 `eventloop.rs` 里 `into_client_request`），少了 scheme/端口/路径会连不上。
    #[must_use]
    pub fn broker_address(&self) -> String {
        if self.websocket {
            format!("{}://{}:{}{}", self.scheme(), self.host, self.port, self.path)
        } else {
            self.host.clone()
        }
    }

    /// 人读描述（`/readyz` 与日志用）。
    #[must_use]
    pub fn describe(&self) -> String {
        format!("{}://{}:{}", self.scheme(), self.host, self.port)
    }
}

/// WebSocket 端点的默认路径（mosquitto 的 `protocol websockets` 监听不校验路径，
/// 但 MQTT-over-WS 生态默认 `/mqtt`；写成 `ws://host:9001/xxx` 可覆盖）。
pub const DEFAULT_WS_PATH: &str = "/mqtt";

/// 解析 broker 端点（纯函数）。
///
/// 接受 `mqtt://host:1883` / `tcp://host:1883` / `mqtts://host:8883` / `ssl://host` /
/// **`ws://host:9001`** / **`wss://host:9002`**（可带路径，如 `ws://host:9001/mqtt`）/
/// `host:1883` / `host`（TCP 默认 1883；TLS 默认 8883；`ws` 默认 80、`wss` 默认 443）。
///
/// # Errors
/// scheme 不受支持、主机为空或端口非法。
pub fn parse_endpoint(endpoint: &str) -> DomainResult<MqttEndpoint> {
    let trimmed = endpoint.trim();
    if trimmed.is_empty() {
        return Err(DomainError::Config("MQTT 需要 broker 地址（connection.endpoint）".to_string()));
    }
    let (scheme, rest) = match trimmed.split_once("://") {
        Some((scheme, rest)) => (scheme.to_ascii_lowercase(), rest.to_string()),
        None => ("mqtt".to_string(), trimmed.to_string()),
    };
    let (tls, websocket) = match scheme.as_str() {
        "mqtt" | "tcp" => (false, false),
        "mqtts" | "ssl" | "tls" => (true, false),
        "ws" => (false, true),
        "wss" => (true, true),
        other => {
            return Err(DomainError::Config(format!(
                "MQTT 不支持的 scheme: {other}://（可用 mqtt:// / mqtts:// / ws:// / wss://）"
            )));
        }
    };
    // 主机:端口 与（WS 的）路径分开：`ws://host:9001/mqtt` 的路径必须原样带进请求 URI
    let (authority, raw_path) = match rest.split_once('/') {
        Some((authority, path)) => (authority.to_string(), format!("/{path}")),
        None => (rest.clone(), String::new()),
    };
    if authority.is_empty() {
        return Err(DomainError::Config(format!("MQTT broker 地址缺少主机: {endpoint}")));
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => {
            let port = port.parse::<u16>().map_err(|e| DomainError::Config(format!("MQTT 端口 {port:?} 非法: {e}")))?;
            (host.to_string(), port)
        }
        None => (authority, default_port(websocket, tls)),
    };
    if host.is_empty() {
        return Err(DomainError::Config(format!("MQTT broker 地址缺少主机: {endpoint}")));
    }
    let path = if websocket {
        if raw_path.is_empty() { DEFAULT_WS_PATH.to_string() } else { raw_path }
    } else {
        String::new()
    };
    Ok(MqttEndpoint { host, port, tls, websocket, path })
}

/// scheme 默认端口（MQTT 1883/8883；WebSocket 80/443，与 `rumqttc` 的 URL 默认口径一致）。
const fn default_port(websocket: bool, tls: bool) -> u16 {
    match (websocket, tls) {
        (true, true) => 443,
        (true, false) => 80,
        (false, true) => 8883,
        (false, false) => 1883,
    }
}

/// QoS（0/1/2）→ `rumqttc::QoS`（MQTT 3.1.1 连接用）。
#[must_use]
pub fn qos_from_u8(qos: u8) -> QoS {
    match qos {
        0 => QoS::AtMostOnce,
        2 => QoS::ExactlyOnce,
        _ => QoS::AtLeastOnce,
    }
}

/// `rumqttc::QoS` → QoS 数值。
#[must_use]
pub const fn qos_to_u8(qos: QoS) -> u8 {
    match qos {
        QoS::AtMostOnce => 0,
        QoS::AtLeastOnce => 1,
        QoS::ExactlyOnce => 2,
    }
}

/// QoS（0/1/2）→ **MQTT 5** 的 `QoS`（`rumqttc::v5` 是独立模块，枚举与 3.1.1 不通用）。
#[must_use]
pub fn qos_from_u8_v5(qos: u8) -> V5QoS {
    match qos {
        0 => V5QoS::AtMostOnce,
        2 => V5QoS::ExactlyOnce,
        _ => V5QoS::AtLeastOnce,
    }
}

/// **MQTT 5** 的 `QoS` → 数值。
#[must_use]
pub const fn qos_to_u8_v5(qos: V5QoS) -> u8 {
    match qos {
        V5QoS::AtMostOnce => 0,
        V5QoS::AtLeastOnce => 1,
        V5QoS::ExactlyOnce => 2,
    }
}

// ---------------------------------------------------------------------------
// 主题与共享订阅
// ---------------------------------------------------------------------------

/// 共享订阅：`$share/<group>/<filter>`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedSubscription {
    /// 共享组名（同组内竞争消费）。
    pub group: String,
    /// 实际主题过滤器（如 `agf/sec/#`）。
    pub filter: String,
}

impl SharedSubscription {
    /// 提交给 broker 的完整主题。
    #[must_use]
    pub fn share_topic(&self) -> String {
        format!("$share/{}/{}", self.group, self.filter)
    }
}

/// 共享订阅前缀（MQTT 规范固定字面量，大小写敏感）。
pub const SHARED_SUBSCRIPTION_PREFIX: &str = "$share/";

/// 校验 MQTT 主题过滤器（`+`/`#` 必须独占一层，`#` 只能在末尾）。
///
/// # Errors
/// 过滤器为空、含非法通配符用法。
pub fn validate_topic_filter(filter: &str) -> DomainResult<()> {
    if filter.trim().is_empty() {
        return Err(DomainError::Config("MQTT 主题过滤器为空".to_string()));
    }
    let levels: Vec<&str> = filter.split('/').collect();
    for (index, level) in levels.iter().enumerate() {
        if level.contains('#') {
            if *level != "#" {
                return Err(DomainError::Config(format!(
                    "MQTT 主题过滤器 {filter:?} 非法：`#` 必须独占一层（第 {} 层为 {level:?}）",
                    index + 1
                )));
            }
            if index + 1 != levels.len() {
                return Err(DomainError::Config(format!("MQTT 主题过滤器 {filter:?} 非法：`#` 只能是最后一层")));
            }
        }
        if level.contains('+') && *level != "+" {
            return Err(DomainError::Config(format!(
                "MQTT 主题过滤器 {filter:?} 非法：`+` 必须独占一层（第 {} 层为 {level:?}）",
                index + 1
            )));
        }
    }
    Ok(())
}

/// 解析 `$share/<group>/<filter>`；非共享主题返回 `Ok(None)`。
///
/// # Errors
/// 共享订阅语法非法：组名为空/含通配符、缺少过滤器、过滤器非法、嵌套 `$share`。
pub fn parse_shared_subscription(topic: &str) -> DomainResult<Option<SharedSubscription>> {
    let trimmed = topic.trim();
    let Some(rest) = trimmed.strip_prefix(SHARED_SUBSCRIPTION_PREFIX) else {
        return Ok(None);
    };
    let Some((group, filter)) = rest.split_once('/') else {
        return Err(DomainError::Config(format!(
            "共享订阅 {topic:?} 非法：形如 {SHARED_SUBSCRIPTION_PREFIX}<group>/<filter>，缺少主题过滤器"
        )));
    };
    if group.is_empty() {
        return Err(DomainError::Config(format!("共享订阅 {topic:?} 非法：共享组名为空")));
    }
    if group.contains('+') || group.contains('#') {
        return Err(DomainError::Config(format!("共享订阅 {topic:?} 非法：共享组名不得包含通配符")));
    }
    if filter.is_empty() {
        return Err(DomainError::Config(format!("共享订阅 {topic:?} 非法：主题过滤器为空")));
    }
    if filter.starts_with(SHARED_SUBSCRIPTION_PREFIX) {
        return Err(DomainError::Config(format!("共享订阅 {topic:?} 非法：不允许嵌套 {SHARED_SUBSCRIPTION_PREFIX}")));
    }
    validate_topic_filter(filter)?;
    Ok(Some(SharedSubscription { group: group.to_string(), filter: filter.to_string() }))
}

/// 一次订阅请求的解析结果。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SubscribePlan {
    /// 提交给 broker 的完整主题（共享订阅会带 `$share/<group>/` 前缀）。
    pub topic: String,
    /// 共享订阅解析结果（非共享主题为 `None`）。
    pub shared: Option<SharedSubscription>,
    /// QoS（0/1/2）。
    pub qos: u8,
}

/// 解析订阅计划：严格校验共享订阅；**普通主题**的过滤器非法只 `warn`（保持既有行为，
/// 由 broker 决定是否接受），共享订阅非法则直接报错（必须在启用阶段就暴露）。
///
/// # Errors
/// 主题为空；共享订阅语法非法；QoS 越界。
pub fn plan_subscribe(topic: &str, qos: u8) -> DomainResult<SubscribePlan> {
    let trimmed = topic.trim();
    if trimmed.is_empty() {
        return Err(DomainError::Config("MQTT 需要订阅主题（connection.topic）".to_string()));
    }
    if qos > 2 {
        return Err(DomainError::Config(format!("MQTT qos {qos} 超出范围（0/1/2）")));
    }
    let shared = parse_shared_subscription(trimmed)?;
    if shared.is_none() {
        if let Err(e) = validate_topic_filter(trimmed) {
            warn!(topic = trimmed, error = %e, "MQTT 主题过滤器形态可疑（仍按原样订阅，由 broker 裁决）");
        }
    }
    Ok(SubscribePlan {
        topic: shared.as_ref().map_or_else(|| trimmed.to_string(), SharedSubscription::share_topic),
        shared,
        qos,
    })
}

// ---------------------------------------------------------------------------
// TLS
// ---------------------------------------------------------------------------
