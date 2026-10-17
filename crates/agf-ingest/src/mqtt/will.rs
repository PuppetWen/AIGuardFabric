//! 遗嘱（LWT）与重连退避：`AGF_INGEST_MQTT_WILL*` / `AGF_INGEST_MQTT_RECONNECT*` 配置与退避状态机。

// ---------------------------------------------------------------------------
// 遗嘱消息（LWT）
// ---------------------------------------------------------------------------

use super::*;

/// 环境变量：遗嘱主题。
pub const ENV_WILL_TOPIC: &str = "AGF_INGEST_MQTT_WILL_TOPIC";
/// 环境变量：遗嘱载荷。
pub const ENV_WILL_PAYLOAD: &str = "AGF_INGEST_MQTT_WILL_PAYLOAD";
/// 环境变量：遗嘱 QoS。
pub const ENV_WILL_QOS: &str = "AGF_INGEST_MQTT_WILL_QOS";
/// 环境变量：遗嘱 retain。
pub const ENV_WILL_RETAIN: &str = "AGF_INGEST_MQTT_WILL_RETAIN";
/// 遗嘱默认载荷。
pub const DEFAULT_WILL_PAYLOAD: &str = "agf-ingest collector offline";

/// 遗嘱消息（Last Will and Testament）：客户端**非正常断开**时由 broker 代发，
/// 用于"采集器掉线"告警（正常 DISCONNECT 不会触发）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MqttWill {
    /// 主题（必填；`AGF_INGEST_MQTT_WILL_TOPIC`）。
    pub topic: String,
    /// 载荷（默认 [`DEFAULT_WILL_PAYLOAD`]）。
    pub payload: Vec<u8>,
    /// QoS（0/1/2，默认 1）。
    pub qos: u8,
    /// retain（默认 false；置 true 便于"读一次就知道离线"的监控）。
    pub retain: bool,
}

impl MqttWill {
    /// 从进程环境读取。
    #[must_use]
    pub fn from_env() -> Option<Self> {
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    /// 从任意键值查找函数读取：**配了 topic 才生效**；只有载荷/QoS/retain 而没有主题
    /// 视为配置不完整 ⇒ `warn` + 不注册（不静默按默认主题发遗嘱）。
    #[must_use]
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Option<Self> {
        let topic = lookup(ENV_WILL_TOPIC).map(|value| value.trim().to_string()).filter(|v| !v.is_empty());
        let payload = lookup(ENV_WILL_PAYLOAD).filter(|value| !value.is_empty());
        let qos = lookup(ENV_WILL_QOS);
        let retain = lookup(ENV_WILL_RETAIN);
        if topic.is_none() {
            if payload.is_some() || qos.is_some() || retain.is_some() {
                warn!("MQTT 遗嘱配置缺少 {ENV_WILL_TOPIC}，遗嘱未注册（其余配置被忽略）");
            }
            return None;
        }
        let topic = topic?;
        let mut qos_value = number(&lookup, ENV_WILL_QOS, 1);
        if qos_value > 2 {
            warn!(value = qos_value, "MQTT 遗嘱 QoS 越界（0/1/2），回退为 1");
            qos_value = 1;
        }
        // 主题形态可疑只 warn（与订阅主题同口径：由 broker 裁决）
        if let Err(e) = validate_topic_filter(&topic) {
            warn!(topic = %topic, error = %e, "MQTT 遗嘱主题形态可疑（仍按原样注册）");
        }
        Some(Self {
            topic,
            payload: payload.unwrap_or_else(|| DEFAULT_WILL_PAYLOAD.to_string()).into_bytes(),
            qos: u8::try_from(qos_value).unwrap_or(1),
            retain: flag(&lookup, ENV_WILL_RETAIN, false),
        })
    }

    /// → `rumqttc::LastWill`（MQTT 3.1.1 连接用）。
    #[must_use]
    pub fn to_last_will(&self) -> LastWill {
        LastWill::new(self.topic.clone(), self.payload.clone(), qos_from_u8(self.qos), self.retain)
    }

    /// → `rumqttc::v5::mqttbytes::v5::LastWill`（**MQTT 5** 连接用；v5 的遗嘱还允许
    /// 属性，这里不设属性 —— 与 3.1.1 的语义逐字段等价）。
    #[must_use]
    pub fn to_last_will_v5(&self) -> V5LastWill {
        V5LastWill::new(self.topic.clone(), self.payload.clone(), qos_from_u8_v5(self.qos), self.retain, None)
    }

    /// 人读描述（`/readyz` 用）。
    #[must_use]
    pub fn describe(&self) -> String {
        format!("LWT topic={} qos={} retain={} payload={} 字节", self.topic, self.qos, self.retain, self.payload.len())
    }
}

// ---------------------------------------------------------------------------
// 退避重连
// ---------------------------------------------------------------------------

/// 环境变量：退避初始秒数。
pub const ENV_RECONNECT_INITIAL_SECS: &str = "AGF_INGEST_MQTT_RECONNECT_INITIAL_SECS";
/// 环境变量：退避上限秒数。
pub const ENV_RECONNECT_MAX_SECS: &str = "AGF_INGEST_MQTT_RECONNECT_MAX_SECS";

/// 指数退避状态机（**纯逻辑**，可离线单测）：1s → 2s → 4s → … → 上限，成功后 [`Self::reset`]。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackoffPolicy {
    initial_secs: u64,
    max_secs: u64,
    current: u64,
}

impl Default for BackoffPolicy {
    fn default() -> Self {
        Self::new(1, 30)
    }
}

impl BackoffPolicy {
    /// 构造（`initial` 至少 1s，`max` 不得小于 `initial`）。
    #[must_use]
    pub fn new(initial_secs: u64, max_secs: u64) -> Self {
        let initial = initial_secs.max(1);
        let max = max_secs.max(initial);
        Self { initial_secs: initial, max_secs: max, current: initial }
    }

    /// 从进程环境读取（非法值只 warn + 回退默认）。
    #[must_use]
    pub fn from_env() -> Self {
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    /// 从任意键值查找函数读取。
    #[must_use]
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Self {
        let defaults = Self::default();
        Self::new(
            number(&lookup, ENV_RECONNECT_INITIAL_SECS, defaults.initial_secs),
            number(&lookup, ENV_RECONNECT_MAX_SECS, defaults.max_secs),
        )
    }

    /// 取下一次退避时长并推进状态（`1,2,4,…,max,max,…`）。
    pub fn next_delay(&mut self) -> Duration {
        let delay = self.current;
        self.current = self.current.saturating_mul(2).min(self.max_secs);
        Duration::from_secs(delay)
    }

    /// 连接恢复：回到初始退避。
    pub fn reset(&mut self) {
        self.current = self.initial_secs;
    }

    /// 下一次退避时长（秒，只读）。
    #[must_use]
    pub const fn current_secs(&self) -> u64 {
        self.current
    }

    /// 初始 / 上限（秒）。
    #[must_use]
    pub const fn bounds_secs(&self) -> (u64, u64) {
        (self.initial_secs, self.max_secs)
    }
}

// ---------------------------------------------------------------------------
// 链路错误分类计数（Prometheus）
// ---------------------------------------------------------------------------
