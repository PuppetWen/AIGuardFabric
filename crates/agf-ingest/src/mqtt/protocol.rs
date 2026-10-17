//! MQTT 协议版本与 **MQTT 5 专有特性**配置：`AGF_INGEST_MQTT_PROTOCOL_VERSION`、
//! 会话过期/Clean Start、Topic Alias、Receive Maximum、订阅选项（NoLocal / RetainAsPublished /
//! RetainHandling）与 CONNECT 用户属性。
//!
//! ## 兼容性口径（**不静默忽略配置**）
//!
//! * 默认 **3.1.1**（既有部署行为逐字节不变：`clean_session=true`、无 v5 字段）；
//! * `AGF_INGEST_MQTT_PROTOCOL_VERSION=5` ⇒ 走 `rumqttc::v5` 客户端，下面的 v5 项生效；
//! * 版本仍是 3.1.1 却**显式配了** v5 专有项（会话过期/Topic Alias/Receive Maximum/
//!   订阅选项/用户属性）⇒ [`MqttProtocolConfig::validate`] **直接报错**：
//!   3.1.1 的报文里根本没有这些字段，"配了却当没看见"是最坏的一种沉默——
//!   调用方会把它写进 `/readyz` 的 notes（"MQTT 未启用：…"），运维一眼能看到原因。
//! * `AGF_INGEST_MQTT_PROTOCOL_VERSION` 取值无法识别 ⇒ 只 `warn` + 回退 3.1.1，
//!   但**记住"曾经配过"**（[`MqttProtocolConfig::version_configured`]），描述里如实写出。
//!
//! `clean_start`（`AGF_INGEST_MQTT_CLEAN_START`）在 v3.1.1 上映射为 `clean_session`、
//! 在 v5 上映射为 `clean start`——两边都是真实存在的字段，因此**不算** v5 专有项。

use super::*;

/// 环境变量：协议版本（`3.1.1` / `5`）。
pub const ENV_PROTOCOL_VERSION: &str = "AGF_INGEST_MQTT_PROTOCOL_VERSION";
/// 环境变量：会话过期间隔（秒，v5 专有）。
pub const ENV_SESSION_EXPIRY_SECS: &str = "AGF_INGEST_MQTT_SESSION_EXPIRY_SECS";
/// 环境变量：Clean Start / clean session。
pub const ENV_CLEAN_START: &str = "AGF_INGEST_MQTT_CLEAN_START";
/// 环境变量：我方接受的最大 topic alias（v5 专有；`0` = 不接受）。
pub const ENV_TOPIC_ALIAS_MAX: &str = "AGF_INGEST_MQTT_TOPIC_ALIAS_MAX";
/// 环境变量：Receive Maximum（流控，v5 专有）。
pub const ENV_RECEIVE_MAXIMUM: &str = "AGF_INGEST_MQTT_RECEIVE_MAXIMUM";
/// 环境变量：订阅选项 NoLocal（v5 专有）。
pub const ENV_SUBSCRIBE_NOLOCAL: &str = "AGF_INGEST_MQTT_SUBSCRIBE_NOLOCAL";
/// 环境变量：订阅选项 RetainAsPublished（v5 专有）。
pub const ENV_SUBSCRIBE_RETAIN_AS_PUBLISHED: &str = "AGF_INGEST_MQTT_SUBSCRIBE_RETAIN_AS_PUBLISHED";
/// 环境变量：订阅选项 RetainHandling（0/1/2，v5 专有）。
pub const ENV_SUBSCRIBE_RETAIN_HANDLING: &str = "AGF_INGEST_MQTT_SUBSCRIBE_RETAIN_HANDLING";
/// 环境变量：CONNECT 用户属性（`k=v,k2=v2`，v5 专有）。
pub const ENV_USER_PROPERTIES: &str = "AGF_INGEST_MQTT_USER_PROPERTIES";

/// MQTT 协议版本。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum MqttProtocolVersion {
    /// MQTT 3.1.1（默认；`rumqttc` 的 v4 客户端）。
    #[default]
    V3_1_1,
    /// MQTT 5.0（`rumqttc::v5`）。
    V5,
}

impl MqttProtocolVersion {
    /// 稳定短标识（日志/描述用）。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::V3_1_1 => "3.1.1",
            Self::V5 => "5",
        }
    }

    /// 解析（宽松接受 `3.1.1` / `3.1` / `311` / `3` / `v3.1.1` / `4` 与 `5` / `5.0` / `v5`）。
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let normalized = text.trim().to_ascii_lowercase();
        let normalized = normalized.trim_start_matches('v').replace(['_', '-'], ".");
        match normalized.as_str() {
            "3.1.1" | "3.1" | "311" | "31" | "3" | "4" => Some(Self::V3_1_1),
            "5" | "5.0" | "50" | "5.0.0" => Some(Self::V5),
            _ => None,
        }
    }

    /// 是否 MQTT 5。
    #[must_use]
    pub const fn is_v5(self) -> bool {
        matches!(self, Self::V5)
    }
}

/// Retain Handling（v5 订阅选项第 4/5 位）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum RetainHandling {
    /// `0`：每次订阅都下发保留消息（**默认**，与既有行为一致）。
    #[default]
    OnEverySubscribe,
    /// `1`：只在订阅**不存在**时下发。
    OnNewSubscribe,
    /// `2`：从不下发保留消息。
    Never,
}

impl RetainHandling {
    /// 数值（0/1/2）。
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::OnEverySubscribe => 0,
            Self::OnNewSubscribe => 1,
            Self::Never => 2,
        }
    }

    /// 解析（非法 ⇒ `None`，由调用方 `warn` + 回退默认）。
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text.trim() {
            "0" => Some(Self::OnEverySubscribe),
            "1" => Some(Self::OnNewSubscribe),
            "2" => Some(Self::Never),
            _ => None,
        }
    }

    /// 人读描述。
    #[must_use]
    pub const fn describe(self) -> &'static str {
        match self {
            Self::OnEverySubscribe => "每次订阅都下发保留消息(0)",
            Self::OnNewSubscribe => "仅新订阅下发保留消息(1)",
            Self::Never => "从不下发保留消息(2)",
        }
    }
}

/// 订阅选项（MQTT 5 专有）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SubscribeOptions {
    /// NoLocal：**不接收自己发布的消息**（同 ClientID）。
    pub no_local: bool,
    /// RetainAsPublished：转发时保留原始 RETAIN 标志（默认 false ⇒ broker 置 0）。
    pub retain_as_published: bool,
    /// Retain Handling。
    pub retain_handling: RetainHandling,
}

impl SubscribeOptions {
    /// 是否全部为默认值（默认值下 v3.1.1 与 v5 的订阅语义一致）。
    #[must_use]
    pub fn is_default(&self) -> bool {
        !self.no_local && !self.retain_as_published && self.retain_handling == RetainHandling::OnEverySubscribe
    }

    /// 人读描述（`/readyz` 用）。
    #[must_use]
    pub fn describe(&self) -> String {
        format!(
            "NoLocal={}，RetainAsPublished={}，RetainHandling={}",
            self.no_local,
            self.retain_as_published,
            self.retain_handling.describe()
        )
    }
}

/// MQTT 5 专有特性配置（v3.1.1 连接上除 [`Self::clean_start`] 外都不生效）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MqttV5Config {
    /// 会话过期间隔（秒；`None` ⇒ 不下发该属性，broker 用默认 0）。
    pub session_expiry_secs: Option<u32>,
    /// Clean Start（v5）/ clean session（v3.1.1）；默认 `true`（既有行为）。
    pub clean_start: bool,
    /// 我方声明的 `topic_alias_maximum`（入站别名上限；`0` = 不接受别名）。
    pub topic_alias_max: u16,
    /// Receive Maximum（流控；`None` ⇒ 不下发，broker 默认 65535）。
    pub receive_maximum: Option<u16>,
    /// 订阅选项。
    pub subscribe: SubscribeOptions,
    /// CONNECT 用户属性（v5 专有）。
    pub user_properties: Vec<(String, String)>,
    /// **显式配置**过的项（键名；用于版本兼容性校验与描述）。
    pub configured: Vec<&'static str>,
}

impl Default for MqttV5Config {
    fn default() -> Self {
        Self {
            session_expiry_secs: None,
            clean_start: true,
            topic_alias_max: 0,
            receive_maximum: None,
            subscribe: SubscribeOptions::default(),
            user_properties: Vec::new(),
            configured: Vec::new(),
        }
    }
}

impl MqttV5Config {
    /// 从进程环境读取。
    #[must_use]
    pub fn from_env() -> Self {
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    /// 从任意键值查找函数读取（单测注入用）。
    #[must_use]
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Self {
        let mut configured: Vec<&'static str> = Vec::new();

        let (session_expiry, expiry_set) = u32_of(&lookup, ENV_SESSION_EXPIRY_SECS);
        if expiry_set {
            configured.push(ENV_SESSION_EXPIRY_SECS);
        }
        let (topic_alias_max, alias_set) = u16_of(&lookup, ENV_TOPIC_ALIAS_MAX);
        let topic_alias_max = topic_alias_max.unwrap_or(0);
        if alias_set && topic_alias_max > 0 {
            configured.push(ENV_TOPIC_ALIAS_MAX);
        }
        let (receive_maximum, receive_set) = u16_of(&lookup, ENV_RECEIVE_MAXIMUM);
        if receive_set {
            configured.push(ENV_RECEIVE_MAXIMUM);
        }
        if receive_maximum == Some(0) {
            warn!(key = ENV_RECEIVE_MAXIMUM, "Receive Maximum=0 非法（MQTT 5 要求 ≥1），按未配置处理");
        }
        let no_local = flag(&lookup, ENV_SUBSCRIBE_NOLOCAL, false);
        if no_local {
            configured.push(ENV_SUBSCRIBE_NOLOCAL);
        }
        let retain_as_published = flag(&lookup, ENV_SUBSCRIBE_RETAIN_AS_PUBLISHED, false);
        if retain_as_published {
            configured.push(ENV_SUBSCRIBE_RETAIN_AS_PUBLISHED);
        }
        let (retain_handling, handling_set) = retain_handling_of(&lookup);
        if handling_set {
            configured.push(ENV_SUBSCRIBE_RETAIN_HANDLING);
        }
        let user_properties = user_properties_of(&lookup);
        if !user_properties.is_empty() {
            configured.push(ENV_USER_PROPERTIES);
        }
        // Clean Start 只是"显式配过就记一笔"（v3.1.1 上映射为 clean_session，不算 v5 专有）
        let clean_start = flag(&lookup, ENV_CLEAN_START, true);
        if lookup(ENV_CLEAN_START).is_some() {
            configured.push(ENV_CLEAN_START);
        }
        if clean_start && session_expiry == Some(0) {
            warn!("MQTT 5：CleanStart=true 且会话过期=0 ⇒ 每次连接都是全新会话（会话过期的配置形同未生效）");
        }
        Self {
            session_expiry_secs: session_expiry,
            clean_start,
            topic_alias_max,
            receive_maximum: receive_maximum.filter(|value| *value > 0),
            subscribe: SubscribeOptions { no_local, retain_as_published, retain_handling },
            user_properties,
            configured,
        }
    }

    /// **v5 专有**且被显式配置的项（clean start 不算：v3.1.1 也有等价字段）。
    #[must_use]
    pub fn v5_only_configured(&self) -> Vec<&'static str> {
        self.configured.iter().copied().filter(|key| *key != ENV_CLEAN_START).collect()
    }

    /// 人读描述（`/readyz` notes 用）。
    #[must_use]
    pub fn describe(&self) -> String {
        if self.configured.is_empty() {
            return "MQTT 5 专有特性未配置（默认值）".to_string();
        }
        let session = match self.session_expiry_secs {
            Some(secs) => format!("会话过期={secs}s"),
            None => "会话过期=未配置".to_string(),
        };
        let alias = format!("TopicAlias≤{}", self.topic_alias_max);
        let receive = match self.receive_maximum {
            Some(max) => format!("ReceiveMaximum={max}"),
            None => "ReceiveMaximum=未配置".to_string(),
        };
        let props = if self.user_properties.is_empty() {
            String::new()
        } else {
            format!("，CONNECT 用户属性={} 条", self.user_properties.len())
        };
        format!(
            "{session}，CleanStart={}，{alias}，{receive}，{}（订阅选项）{props}",
            self.clean_start,
            self.subscribe.describe()
        )
    }
}

/// 协议配置（版本 + v5 特性）。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MqttProtocolConfig {
    /// 协议版本。
    pub version: MqttProtocolVersion,
    /// 版本是否被**显式配置**（配了但无法识别时为 `true`：描述里如实说明回退）。
    pub version_configured: bool,
    /// v5 专有特性。
    pub v5: MqttV5Config,
}

impl MqttProtocolConfig {
    /// 从进程环境读取。
    #[must_use]
    pub fn from_env() -> Self {
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    /// 从任意键值查找函数读取（单测注入用）。
    #[must_use]
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Self {
        let raw = lookup(ENV_PROTOCOL_VERSION).map(|value| value.trim().to_string()).filter(|v| !v.is_empty());
        let (version, version_configured) = match &raw {
            None => (MqttProtocolVersion::default(), false),
            Some(text) => match MqttProtocolVersion::parse(text) {
                Some(version) => (version, true),
                None => {
                    warn!(
                        key = ENV_PROTOCOL_VERSION,
                        value = %text,
                        "MQTT 协议版本无法识别（可用 3.1.1 / 5），回退 3.1.1（**不静默**：描述与 /readyz 会写明）"
                    );
                    (MqttProtocolVersion::default(), true)
                }
            },
        };
        Self { version, version_configured, v5: MqttV5Config::from_lookup(&lookup) }
    }

    /// 版本与 v5 专有配置是否自洽。
    ///
    /// # Errors
    /// 版本为 3.1.1（或回退到 3.1.1）却显式配置了 v5 专有项——3.1.1 报文里没有这些字段，
    /// 与其"配了当没看见"，不如明确报错（调用方写进 `/readyz` 的 notes）。
    pub fn validate(&self) -> DomainResult<()> {
        if self.version.is_v5() {
            return Ok(());
        }
        let offending = self.v5.v5_only_configured();
        if offending.is_empty() {
            return Ok(());
        }
        let reason = if self.version_configured {
            format!("{ENV_PROTOCOL_VERSION}={} ", self.version.as_str())
        } else {
            format!("{ENV_PROTOCOL_VERSION} 未配置（默认 {}）", self.version.as_str())
        };
        Err(DomainError::Config(format!(
            "MQTT 5 专有特性在 MQTT {} 上不存在：{reason}，却配置了 {offending:?}；\
             请设 {ENV_PROTOCOL_VERSION}=5（或清掉这些变量）——绝不静默忽略配置",
            self.version.as_str()
        )))
    }

    /// 人读描述（`/readyz` notes 与 `MqttReceiver::describe` 共用）。
    #[must_use]
    pub fn describe(&self) -> String {
        let fallback = if self.version_configured && !self.version.is_v5() {
            "（版本显式配置/回退为 3.1.1）"
        } else {
            ""
        };
        if self.version.is_v5() {
            format!("MQTT {}：{}", self.version.as_str(), self.v5.describe())
        } else {
            format!("MQTT {}{fallback}：clean_session={}", self.version.as_str(), self.v5.clean_start)
        }
    }
}

/// u32 环境变量：返回 `(值, 是否显式配置)`；非法值只 `warn` + `(None, true)`。
fn u32_of(lookup: &impl Fn(&str) -> Option<String>, key: &str) -> (Option<u32>, bool) {
    match lookup(key) {
        Some(raw) if !raw.trim().is_empty() => match raw.trim().parse::<u32>() {
            Ok(value) => (Some(value), true),
            Err(e) => {
                warn!(key, value = %raw, error = %e, "环境变量不是合法数字，按未配置处理（**不静默**：仍记为显式配置）");
                (None, true)
            }
        },
        _ => (None, false),
    }
}

/// u16 环境变量：返回 `(值, 是否显式配置)`。
fn u16_of(lookup: &impl Fn(&str) -> Option<String>, key: &str) -> (Option<u16>, bool) {
    match lookup(key) {
        Some(raw) if !raw.trim().is_empty() => match raw.trim().parse::<u16>() {
            Ok(value) => (Some(value), true),
            Err(e) => {
                warn!(key, value = %raw, error = %e, "环境变量不是合法数字（0..65535），按未配置处理");
                (None, true)
            }
        },
        _ => (None, false),
    }
}

/// Retain Handling：`(值, 是否显式配置)`；越界/非法 ⇒ `warn` + 默认 0。
fn retain_handling_of(lookup: &impl Fn(&str) -> Option<String>) -> (RetainHandling, bool) {
    match lookup(ENV_SUBSCRIBE_RETAIN_HANDLING) {
        Some(raw) if !raw.trim().is_empty() => match RetainHandling::parse(&raw) {
            Some(value) => (value, true),
            None => {
                warn!(value = %raw, "RetainHandling 只能是 0/1/2，回退 0（每次订阅都下发保留消息）");
                (RetainHandling::OnEverySubscribe, true)
            }
        },
        _ => (RetainHandling::OnEverySubscribe, false),
    }
}

/// CONNECT 用户属性：`k=v,k2=v2`（值里可含 `=`；空项与缺 `=` 的项只 `warn` 并跳过）。
fn user_properties_of(lookup: &impl Fn(&str) -> Option<String>) -> Vec<(String, String)> {
    let Some(raw) = lookup(ENV_USER_PROPERTIES).map(|value| value.trim().to_string()).filter(|v| !v.is_empty()) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in raw.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        match entry.split_once('=') {
            Some((key, value)) if !key.trim().is_empty() => {
                out.push((key.trim().to_string(), value.trim().to_string()));
            }
            _ => warn!(entry, "用户属性项缺少 `key=value` 形态，已跳过"),
        }
    }
    out
}
