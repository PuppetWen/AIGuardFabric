//! Syslog 报文模型：PRI 上限、RFC 版本标识、结构化数据元素与 `SyslogMessage`（facility/severity 归一）。

use super::*;

/// 单条 syslog 报文的最大 PRI 数值（`facility * 8 + severity`）。
pub const MAX_PRI: u16 = 191;

/// RFC 版本标识。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SyslogRfc {
    /// RFC3164（BSD syslog，无年份）。
    Rfc3164,
    /// RFC5424（结构化、带版本号）。
    Rfc5424,
}

impl SyslogRfc {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Rfc3164 => "rfc3164",
            Self::Rfc5424 => "rfc5424",
        }
    }
}

/// 一个结构化数据元素（RFC5424 `[SD-ID PARAM="VALUE" ...]`）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructuredDataElement {
    /// SD-ID。
    pub id: String,
    /// 参数键值（保持出现顺序）。
    pub params: Vec<(String, String)>,
}

impl StructuredDataElement {
    /// 读取参数。
    #[must_use]
    pub fn param(&self, key: &str) -> Option<&str> {
        self.params.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    }
}

/// 解析后的 syslog 报文。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyslogMessage {
    /// 来源 RFC。
    pub rfc: SyslogRfc,
    /// facility（0-23 常用，最大 23；数值范围 0-23 = PRI/8）。
    pub facility: u8,
    /// syslog severity（0-7，0 最严重）。
    pub severity_code: u8,
    /// 映射到平台等级后的严重等级。
    pub severity: Severity,
    /// RFC5424 VERSION（RFC3164 为 `None`）。
    pub version: Option<u16>,
    /// 事件时间（解析成功时）。
    pub timestamp: Option<Timestamp>,
    /// 时间戳原文（保真，便于回放时重解析）。
    pub timestamp_raw: Option<String>,
    /// 主机名（NILVALUE `-` 归一为 `None`）。
    pub hostname: Option<String>,
    /// APP-NAME / TAG。
    pub app_name: Option<String>,
    /// PROCID / PID。
    pub proc_id: Option<String>,
    /// MSGID（RFC5424）。
    pub msg_id: Option<String>,
    /// 结构化数据元素（RFC3164 为空）。
    pub structured_data: Vec<StructuredDataElement>,
    /// 消息体。
    pub msg: String,
}

impl SyslogMessage {
    /// 读取结构化数据参数（`sd_param("timeQuality", "tzKnown")`）。
    #[must_use]
    pub fn sd_param(&self, sd_id: &str, key: &str) -> Option<&str> {
        self.structured_data.iter().find(|e| e.id == sd_id).and_then(|e| e.param(key))
    }

    /// facility 名称（IANA 常用取值；未知返回 `unknown`）。
    #[must_use]
    pub fn facility_name(&self) -> &'static str {
        facility_name(self.facility)
    }

    /// 转成解析引擎可直接消费的 AGF-ECS 字段表。
    ///
    /// 键名语义与 `agf_core::event::Event` 一致（`host.name` / `event.time` / `message`…），
    /// 厂商模板可在其上追加 `mapping` 做二次映射。
    #[must_use]
    pub fn to_fields(&self) -> std::collections::BTreeMap<String, serde_json::Value> {
        use serde_json::Value;
        let mut out = std::collections::BTreeMap::new();
        out.insert("event.severity".to_string(), Value::from(self.severity.as_str()));
        out.insert("syslog.rfc".to_string(), Value::from(self.rfc.as_str()));
        out.insert("syslog.facility".to_string(), Value::from(self.facility));
        out.insert("syslog.facility_name".to_string(), Value::from(self.facility_name()));
        out.insert("syslog.severity_code".to_string(), Value::from(self.severity_code));
        if let Some(ts) = self.timestamp {
            out.insert("event.time".to_string(), Value::from(ts.to_rfc3339()));
        }
        if let Some(raw) = &self.timestamp_raw {
            out.insert("syslog.timestamp_raw".to_string(), Value::from(raw.clone()));
        }
        if let Some(h) = &self.hostname {
            out.insert("host.name".to_string(), Value::from(h.clone()));
        }
        if let Some(a) = &self.app_name {
            out.insert("syslog.app_name".to_string(), Value::from(a.clone()));
        }
        if let Some(p) = &self.proc_id {
            out.insert("syslog.proc_id".to_string(), Value::from(p.clone()));
        }
        if let Some(m) = &self.msg_id {
            out.insert("syslog.msg_id".to_string(), Value::from(m.clone()));
        }
        if let Some(v) = self.version {
            out.insert("syslog.version".to_string(), Value::from(v));
        }
        for sd in &self.structured_data {
            for (k, v) in &sd.params {
                out.insert(format!("syslog.sd.{}.{}", sd.id, k), Value::from(v.clone()));
            }
        }
        out.insert("message".to_string(), Value::from(self.msg.clone()));
        out
    }

    /// 是否为"解析出结构化线索"的报文（有主机名或应用名）。
    #[must_use]
    pub fn is_attributed(&self) -> bool {
        self.hostname.is_some() || self.app_name.is_some()
    }
}

/// syslog severity（0-7）→ 平台 [`Severity`]。
///
/// 映射依据：0=emergency/1=alert/2=critical 是"需立即介入"，3=error 归 High，
/// 4=warning 归 Medium，5=notice 归 Low，6=informational/7=debug 归 Info。
#[must_use]
pub const fn severity_from_syslog(code: u8) -> Severity {
    match code {
        0..=2 => Severity::Critical,
        3 => Severity::High,
        4 => Severity::Medium,
        5 => Severity::Low,
        _ => Severity::Info,
    }
}

/// facility（0-23）→ 名称。
#[must_use]
pub const fn facility_name(code: u8) -> &'static str {
    match code {
        0 => "kern",
        1 => "user",
        2 => "mail",
        3 => "daemon",
        4 => "auth",
        5 => "syslog",
        6 => "lpr",
        7 => "news",
        8 => "uucp",
        9 => "cron",
        10 => "authpriv",
        11 => "ftp",
        12 => "ntp",
        13 => "security",
        14 => "console",
        15 => "solaris-cron",
        16 => "local0",
        17 => "local1",
        18 => "local2",
        19 => "local3",
        20 => "local4",
        21 => "local5",
        22 => "local6",
        23 => "local7",
        _ => "unknown",
    }
}
