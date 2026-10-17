//! 日志源与南向采集配置（§4.5）。

mod record;
pub use record::{SourceRecord, native_receiver_protocol};

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::enums::{HealthState, IngestProtocol};
use crate::ids::{Id, TenantId, TenantScoped};
use crate::time::Timestamp;

/// 日志源（一个接入端点 = 一个 source）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogSource {
    /// 主键。
    pub id: Id,
    /// 租户。
    pub tenant_id: TenantId,
    /// 名称。
    pub name: String,
    /// 接入协议。
    pub protocol: IngestProtocol,
    /// 厂商。
    #[serde(default)]
    pub vendor: String,
    /// 产品。
    #[serde(default)]
    pub product: String,
    /// 是否启用。
    pub enabled: bool,
    /// 指定解析器 id（空 = 自动匹配模板）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parser_id: Option<Id>,
    /// 协议连接配置。
    pub connection: SourceConnection,
    /// 采集模式（推送 / 拉取）。
    pub mode: CollectionMode,
    /// 拉取间隔（秒，`mode=pull` 时有效）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub poll_interval_secs: Option<i64>,
    /// 是否要求 mTLS（南向采集器强制）。
    #[serde(default)]
    pub require_mtls: bool,
    /// 允许的来源 IP/CIDR 白名单（推送模式）。
    #[serde(default)]
    pub allowed_cidrs: Vec<String>,
    /// 单条报文最大字节数。
    #[serde(default = "default_max_bytes")]
    pub max_message_bytes: usize,
    /// 每秒最大事件数（保护平台自身）。
    #[serde(default = "default_eps")]
    pub max_eps: u32,
    /// 附加标签（写入事件）。
    #[serde(default)]
    pub tags: Vec<String>,
    /// 健康状态。
    pub health: HealthState,
    /// 最近一次成功接收时间。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_event_at: Option<Timestamp>,
    /// 累计事件数（近似，用于 SLO 展示）。
    #[serde(default)]
    pub total_events: u64,
    /// 最近错误。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    /// 创建时间。
    pub created_at: Timestamp,
    /// 更新时间。
    pub updated_at: Timestamp,
}

const fn default_max_bytes() -> usize {
    1_048_576
}

const fn default_eps() -> u32 {
    10_000
}

impl TenantScoped for LogSource {
    fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }
}

impl LogSource {
    /// 是否为"平台主动出网取数"模式（需要出网/订阅凭据，而不是等待设备推送）。
    #[must_use]
    pub const fn is_pull(&self) -> bool {
        matches!(self.mode, CollectionMode::Pull | CollectionMode::Poll | CollectionMode::Subscribe)
    }

    /// 是否需要 mTLS 校验后才能接收（推送模式）。
    #[must_use]
    pub const fn needs_client_cert(&self) -> bool {
        self.require_mtls && !self.is_pull()
    }
}

/// 采集模式。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CollectionMode {
    /// 设备主动推送。
    Push,
    /// 平台主动拉取。
    Pull,
    /// 轮询查询（数据库/SQL）。
    Poll,
    /// 订阅（Kafka/NATS/MQTT/Pulsar）。
    Subscribe,
    /// 本地文件采集（collector）。
    Tail,
}

impl CollectionMode {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Push => "push",
            Self::Pull => "pull",
            Self::Poll => "poll",
            Self::Subscribe => "subscribe",
            Self::Tail => "tail",
        }
    }
}

/// 协议连接配置（按协议取用对应字段；未用字段留空）。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SourceConnection {
    /// 监听地址（推送模式，如 `0.0.0.0:5514`）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub listen: Option<String>,
    /// 远端地址（拉取/订阅模式，如 `nats://127.0.0.1:4222`、`https://api.example.com/logs`）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// topic / stream / queue 名。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub topic: Option<String>,
    /// 凭据引用（密文存 `credentials`）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_ref: Option<Id>,
    /// TLS 开关。
    #[serde(default)]
    pub tls: bool,
    /// 是否跳过证书校验（仅测试；生产禁止）。
    #[serde(default)]
    pub insecure_skip_verify: bool,
    /// 追加请求头（拉取模式）。
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    /// 数据库 DSN 引用（JDBC/SQL 轮询）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dsn_ref: Option<Id>,
    /// 轮询 SQL。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sql: Option<String>,
    /// 增量游标字段。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor_field: Option<String>,
    /// 上次游标值。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor_value: Option<String>,
    /// 对象存储前缀（OSS/S3 拉取）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object_prefix: Option<String>,
    /// 本地路径（文件采集）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_path: Option<String>,
}

impl SourceConnection {
    /// 目标描述（用于 UI 与日志，**不泄露凭据**）。
    #[must_use]
    pub fn target_label(&self) -> String {
        self.listen
            .clone()
            .or_else(|| self.endpoint.clone())
            .or_else(|| self.topic.clone())
            .or_else(|| self.file_path.clone())
            .unwrap_or_else(|| "<未配置>".to_string())
    }

    /// 是否已配置可达目标。
    #[must_use]
    pub fn is_configured(&self) -> bool {
        self.listen.is_some() || self.endpoint.is_some() || self.topic.is_some() || self.file_path.is_some()
    }
}

/// 南向采集器注册信息（不可开放 MCP 的设备侧）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectorRegistration {
    /// 主键。
    pub id: Id,
    /// 租户。
    pub tenant_id: TenantId,
    /// 采集器 id（终端生成）。
    pub collector_id: String,
    /// 名称/主机名。
    pub name: String,
    /// 客户侧网络位置（打标用，不做入向端口）。
    #[serde(default)]
    pub site: String,
    /// 采集器版本。
    pub version: String,
    /// 是否启用。
    pub enabled: bool,
    /// 上次心跳。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_heartbeat_at: Option<Timestamp>,
    /// 心跳间隔。
    pub heartbeat_interval_secs: i64,
    /// 出网方式（`direct` / `privatelink` / `tunnel` / `proxy`）。
    #[serde(default)]
    pub uplink_mode: String,
    /// mTLS 证书指纹（用于双向校验）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert_fingerprint: Option<String>,
    /// 证书过期时间。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert_expires_at: Option<Timestamp>,
    /// 离线缓存待补传事件数。
    #[serde(default)]
    pub pending_upload: u64,
    /// 绑定的日志源 id。
    #[serde(default)]
    pub bound_source_ids: Vec<Id>,
    /// 创建时间。
    pub created_at: Timestamp,
}

impl TenantScoped for CollectorRegistration {
    fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }
}

impl CollectorRegistration {
    /// 心跳是否新鲜。
    #[must_use]
    pub fn is_alive(&self, now: Timestamp) -> bool {
        self.enabled && self.last_heartbeat_at.is_some_and(|at| now.since_secs(&at) <= self.heartbeat_interval_secs * 3)
    }

    /// 证书是否临近过期（30 天内）。
    #[must_use]
    pub fn cert_expiring_soon(&self, now: Timestamp) -> bool {
        self.cert_expires_at.is_some_and(|e| e.unix_secs() - now.unix_secs() < 30 * 86_400)
    }
}

/// 内置解析模板的词条（厂商 → 产品 → 模板名）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateDescriptor {
    /// 模板稳定键。
    pub key: String,
    /// 厂商。
    pub vendor: String,
    /// 产品。
    pub product: String,
    /// 接入协议。
    pub protocol: IngestProtocol,
    /// 样例文件（`tests/fixtures/` 内相对路径）。
    pub sample_fixture: String,
    /// 是否使用真实公开样本（区分合成样本）。
    pub real_sample: bool,
    /// 描述。
    #[serde(default)]
    pub description: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source(protocol: IngestProtocol, mode: CollectionMode) -> LogSource {
        let now = Timestamp::now();
        LogSource {
            id: Id::new(),
            tenant_id: TenantId::default_tenant(),
            name: "s".into(),
            protocol,
            vendor: "青藤云".into(),
            product: "蜂巢".into(),
            enabled: true,
            parser_id: None,
            connection: SourceConnection::default(),
            mode,
            poll_interval_secs: None,
            require_mtls: false,
            allowed_cidrs: vec![],
            max_message_bytes: default_max_bytes(),
            max_eps: default_eps(),
            tags: vec![],
            health: HealthState::Unconfigured,
            last_event_at: None,
            total_events: 0,
            last_error: None,
            created_at: now,
            updated_at: now,
        }
    }

    #[test]
    fn push_and_pull_mode_classification() {
        let push = source(IngestProtocol::Syslog, CollectionMode::Push);
        assert!(!push.is_pull());
        let sub = source(IngestProtocol::Kafka, CollectionMode::Subscribe);
        assert!(sub.is_pull());
        let poll = source(IngestProtocol::SqlPoll, CollectionMode::Poll);
        assert!(poll.is_pull());
        let tail = source(IngestProtocol::File, CollectionMode::Tail);
        assert!(!tail.is_pull());
    }

    #[test]
    fn mtls_only_enforced_for_push() {
        let mut s = source(IngestProtocol::Syslog, CollectionMode::Push);
        s.require_mtls = true;
        assert!(s.needs_client_cert());
        s.mode = CollectionMode::Pull;
        assert!(!s.needs_client_cert());
    }

    #[test]
    fn connection_target_label_never_leaks_secret() {
        let mut c =
            SourceConnection { endpoint: Some("https://siem.example.com/api".into()), tls: true, ..Default::default() };
        c.headers.insert("Authorization".into(), "Bearer xxx".into());
        assert_eq!(c.target_label(), "https://siem.example.com/api");
        assert!(c.is_configured());
        assert!(!SourceConnection::default().is_configured());
        assert_eq!(SourceConnection::default().target_label(), "<未配置>");
    }

    #[test]
    fn collector_liveness() {
        let now = Timestamp::now();
        let base = CollectorRegistration {
            id: Id::new(),
            tenant_id: TenantId::default_tenant(),
            collector_id: "c1".into(),
            name: "site-a".into(),
            site: "site-a".into(),
            version: "0.1.0".into(),
            enabled: true,
            last_heartbeat_at: Some(now),
            heartbeat_interval_secs: 30,
            uplink_mode: "privatelink".into(),
            cert_fingerprint: None,
            cert_expires_at: None,
            pending_upload: 0,
            bound_source_ids: vec![],
            created_at: now,
        };
        assert!(base.is_alive(now));
        let mut dead = base.clone();
        dead.last_heartbeat_at = Some(now.offset_secs(-200));
        assert!(!dead.is_alive(now));
        let mut disabled = base;
        disabled.enabled = false;
        assert!(!disabled.is_alive(now));
    }

    #[test]
    fn cert_expiry_warning() {
        let now = Timestamp::now();
        let mut c = CollectorRegistration {
            id: Id::new(),
            tenant_id: TenantId::default_tenant(),
            collector_id: "c1".into(),
            name: "n".into(),
            site: String::new(),
            version: "0.1.0".into(),
            enabled: true,
            last_heartbeat_at: None,
            heartbeat_interval_secs: 30,
            uplink_mode: String::new(),
            cert_fingerprint: None,
            cert_expires_at: None,
            pending_upload: 0,
            bound_source_ids: vec![],
            created_at: now,
        };
        assert!(!c.cert_expiring_soon(now));
        c.cert_expires_at = Some(now.offset_secs(10 * 86_400));
        assert!(c.cert_expiring_soon(now));
        c.cert_expires_at = Some(now.offset_secs(90 * 86_400));
        assert!(!c.cert_expiring_soon(now));
    }

    #[test]
    fn collection_mode_str() {
        assert_eq!(CollectionMode::Subscribe.as_str(), "subscribe");
        assert_eq!(CollectionMode::Tail.as_str(), "tail");
    }
}
