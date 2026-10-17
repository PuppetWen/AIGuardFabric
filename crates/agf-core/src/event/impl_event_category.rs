//! 由 `event.rs` 拆分：`Event`/`EventAction`/`EventCategory`/`RawLog` 的实现（纯搬移，逻辑不变）。
use super::*;

use crate::enums::{IngestProtocol, Severity};
use crate::ids::{Id, TenantId, TenantScoped};
use crate::time::Timestamp;
use std::collections::BTreeMap;

impl EventCategory {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Authentication => "authentication",
            Self::Network => "network",
            Self::Process => "process",
            Self::File => "file",
            Self::Database => "database",
            Self::Web => "web",
            Self::AiSession => "ai-session",
            Self::AiToolCall => "ai-tool-call",
            Self::AiModel => "ai-model",
            Self::Configuration => "configuration",
            Self::CloudControl => "cloud-control",
            Self::Malware => "malware",
            Self::Intrusion => "intrusion",
            Self::Policy => "policy",
            Self::Other => "other",
        }
    }

    /// 全部类别。
    #[must_use]
    pub const fn all() -> [Self; 15] {
        [
            Self::Authentication,
            Self::Network,
            Self::Process,
            Self::File,
            Self::Database,
            Self::Web,
            Self::AiSession,
            Self::AiToolCall,
            Self::AiModel,
            Self::Configuration,
            Self::CloudControl,
            Self::Malware,
            Self::Intrusion,
            Self::Policy,
            Self::Other,
        ]
    }
}

impl EventAction {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::Denied => "denied",
            Self::Created => "created",
            Self::Updated => "updated",
            Self::Deleted => "deleted",
            Self::Login => "login",
            Self::Logout => "logout",
            Self::Read => "read",
            Self::Write => "write",
            Self::Execute => "execute",
            Self::Connect => "connect",
            Self::Disconnect => "disconnect",
            Self::Alert => "alert",
            Self::Detect => "detect",
            Self::Exfiltrate => "exfiltrate",
            Self::Elevate => "elevate",
            Self::Unknown => "unknown",
        }
    }
}

impl TenantScoped for Event {
    fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }
}

impl Event {
    /// 构造最小事件（供解析器填充）。
    #[must_use]
    pub fn new(tenant_id: TenantId, source_id: Id, protocol: IngestProtocol) -> Self {
        let now = Timestamp::now();
        Self {
            id: Id::new(),
            tenant_id,
            time: now,
            ingested_at: now,
            category: EventCategory::Other,
            action: EventAction::Unknown,
            action_raw: String::new(),
            severity: Severity::Info,
            source_id,
            source_name: String::new(),
            protocol,
            parser_id: None,
            parser_name: None,
            vendor: String::new(),
            product: String::new(),
            host: HostInfo::default(),
            user: UserInfo::default(),
            network: NetworkInfo::default(),
            ai: AiContext::default(),
            message: String::new(),
            raw: serde_json::Value::Null,
            raw_ref: None,
            raw_hash: String::new(),
            redacted: false,
            tags: Vec::new(),
            extra: BTreeMap::new(),
        }
    }

    /// 是否与"AI 相关"（用于 AI 视图与专用规则）。
    #[must_use]
    pub const fn is_ai_event(&self) -> bool {
        matches!(self.category, EventCategory::AiSession | EventCategory::AiToolCall | EventCategory::AiModel)
    }

    /// 端到端接入延迟（毫秒）。
    #[must_use]
    pub fn ingest_latency_ms(&self) -> i64 {
        self.ingested_at.unix_millis() - self.time.unix_millis()
    }

    /// 事件去重键（同源 + 同时间 + 同原始哈希）。
    #[must_use]
    pub fn dedup_key(&self) -> String {
        format!("{}:{}:{}", self.source_id, self.time.unix_millis(), self.raw_hash)
    }
}

impl TenantScoped for RawLog {
    fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }
}
