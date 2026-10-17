//! 由 `event.rs` 拆分：`new_event_defaults` 等 6 个函数（纯搬移，逻辑不变）。

use crate::enums::{IngestProtocol, Severity};
use crate::ids::{Id, TenantId};
use crate::time::Timestamp;

use super::*;

#[test]
pub(crate) fn new_event_defaults() {
    let e = Event::new(TenantId::default_tenant(), Id::new(), IngestProtocol::Syslog);
    assert_eq!(e.category, EventCategory::Other);
    assert_eq!(e.action, EventAction::Unknown);
    assert_eq!(e.severity, Severity::Info);
    assert!(!e.is_ai_event());
    assert!(!e.redacted);
}

#[test]
pub(crate) fn ai_event_detection() {
    let mut e = Event::new(TenantId::default_tenant(), Id::new(), IngestProtocol::Mcp);
    e.category = EventCategory::AiToolCall;
    assert!(e.is_ai_event());
    e.category = EventCategory::Network;
    assert!(!e.is_ai_event());
}

#[test]
pub(crate) fn ingest_latency_computation() {
    let mut e = Event::new(TenantId::default_tenant(), Id::new(), IngestProtocol::Webhook);
    e.time = Timestamp::now().offset_secs(-3);
    e.ingested_at = Timestamp::now();
    let lat = e.ingest_latency_ms();
    assert!((2_900..=3_200).contains(&lat), "延迟计算异常: {lat}");
}

#[test]
pub(crate) fn dedup_key_is_deterministic() {
    let mut e = Event::new(TenantId::default_tenant(), Id::new(), IngestProtocol::Kafka);
    e.raw_hash = "abc".into();
    assert_eq!(e.dedup_key(), e.dedup_key());
    let mut f = e.clone();
    f.raw_hash = "def".into();
    assert_ne!(e.dedup_key(), f.dedup_key());
}

#[test]
pub(crate) fn event_category_and_action_str() {
    assert_eq!(EventCategory::AiSession.as_str(), "ai-session");
    assert_eq!(EventAction::Exfiltrate.as_str(), "exfiltrate");
    assert_eq!(EventCategory::all().len(), 15);
}

#[test]
pub(crate) fn raw_log_serde_roundtrip() {
    let r = RawLog {
        id: Id::new(),
        tenant_id: TenantId::default_tenant(),
        source_id: Id::new(),
        received_at: Timestamp::now(),
        protocol: IngestProtocol::Syslog,
        payload_b64: "aGVsbG8=".into(),
        payload_hash: "h".into(),
        bytes: 5,
        origin: "10.0.0.1:514".into(),
        parsed: false,
        parse_error: None,
        event_id: None,
    };
    let j = serde_json::to_string(&r);
    assert!(j.is_ok());
    let back: Result<RawLog, _> = serde_json::from_str(j.as_deref().unwrap_or("{}"));
    assert!(back.is_ok());
}
