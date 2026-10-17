//! 由 `repository.rs` 拆分：`enum_parsers_are_total_on_known_values` 等 6 个函数（纯搬移，逻辑不变）。

use agf_core::audit::AuditAction;
use agf_core::enums::{DataClass, DiscoverySource, LifecycleState};

use super::*;

#[test]
pub(crate) fn enum_parsers_are_total_on_known_values() {
    assert_eq!(parse_data_class("public"), Ok(DataClass::Public));
    assert_eq!(parse_data_class("restricted"), Ok(DataClass::Restricted));
    assert!(parse_data_class("unknown").is_err());

    assert_eq!(parse_lifecycle("under-review"), Ok(LifecycleState::UnderReview));
    assert_eq!(parse_lifecycle("under_review"), Ok(LifecycleState::UnderReview));
    assert!(parse_lifecycle("nope").is_err());

    assert_eq!(parse_discovery("agent-report"), Ok(DiscoverySource::AgentReport));
    assert!(parse_discovery("nope").is_err());
}

#[test]
pub(crate) fn protocol_parser_covers_all_variants() {
    for p in [
        agf_core::enums::Protocol::McpStdio,
        agf_core::enums::Protocol::McpSse,
        agf_core::enums::Protocol::McpHttp,
        agf_core::enums::Protocol::OpenAiCompat,
        agf_core::enums::Protocol::Anthropic,
        agf_core::enums::Protocol::Gemini,
        agf_core::enums::Protocol::A2a,
        agf_core::enums::Protocol::Http,
        agf_core::enums::Protocol::Grpc,
        agf_core::enums::Protocol::WebSocket,
        agf_core::enums::Protocol::Syslog,
        agf_core::enums::Protocol::Kafka,
        agf_core::enums::Protocol::Nats,
        agf_core::enums::Protocol::Mqtt,
        agf_core::enums::Protocol::Other,
    ] {
        assert_eq!(parse_protocol(p.as_str()), Some(p), "协议 {} 未覆盖", p.as_str());
    }
    assert_eq!(parse_protocol("bogus"), None);
}

#[test]
pub(crate) fn ingest_protocol_parser_covers_all_variants() {
    for p in agf_core::enums::IngestProtocol::all() {
        assert_eq!(parse_ingest_protocol(p.as_str()), p);
    }
    assert_eq!(parse_ingest_protocol("bogus"), agf_core::enums::IngestProtocol::File);
}

#[test]
pub(crate) fn audit_action_parser_maps_all() {
    for (raw, expect) in [
        ("login", AuditAction::Login),
        ("logout", AuditAction::Logout),
        ("create", AuditAction::Create),
        ("read", AuditAction::Read),
        ("update", AuditAction::Update),
        ("delete", AuditAction::Delete),
        ("export", AuditAction::Export),
        ("execute", AuditAction::Execute),
        ("configure", AuditAction::Configure),
        ("grant", AuditAction::Grant),
        ("approve", AuditAction::Approve),
        ("contain", AuditAction::Contain),
        ("system", AuditAction::System),
    ] {
        assert_eq!(parse_audit_action(raw), expect);
    }
    assert_eq!(parse_audit_action("weird"), AuditAction::System);
}

#[test]
pub(crate) fn finding_state_and_evidence_parsers() {
    assert_eq!(parse_finding_state("verified"), agf_core::risk::FindingState::Verified);
    assert_eq!(parse_finding_state("false-positive"), agf_core::risk::FindingState::FalsePositive);
    assert_eq!(parse_finding_state("pending"), agf_core::risk::FindingState::Pending);
    assert_eq!(parse_evidence_level("impact"), agf_core::enums::EvidenceLevel::Impact);
    assert_eq!(parse_evidence_level("bogus"), agf_core::enums::EvidenceLevel::Unknown);
}

#[test]
pub(crate) fn json_helper_never_panics() {
    let v = to_json(&serde_json::json!({"a": 1}));
    assert_eq!(v["a"], serde_json::json!(1));
}
