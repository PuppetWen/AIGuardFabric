//! 由 `enums.rs` 拆分：`severity_parse_and_weight` 等 9 个函数（纯搬移，逻辑不变）。

use super::*;

#[test]
pub(crate) fn severity_parse_and_weight() {
    assert_eq!(Severity::parse("CRITICAL"), Ok(Severity::Critical));
    assert!(Severity::parse("nope").is_err());
    assert!(Severity::Critical.weight() > Severity::High.weight());
    assert_eq!(Severity::High.to_string(), "high");
}

#[test]
pub(crate) fn risk_domain_roundtrip() {
    for d in RiskDomain::all() {
        assert_eq!(RiskDomain::parse(d.as_str()), Ok(d));
        assert!(!d.display_zh().is_empty());
    }
    assert_eq!(RiskDomain::parse("RAG_POISON"), Ok(RiskDomain::RagPoison));
    assert!(RiskDomain::parse("bogus").is_err());
}

#[test]
pub(crate) fn asset_kind_roundtrip() {
    for k in AssetKind::all() {
        assert_eq!(AssetKind::parse(k.as_str()), Ok(k));
    }
    assert!(AssetKind::parse("unknown-kind").is_err());
}

#[allow(clippy::unwrap_used)]
#[test]
pub(crate) fn protocol_database_values_roundtrip_as_json() {
    let protocols = [
        Protocol::McpStdio,
        Protocol::McpSse,
        Protocol::McpHttp,
        Protocol::OpenAiCompat,
        Protocol::Anthropic,
        Protocol::Gemini,
        Protocol::A2a,
        Protocol::Http,
        Protocol::Grpc,
        Protocol::WebSocket,
        Protocol::Syslog,
        Protocol::Kafka,
        Protocol::Nats,
        Protocol::Mqtt,
        Protocol::Other,
    ];
    for protocol in protocols {
        let text = protocol.as_str();
        assert_eq!(serde_json::to_value(protocol).unwrap(), text);
        assert_eq!(serde_json::from_value::<Protocol>(serde_json::json!(text)).unwrap(), protocol);
    }
    assert_eq!(serde_json::from_str::<Protocol>("\"open-ai-compat\"").unwrap(), Protocol::OpenAiCompat);
}

#[test]
pub(crate) fn lifecycle_transitions() {
    assert!(LifecycleState::Requested.can_transition_to(LifecycleState::UnderReview));
    assert!(!LifecycleState::Requested.can_transition_to(LifecycleState::Production));
    assert!(!LifecycleState::Archived.can_transition_to(LifecycleState::Trial));
    assert!(!LifecycleState::Rejected.can_transition_to(LifecycleState::Trial));
}

#[test]
pub(crate) fn policy_action_parse_aliases() {
    assert_eq!(PolicyAction::parse("block"), Ok(PolicyAction::Deny));
    assert_eq!(PolicyAction::parse("circuit_break"), Ok(PolicyAction::CircuitBreak));
    assert!(PolicyAction::Redact.mutates_payload());
    assert!(!PolicyAction::Deny.mutates_payload());
}

#[test]
pub(crate) fn llm_provider_openai_compat_matrix() {
    assert!(LlmProvider::DeepSeek.is_openai_compatible());
    assert!(!LlmProvider::Anthropic.is_openai_compatible());
    assert!(!LlmProvider::Mock.is_openai_compatible());
    for p in LlmProvider::all() {
        assert_eq!(LlmProvider::parse(p.as_str()), Ok(p));
    }
}

#[test]
pub(crate) fn quorum_dimensions_and_scopes() {
    assert_eq!(QuotaDimension::all().len(), 4);
    assert_eq!(QuotaScope::Tenant.as_str(), "tenant");
    assert_eq!(IngestProtocol::all().len(), 16);
    assert_eq!(AliCloudService::all().len(), 6);
}

#[test]
pub(crate) fn evidence_level_ordering() {
    assert!(EvidenceLevel::Impact > EvidenceLevel::Confirmed);
    assert!(EvidenceLevel::Confirmed > EvidenceLevel::Partial);
}

#[test]
pub(crate) fn data_class_local_inference() {
    assert!(DataClass::Restricted.requires_local_inference());
    assert!(!DataClass::Internal.requires_local_inference());
}
