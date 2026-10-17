//! 由 `contract.rs` 拆分：`message_idempotency_key_is_time_independent` 等 7 个函数（纯搬移，逻辑不变）。
use super::*;

#[test]
pub(crate) fn message_idempotency_key_is_time_independent() {
    let a = AdapterMessage::notification("标题", "摘要");
    let b = AdapterMessage::notification("标题", "摘要");
    assert_eq!(a.idempotency_key, b.idempotency_key, "同一内容必须得到同一幂等键");
    let c = AdapterMessage::notification("标题2", "摘要");
    assert_ne!(a.idempotency_key, c.idempotency_key);
}

#[test]
pub(crate) fn message_render_text_is_deterministic_and_informative() {
    let msg = AdapterMessage::event(
        "ai.asset.discovered",
        Severity::High,
        "发现未纳管 Agent",
        "cursor@host1 未登记",
        serde_json::json!({"asset": "cursor@host1"}),
    )
    .with_asset("cursor@host1")
    .with_label("team", "sec");
    let text = msg.render_text();
    assert!(text.starts_with("【high】发现未纳管 Agent"));
    assert!(text.contains("event=ai.asset.discovered"));
    assert!(text.contains("asset=cursor@host1"));
    assert!(text.contains("team=sec"));
    assert_eq!(text, msg.render_text());
}

#[test]
pub(crate) fn message_prefix_and_severity_matching() {
    let msg = AdapterMessage::event("ai.asset.discovered", Severity::Low, "t", "s", serde_json::Value::Null);
    assert!(msg.matches_prefix(&["*".to_string()]));
    assert!(msg.matches_prefix(&["ai.".to_string()]));
    assert!(!msg.matches_prefix(&["notify.".to_string()]));
    assert!(msg.meets_severity(None));
    assert!(msg.meets_severity(Some(Severity::Info)));
    assert!(!msg.meets_severity(Some(Severity::High)));
}

#[test]
pub(crate) fn metadata_descriptor_fields_are_non_empty() {
    let meta = AdapterMetadata::new("feishu", "飞书机器人", "字节跳动", AdapterCategory::Notification)
        .with_secrets(&["webhook_url"], &["signing_secret"])
        .with_capabilities(vec![AdapterCapability::PushEvents]);
    let d = meta.to_descriptor();
    assert_eq!(d.name, "feishu");
    assert_eq!(d.category, "message");
    assert!(!d.degradation.is_empty(), "必须写明降级行为");
    assert!(!d.mock_location.is_empty(), "必须写明 Mock 实现位置");
    assert!(!d.real_implementation, "阶段一无真实传输实现，必须如实登记");
    assert_eq!(meta.version, env!("CARGO_PKG_VERSION"));
    assert_eq!(d.doc_anchor, "docs/adapter-spec.md#feishu");
}

#[test]
pub(crate) fn metadata_missing_secrets_diff() {
    let meta = AdapterMetadata::new("jira", "Jira", "Atlassian", AdapterCategory::Itsm)
        .with_secrets(&["api_token", "user_email"], &[]);
    let present = vec!["api_token".to_string()];
    assert_eq!(meta.missing_secrets(&present), vec!["user_email"]);
    assert!(meta.missing_secrets(&["api_token".into(), "user_email".into()]).is_empty());
}

#[test]
pub(crate) fn camel_conversion() {
    assert_eq!(camel("feishu"), "Feishu");
    assert_eq!(camel("service-now"), "ServiceNow");
    assert_eq!(camel("edr_isolation"), "EdrIsolation");
    assert_eq!(camel(""), "");
}

#[test]
pub(crate) fn category_texts() {
    assert_eq!(AdapterCategory::Notification.as_str(), "message");
    assert_eq!(AdapterCategory::Itsm.as_str(), "itsm");
    assert_eq!(AdapterCategory::SecurityPlatform.as_str(), "siem");
    assert_eq!(MessageKind::Event.as_str(), "event");
}
