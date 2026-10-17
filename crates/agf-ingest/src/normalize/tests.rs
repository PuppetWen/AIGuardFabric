//! 归一化单元测试：类别/动作推断、字段映射、未映射字段与 AI 事件判定。

use super::*;
use agf_core::parser::ParseOutcome;

fn meta() -> SourceMeta {
    SourceMeta {
        tenant_id: TenantId::default_tenant(),
        source_id: Id::new(),
        source_name: "waf-webhook".to_string(),
        vendor: "阿里云".to_string(),
        product: "WAF".to_string(),
        protocol: IngestProtocol::Webhook,
        tags: vec!["edge".to_string()],
        ingested_at: Timestamp::now(),
    }
}

fn outcome(fields: &[(&str, Value)]) -> ParseOutcome {
    let mut map = BTreeMap::new();
    for (k, v) in fields {
        map.insert((*k).to_string(), v.clone());
    }
    ParseOutcome::hit("aliyun-waf", map)
}

#[test]
fn normalizes_core_ecs_fields() {
    let parsed = outcome(&[
        ("event.time", Value::from("2026-02-21T10:23:45+08:00")),
        ("event.severity", Value::from("high")),
        ("event.category", Value::from("web")),
        ("event.action", Value::from("blocked")),
        ("host.name", Value::from("www.example.com")),
        ("source.ip", Value::from("203.0.113.77")),
        ("network.source_port", Value::from(54_321)),
        ("destination.ip", Value::from("10.20.30.50")),
        ("network.destination_port", Value::from(443)),
        ("network.transport", Value::from("tcp")),
        ("network.bytes_in", Value::from(2_048)),
        ("user.name", Value::from("alice")),
        ("user.department", Value::from("研发")),
        ("message", Value::from("检测到 SQL 注入")),
        ("url.domain", Value::from("www.example.com")),
    ]);
    let event = normalize(&parsed, &meta(), "raw payload", "203.0.113.77:5514");
    assert_eq!(event.severity, Severity::High);
    assert_eq!(event.category, EventCategory::Web);
    assert_eq!(event.action, EventAction::Denied);
    assert_eq!(event.action_raw, "blocked");
    assert_eq!(event.host.name.as_deref(), Some("www.example.com"));
    assert_eq!(event.network.source_ip.as_deref(), Some("203.0.113.77"));
    assert_eq!(event.network.source_port, Some(54_321));
    assert_eq!(event.network.destination_port, Some(443));
    assert_eq!(event.network.transport.as_deref(), Some("tcp"));
    assert_eq!(event.network.bytes_in, Some(2_048));
    assert_eq!(event.network.domain.as_deref(), Some("www.example.com"));
    assert_eq!(event.user.name.as_deref(), Some("alice"));
    assert_eq!(event.message, "检测到 SQL 注入");
    assert_eq!(event.parser_name.as_deref(), Some("aliyun-waf"));
    assert!(event.parser_id.is_some());
    assert_eq!(event.vendor, "阿里云");
    assert_eq!(event.tags, vec!["edge".to_string()]);
    assert_eq!(event.extra.get("log.origin").and_then(Value::as_str), Some("203.0.113.77:5514"));
}

#[test]
fn unmatched_fields_land_in_extra() {
    let parsed = outcome(&[("cef.cs1", Value::from("QAX-CMD-INJECT")), ("weird_field", Value::from(1))]);
    let event = normalize(&parsed, &meta(), "x", "");
    assert_eq!(event.extra.get("cef.cs1").and_then(Value::as_str), Some("QAX-CMD-INJECT"));
    assert_eq!(event.extra.get("weird_field").and_then(Value::as_u64), Some(1));
    assert_eq!(unmapped_fields(&event).len(), 2);
}

#[test]
fn raw_hash_and_raw_payload_are_faithful() {
    let json = r#"{"a":1,"nested":{"b":"x"}}"#;
    let event = normalize(&outcome(&[]), &meta(), json, "");
    assert!(event.raw.is_object());
    assert_eq!(event.raw.get("nested").and_then(|v| v.get("b")).and_then(Value::as_str), Some("x"));
    assert_eq!(event.raw_hash, content_hash(json));
    assert_eq!(event.raw_hash.len(), 64);
    let plain = normalize(&outcome(&[]), &meta(), "纯文本载荷", "");
    assert_eq!(plain.raw, Value::String("纯文本载荷".to_string()));
    assert_eq!(plain.message, "纯文本载荷");
}

#[test]
fn ai_fields_are_mapped() {
    let agent = Id::new();
    let parsed = outcome(&[
        ("ai.tool_name", Value::from("shell_exec")),
        ("ai.session_id", Value::from("s-1")),
        ("ai.agent_id", Value::from(agent.to_string())),
        ("ai.model", Value::from("qwen-max")),
        ("ai.prompt_tokens", Value::from(120)),
        ("ai.completion_tokens", Value::from(30)),
        ("ai.cost_micro", Value::from(1_500)),
        ("ai.rule_keys", Value::from("prompt-injection")),
        ("ai.mocked", Value::from(true)),
        ("event.severity", Value::from("critical")),
        ("event.category", Value::from("ai-tool-call")),
    ]);
    let event = normalize(&parsed, &meta(), "{}", "");
    assert_eq!(event.ai.tool_name.as_deref(), Some("shell_exec"));
    assert_eq!(event.ai.agent_id, Some(agent));
    assert_eq!(event.ai.model.as_deref(), Some("qwen-max"));
    assert_eq!(event.ai.prompt_tokens, Some(120));
    assert_eq!(event.ai.completion_tokens, Some(30));
    assert_eq!(event.ai.cost_micro, Some(1_500));
    assert_eq!(event.ai.rule_keys, vec!["prompt-injection".to_string()]);
    assert!(event.ai.mocked);
    assert!(event.is_ai_event());
    assert!(is_ai_high_risk(&event));
}

#[test]
fn host_ips_are_accumulated_without_duplicates() {
    let parsed = outcome(&[("host.ip", Value::from("10.0.0.1"))]);
    let event = normalize(&parsed, &meta(), "x", "");
    assert_eq!(event.host.ips, vec!["10.0.0.1".to_string()]);
}

#[test]
fn missing_time_falls_back_to_ingest_time() {
    let parsed = outcome(&[("event.severity", Value::from("info"))]);
    let event = normalize(&parsed, &meta(), "x", "");
    assert!(event.ingest_latency_ms().abs() < 5_000);
    assert_eq!(event.category, EventCategory::Other);
}

#[test]
fn severity_and_action_parsing_tables() {
    assert_eq!(severity_from_text("CRITICAL"), Severity::Critical);
    assert_eq!(severity_from_text("未知"), Severity::Info);
    assert_eq!(event_action_from("Allow"), EventAction::Allowed);
    assert_eq!(event_action_from("dropped"), EventAction::Denied);
    assert_eq!(event_action_from("quarantine"), EventAction::Denied);
    assert_eq!(event_action_from("Failed"), EventAction::Unknown);
    assert_eq!(event_action_from("login"), EventAction::Login);
    assert_eq!(event_action_from("EXECUTE"), EventAction::Execute);
    assert_eq!(direction_from("egress"), NetworkDirection::Outbound);
    assert_eq!(direction_from("nope"), NetworkDirection::Unknown);
}

#[test]
fn category_inference_and_aliases() {
    assert_eq!(event_category_from("intrusion"), EventCategory::Intrusion);
    assert_eq!(event_category_from("Web-Attack"), EventCategory::Web);
    assert_eq!(event_category_from("webshell"), EventCategory::Web);
    assert_eq!(event_category_from("AI Tool Call"), EventCategory::AiToolCall);
    assert_eq!(event_category_from("nonexistent"), EventCategory::Other);
    assert_eq!(infer_category("深信服", "AF", "SQL 注入攻击"), EventCategory::Intrusion);
    assert_eq!(infer_category("", "", "MCP tool_call 被拒绝"), EventCategory::AiToolCall);
    assert_eq!(infer_category("", "", "登录失败"), EventCategory::Authentication);
    assert_eq!(infer_category("", "", "杂项"), EventCategory::Other);
}

#[test]
fn parser_id_is_stable() {
    assert_eq!(parser_id_for("wazuh-alert"), parser_id_for("wazuh-alert"));
    assert_ne!(parser_id_for("wazuh-alert"), parser_id_for("suricata-eve"));
}

#[test]
fn truncation_keeps_utf8_boundaries() {
    let text = "中文日志".repeat(1_000);
    let cut = truncate_chars(&text, 10);
    assert!(cut.starts_with("中文日志中文日志中文"));
    assert!(cut.ends_with("（已截断）"));
    assert_eq!(truncate_chars("短", 10), "短");
}

#[test]
fn value_coercion_helpers() {
    assert_eq!(as_string(&Value::from(7)), Some("7".to_string()));
    assert_eq!(as_string(&Value::Null), None);
    assert_eq!(as_u64(&Value::from("42")), Some(42));
    assert_eq!(as_u16(&Value::from(70_000)), None);
    assert_eq!(as_u16(&Value::from(443)), Some(443));
    assert_eq!(as_string_list(&Value::from(vec!["a", "b"])).len(), 2);
    assert_eq!(as_string_list(&Value::from("a")), vec!["a".to_string()]);
}
