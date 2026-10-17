//! AI 推断解析器单元测试：形状识别、ECS 猜测、严重度映射与离线/Mock 提供方行为。

use super::*;
use crate::engine;
use crate::normalize::{self, SourceMeta};
use agf_core::ids::{Id, TenantId};

const UNKNOWN_JSON: &str = r#"{"client_ip":"203.0.113.5","path":"/checkout","code":"500","ts":"2026-02-21T10:23:45Z","who":"root","detail":"支付回调异常"}"#;

fn request(samples: &[&str]) -> AiParserRequest {
    AiParserRequest {
        samples: samples.iter().map(|s| (*s).to_string()).collect(),
        vendor_hint: None,
        protocol: None,
        target_paths: vec!["source.ip".to_string(), "event.time".to_string()],
    }
}

#[test]
fn infers_json_shape_and_maps_paths() {
    let suggestion = infer_suggestion(&[UNKNOWN_JSON.to_string()], Some("自研"), None);
    assert!(suggestion.is_some());
    let Some(suggestion) = suggestion else { return };
    assert_eq!(suggestion.definition.engine, ParserEngine::JsonPath);
    assert_eq!(suggestion.definition.key, HEURISTIC_KEY);
    assert!(suggestion.definition.ai_inferred);
    assert!(!suggestion.definition.builtin);
    assert!(suggestion.mocked, "离线启发式必须标记 mocked=true");
    assert!(suggestion.confidence > 0.3 && suggestion.confidence <= 0.85);
    assert!(suggestion.rationale.contains("启发式"));

    let outcome = engine::parse_with(&suggestion.definition, UNKNOWN_JSON);
    assert!(outcome.matched, "{outcome:?}");
    let meta = SourceMeta {
        tenant_id: TenantId::default_tenant(),
        source_id: Id::new(),
        source_name: "unknown".to_string(),
        vendor: "自研".to_string(),
        product: "inferred".to_string(),
        protocol: IngestProtocol::Webhook,
        tags: vec![],
        ingested_at: Timestamp::now(),
    };
    let event = normalize::normalize(&outcome, &meta, UNKNOWN_JSON, "webhook");
    assert_eq!(event.network.source_ip.as_deref(), Some("203.0.113.5"));
    assert_eq!(event.user.name.as_deref(), Some("root"));
    assert_eq!(event.message, "支付回调异常");
    assert_eq!(event.time.to_rfc3339(), "2026-02-21T10:23:45.000Z");
    assert_eq!(event.severity, Severity::Info, "无等级字段时默认 info");
}

#[test]
fn infers_kv_shape_with_severity_and_action() {
    let raw = "level=error src=10.0.0.9 user=alice act=block msg=越权访问被拒绝";
    let suggestion = infer_suggestion(&[raw.to_string()], Some("自研"), None);
    assert!(suggestion.is_some());
    let Some(suggestion) = suggestion else { return };
    assert_eq!(suggestion.definition.engine, ParserEngine::Kv);
    let outcome = engine::parse_with(&suggestion.definition, raw);
    assert!(outcome.matched, "{outcome:?}");
    assert_eq!(outcome.fields.get("event.severity").and_then(Value::as_str), Some("high"));
    assert_eq!(outcome.fields.get("event.action").and_then(Value::as_str), Some("denied"));
    assert_eq!(outcome.fields.get("event.action_raw").and_then(Value::as_str), Some("block"));
    assert_eq!(outcome.fields.get("source.ip").and_then(Value::as_str), Some("10.0.0.9"));
    assert_eq!(outcome.fields.get("user.name").and_then(Value::as_str), Some("alice"));
}

#[test]
fn infers_tsv_shape_with_positional_names() {
    let raw = "10.0.0.1\t10.0.0.2\t443\ttcp";
    let suggestion = infer_suggestion(&[raw.to_string()], None, None);
    assert!(suggestion.is_some());
    let Some(suggestion) = suggestion else { return };
    assert_eq!(suggestion.definition.engine, ParserEngine::Csv);
    assert!(suggestion.definition.pattern.contains("f0,f1,f2,f3"));
    let outcome = engine::parse_with(&suggestion.definition, raw);
    assert!(outcome.matched, "{outcome:?}");
}

#[test]
fn gibberish_returns_none() {
    assert!(infer_suggestion(&["完全无法识别的自由文本没有分隔符".to_string()], None, None).is_none());
    assert!(infer_suggestion(&[], None, None).is_none());
    assert!(infer_suggestion(&["{不是合法 json".to_string()], None, None).is_none());
}

#[test]
fn nested_json_keys_are_flattened() {
    let raw = r#"{"rule":{"level":10,"id":"5712"},"agent":{"name":"web-01"},"full_log":"x"}"#;
    let def = heuristic_definition(&[raw.to_string()], Some("Wazuh"));
    assert!(def.is_some());
    let Some(def) = def else { return };
    assert!(def.pattern.contains("rule.level=$.rule.level"));
    assert!(def.pattern.contains("agent.name=$.agent.name"));
    assert_eq!(def.mapping.map.get("rule.id").map(String::as_str), Some("rule.name"));
    assert_eq!(def.mapping.map.get("agent.name").map(String::as_str), Some("host.name"));
    assert_eq!(def.mapping.map.get("full_log").map(String::as_str), Some("message"));
    let outcome = engine::parse_with(&def, raw);
    assert!(outcome.matched, "{outcome:?}");
    // rule.level=10 → 按数值分档（10-12）判为 High
    assert_eq!(outcome.fields.get("event.severity").and_then(Value::as_str), Some("high"));
    assert_eq!(outcome.fields.get("rule.name").and_then(Value::as_str), Some("5712"));
}

#[test]
fn ecs_path_guessing_table() {
    assert_eq!(guess_ecs_path("client_ip"), Some("source.ip"));
    assert_eq!(guess_ecs_path("dst_ip"), Some("destination.ip"));
    assert_eq!(guess_ecs_path("remote_addr"), Some("source.ip"));
    assert_eq!(guess_ecs_path("dpt"), Some("network.destination_port"));
    assert_eq!(guess_ecs_path("srcport"), Some("source.port"));
    assert_eq!(guess_ecs_path("id.resp_p"), Some("network.destination_port"));
    assert_eq!(guess_ecs_path("id.orig_p"), Some("source.port"));
    assert_eq!(guess_ecs_path("user_name"), Some("user.name"));
    assert_eq!(guess_ecs_path("devname"), Some("host.name"));
    assert_eq!(guess_ecs_path("http_status"), Some("http.response.status_code"));
    assert_eq!(guess_ecs_path("timestamp"), Some("event.time"));
    assert_eq!(guess_ecs_path("severity"), Some("event.severity"));
    assert_eq!(guess_ecs_path("acl_action"), Some("event.action"));
    assert_eq!(guess_ecs_path("full_log"), Some("message"));
    assert_eq!(guess_ecs_path("signature"), Some("rule.name"));
    assert_eq!(guess_ecs_path("完全不认识"), None);
}

#[test]
fn severity_guessing_handles_numbers_and_words() {
    let syslog = guess_severity_map("level", "3");
    assert_eq!(syslog.get("3"), Some(&Severity::High));
    let wazuh = guess_severity_map("rule.level", "12");
    assert_eq!(wazuh.get("12"), Some(&Severity::High));
    let words = guess_severity_map("severity", "high");
    assert_eq!(words.get("high"), Some(&Severity::High));
    assert_eq!(words.get("warning"), Some(&Severity::Medium));
    assert_eq!(numeric_level_severity(0), Severity::Critical);
    assert_eq!(numeric_level_severity(7), Severity::Info);
    assert_eq!(numeric_level_severity(15), Severity::Critical);
}

#[test]
fn heuristic_provider_reports_mocked_and_errors_on_gibberish() {
    let provider = HeuristicAiParser::new();
    assert!(provider.mocked());
    assert_eq!(provider.name(), "heuristic");
    let ok = provider.suggest(&request(&[UNKNOWN_JSON]));
    assert!(ok.is_ok(), "{ok:?}");
    let err = provider.suggest(&request(&["无语料"]));
    assert!(err.is_err());
    let message = err.err().map(|e| e.to_string()).unwrap_or_default();
    assert!(message.contains("TODO ingest-ai-parser-remote"), "{message}");
}

#[test]
fn mock_provider_is_marked_mocked() {
    let provider = MockAiParser::new();
    let suggestion = provider.suggest(&request(&["x"]));
    assert_eq!(provider.name(), "mock");
    assert!(provider.mocked());
    let Ok(suggestion) = suggestion else { return };
    assert!(suggestion.mocked);
    assert_eq!(suggestion.model, "mock");
    assert_eq!(suggestion.definition.engine, ParserEngine::Kv);
}

#[test]
fn remote_provider_is_not_implemented_with_todo() {
    let provider = RemoteAiParser { endpoint: "aigw://log-parser".to_string() };
    assert!(!provider.mocked());
    assert_eq!(provider.name(), "remote");
    let err = provider.suggest(&request(&["x"]));
    let message = err.err().map(|e| e.to_string()).unwrap_or_default();
    assert!(message.contains("TODO ingest-ai-parser-remote"), "{message}");
    assert!(message.contains("aigw://log-parser"));
}

#[test]
fn sanitize_keeps_dots_and_replaces_spaces() {
    assert_eq!(sanitize("id.orig_h"), "id.orig_h");
    assert_eq!(sanitize("a b"), "a_b");
    assert_eq!(sanitize("a-b"), "a_b");
}
