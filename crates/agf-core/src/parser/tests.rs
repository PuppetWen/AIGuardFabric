//! 由 `parser.rs` 拆分：`grok_parser` 等 11 个函数（纯搬移，逻辑不变）。

use crate::enums::IngestProtocol;
use crate::ids::{Id, TenantId};
use crate::time::Timestamp;
use std::collections::BTreeMap;

use super::*;

pub(crate) fn grok_parser() -> ParserDefinition {
    ParserDefinition {
        key: "syslog-generic".into(),
        name: "通用 Syslog".into(),
        vendor: "generic".into(),
        product: "syslog".into(),
        protocols: vec![IngestProtocol::Syslog],
        engine: ParserEngine::Grok,
        pattern: "%{SYSLOGTIMESTAMP:ts} %{HOSTNAME:host} %{DATA:msg}".into(),
        fallback_patterns: vec![],
        mapping: FieldMapping::default(),
        derived: BTreeMap::new(),
        required_fields: vec![],
        version: 1,
        builtin: true,
        ai_inferred: false,
        description: String::new(),
        sample_fixture: "tests/fixtures/logs/syslog_rfc3164.txt".into(),
    }
}

#[test]
pub(crate) fn valid_parser_passes_validation() {
    assert!(grok_parser().validate().is_ok());
}

#[test]
pub(crate) fn missing_pattern_rejected() {
    let mut p = grok_parser();
    p.pattern = String::new();
    assert!(p.validate().is_err());
}

#[test]
pub(crate) fn syslog_engine_allows_empty_pattern() {
    let mut p = grok_parser();
    p.engine = ParserEngine::Syslog;
    p.pattern = String::new();
    assert!(p.validate().is_ok());
}

#[test]
pub(crate) fn invalid_regex_engine_pattern_rejected() {
    let mut p = grok_parser();
    p.engine = ParserEngine::Regex;
    p.pattern = "(unclosed".into();
    let res = p.validate();
    assert!(res.is_err());
    assert!(res.err().unwrap_or_default().iter().any(|e| e.contains("正则非法")));
}

#[test]
pub(crate) fn empty_derived_expression_rejected() {
    let mut p = grok_parser();
    p.derived.insert("event.risk_score".into(), "  ".into());
    assert!(p.validate().is_err());
}

#[test]
pub(crate) fn engine_list_and_str() {
    assert_eq!(ParserEngine::all().len(), 13);
    assert_eq!(ParserEngine::JsonPath.as_str(), "jsonpath");
    assert_eq!(ParserEngine::AiInferred.as_str(), "ai-inferred");
}

#[test]
pub(crate) fn parser_success_rate_and_attention() {
    let now = Timestamp::now();
    let mut p = Parser {
        id: Id::new(),
        tenant_id: TenantId::default_tenant(),
        definition: grok_parser(),
        enabled: true,
        priority: 100,
        content_hash: "h".into(),
        success_count: 90,
        failure_count: 10,
        last_used_at: None,
        created_at: now,
        updated_at: now,
    };
    assert!((p.success_rate() - 0.9).abs() < 1e-6);
    assert!(!p.needs_attention(0.8, 50), "成功率达标不应告警");
    assert!(p.needs_attention(0.95, 50), "成功率低于阈值且样本足够应告警");
    p.success_count = 10;
    p.failure_count = 0;
    assert!(!p.needs_attention(0.95, 50), "样本不足（10 < 50）时不告警");
    p.success_count = 0;
    p.failure_count = 0;
    assert_eq!(p.success_rate(), 0.0);
    assert!(!p.needs_attention(0.9, 1), "无样本时不告警");
}

#[test]
pub(crate) fn parse_outcome_helpers() {
    let mut fields = BTreeMap::new();
    fields.insert("network.source_ip".to_string(), serde_json::Value::from("10.0.0.1"));
    let ok = ParseOutcome::hit("p1", fields);
    assert!(ok.matched);
    assert_eq!(ok.get_str("network.source_ip"), Some("10.0.0.1"));
    assert_eq!(ok.get_str("missing"), None);
    let miss = ParseOutcome::miss("no template matched");
    assert!(!miss.matched);
    assert!(miss.error.is_some());
    // `matched_by` 由注册表在命中时回填；两个构造器都必须给默认值（老调用方零改动）
    assert_eq!(ok.matched_by, None, "构造器默认不写趟次");
    assert_eq!(miss.matched_by, None);
}

#[test]
pub(crate) fn parse_outcome_matched_by_round_trips_and_stays_backward_compatible() {
    let mut ok = ParseOutcome::hit("p1", BTreeMap::new());
    ok.matched_by = Some("protocol-relaxed".to_string());
    let text = serde_json::to_string(&ok).unwrap_or_default();
    assert!(text.contains("\"matched_by\":\"protocol-relaxed\""), "{text}");
    let back: ParseOutcome = serde_json::from_str(&text).unwrap_or_else(|_| ParseOutcome::miss("bad"));
    assert_eq!(back.matched_by.as_deref(), Some("protocol-relaxed"));
    // 老 JSON（没有 `matched_by` 字段）必须仍能反序列化（`#[serde(default)]`）
    let legacy = r#"{"matched":true,"parser_key":"p1","fields":{},"extra":{},"derived_errors":[],"elapsed_micros":7}"#;
    let legacy: ParseOutcome = serde_json::from_str(legacy).unwrap_or_else(|_| ParseOutcome::miss("bad"));
    assert!(legacy.matched);
    assert_eq!(legacy.matched_by, None);
    // `None` 不写进 JSON（与 `error`/`parser_key` 一致的省略风格）
    let plain = serde_json::to_string(&ParseOutcome::miss("x")).unwrap_or_default();
    assert!(!plain.contains("matched_by"), "{plain}");
}

#[test]
pub(crate) fn builtin_requires_sample() {
    assert!(grok_parser().requires_sample());
    let mut custom = grok_parser();
    custom.builtin = false;
    assert!(!custom.requires_sample());
}
