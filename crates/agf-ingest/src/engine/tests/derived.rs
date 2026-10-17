//! 时间/严重度/动作归一与派生字段（CEL）用例，以及引擎与协议能力矩阵断言。

use super::*;

#[test]
fn parse_time_value_handles_multiple_formats() {
    assert!(parse_time_value("2026-03-01T10:00:00Z", None).is_some());
    assert!(parse_time_value("2026-03-01 10:00:00", None).is_some());
    assert!(parse_time_value("2026-03-01", None).is_some());
    assert!(parse_time_value("Mar  1 10:00:00", None).is_some());
    assert!(parse_time_value("2026-02-21T10:23:45.123+0000", None).is_some());
    assert!(parse_time_value("", None).is_none());
    assert!(parse_time_value("not-a-time", None).is_none());
    assert!(parse_time_value("01/03/2026 10:00", Some("%d/%m/%Y %H:%M")).is_some());
    // Unix 秒 / 毫秒（含小数秒）
    assert!(parse_time_value("1771674225", Some("unix")).is_some());
    assert!(parse_time_value("1771674225.123456", Some("unix")).is_some());
    assert!(parse_time_value("1771674225000", Some("unix_millis")).is_some());
    assert!(parse_time_value("1771674225", None).is_some());
    assert!(parse_time_value("1771674225000", None).is_some());
    // 太小的数字不当时间（端口/计数）
    assert!(parse_time_value("443", None).is_none());
    assert_eq!(parse_time_value("1771674225", Some("unix")).map(|t| t.unix_secs()), Some(1_771_674_225));
    assert_eq!(
        parse_time_value("1771674225000", Some("unix_millis")).map(|t| t.unix_millis()),
        Some(1_771_674_225_000)
    );
}

#[test]
fn cef_severity_scale() {
    assert_eq!(cef_severity("0"), Some(Severity::Low));
    assert_eq!(cef_severity("5"), Some(Severity::Medium));
    assert_eq!(cef_severity("8"), Some(Severity::High));
    assert_eq!(cef_severity("10"), Some(Severity::Critical));
    assert_eq!(cef_severity("critical"), Some(Severity::Critical));
    assert_eq!(cef_severity("nonsense"), None);
}

#[test]
fn severity_inference_table() {
    assert_eq!(infer_severity("CRITICAL"), Some(Severity::Critical));
    assert_eq!(infer_severity("error"), Some(Severity::High));
    assert_eq!(infer_severity("WARN"), Some(Severity::Medium));
    assert_eq!(infer_severity("notice"), Some(Severity::Low));
    assert_eq!(infer_severity("info"), Some(Severity::Info));
    assert_eq!(infer_severity("严重"), Some(Severity::Critical));
    assert_eq!(infer_severity("unknown-level"), None);
}

#[test]
fn action_normalization_table() {
    assert_eq!(normalize_action("BLOCK"), "denied");
    assert_eq!(normalize_action("allow"), "allowed");
    assert_eq!(normalize_action("quarantine"), "denied");
    assert_eq!(normalize_action("登录"), "login");
    assert_eq!(normalize_action("somethingelse"), "somethingelse");
}

#[test]
fn derived_expression_reporting() {
    let mut d = def(ParserEngine::Regex, r"(?P<a>\S+)");
    d.derived.insert("x".into(), "copy:a".into());
    let out = parse_with(&d, "v");
    assert!(out.derived_errors.is_empty(), "{:?}", out.derived_errors);
    assert_eq!(field(&out, "x").and_then(Value::as_str), Some("v"));

    let mut d2 = def(ParserEngine::Regex, r"(?P<a>\S+)");
    d2.derived.insert("y".into(), "copy:missing".into());
    let out2 = parse_with(&d2, "v");
    assert_eq!(out2.derived_errors.len(), 1);

    // CEL 表达式语法非法 → 记入 derived_errors，不中断解析。
    let mut d3 = def(ParserEngine::Regex, r"(?P<a>\S+)");
    d3.derived.insert("z".into(), "1 +".into());
    let out3 = parse_with(&d3, "v");
    assert_eq!(out3.derived_errors.len(), 1);
    assert!(out3.matched);
}

#[test]
fn derived_cel_expression_evaluates() {
    // 真实 CEL 三元表达式：按抽取出的整型字段派生严重度标签。
    let mut d = def(ParserEngine::Regex, r"level=(?P<level>\d+)");
    let mut flat = BTreeMap::new();
    flat.insert("level".to_string(), Value::from(9));
    // 直接对 apply_derived 求值（fields 已含 level=9）。
    d.derived.insert("severity_label".into(), "int(fields['level']) >= 7 ? 'high' : 'low'".into());
    let mut fields = flat.clone();
    let errors = crate::cel::apply_derived(&d, &mut fields, &BTreeMap::new());
    assert!(errors.is_empty(), "{errors:?}");
    assert_eq!(fields.get("severity_label").and_then(Value::as_str), Some("high"));
}

#[test]
fn derived_const_and_copy_into_fields() {
    let mut d = def(ParserEngine::Regex, r"(?P<user>\S+)");
    d.derived.insert("user.name".into(), "copy:user".into());
    d.derived.insert("observer.type".into(), "const:firewall".into());
    let out = parse_with(&d, "alice");
    assert!(out.derived_errors.is_empty(), "{:?}", out.derived_errors);
    assert_eq!(field(&out, "user.name").and_then(Value::as_str), Some("alice"));
    assert_eq!(field(&out, "observer.type").and_then(Value::as_str), Some("firewall"));
}

#[test]
fn engine_and_protocol_support_matrices() {
    let matrix = engine_support_matrix();
    assert_eq!(matrix.len(), ParserEngine::all().len());
    assert!(matrix.iter().any(|(e, ok, _)| *e == ParserEngine::Cel && *ok));
    // Plugin 本轮已接线 ⇒ 矩阵里必须是"已实现"（不再是"未实现"）
    assert!(matrix.iter().any(|(e, ok, note)| *e == ParserEngine::Plugin && *ok && note.contains("已实现")));
    assert!(matrix.iter().any(|(e, ok, _)| *e == ParserEngine::Grok && *ok));
    assert!(protocol_supported(IngestProtocol::Syslog));
    assert!(!protocol_supported(IngestProtocol::Kafka));
}

#[test]
fn ai_inferred_engine_dispatches_by_shape() {
    let json_def = def(ParserEngine::AiInferred, "$");
    let out = parse_with(&json_def, r#"{"a":"1"}"#);
    assert!(out.matched, "{:?}", out.error);
    let kv_def = def(ParserEngine::AiInferred, "");
    let out2 = parse_with(&kv_def, "a=1 b=2");
    assert!(out2.matched, "{:?}", out2.error);
    let csv_def = def(ParserEngine::AiInferred, "");
    let out3 = parse_with(&csv_def, "1,2,3");
    assert!(out3.matched, "{:?}", out3.error);
}

#[test]
fn ecs_path_detection() {
    assert!(is_ecs_path("event.category_raw"));
    assert!(is_ecs_path("source.ip"));
    assert!(is_ecs_path("message"));
    assert!(!is_ecs_path("src"));
    assert!(!is_ecs_path("event_type"));
    assert!(!is_ecs_path("ruleId"));
}
