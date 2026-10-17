//! 样本打分与必需字段门禁用例：阈值、默认值不计分、扁平字段口径一致。

use super::*;

#[test]
fn time_field_mapping_sets_event_time() {
    let mut d = def(ParserEngine::Regex, r"(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (?P<msg>.*)");
    d.mapping.map.insert("ts".into(), "event.time".into());
    d.mapping.time_field = Some("ts".into());
    d.mapping.time_format = Some("%Y-%m-%d %H:%M:%S".into());
    let out = parse_with(&d, "2026-03-01 10:00:00 hello");
    assert!(out.matched, "{:?}", out.error);
    assert!(out.fields.contains_key("event.time"), "{:?}", out.fields);
    assert_eq!(field(&out, "event.time").and_then(Value::as_str), Some("2026-03-01T10:00:00.000Z"));
}

#[test]
fn required_fields_gate_matching() {
    let mut d = def(ParserEngine::Regex, r"(?P<a>\S+)");
    d.required_fields = vec!["b".into()];
    let out = parse_with(&d, "x");
    assert!(!out.matched, "缺少必需字段应不匹配");
}

#[test]
fn fallback_patterns_are_tried() {
    let mut d = def(ParserEngine::Regex, r"NOMATCH-(?P<a>\S+)");
    d.fallback_patterns = vec![r"(?P<a>\S+)".into()];
    let out = parse_with(&d, "value");
    assert!(out.matched, "{:?}", out.error);
    assert_eq!(field(&out, "a").and_then(Value::as_str), Some("value"));
}

#[test]
fn sample_match_score_prefers_richer_extraction() {
    let rich = def(ParserEngine::Regex, r"(?P<a>\S+) (?P<b>\S+) (?P<c>\S+)");
    let poor = def(ParserEngine::Regex, r"(?P<a>\S+)");
    let raw = "x y z";
    let s_rich = sample_match_score(&rich, raw);
    let s_poor = sample_match_score(&poor, raw);
    assert!(s_rich > s_poor, "rich={s_rich} poor={s_poor}");
    assert!(s_rich <= 1.0 && s_rich > MATCH_THRESHOLD);
    let miss = def(ParserEngine::Regex, r"NEVER_MATCHES_ANYTHING");
    assert!(sample_match_score(&miss, raw).abs() < f32::EPSILON);
}

/// 回归（核心缺陷）：打分必须与 `parse_with` 用**同一套字段名口径**（映射前）。
///
/// 修复前：`sample_match_score` 拿**映射后**的 `fields`/`extra` 去查
/// `required_fields`；模板里写的是源字段名（`src`/`rule_id`），映射后已改名成
/// `source.ip`/`rule.id`，因此"字段明明齐备"也被判成不齐 ⇒ 得分腰斩为
/// `base * 0.5`（上限 0.495）⇒ 永远低于 `MATCH_THRESHOLD`，第 4 步对该模板失效。
#[test]
fn required_fields_template_scores_above_threshold_when_fields_present() {
    let mut d = def(ParserEngine::Regex, r"(?P<src>[\d.]+) (?P<rule_id>\S+) (?P<msg>.*)");
    d.required_fields = vec!["src".into(), "rule_id".into()];
    d.mapping.map.insert("src".into(), "source.ip".into());
    d.mapping.map.insert("rule_id".into(), "rule.id".into());
    d.mapping.map.insert("msg".into(), "message".into());
    let raw = "10.0.0.1 RULE-1 attack detected";

    let out = parse_with(&d, raw);
    assert!(out.matched, "{:?}", out.error);
    // 映射后 `src`/`rule_id` 两个键都已改名 —— 旧口径在这里必然查不到（缺陷根因）
    assert!(out.fields.contains_key("source.ip"), "{:?}", out.fields);
    assert!(out.fields.contains_key("rule.id"), "{:?}", out.fields);
    assert!(!out.fields.contains_key("src") && !out.extra.contains_key("src"));

    let score = sample_match_score(&d, raw);
    assert!(score > MATCH_THRESHOLD, "字段齐备时必须过阈值: {score}");
    // 抽到 3 个字段 → 3 / (3 + 2) = 0.6（不再是 0.6 * 0.5 = 0.3）
    assert!((score - 0.6).abs() < 1e-6, "得分公式 = n/(n+2): {score}");
}

/// 另一半：`required_fields` 缺字段时必须**被拒**（0 分），而不是"打折接受"。
#[test]
fn required_fields_template_is_rejected_when_field_missing() {
    let mut d = def(ParserEngine::Regex, r"(?P<src>[\d.]+) (?P<rule_id>\S+)");
    d.required_fields = vec!["src".into(), "rule_id".into()];
    d.mapping.map.insert("src".into(), "source.ip".into());
    d.mapping.map.insert("rule_id".into(), "rule.id".into());
    // 主模式只抽到 src：缺 rule_id ⇒ 不匹配 ⇒ 0 分（旧口径会给出 base*0.5 的"部分分"）
    let mut partial = d.clone();
    partial.pattern = r"(?P<src>[\d.]+) .*".to_string();
    let raw = "10.0.0.1 attack detected";
    assert!(!parse_with(&partial, raw).matched, "缺必需字段必须不匹配");
    assert!(sample_match_score(&partial, raw).abs() < f32::EPSILON, "缺必需字段必须 0 分");
    // 字段齐备的样本仍然命中（对照组，证明拒绝来自"缺字段"而不是模板本身坏掉）
    assert!(parse_with(&d, "10.0.0.1 RULE-1").matched);
}

/// 得分只看**引擎抽到的字段数**，不被 `mapping.defaults` 凭声明补出的字段抬高。
#[test]
fn sample_match_score_ignores_mapping_defaults() {
    let mut d = def(ParserEngine::Regex, r"(?P<a>\S+) (?P<b>\S+)");
    for i in 0..5 {
        d.mapping.defaults.insert(format!("event.dataset.{i}"), Value::from("x"));
    }
    // 抽到 2 个字段 → 2/4 = 0.5；映射后的字段数是 7（2 + 5 个默认值）——旧口径会给出 7/9
    let score = sample_match_score(&d, "x y");
    assert!((score - 0.5).abs() < 1e-6, "默认值不得抬高得分: {score}");
}

/// 必需字段口径助手：只有**全部**齐备才算满足（与 `parse_with` 判定一致）。
#[test]
fn required_fields_satisfied_checks_pre_mapping_names() {
    let mut flat = BTreeMap::new();
    flat.insert("rule_id".to_string(), Value::from("R-1"));
    assert!(required_fields_satisfied(&[], &flat), "无必需字段 = 永真");
    assert!(required_fields_satisfied(&["rule_id".to_string()], &flat));
    assert!(!required_fields_satisfied(&["rule_id".to_string(), "src".to_string()], &flat));
    // 映射后的路径不在**映射前**的表里——内核传的就是映射前的表，
    // 因此模板的 `required_fields` 必须写源字段名（这也是缺陷的另一面）
    assert!(!required_fields_satisfied(&["rule.id".to_string()], &flat));
}

#[test]
fn sample_match_score_uses_same_flat_fields_as_parse_with() {
    // 引擎直出 ECS 路径的模板（CEF）与写源字段名的模板（JSONPath）都要能过阈值
    let cef = def(ParserEngine::Cef, "");
    let raw = "<134>Feb 21 10:23:45 fw1 CEF:0|Vendor|Product|1.0|100|Evt|5|src=10.0.0.1 dst=10.0.0.2 spt=1 dpt=2";
    assert!(sample_match_score(&cef, raw) > MATCH_THRESHOLD);

    let mut json = def(ParserEngine::JsonPath, "rule_id=$.rule_id\nsrc_ip=$.src_ip\nmsg=$.msg");
    json.required_fields = vec!["rule_id".into(), "src_ip".into()];
    json.mapping.map.insert("rule_id".into(), "rule.id".into());
    json.mapping.map.insert("src_ip".into(), "source.ip".into());
    json.mapping.map.insert("msg".into(), "message".into());
    let payload = r#"{"rule_id":"R-9","src_ip":"203.0.113.5","msg":"blocked"}"#;
    let score = sample_match_score(&json, payload);
    assert!(score > MATCH_THRESHOLD, "带 required_fields 的 JSONPath 模板必须过阈值: {score}");
    // 缺 `src_ip`：判定为不匹配 ⇒ 0 分（不是"打折接受"）
    assert!(sample_match_score(&json, r#"{"rule_id":"R-9"}"#).abs() < f32::EPSILON, "缺 src_ip 必须 0 分");
}
