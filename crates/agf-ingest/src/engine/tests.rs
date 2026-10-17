//! 解析引擎单元测试：Grok/Regex/JSONPath/JQ/CSV/KV/CEF/LEEF/GELF/Syslog 与字段映射（打分与派生字段用例见子模块）。

use super::*;

/// 断言辅助：引擎直出/已映射字段在 `fields`，未映射字段在 `extra`；
/// 测试只关心"解析出来了没有"，所以两张表都查。
fn field<'a>(out: &'a ParseOutcome, key: &str) -> Option<&'a Value> {
    out.fields.get(key).or_else(|| out.extra.get(key))
}

fn def(engine: ParserEngine, pattern: &str) -> ParserDefinition {
    ParserDefinition {
        key: "test".into(),
        name: "测试解析器".into(),
        vendor: "test".into(),
        product: "unit".into(),
        protocols: vec![IngestProtocol::Syslog],
        engine,
        pattern: pattern.to_string(),
        fallback_patterns: vec![],
        mapping: FieldMapping::default(),
        derived: BTreeMap::new(),
        required_fields: vec![],
        version: 1,
        builtin: false,
        ai_inferred: false,
        description: String::new(),
        sample_fixture: String::new(),
    }
}

#[test]
fn grok_expansion_produces_named_groups() {
    let (re, warnings) = grok_to_regex("%{IP:src} %{WORD:action} %{INT:code}");
    assert!(warnings.is_empty());
    assert!(re.contains("(?P<src>"));
    assert!(re.contains("(?P<action>"));
    let Ok(compiled) = Regex::new(&re) else {
        unreachable!("展开后的正则必须可编译: {re}");
    };
    let Some(caps) = compiled.captures("10.0.0.1 ALLOW 200") else {
        unreachable!("样例必须匹配: {re}");
    };
    assert_eq!(caps.name("src").map(|m| m.as_str()), Some("10.0.0.1"));
    assert_eq!(caps.name("action").map(|m| m.as_str()), Some("ALLOW"));
}

#[test]
fn grok_unknown_pattern_degrades_with_warning() {
    let (re, warnings) = grok_to_regex("%{NOT_A_REAL_PATTERN:x}");
    assert_eq!(warnings.len(), 1);
    assert!(warnings[0].contains("NOT_A_REAL_PATTERN"));
    assert!(Regex::new(&re).is_ok());
}

#[test]
fn grok_without_name_gets_synthetic_group() {
    let (re, _) = grok_to_regex("%{WORD} %{WORD}");
    assert!(re.contains("(?P<g1>"));
    assert!(re.contains("(?P<g2>"));
}

#[test]
fn grok_unclosed_brace_is_preserved() {
    let (re, warnings) = grok_to_regex("literal %{WORD");
    assert!(warnings.is_empty());
    assert!(re.contains("%{WORD"));
}

#[test]
fn regex_engine_parses_named_groups() {
    let d = def(ParserEngine::Regex, r"(?P<host>\S+) (?P<action>\S+) (?P<code>\d+)");
    let out = parse_with(&d, "web01 DENY 403");
    assert!(out.matched, "{:?}", out.error);
    assert_eq!(field(&out, "host").and_then(Value::as_str), Some("web01"));
    assert_eq!(field(&out, "code").and_then(Value::as_str), Some("403"));
    assert_eq!(out.parser_key.as_deref(), Some("test"));
}

#[test]
fn regex_engine_falls_back_to_positional_groups() {
    let d = def(ParserEngine::Regex, r"(\S+) (\d+)");
    let out = parse_with(&d, "abc 42");
    assert!(out.matched, "{:?}", out.error);
    assert_eq!(field(&out, "g1").and_then(Value::as_str), Some("abc"));
    assert_eq!(field(&out, "g2").and_then(Value::as_str), Some("42"));
}

#[test]
fn regex_engine_sees_through_syslog_envelope() {
    let d = def(ParserEngine::Regex, r"type=EXECVE uid=(?P<uid>\d+)");
    let raw = "<38>Feb 21 10:23:49 app-prod-01 auditd[1120]: type=EXECVE uid=0";
    let out = parse_with(&d, raw);
    assert!(out.matched, "{:?}", out.error);
    assert_eq!(field(&out, "uid").and_then(Value::as_str), Some("0"));
    assert_eq!(field(&out, "host.name").and_then(Value::as_str), Some("app-prod-01"));
    assert_eq!(field(&out, "process.name").and_then(Value::as_str), Some("auditd"));
}

#[test]
fn jsonpath_engine_maps_named_paths() {
    let d = def(ParserEngine::JsonPath, "category=$.event.category\nsrc_ip=$.event.src.ip");
    let raw = r#"{"event":{"category":"web","src":{"ip":"10.0.0.1"},"cnt":3}}"#;
    let out = parse_with(&d, raw);
    assert!(out.matched, "{:?}", out.error);
    assert_eq!(field(&out, "category").and_then(Value::as_str), Some("web"));
    assert_eq!(field(&out, "src_ip").and_then(Value::as_str), Some("10.0.0.1"));
}

#[test]
fn jsonpath_engine_flattens_bare_path_object() {
    let d = def(ParserEngine::JsonPath, "$.event");
    let raw = r#"{"event":{"category":"web","src":{"ip":"10.0.0.1"}}}"#;
    let out = parse_with(&d, raw);
    assert!(out.matched, "{:?}", out.error);
    assert_eq!(field(&out, "category").and_then(Value::as_str), Some("web"));
    assert_eq!(field(&out, "src.ip").and_then(Value::as_str), Some("10.0.0.1"));
}

#[test]
fn jsonpath_engine_skips_missing_paths_and_collects_arrays() {
    let d = def(ParserEngine::JsonPath, "a=$.a\nb=$.missing\nlist=$.arr[*]");
    let out = parse_with(&d, r#"{"a":1,"arr":[1,2,3]}"#);
    assert!(out.matched, "{:?}", out.error);
    assert_eq!(field(&out, "a").and_then(Value::as_i64), Some(1));
    assert!(field(&out, "b").is_none());
    assert_eq!(field(&out, "list").and_then(Value::as_array).map(Vec::len), Some(3));
}

#[test]
fn jsonpath_engine_rejects_invalid_json_and_bad_path() {
    let d = def(ParserEngine::JsonPath, "a=$.a");
    let out = parse_with(&d, "not json");
    assert!(!out.matched);
    assert!(out.error.unwrap_or_default().contains("JSON"));
    let bad = def(ParserEngine::JsonPath, "a=$ [[[");
    let out2 = parse_with(&bad, "{\"a\":1}");
    assert!(!out2.matched, "{out2:?}");
}

#[test]
fn jq_engine_transforms_json() {
    let d = def(ParserEngine::Jq, r"{host: .host, act: .action}");
    let out = parse_with(&d, r#"{"host":"h1","action":"deny"}"#);
    assert!(out.matched, "{:?}", out.error);
    assert_eq!(field(&out, "host").and_then(Value::as_str), Some("h1"));
    assert_eq!(field(&out, "act").and_then(Value::as_str), Some("deny"));
}

#[test]
fn jq_engine_reports_syntax_error() {
    let d = def(ParserEngine::Jq, "this is not jq ((");
    let out = parse_with(&d, "{\"a\":1}");
    assert!(!out.matched);
    assert!(out.error.unwrap_or_default().contains("JQ"));
}

#[test]
fn csv_engine_maps_header_and_detects_tab() {
    let d = def(ParserEngine::Csv, "time,src,dst,action");
    let out = parse_with(&d, "2026-03-01T10:00:00Z,10.0.0.1,10.0.0.2,allow");
    assert!(out.matched, "{:?}", out.error);
    assert_eq!(field(&out, "src").and_then(Value::as_str), Some("10.0.0.1"));

    // 表头用逗号声明，数据是制表符分隔（Zeek conn.log 形态）
    let tsv = def(ParserEngine::Csv, "ts,uid,id.orig_h");
    let out2 = parse_with(&tsv, "1771674225.123\tCd8xYz\t10.20.30.130");
    assert!(out2.matched, "{:?}", out2.error);
    assert_eq!(field(&out2, "id.orig_h").and_then(Value::as_str), Some("10.20.30.130"));
}

#[test]
fn csv_engine_skips_comments_and_syslog_prefix() {
    let d = def(ParserEngine::Csv, "start,serial,type");
    let raw = "Feb 21 10:23:45 PA-VM-FW1 1,001801000001,TRAFFIC";
    let out = parse_with(&d, raw);
    assert!(out.matched, "{:?}", out.error);
    assert_eq!(field(&out, "serial").and_then(Value::as_str), Some("001801000001"));
    assert_eq!(field(&out, "host.name").and_then(Value::as_str), Some("PA-VM-FW1"));
}

#[test]
fn kv_engine_parses_various_forms() {
    let d = def(ParserEngine::Kv, "");
    let out = parse_with(&d, r#"src=10.0.0.1 dst="10.0.0.2" action='deny' code=403"#);
    assert!(out.matched, "{:?}", out.error);
    assert_eq!(field(&out, "src").and_then(Value::as_str), Some("10.0.0.1"));
    assert_eq!(field(&out, "dst").and_then(Value::as_str), Some("10.0.0.2"));
    assert_eq!(field(&out, "action").and_then(Value::as_str), Some("deny"));
}

#[test]
fn kv_engine_keeps_quoted_values_with_spaces() {
    let d = def(ParserEngine::Kv, "=");
    let raw = r#"<189>devname="FGT-EDGE-01" level="alert" msg="IP 10.0.0.1 上的攻击已阻断""#;
    let out = parse_with(&d, raw);
    assert!(out.matched, "{:?}", out.error);
    assert_eq!(field(&out, "msg").and_then(Value::as_str), Some("IP 10.0.0.1 上的攻击已阻断"));
}

#[test]
fn kv_extension_helper() {
    let pairs = parse_kv_extension("a=1 b=2");
    assert_eq!(pairs.len(), 2);
    assert_eq!(pairs[0], ("a".to_string(), "1".to_string()));
}

#[test]
fn cef_engine_rewrites_standard_keys() {
    let d = def(ParserEngine::Cef, "");
    let raw = "<134>Feb 21 10:23:45 fw1 CEF:0|Vendor|Product|1.0|100|Test Event|5|src=10.0.0.1 dst=10.0.0.2 spt=1234 dpt=80 proto=TCP act=block cat=Test msg=检测到攻击 cs1=RULE-1";
    let out = parse_with(&d, raw);
    assert!(out.matched, "{:?}", out.error);
    assert_eq!(field(&out, "observer.vendor").and_then(Value::as_str), Some("Vendor"));
    assert_eq!(field(&out, "rule.name").and_then(Value::as_str), Some("Test Event"));
    assert_eq!(field(&out, "source.ip").and_then(Value::as_str), Some("10.0.0.1"));
    assert_eq!(field(&out, "destination.ip").and_then(Value::as_str), Some("10.0.0.2"));
    assert_eq!(field(&out, "source.port").and_then(Value::as_str), Some("1234"));
    assert_eq!(field(&out, "network.transport").and_then(Value::as_str), Some("TCP"));
    assert_eq!(field(&out, "event.action").and_then(Value::as_str), Some("denied"));
    assert_eq!(field(&out, "event.action_raw").and_then(Value::as_str), Some("block"));
    assert_eq!(field(&out, "event.category_raw").and_then(Value::as_str), Some("Test"));
    assert_eq!(field(&out, "message").and_then(Value::as_str), Some("检测到攻击"));
    assert_eq!(field(&out, "cs1").and_then(Value::as_str), Some("RULE-1"));
    assert_eq!(field(&out, "host.name").and_then(Value::as_str), Some("fw1"));
    // CEF 头等级 5 → 中危
    assert_eq!(field(&out, "event.severity").and_then(Value::as_str), Some("medium"));
}

#[test]
fn cef_escape_handling() {
    let parts = split_cef(r"0|Ven\|dor|Prod|1.0|1|Na\|me|5");
    assert_eq!(parts.len(), 7);
    assert_eq!(parts[1], "Ven|dor");
    assert_eq!(parts[5], "Na|me");
}

#[test]
fn cef_extension_keeps_spaces_in_values() {
    let pairs = parse_cef_extension("src=10.0.0.1 msg=检测到针对 203.0.113.10 的攻击 request=http://a/b?id=1");
    assert_eq!(pairs.len(), 3);
    assert_eq!(pairs[1], ("msg".to_string(), "检测到针对 203.0.113.10 的攻击".to_string()));
    assert_eq!(pairs[2].1, "http://a/b?id=1");
}

#[test]
fn cef_engine_rejects_short_input() {
    let d = def(ParserEngine::Cef, "");
    let out = parse_with(&d, "CEF:0|only|three");
    assert!(!out.matched);
}

#[test]
fn leef_engine_parses_v2_and_v1() {
    let d = def(ParserEngine::Leef, "");
    let v2 = "<134>Feb 21 10:23:47 nsfocus-ips1 LEEF:2.0|NSFOCUS|IPS|5.6.10.0|1001|^|devTime=Feb 21 2026 10:23:47^cat=Attack^sev=7^src=10.20.30.61^msg=Log4j 攻击^ruleId=NSF-1";
    let out = parse_with(&d, v2);
    assert!(out.matched, "{:?}", out.error);
    assert_eq!(field(&out, "observer.vendor").and_then(Value::as_str), Some("NSFOCUS"));
    assert_eq!(field(&out, "rule.id").and_then(Value::as_str), Some("1001"));
    assert_eq!(field(&out, "source.ip").and_then(Value::as_str), Some("10.20.30.61"));
    assert_eq!(field(&out, "event.severity").and_then(Value::as_str), Some("high"));
    assert_eq!(field(&out, "event.category_raw").and_then(Value::as_str), Some("Attack"));
    assert_eq!(field(&out, "ruleId").and_then(Value::as_str), Some("NSF-1"));
    assert_eq!(field(&out, "host.name").and_then(Value::as_str), Some("nsfocus-ips1"));

    let v1 = "LEEF:1.0|Topsec|TopSAP|3.2.1|1002|usrName=admin\tsrc=10.20.30.71\tsev=7\tcat=Authentication\tmsg=连续 5 次登录失败";
    let out1 = parse_with(&d, v1);
    assert!(out1.matched, "{:?}", out1.error);
    assert_eq!(field(&out1, "user.name").and_then(Value::as_str), Some("admin"));
    assert_eq!(field(&out1, "source.ip").and_then(Value::as_str), Some("10.20.30.71"));
    assert_eq!(field(&out1, "event.category_raw").and_then(Value::as_str), Some("Authentication"));
    assert_eq!(field(&out1, "message").and_then(Value::as_str), Some("连续 5 次登录失败"));
}

#[test]
fn gelf_engine_parses_json() {
    let d = def(ParserEngine::Gelf, "");
    let raw = "{\"version\":\"1.1\",\"host\":\"h1\",\"short_message\":\"hello\",\"level\":4,\"custom\":\"x\"}";
    let out = parse_with(&d, raw);
    assert!(out.matched, "{:?}", out.error);
    assert_eq!(field(&out, "host.name").and_then(Value::as_str), Some("h1"));
    assert_eq!(field(&out, "message").and_then(Value::as_str), Some("hello"));
    assert_eq!(field(&out, "gelf.level").and_then(Value::as_i64), Some(4));
    assert_eq!(field(&out, "gelf.custom").and_then(Value::as_str), Some("x"));
}

#[test]
fn syslog_engine_parses_rfc3164() {
    let d = def(ParserEngine::Syslog, "");
    let raw = "<34>Feb 21 10:23:45 web-prod-01 sshd[2311]: Failed password for root from 203.0.113.77";
    let out = parse_with(&d, raw);
    assert!(out.matched, "{:?}", out.error);
    assert_eq!(field(&out, "host.name").and_then(Value::as_str), Some("web-prod-01"));
    assert_eq!(field(&out, "syslog.facility_name").and_then(Value::as_str), Some("auth"));
    assert_eq!(field(&out, "event.severity").and_then(Value::as_str), Some("critical"));
    assert!(field(&out, "message").and_then(Value::as_str).unwrap_or_default().contains("Failed password"));
}

#[test]
fn plugin_engine_is_declared_implemented_and_spec_is_validated() {
    // 本轮起 `Plugin` 已接线（不再是"未实现"）：规格非法仍在**加载期**被拒，
    // 合法规格通过。运行时的调用行为由 `engine::plugin::tests` 用假插件覆盖。
    let good = def(ParserEngine::Plugin, "plugin=agf-plugin-example");
    assert!(validate_pattern(&good).is_ok());
    let with_entry = def(ParserEngine::Plugin, "plugin=agf-plugin-example entry=normalize ctx=envelope");
    assert!(validate_pattern(&with_entry).is_ok());
    // 缺插件名 / 入口不是 normalize / 插件名非法 / 未知规格项 ⇒ 一律拒绝
    assert!(validate_pattern(&def(ParserEngine::Plugin, "entry=normalize")).is_err());
    assert!(validate_pattern(&def(ParserEngine::Plugin, "plugin=x entry=parse")).is_err());
    assert!(validate_pattern(&def(ParserEngine::Plugin, "plugin=bad name")).is_err());
    assert!(validate_pattern(&def(ParserEngine::Plugin, "plugin=x unknown=1")).is_err());
    assert!(validate_pattern(&def(ParserEngine::Plugin, "")).is_err());

    // 能力矩阵如实：Plugin 一行是"已实现"（不再是 TODO 锚点）
    let matrix = engine_support_matrix();
    let row = matrix.iter().find(|(engine, _, _)| *engine == ParserEngine::Plugin);
    assert!(row.is_some_and(|(_, ok, note)| *ok && note.contains("已实现")), "{row:?}");
    // `unimplemented_engine_error` 仍是**可降级**的明确错误（留给上层兜底路径，不再有引擎因"没写代码"走到它）
    assert!(unimplemented_engine_error(ParserEngine::Plugin).is_degradable());
}

#[test]
fn validate_pattern_catches_bad_regex_and_good_ones() {
    assert!(validate_pattern(&def(ParserEngine::Regex, "(unclosed")).is_err());
    assert!(validate_pattern(&def(ParserEngine::Regex, r"(\d+)")).is_ok());
    assert!(validate_pattern(&def(ParserEngine::Grok, "%{IP:x}")).is_ok());
    assert!(validate_pattern(&def(ParserEngine::Regex, "")).is_err());
    assert!(validate_pattern(&def(ParserEngine::Grok, "")).is_err());
    assert!(validate_pattern(&def(ParserEngine::Csv, "")).is_err());
    assert!(validate_pattern(&def(ParserEngine::JsonPath, "a=$.a\nb=$.b")).is_ok());
    assert!(validate_pattern(&def(ParserEngine::JsonPath, "[[[")).is_err());
    assert!(validate_pattern(&def(ParserEngine::JsonPath, "")).is_err());
    assert!(validate_pattern(&def(ParserEngine::Jq, ".a")).is_ok());
    assert!(validate_pattern(&def(ParserEngine::Jq, "(((")).is_err());
    assert!(validate_pattern(&def(ParserEngine::Syslog, "")).is_ok());
    assert!(validate_pattern(&def(ParserEngine::Cef, "CEF:0")).is_ok());
    assert!(validate_pattern(&def(ParserEngine::Kv, "")).is_ok());
}

#[test]
fn mapping_applies_severity_category_action_and_defaults() {
    let mut d = def(ParserEngine::Regex, r"(?P<host>\S+) (?P<sev>\S+) (?P<cat>\S+) (?P<act>\S+)");
    d.mapping.map.insert("host".into(), "host.name".into());
    d.mapping.severity_field = Some("sev".into());
    d.mapping.severity_map.insert("5".into(), Severity::Critical);
    d.mapping.category_map.insert("waf".into(), "web".into());
    d.mapping.action_field = Some("act".into());
    d.mapping.defaults.insert("event.dataset".into(), Value::from("test.dataset"));
    d.mapping.map.insert("cat".into(), "event.category_raw".into());
    let out = parse_with(&d, "h1 5 waf deny");
    assert!(out.matched, "{:?}", out.error);
    assert_eq!(field(&out, "host.name").and_then(Value::as_str), Some("h1"));
    assert_eq!(field(&out, "event.severity").and_then(Value::as_str), Some("critical"));
    assert_eq!(field(&out, "event.category").and_then(Value::as_str), Some("web"));
    assert_eq!(field(&out, "event.action").and_then(Value::as_str), Some("denied"));
    assert_eq!(field(&out, "event.action_raw").and_then(Value::as_str), Some("deny"));
    assert_eq!(field(&out, "event.dataset").and_then(Value::as_str), Some("test.dataset"));
}

#[test]
fn mapping_defaults_beat_category_map() {
    // 模板显式声明 event.category 时，优先级高于 category_map 推断
    let mut d = def(ParserEngine::Regex, r"(?P<cat>\S+)");
    d.mapping.map.insert("cat".into(), "event.category_raw".into());
    d.mapping.category_map.insert("crack".into(), "authentication".into());
    d.mapping.defaults.insert("event.category".into(), Value::from("intrusion"));
    let out = parse_with(&d, "crack");
    assert_eq!(field(&out, "event.category").and_then(Value::as_str), Some("intrusion"));
}

#[test]
fn mapping_category_from_rule_id_and_action() {
    let mut d = def(ParserEngine::Regex, r"(?P<rule_id>\S+) (?P<action>\S+)");
    d.mapping.map.insert("rule_id".into(), "rule.id".into());
    d.mapping.action_field = Some("action".into());
    d.mapping.category_map.insert("5712".into(), "authentication".into());
    d.mapping.category_map.insert("block".into(), "intrusion".into());
    let out = parse_with(&d, "5712 alert");
    assert_eq!(field(&out, "event.category").and_then(Value::as_str), Some("authentication"));
    let out2 = parse_with(&d, "9999 block");
    assert_eq!(field(&out2, "event.category").and_then(Value::as_str), Some("intrusion"));
}

#[test]
fn mapping_without_explicit_severity_map_infers() {
    let mut d = def(ParserEngine::Regex, r"(?P<sev>\S+)");
    d.mapping.severity_field = Some("sev".into());
    let out = parse_with(&d, "ERROR");
    assert_eq!(field(&out, "event.severity").and_then(Value::as_str), Some("high"));
}

mod derived;
mod score;
