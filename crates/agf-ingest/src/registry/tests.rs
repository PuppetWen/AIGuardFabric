//! 注册表单元测试：内置模板匹配、优先级、打分回退与能力矩阵。

use super::*;
use crate::normalize::SourceMeta;

const SURICATA: &str = r#"{"timestamp":"2026-02-21T10:23:45.123456+0000","event_type":"alert","src_ip":"203.0.113.120","src_port":44321,"dest_ip":"10.20.30.120","dest_port":80,"proto":"TCP","alert":{"action":"allowed","gid":1,"signature_id":2024897,"rev":3,"signature":"ET SCAN Potential SSH Scan","category":"Attempted Information Leak","severity":2},"host":"ids-01"}"#;

fn registry() -> ParserRegistry {
    ParserRegistry::with_builtins()
}

#[test]
fn builtins_are_registered_without_invalid() {
    let reg = registry();
    assert_eq!(reg.stats().builtin, template::builtin_count());
    assert_eq!(reg.stats().invalid, 0, "内置模板必须全部可加载: {:?}", reg.invalid_templates());
    assert_eq!(reg.all().len(), template::builtin_count());
    assert!(reg.find_key("suricata-eve-json").is_some());
    assert!(reg.find_id(parser_id_for("wazuh-alert-json")).is_some());
}

#[test]
fn match_by_vendor_and_protocol() {
    let mut reg = registry();
    let outcome = reg.match_raw(SURICATA, IngestProtocol::File, Some("Suricata"), None);
    assert!(outcome.matched, "{outcome:?}");
    assert_eq!(outcome.parser_key.as_deref(), Some("suricata-eve-json"));
    assert_eq!(reg.stats().matched_counts.get("suricata-eve-json"), Some(&1));
    assert_eq!(reg.find_key("suricata-eve-json").map(|p| p.success_count), Some(1));
}

#[test]
fn explicit_parser_key_wins() {
    let mut reg = registry();
    let outcome = reg.match_raw(SURICATA, IngestProtocol::File, None, Some("suricata-eve-json"));
    assert!(outcome.matched);
    assert_eq!(outcome.parser_key.as_deref(), Some("suricata-eve-json"));
    // 显式指定但未命中时回退（用一条非 Suricata 报文指定 Suricata 解析器）
    let fallback = reg.match_raw(
        "<34>Feb 21 10:23:45 h sshd[1]: Failed password",
        IngestProtocol::Syslog,
        None,
        Some("suricata-eve-json"),
    );
    assert!(fallback.matched, "回退后应命中其他模板: {fallback:?}");
    assert_ne!(fallback.parser_key.as_deref(), Some("suricata-eve-json"));
}

/// 内置模板样本的原始数据行（读仓库样本，不手抄、不编造字段）。
fn fixture_line(name: &str) -> String {
    let path = template::repo_fixture_dir().join(name);
    let text = std::fs::read_to_string(&path).unwrap_or_default();
    template::first_data_line(&text).to_string()
}

/// 取一条内置模板定义并改 key / 协议（构造"模板只声明旧协议"的受控场景）。
fn def_like(source_key: &str, key: &str, protocols: &[IngestProtocol]) -> Option<ParserDefinition> {
    let mut def = template::find(source_key)?;
    def.key = key.to_string();
    def.protocols = protocols.to_vec();
    Some(def)
}

/// **放宽趟要解决的缺陷**：同一条阿里云 WAF JSON，走 Webhook 命中、走 MQTT
/// （模板未声明该协议）此前是 `parse_failed`。修复后必须命中且**如实标注**趟次。
#[test]
fn relaxed_pass_matches_alicloud_waf_json_over_mqtt() {
    let raw = fixture_line("aliyun-waf-1.log");
    assert!(!raw.is_empty(), "样本 aliyun-waf-1.log 必须存在");
    let mut reg = registry();

    // 对照：模板声明过 Webhook → 严格趟命中，不计入放宽
    let (strict, strict_mode) = reg.match_raw_with_mode(&raw, IngestProtocol::Webhook, None, None);
    assert!(strict.matched, "{:?}", strict.error);
    assert_eq!(strict_mode, Some(MatchMode::Protocol), "声明过的协议必须走严格趟");
    assert_eq!(reg.stats().matched_relaxed, 0);

    // 缺陷点：MQTT 未声明 → 严格趟零命中 → 放宽趟救回，并标注 protocol-relaxed
    let (relaxed, relaxed_mode) = reg.match_raw_with_mode(&raw, IngestProtocol::Mqtt, None, None);
    assert!(relaxed.matched, "经 MQTT 进来的同一载荷必须命中: {:?}", relaxed.error);
    assert_eq!(relaxed_mode, Some(MatchMode::ProtocolRelaxed));
    assert_eq!(relaxed.parser_key.as_deref(), Some("aliyun-waf-webhook"));
    assert_eq!(reg.stats().matched_relaxed, 1, "放宽命中必须如实计数");
    assert_eq!(reg.stats().mode_count(MatchMode::ProtocolRelaxed), 1);
    assert_eq!(reg.stats().mode_count(MatchMode::Protocol), 1);
    assert_eq!(reg.stats().relaxed_hits.get("aliyun-waf-webhook"), Some(&1));
    assert_eq!(reg.stats().matched_total(), 2);
    // 同一条报文：严格趟与放宽趟抽取的字段完全一致（放宽只改"谁来解析"，不改"解析出什么"）
    assert_eq!(relaxed.fields, strict.fields);
}

/// 安全网①：放宽趟**只在严格趟零命中时**才跑——声明过的协议绝不因放宽而改选模板。
#[test]
fn relaxed_pass_never_preempts_a_strict_hit() {
    let raw = fixture_line("aliyun-waf-1.log");
    assert!(!raw.is_empty());
    // 高优先级（priority=1）模板只声明 Syslog，低优先级（priority=2）声明 Webhook：
    // 若放宽趟抢跑，命中的会是 priority=1 那个；正确行为是 strict 命中 priority=2。
    let mut reg = ParserRegistry::new();
    let Some(high) = def_like("aliyun-waf-webhook", "probe-higher-priority-syslog", &[IngestProtocol::Syslog]) else {
        return;
    };
    let Some(low) = def_like("aliyun-waf-webhook", "probe-strict-webhook", &[IngestProtocol::Webhook]) else {
        return;
    };
    let r1 = reg.register(high, 1);
    let r2 = reg.register(low, 2);
    assert!(r1.is_ok() && r2.is_ok(), "{r1:?} {r2:?}");

    let (outcome, mode) = reg.match_raw_with_mode(&raw, IngestProtocol::Webhook, None, None);
    assert!(outcome.matched, "{:?}", outcome.error);
    assert_eq!(outcome.parser_key.as_deref(), Some("probe-strict-webhook"), "严格趟必须先跑完");
    assert_eq!(mode, Some(MatchMode::Protocol));
    assert_eq!(reg.stats().matched_relaxed, 0);
}

/// 安全网②：`required_fields` 在放宽趟里**照常生效**（不能因为放宽就接受缺字段的载荷）。
#[test]
fn relaxed_pass_still_enforces_required_fields() {
    // 模板只声明 Syslog，投递协议用 Webhook → 只能靠放宽趟；required_fields = ["rule_id"]
    let Some(def) = def_like("aliyun-waf-webhook", "probe-relaxed-required", &[IngestProtocol::Syslog]) else {
        return;
    };
    assert_eq!(def.required_fields, vec!["rule_id".to_string()], "该模板以 rule_id 作为消歧必要条件");
    let mut reg = ParserRegistry::new();
    let registered = reg.register(def, 1);
    assert!(registered.is_ok(), "{registered:?}");

    let with_rule = fixture_line("aliyun-waf-1.log");
    assert!(with_rule.contains("rule_id"));
    let without_rule = with_rule.replace("\"rule_id\":\"d7f8a1c2\",", "");
    assert!(!without_rule.contains("rule_id"));

    let (miss, miss_mode) = reg.match_raw_with_mode(&without_rule, IngestProtocol::Webhook, None, None);
    assert!(!miss.matched, "缺 required_fields 的载荷不得被放宽趟接受: {miss:?}");
    assert_eq!(miss_mode, None);
    assert_eq!(reg.stats().unmatched, 1);
    assert_eq!(reg.stats().matched_relaxed, 0, "未命中不得计入放宽命中");

    let (hit, hit_mode) = reg.match_raw_with_mode(&with_rule, IngestProtocol::Webhook, None, None);
    assert!(hit.matched, "字段齐备的载荷必须被放宽趟接受: {:?}", hit.error);
    assert_eq!(hit_mode, Some(MatchMode::ProtocolRelaxed));
    assert_eq!(reg.stats().matched_relaxed, 1);
}

/// 安全网③：放宽趟的**格式自证**闸门——JSON 载荷不得交给 CSV 模板
/// （否则 CSV 引擎会把 JSON 按逗号切开、按列名凑出 required_fields，造成假命中：
/// 实测 `paloalto-panos-csv` 曾吃掉一条 JSON 载荷，把 AI 兜底与回放的两条既有测试顶掉）。
#[test]
fn relaxed_format_gate_rejects_json_for_csv_templates() {
    let Some(csv_def) = template::find("paloalto-panos-csv") else { return };
    assert_eq!(csv_def.engine, ParserEngine::Csv, "该用例依赖 CSV 引擎模板");
    for json in [
        r#"{"zzz_client":"203.0.113.42","zzz_level":"high","zzz_detail":"异常登录","zzz_action":"block"}"#,
        "[1,2,3]",
        r#"  {"a": 1}"#,
    ] {
        assert!(!format_plausible(&csv_def, json), "JSON 载荷不得进入 CSV 模板的放宽趟：{json}");
    }
    // 真正的 CSV 行不受影响（闸门只认"是不是 JSON 文档"，不按引擎一刀切）
    assert!(format_plausible(&csv_def, "1,2,3,4"), "CSV 行照常放行");
    assert!(format_plausible(&csv_def, "not json at all"));
    // 其它引擎不受此闸门影响（JSON 引擎自己会拒绝非 JSON）
    let Some(json_def) = template::find("aliyun-waf-webhook") else { return };
    assert_eq!(json_def.engine, ParserEngine::JsonPath);
    assert!(format_plausible(&json_def, r#"{"a":1}"#));
    assert!(format_plausible(&json_def, "一行纯文本"));
}

/// 安全网⑤：样本打分趟（第 4 步）与放宽趟共用同一张格式自证闸门。
///
/// 打分修好后第 4 步才真正生效，若没有这道闸门，`Csv` 模板会"用逗号切 JSON"凑出
/// `serial` 这样的必需字段并拿到高分，从另一个门复现同一类假命中。
#[test]
fn sample_score_pass_respects_format_gate() {
    let Some(csv_def) = template::find("paloalto-panos-csv") else { return };
    assert_eq!(csv_def.engine, ParserEngine::Csv);
    assert!(!csv_def.protocols.contains(&IngestProtocol::Mqtt), "该用例依赖 mqtt 未声明");
    let mut reg = ParserRegistry::new();
    assert!(reg.register(csv_def, 1).is_ok());

    // JSON 载荷（含逗号，且第 3 个逗号段能凑出 serial）：三趟都不接受
    let json = r#"{"serial":"001801000001","src_ip":"10.0.0.1","x":"2","y":"3"}"#;
    let (outcome, mode) = reg.match_raw_with_mode(json, IngestProtocol::Mqtt, None, None);
    assert!(!outcome.matched, "JSON 载荷不得被 CSV 模板经样本打分趟接受: {outcome:?}");
    assert_eq!(mode, None);

    // 真正的 CSV 行不受影响：放宽趟照常接住（闸门只认"是不是 JSON 文档"）
    let line = "2026/03/01 10:00:00,2026/03/01 10:00:01,001801000001,TRAFFIC,end";
    let (hit, hit_mode) = reg.match_raw_with_mode(line, IngestProtocol::Mqtt, None, None);
    assert!(hit.matched, "CSV 行必须照常命中: {:?}", hit.error);
    assert_eq!(hit_mode, Some(MatchMode::ProtocolRelaxed));
    assert_eq!(hit.matched_by.as_deref(), Some("protocol-relaxed"));
}

/// 安全网④：放宽趟内部同样按 `(priority, 内置优先, key)` 顺序——结果确定、可解释。
#[test]
fn relaxed_pass_is_priority_deterministic() {
    let raw = fixture_line("aliyun-waf-1.log");
    assert!(!raw.is_empty());
    let mut reg = ParserRegistry::new();
    let Some(low) = def_like("aliyun-waf-webhook", "probe-relaxed-priority-9", &[IngestProtocol::Syslog]) else {
        return;
    };
    let Some(high) = def_like("aliyun-waf-webhook", "probe-relaxed-priority-5", &[IngestProtocol::Syslog]) else {
        return;
    };
    // 故意先注册低优先级，再注册高优先级：命中必须是 priority 数值更小者
    let r1 = reg.register(low, 9);
    let r2 = reg.register(high, 5);
    assert!(r1.is_ok() && r2.is_ok(), "{r1:?} {r2:?}");

    let (outcome, mode) = reg.match_raw_with_mode(&raw, IngestProtocol::Mqtt, None, None);
    assert!(outcome.matched, "{:?}", outcome.error);
    assert_eq!(outcome.parser_key.as_deref(), Some("probe-relaxed-priority-5"));
    assert_eq!(mode, Some(MatchMode::ProtocolRelaxed));
    assert_eq!(reg.stats().relaxed_hits.len(), 1);
}

#[test]
fn unmatched_message_is_reported() {
    let mut reg = registry();
    let outcome = reg.match_raw("这是一条完全无法识别的自由文本", IngestProtocol::Webhook, None, None);
    assert!(!outcome.matched);
    assert!(outcome.error.unwrap_or_default().contains("无模板命中"));
    assert_eq!(reg.stats().unmatched, 1);
}

#[test]
fn sample_scoring_disambiguates_cef_from_json() {
    let mut reg = registry();
    let cef = "<134>Feb 21 10:23:45 fw1 CEF:0|Sangfor|AF|8.0.17|1001|IPS 攻击|5|src=10.20.30.50 dst=203.0.113.10 spt=54321 dpt=80 proto=TCP act=block cat=入侵检测 msg=SQL 注入";
    let outcome = reg.match_raw(cef, IngestProtocol::Syslog, None, None);
    assert!(outcome.matched);
    assert_eq!(outcome.parser_key.as_deref(), Some("sangfor-af-cef"));
}

/// **逐条透出 `matched_by`**：五条命中路径都必须把趟次写进结果本身
/// （不只是写进聚合统计）——否则"命中了，但凭什么命中"不可观测。
#[test]
fn matched_by_is_stamped_on_every_hit_path() {
    let raw = fixture_line("aliyun-waf-1.log");
    assert!(!raw.is_empty());

    // ① 显式指定
    let mut reg = registry();
    let (outcome, mode) = reg.match_raw_with_mode(&raw, IngestProtocol::File, None, Some("aliyun-waf-webhook"));
    assert_eq!(mode, Some(MatchMode::Explicit));
    assert_eq!(outcome.matched_by.as_deref(), Some("explicit"));

    // ② 严格趟（模板声明过 webhook）
    let mut reg = registry();
    let (outcome, mode) = reg.match_raw_with_mode(&raw, IngestProtocol::Webhook, None, None);
    assert_eq!(mode, Some(MatchMode::Protocol));
    assert_eq!(outcome.matched_by.as_deref(), Some("protocol"));

    // ③ 放宽趟（模板未声明 mqtt）
    let mut reg = registry();
    let (outcome, mode) = reg.match_raw_with_mode(&raw, IngestProtocol::Mqtt, None, None);
    assert_eq!(mode, Some(MatchMode::ProtocolRelaxed));
    assert_eq!(outcome.matched_by.as_deref(), Some("protocol-relaxed"));

    // ④ 样本打分：厂商提示把严格趟与放宽趟都挡掉，只剩第 4 步（它不看厂商）
    let mut reg = registry();
    let (outcome, mode) = reg.match_raw_with_mode(&raw, IngestProtocol::Webhook, Some("Suricata"), None);
    assert!(outcome.matched, "第 4 步必须接住被厂商提示挡掉的模板: {:?}", outcome.error);
    assert_eq!(outcome.parser_key.as_deref(), Some("aliyun-waf-webhook"));
    assert_eq!(mode, Some(MatchMode::SampleScore));
    assert_eq!(outcome.matched_by.as_deref(), Some("sample-score"));
    assert_eq!(reg.stats().mode_count(MatchMode::SampleScore), 1);
    assert_eq!(reg.stats().matched_by_mode.get("sample-score"), Some(&1));

    // ⑤ AI 推断兜底
    let mut reg = ParserRegistry::with_builtins();
    reg.set_ai_fallback(true);
    let unknown = r#"{"client_ip":"203.0.113.5","path":"/x","code":"200","ts":"2026-02-21T10:23:45Z","who":"root"}"#;
    let (outcome, mode) = reg.match_raw_with_mode(unknown, IngestProtocol::Webhook, None, None);
    assert_eq!(mode, Some(MatchMode::AiInferred));
    assert_eq!(outcome.matched_by.as_deref(), Some("ai-inferred"));

    // 未命中：不得写趟次（`None` 与"命中但趟次未知"必须区分得开）
    let miss = reg.match_raw("完全无法识别的自由文本，没有分隔符也没有结构", IngestProtocol::Webhook, None, None);
    assert!(!miss.matched);
    assert_eq!(miss.matched_by, None);
}

/// 样本打分趟修好后**真的会命中**：`required_fields` 写源字段名的模板不再被腰斩。
///
/// 受控场景：模板只声明 `syslog`，用厂商提示把严格趟 / 放宽趟都挡掉，
/// 于是唯一可能的命中路径就是第 4 步。
#[test]
fn sample_score_pass_hits_required_fields_template() {
    let raw = fixture_line("aliyun-waf-1.log");
    assert!(!raw.is_empty());
    let Some(def) = def_like("aliyun-waf-webhook", "probe-sample-score-required", &[IngestProtocol::Syslog]) else {
        return;
    };
    assert_eq!(def.required_fields, vec!["rule_id".to_string()], "该模板以源字段名 rule_id 消歧");
    let mut reg = ParserRegistry::new();
    assert!(reg.register(def, 1).is_ok());

    let (outcome, mode) = reg.match_raw_with_mode(&raw, IngestProtocol::Webhook, Some("Suricata"), None);
    assert!(outcome.matched, "字段齐备时必须被第 4 步接住: {:?}", outcome.error);
    assert_eq!(mode, Some(MatchMode::SampleScore));
    assert_eq!(reg.stats().matched_relaxed, 0, "第 4 步命中不得计入放宽命中");

    // 缺 `rule_id` 的同一载荷：第 4 步也不接受（打分口径与判定口径一致）
    let without = raw.replace("\"rule_id\":\"d7f8a1c2\",", "");
    assert!(!without.contains("rule_id"));
    let (miss, miss_mode) = reg.match_raw_with_mode(&without, IngestProtocol::Webhook, Some("Suricata"), None);
    assert!(!miss.matched, "缺必需字段时第 4 步也必须拒绝: {miss:?}");
    assert_eq!(miss_mode, None);
}

#[test]
fn invalid_template_is_rejected_not_panicking() {
    let mut reg = ParserRegistry::new();
    let mut def = template::find("suricata-eve-json").unwrap_or_else(|| template::builtin_templates().remove(0));
    def.key = "broken".to_string();
    def.engine = ParserEngine::Regex;
    def.pattern = "(unclosed".to_string();
    let err = reg.register(def, 1);
    assert!(err.is_err());
    assert_eq!(reg.stats().invalid, 1);
    assert_eq!(reg.invalid_templates().len(), 1);
    assert!(reg.all().is_empty());
}

#[test]
fn yaml_dir_loading_reads_single_and_wrapped_files() {
    let dir = std::env::temp_dir().join(format!("agf-parsers-{}", uuid::Uuid::new_v4()));
    assert!(std::fs::create_dir_all(dir.join("nested")).is_ok());
    let single = r#"
key: custom-app-kv
name: 自研应用 KV
vendor: 自研
product: AppLog
protocols: [file]
engine: kv
pattern: "="
mapping:
  map:
    client: source.ip
    user: user.name
  severity_field: level
  severity_map:
    warn: medium
    error: high
  action_field: act
  defaults:
    event.category: web
required_fields: [client]
"#;
    let wrapped = r"
parsers:
  - key: custom-app-regex
    name: 自研应用正则
    vendor: 自研
    product: AppLog
    engine: regex
    pattern: 'client=(?P<client>[\d.]+) user=(?P<user>\w+)'
";
    assert!(std::fs::write(dir.join("single.yaml"), single).is_ok());
    assert!(std::fs::write(dir.join("nested").join("wrapped.yml"), wrapped).is_ok());
    assert!(std::fs::write(dir.join("ignored.txt"), "不是 YAML").is_ok());

    let mut reg = ParserRegistry::with_builtins();
    let loaded = reg.load_dir(&dir);
    assert_eq!(loaded.ok(), Some(2), "应加载 2 个模板: {:?}", reg.invalid_templates());
    assert_eq!(reg.stats().loaded, 2);
    assert!(reg.find_key("custom-app-kv").is_some());
    assert!(reg.find_key("custom-app-regex").is_some());

    let raw = "client=10.1.2.3 user=alice level=error act=block";
    let outcome = reg.match_raw(raw, IngestProtocol::File, Some("自研"), None);
    assert!(outcome.matched, "{outcome:?}");
    assert_eq!(outcome.fields.get("event.severity").and_then(|v| v.as_str()), Some("high"));
    assert_eq!(outcome.fields.get("event.action").and_then(|v| v.as_str()), Some("denied"));
    let meta = SourceMeta {
        tenant_id: agf_core::ids::TenantId::default_tenant(),
        source_id: Id::new(),
        source_name: "custom".to_string(),
        vendor: "自研".to_string(),
        product: "AppLog".to_string(),
        protocol: IngestProtocol::File,
        tags: vec![],
        ingested_at: Timestamp::now(),
    };
    let event = crate::normalize::normalize(&outcome, &meta, raw, "file");
    assert_eq!(event.network.source_ip.as_deref(), Some("10.1.2.3"));
    assert_eq!(event.category, agf_core::event::EventCategory::Web);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn missing_dir_reports_error() {
    let mut reg = ParserRegistry::new();
    let err = reg.load_dir(Path::new("D:/definitely/not/exists/agf"));
    assert!(err.is_err());
}

#[test]
fn ai_suggestion_can_be_registered() {
    let mut reg = ParserRegistry::new();
    let suggestion = crate::ai_parser::infer_suggestion(&[SURICATA.to_string()], Some("Suricata"), None);
    assert!(suggestion.is_some(), "启发式推断应能生成解析器");
    let Some(suggestion) = suggestion else { return };
    let registered = reg.register_ai_inferred(&suggestion, 5_000);
    assert!(registered.is_ok(), "{registered:?}");
    assert_eq!(reg.stats().ai_inferred, 1);
    let def = reg.all().first().map(|p| p.definition.clone());
    assert!(def.as_ref().is_some_and(|d| d.ai_inferred && !d.builtin));
}

#[test]
fn ai_fallback_can_match_unknown_payload() {
    let mut reg = ParserRegistry::with_builtins();
    reg.set_ai_fallback(true);
    let raw = r#"{"client_ip":"203.0.113.5","path":"/x","code":"200","ts":"2026-02-21T10:23:45Z","who":"root"}"#;
    let outcome = reg.match_raw(raw, IngestProtocol::Webhook, None, None);
    assert!(outcome.matched, "AI 兜底应命中: {outcome:?}");
    assert_eq!(outcome.parser_key.as_deref(), Some(crate::ai_parser::HEURISTIC_KEY));
}

#[test]
fn engine_support_matrix_is_complete() {
    let matrix = engine_support_matrix();
    assert_eq!(matrix.len(), ParserEngine::all().len());
    assert_eq!(matrix.get("grok"), Some(&"已实现"));
    // 口径修正：`cel` 是**已实现**的派生字段求值（旧文案"未实现（TODO ingest-cel）"与事实不符）；
    // `plugin` 本轮接线完成（旧文案"未实现（TODO ingest-plugin）"同样已失效）。
    let cel = matrix.get("cel").copied().unwrap_or_default();
    assert!(cel.contains("已实现") && !cel.contains("TODO"), "cel 行口径必须与实现一致: {cel}");
    let plugin = matrix.get("plugin").copied().unwrap_or_default();
    assert!(plugin.contains("已实现") && !plugin.contains("TODO"), "plugin 行口径必须与实现一致: {plugin}");
}
