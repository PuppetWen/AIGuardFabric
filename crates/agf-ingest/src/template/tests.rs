//! 内置模板目录单元测试：数量/唯一性/manifest 对齐/正样本真实解析。

use super::*;
use crate::engine;
use crate::normalize::{self, SourceMeta};
use agf_core::ids::{Id, TenantId};
use agf_core::time::Timestamp;

fn fixture_text(dir: &Path, name: &str) -> String {
    let path = dir.join(name);
    std::fs::read_to_string(&path).unwrap_or_default()
}

fn manifest() -> (PathBuf, FixtureManifest) {
    let dir = repo_fixture_dir();
    let manifest = load_manifest(&dir);
    assert!(manifest.is_ok(), "manifest.json 读取失败: {manifest:?}");
    (dir, manifest.unwrap_or_else(|_| FixtureManifest { version: 0, note: String::new(), templates: BTreeMap::new() }))
}

#[test]
fn builtin_catalog_has_nineteen_templates() {
    let templates = builtin_templates();
    assert_eq!(templates.len(), 19, "内置模板数量变化需同步 SOURCES.md 与 manifest.json");
    // key 唯一
    let mut keys: Vec<&str> = templates.iter().map(|d| d.key.as_str()).collect();
    keys.sort_unstable();
    keys.dedup();
    assert_eq!(keys.len(), templates.len(), "模板 key 必须唯一");
    // 每个模板都能通过 agf-core 的加载期校验
    for d in &templates {
        assert!(d.validate().is_ok(), "模板 {} 校验失败: {:?}", d.key, d.validate());
        assert!(d.builtin);
        assert!(!d.sample_fixture.is_empty(), "模板 {} 缺少样例", d.key);
        assert!(d.requires_sample());
        assert!(!d.name.is_empty() && !d.description.is_empty());
        // 引擎覆盖：不出现 cel/plugin/ai-inferred
        assert!(!matches!(d.engine, ParserEngine::Cel | ParserEngine::Plugin | ParserEngine::AiInferred));
    }
}

#[test]
fn every_engine_used_by_catalog_is_implemented() {
    let used: Vec<ParserEngine> = builtin_templates().into_iter().map(|d| d.engine).collect();
    for engine in [
        ParserEngine::Grok,
        ParserEngine::Regex,
        ParserEngine::JsonPath,
        ParserEngine::Cef,
        ParserEngine::Leef,
        ParserEngine::Kv,
        ParserEngine::Csv,
        ParserEngine::Syslog,
    ] {
        assert!(used.contains(&engine), "内置模板未覆盖引擎 {engine:?}");
    }
}

#[test]
fn vendor_coverage_matches_specification() {
    let templates = builtin_templates();
    for vendor in [
        "青藤云",
        "阿里云",
        "华为云",
        "腾讯云",
        "深信服",
        "奇安信",
        "绿盟",
        "天融信",
        "Fortinet",
        "Palo Alto",
        "CrowdStrike",
        "Wazuh",
        "Suricata",
        "Zeek",
    ] {
        assert!(templates.iter().any(|d| d.vendor == vendor), "缺少厂商模板: {vendor}");
    }
    // 阿里云与华为云各有两个产品
    assert!(templates.iter().filter(|d| d.vendor == "阿里云").count() >= 2);
    assert!(templates.iter().filter(|d| d.vendor == "华为云").count() >= 2);
}

#[test]
fn lookup_by_vendor_product_protocol() {
    let hits = lookup("Fortinet", "FortiGate", Some(IngestProtocol::Syslog));
    assert_eq!(hits.len(), 1);
    assert_eq!(hits.first().map(|d| d.key.as_str()), Some("fortinet-fortigate-kv"));
    assert!(lookup("Fortinet", "FortiGate", Some(IngestProtocol::Jdbc)).is_empty());
    assert_eq!(lookup("", "", None).len(), builtin_count());
    assert_eq!(find("wazuh-alert-json").map(|d| d.product), Some("Wazuh Manager".to_string()));
    assert!(find("no-such-template").is_none());
}

#[test]
fn manifest_covers_every_template_and_fixture_exists() {
    let (dir, manifest) = manifest();
    assert_eq!(manifest.version, 1);
    let templates = builtin_templates();
    assert_eq!(manifest.templates.len(), templates.len(), "manifest 与内置模板数量不一致");
    let known: Vec<&str> = templates.iter().map(|d| d.key.as_str()).collect();
    let unknown: Vec<&String> = manifest.templates.keys().filter(|k| !known.contains(&k.as_str())).collect();
    assert!(unknown.is_empty(), "manifest 中的模板在内置目录中不存在: {unknown:?}");
    for d in &templates {
        let entry = manifest.templates.get(&d.key);
        assert!(entry.is_some(), "manifest 缺少模板 {}", d.key);
        let Some(entry) = entry else { continue };
        let path = dir.join(&entry.fixture);
        assert!(path.exists(), "样本文件不存在: {}", path.display());
        assert_eq!(
            d.sample_fixture,
            format!("{FIXTURE_DIR_REL}/{}", entry.fixture),
            "模板 {} 的 sample_fixture 与 manifest 不一致",
            d.key
        );
        assert_eq!(entry.vendor, d.vendor);
        assert_eq!(entry.product, d.product);
    }
}

/// 验收准则："N 家厂商模板开箱即用 + 原始日志可回放"。
#[test]
fn every_manifest_fixture_parses_into_expected_event() {
    let (dir, manifest) = manifest();
    let templates = builtin_templates();
    let mut checked = 0_usize;
    for (key, entry) in &manifest.templates {
        let Some(def) = templates.iter().find(|d| &d.key == key) else {
            continue;
        };
        let text = fixture_text(&dir, &entry.fixture);
        assert!(!text.trim().is_empty(), "样本 {0} 为空", entry.fixture);
        let line = first_data_line(&text);
        assert!(!line.is_empty(), "样本 {0} 无数据行", entry.fixture);

        let outcome = engine::parse_with(def, line);
        assert!(outcome.matched, "模板 {key} 解析样本 {} 失败: {:?}", entry.fixture, outcome.error);
        assert_eq!(outcome.parser_key.as_deref(), Some(key.as_str()));

        let meta = SourceMeta {
            tenant_id: TenantId::default_tenant(),
            source_id: Id::new(),
            source_name: format!("fixture-{key}"),
            vendor: def.vendor.clone(),
            product: def.product.clone(),
            protocol: def.protocols.first().copied().unwrap_or(IngestProtocol::File),
            tags: vec!["fixture".to_string()],
            ingested_at: Timestamp::now(),
        };
        let event = normalize::normalize(&outcome, &meta, line, &entry.fixture);

        assert_eq!(event.severity.as_str(), entry.severity, "模板 {key} 严重等级不符（样本 {}）", entry.fixture);
        assert_eq!(event.category.as_str(), entry.category, "模板 {key} 事件类别不符（样本 {}）", entry.fixture);
        if !entry.host.is_empty() {
            assert_eq!(event.host.name.as_deref(), Some(entry.host.as_str()), "模板 {key} 主机名不符");
        }
        if !entry.ip.is_empty() {
            let candidates = [event.network.source_ip.as_deref(), event.network.destination_ip.as_deref()];
            let hit = candidates.contains(&Some(entry.ip.as_str())) || event.host.ips.iter().any(|ip| ip == &entry.ip);
            assert!(hit, "模板 {key} 未命中期望 IP {}：{event:?}", entry.ip);
        }
        // 原始日志可回放：raw_hash 必须等于原始行的内容哈希，raw 保真
        assert_eq!(event.raw_hash, agf_core::secret::content_hash(line));
        assert!(event.raw.is_string() || event.raw.is_object());
        assert!(!event.message.is_empty());
        checked += 1;
    }
    assert!(checked >= 12, "至少需要 12 个厂商模板样本，实际 {checked}");
}

#[test]
fn fixtures_have_no_placeholder_content() {
    let (dir, manifest) = manifest();
    for (key, entry) in &manifest.templates {
        let text = fixture_text(&dir, &entry.fixture);
        let lower = text.to_lowercase();
        for bad in ["test log", "lorem ipsum", "foo bar", "示例日志 1"] {
            assert!(!lower.contains(bad), "样本 {} 含占位内容 `{bad}`", entry.fixture);
        }
        assert!(text.len() > 80, "样本 {} 过短，不像真实日志（模板 {key}）", entry.fixture);
    }
}

#[test]
fn sources_md_documents_every_fixture() {
    let dir = repo_fixture_dir();
    let doc = fixture_text(&dir, "SOURCES.md");
    assert!(!doc.is_empty(), "SOURCES.md 缺失");
    assert!(doc.contains("synthetic=true"), "SOURCES.md 必须显式标注合成样本");
    let (_, manifest) = manifest();
    for entry in manifest.templates.values() {
        assert!(doc.contains(&entry.fixture), "SOURCES.md 未记录样本 {}", entry.fixture);
    }
}

/// **真实 OTLP 归一化载荷**（逐字取自本仓库 OTLP 接收器的产物形状：
/// `otlp::OtlpLogRecord::to_payload`，取值同 `tools/simulators/otlp_logs.py`）。
const OTLP_LOG: &str = r#"{"@timestamp":"2026-02-21T10:23:45.000000123Z","message":"otlp-sim event 0: upstream timeout after 3000ms","severity_text":"ERROR","severity_number":17,"trace_id":"4bf92f3577b34da6a3ce929d0e0e4736","span_id":"00f067aa0ba902b7","event_name":"upstream.timeout","resource":{"host.name":"agf-sim-host","service.name":"agf-otlp-sim"},"attributes":{"http.status_code":"500","sim.flag":"true","sim.index":"0","sim.note":"note-0"},"scope":{"name":"tools.simulators.otlp_logs","version":"1.0.0"}}"#;

fn otlp_source_meta() -> SourceMeta {
    SourceMeta {
        tenant_id: TenantId::default_tenant(),
        source_id: Id::new(),
        source_name: "otlp-fixture".to_string(),
        vendor: "OpenTelemetry".to_string(),
        product: "OTLP Logs".to_string(),
        protocol: IngestProtocol::Otlp,
        tags: vec!["fixture".to_string()],
        ingested_at: Timestamp::now(),
    }
}

/// 内置 OTLP 模板把归一化载荷搬到 ECS：**字段级**断言（不是"不报错就算过"）。
#[test]
fn otlp_template_maps_real_payload_into_ecs_fields() {
    assert!(find("otlp-json-log").is_some(), "内置 OTLP 模板必须存在（builtin_count 需为 19）");
    let Some(def) = find("otlp-json-log") else { return };
    assert!(def.protocols.contains(&IngestProtocol::Otlp), "OTLP 模板必须显式声明 otlp 协议");
    assert_eq!(def.engine, ParserEngine::JsonPath);

    let outcome = engine::parse_with(&def, OTLP_LOG);
    assert!(outcome.matched, "OTLP 载荷必须命中: {:?}", outcome.error);
    assert_eq!(outcome.parser_key.as_deref(), Some("otlp-json-log"));

    // `$.message → message`
    assert_eq!(outcome.get_str("message"), Some("otlp-sim event 0: upstream timeout after 3000ms"));
    // `$.severity_text → event.severity`（大小写归一：ERROR → 平台 high）
    assert_eq!(outcome.get_str("event.severity"), Some("high"));
    // 原文标签保真（后续可解释"厂商原值 → 平台等级"的换算）
    assert_eq!(outcome.get_str("log.level"), Some("ERROR"));
    // `$.resource.host.name` / `$.resource.service.name`（接收器输出的是 OTLP 原文点号键）
    assert_eq!(outcome.get_str("host.name"), Some("agf-sim-host"));
    assert_eq!(outcome.get_str("service.name"), Some("agf-otlp-sim"));
    // `$.trace_id` / `$.span_id`
    assert_eq!(outcome.get_str("trace.id"), Some("4bf92f3577b34da6a3ce929d0e0e4736"));
    assert_eq!(outcome.get_str("trace.span_id"), Some("00f067aa0ba902b7"));
    // `@timestamp`（ISO8601 带纳秒）→ `event.time`（平台统一 UTC 毫秒文本）
    assert_eq!(outcome.get_str("event.time"), Some("2026-02-21T10:23:45.000Z"));
    // `$.attributes.*`：整体保真进 `otel.attributes`（既有口径：未识别路径进 extra，不猜语义）
    assert_eq!(
        outcome.fields.get("otel.attributes").and_then(|v| v.get("http.status_code")).and_then(Value::as_str),
        Some("500")
    );

    let event = normalize::normalize(&outcome, &otlp_source_meta(), OTLP_LOG, "otlp-json-1.log");
    assert_eq!(event.severity, Severity::High, "severity_text=ERROR 必须归一化成 high");
    assert_eq!(event.host.name.as_deref(), Some("agf-sim-host"));
    assert_eq!(event.message, "otlp-sim event 0: upstream timeout after 3000ms");
    assert_eq!(event.time.to_rfc3339(), "2026-02-21T10:23:45.000Z");
    assert_eq!(event.time.unix_secs(), 1_771_669_425);
    assert_eq!(event.extra.get("service.name").and_then(Value::as_str), Some("agf-otlp-sim"));
    assert_eq!(event.extra.get("trace.id").and_then(Value::as_str), Some("4bf92f3577b34da6a3ce929d0e0e4736"));
    assert_eq!(event.extra.get("trace.span_id").and_then(Value::as_str), Some("00f067aa0ba902b7"));
    assert_eq!(
        event.extra.get("otel.attributes").and_then(|v| v.get("sim.note")).and_then(Value::as_str),
        Some("note-0")
    );
    // 原始日志保真（可回放）
    assert_eq!(event.raw_hash, agf_core::secret::content_hash(OTLP_LOG));
}

/// OTLP 六值等级词表 → 平台五级，且**大小写不敏感**。
#[test]
fn otlp_severity_vocabulary_is_normalized_case_insensitively() {
    assert!(find("otlp-json-log").is_some(), "内置 OTLP 模板必须存在");
    let Some(def) = find("otlp-json-log") else { return };
    for (label, want) in [
        ("TRACE", "info"),
        ("trace", "info"),
        ("DEBUG", "info"),
        ("debug", "info"),
        ("INFO", "info"),
        ("Info", "info"),
        ("WARN", "medium"),
        ("warn", "medium"),
        ("ERROR", "high"),
        ("error", "high"),
        ("FATAL", "critical"),
        ("fatal", "critical"),
        ("UNSPECIFIED", "info"),
    ] {
        let payload = OTLP_LOG.replace("\"severity_text\":\"ERROR\"", &format!("\"severity_text\":\"{label}\""));
        let outcome = engine::parse_with(&def, &payload);
        assert!(outcome.matched, "severity_text={label} 必须命中: {:?}", outcome.error);
        assert_eq!(outcome.get_str("event.severity"), Some(want), "severity_text={label} 归一化结果不符");
        assert_eq!(outcome.get_str("log.level"), Some(label), "原文标签必须保真");
    }
    // 词表外的取值**不臆造**等级：原样透出，交给 normalize 的兜底（Info）
    let weird = OTLP_LOG.replace("\"severity_text\":\"ERROR\"", "\"severity_text\":\"weird\"");
    let outcome = engine::parse_with(&def, &weird);
    assert!(outcome.matched);
    assert_eq!(outcome.get_str("event.severity"), Some("weird"));
    let event = normalize::normalize(&outcome, &otlp_source_meta(), &weird, "otlp-json-1.log");
    assert_eq!(event.severity, Severity::Info, "无法识别的等级按 info 处理（不猜测）");
}

/// OTLP 模板不得变成"什么 JSON 都吃"的万能模板：`required_fields` 把门。
#[test]
fn otlp_template_rejects_payloads_without_otlp_markers() {
    assert!(find("otlp-json-log").is_some(), "内置 OTLP 模板必须存在");
    let Some(def) = find("otlp-json-log") else { return };
    for raw in [
        r#"{"time":"2026-02-21T10:30:15+08:00","host":"www.example.com","real_client_ip":"203.0.113.77","rule_id":"waf-100012"}"#,
        r#"{"timestamp":"2026-02-21T10:23:45Z","event_type":"alert","src_ip":"10.0.0.1"}"#,
        "这是一条完全无法识别的自由文本",
    ] {
        let outcome = engine::parse_with(&def, raw);
        assert!(!outcome.matched, "非 OTLP 载荷不得被 OTLP 模板接受：{raw}");
    }
}

#[test]
fn first_data_line_skips_comments_and_blanks() {
    let text = "\n#separator \\x09\n#fields a b c\n1\t2\t3\n";
    assert_eq!(first_data_line(text), "1\t2\t3");
    assert_eq!(first_data_line(""), "");
}

#[test]
fn wazuh_severity_table_covers_all_levels() {
    let table = wazuh_severity_map();
    assert_eq!(table.len(), 16);
    assert_eq!(table.get("10"), Some(&Severity::High));
    assert_eq!(table.get("15"), Some(&Severity::Critical));
    assert_eq!(table.get("0"), Some(&Severity::Info));
}

#[test]
fn fixture_dir_is_repo_root_relative() {
    let dir = repo_fixture_dir();
    assert!(dir.ends_with(FIXTURE_DIR_REL.replace('/', std::path::MAIN_SEPARATOR_STR)));
    assert!(dir.join(MANIFEST_FILE).exists(), "样本目录定位错误: {}", dir.display());
}
