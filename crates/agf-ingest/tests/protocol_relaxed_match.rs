//! 协议白名单**放宽趟**的行为锁定（修复"经新协议进来的载荷命中不了模板"）。
//!
//! ## 被修复的缺陷
//!
//! `ParserRegistry::match_raw` 曾对每个模板做 `def.protocols.contains(&protocol)` 过滤，而模板库
//! （内置 19 + `parsers/` 库）几乎没有声明 `otlp` / `mqtt` / `jdbc` / `pulsar` / `snmp-trap`。
//! 结果：**同一条载荷**，走 `webhook` / `http-pull` 命中，走 `mqtt` / `otlp` 就 `parse_failed`
//! ——字段明明对得上，只是"进来的协议没人认领"。
//!
//! ## 修复口径（本文件逐条锁定）
//!
//! 1. 严格趟（协议白名单生效）**行为不变**：凡是"只保留声明了该协议的模板"的注册表能命中的，
//!    完整注册表也必须命中**同一个模板**，且趟次不是放宽；
//! 2. 放宽趟**只在严格趟零命中时**补跑：凡是完整注册表给出 `protocol-relaxed` 的，协议过滤后的
//!    注册表必须**完全没有命中**（否则就是放宽趟抢跑，语义就脏了）；
//! 3. 放宽趟**不放松字段要求**：`required_fields` 由 `engine::parse_with` 照常把关；
//! 4. 命中率数字（严格 / 放宽 / 仍未命中）逐条打印，便于人工核对与回归比对。
//!
//! 跑法：`cargo test -p agf-ingest --test protocol_relaxed_match -- --nocapture`

#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used, clippy::print_stdout)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use agf_core::enums::IngestProtocol;
use agf_ingest::registry::{MatchMode, ParserRegistry};

/// 仓库根（`crates/agf-ingest/tests/` 向上三级）。
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

/// 一条样本。
#[derive(Debug, Clone)]
struct Sample {
    /// 模板 key（样本"自己的"模板）。
    key: String,
    /// 声明的协议文本。
    protocol: String,
    /// 载荷原文（首个非空行）。
    line: String,
}

/// `parsers/*/samples.json` 全部样本 + 1 条真实 OTLP 载荷（按 key 升序）。
fn all_samples() -> Vec<Sample> {
    let parsers = repo_root().join("parsers");
    let fixtures = repo_root().join("tests").join("fixtures").join("logs");
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(&parsers)
        .expect("读取 parsers/ 失败")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_dir())
        .collect();
    dirs.sort();
    let mut out = Vec::new();
    for dir in dirs {
        let path = dir.join("samples.json");
        if !path.is_file() {
            continue;
        }
        let text = std::fs::read_to_string(&path).expect("读取 samples.json 失败");
        let value: serde_json::Value = serde_json::from_str(&text).expect("samples.json 非法 JSON");
        let Some(entries) = value.get("samples").and_then(|v| v.as_object()) else { continue };
        for (key, entry) in entries {
            let protocol = entry.get("protocol").and_then(|v| v.as_str()).unwrap_or("file").to_string();
            let raw = if let Some(fixture) = entry.get("fixture").and_then(|v| v.as_str()) {
                std::fs::read_to_string(fixtures.join(fixture)).expect("读取 fixture 失败")
            } else {
                entry.get("line").and_then(|v| v.as_str()).unwrap_or_default().to_string()
            };
            let line = raw.lines().find(|l| !l.trim().is_empty()).unwrap_or_default().trim().to_string();
            if !line.is_empty() {
                out.push(Sample { key: key.clone(), protocol, line });
            }
        }
    }
    out.sort_by(|a, b| a.key.cmp(&b.key));
    out.push(otlp_sample());
    out
}

/// 真实 OTLP 载荷：由 OTLP 接收器自己的 `to_payload()` 生成（取值同 `tools/simulators/otlp_logs.py`）。
fn otlp_sample() -> Sample {
    use agf_ingest::otlp::OtlpLogRecord;
    let mut record = OtlpLogRecord {
        time_unix_nano: Some(1_771_669_425_000_000_123),
        severity_number: Some(17),
        severity_text: Some("ERROR".to_string()),
        body: Some("otlp-sim event 0: upstream timeout after 3000ms".to_string()),
        trace_id: Some("4bf92f3577b34da6a3ce929d0e0e4736".to_string()),
        span_id: Some("00f067aa0ba902b7".to_string()),
        event_name: Some("upstream.timeout".to_string()),
        scope_name: Some("tools.simulators.otlp_logs".to_string()),
        scope_version: Some("1.0.0".to_string()),
        ..OtlpLogRecord::default()
    };
    record.resource.insert("service.name".to_string(), "agf-otlp-sim".to_string());
    record.resource.insert("host.name".to_string(), "agf-sim-host".to_string());
    record.attributes.insert("http.status_code".to_string(), "500".to_string());
    record.attributes.insert("sim.index".to_string(), "0".to_string());
    Sample {
        key: "otlp-json-log".to_string(),
        protocol: "otlp".to_string(),
        line: String::from_utf8_lossy(&record.to_payload()).to_string(),
    }
}

/// 协议文本 → 枚举（未知回落 `file`）。
fn protocol_of(name: &str) -> IngestProtocol {
    IngestProtocol::all().into_iter().find(|p| p.as_str() == name).unwrap_or(IngestProtocol::File)
}

/// "只有声明了 `protocol` 的模板"的注册表（= 严格趟的候选集，放宽趟看不到任何候选）。
///
/// 用完整注册表里的**同一份定义与同一优先级**重建，因此两者的严格趟结果必须逐字相同。
fn strict_only_registry(full: &ParserRegistry, protocol: IngestProtocol) -> ParserRegistry {
    let mut strict = ParserRegistry::new();
    for parser in full.all() {
        let def = &parser.definition;
        if def.protocols.is_empty() || def.protocols.contains(&protocol) {
            let registered = strict.register(def.clone(), parser.priority);
            assert!(registered.is_ok(), "重建严格注册表失败: {registered:?}");
        }
    }
    strict
}

/// 投放协议探针：第 0 项 = 样本自己声明的协议（原有语义），后三项 = 模板库普遍**未声明**的新协议。
const PROBES: [&str; 4] = ["declared", "mqtt", "otlp", "jdbc"];

/// 第 `index` 项探针实际使用的协议（第 0 项取样本自己声明的协议）。
fn probe_protocol(index: usize, sample: &Sample) -> IngestProtocol {
    match index {
        0 => protocol_of(&sample.protocol),
        1 => IngestProtocol::Mqtt,
        2 => IngestProtocol::Otlp,
        _ => IngestProtocol::Jdbc,
    }
}

/// **核心不变量**：严格趟不变 + 放宽趟不抢跑；顺带打印命中率矩阵。
#[test]
fn relaxed_pass_preserves_strict_semantics_and_only_runs_when_strict_misses() {
    let samples = all_samples();
    let mut full = ParserRegistry::with_builtins();
    let loaded = full.load_dir(&repo_root().join("parsers")).expect("加载 parsers/ 失败");
    println!(
        "\n完整注册表：内置 {} + YAML {loaded}；样本 {} 条\n",
        ParserRegistry::with_builtins().all().len(),
        samples.len()
    );

    let mut strict_registries: BTreeMap<String, ParserRegistry> = BTreeMap::new();
    let mut summary: BTreeMap<String, (usize, usize, usize, usize)> = BTreeMap::new();

    for sample in &samples {
        for (index, label) in PROBES.iter().enumerate() {
            let protocol = probe_protocol(index, sample);
            let key = protocol.as_str().to_string();
            let strict = strict_registries.entry(key).or_insert_with(|| strict_only_registry(&full, protocol));
            let strict_hit = strict.match_raw(&sample.line, protocol, None, None);
            let (full_hit, mode) = full.match_raw_with_mode(&sample.line, protocol, None, None);

            let entry = summary.entry((*label).to_string()).or_insert((0, 0, 0, 0));
            entry.3 += 1;
            match (&strict_hit.matched, &full_hit.matched, mode) {
                // 严格趟能命中：完整注册表必须命中同一模板，且不得标成放宽
                (true, true, Some(m)) => {
                    assert_ne!(m, MatchMode::ProtocolRelaxed, "严格趟已命中却标成放宽：{} {label}", sample.key);
                    assert_eq!(
                        strict_hit.parser_key, full_hit.parser_key,
                        "严格趟命中模板被改变：{} {label}",
                        sample.key
                    );
                    entry.0 += 1;
                }
                // 严格趟零命中：放宽趟才有资格补位（且必须如实标注）
                (false, true, Some(m)) => {
                    assert_eq!(m, MatchMode::ProtocolRelaxed, "严格趟零命中却未标注放宽：{} {label}", sample.key);
                    entry.1 += 1;
                }
                (false, false, None) => entry.2 += 1,
                other => panic!("命中口径自相矛盾：{} {label} strict/full/mode = {other:?}", sample.key),
            }
            if index > 0 || full_hit.matched {
                println!(
                    "{:<42} via {:<8} strict={:<24} full={:<24} mode={}",
                    sample.key,
                    label,
                    strict_hit.parser_key.as_deref().unwrap_or("<未命中>"),
                    full_hit.parser_key.as_deref().unwrap_or("<未命中>"),
                    mode.map_or("-", |m| m.as_str())
                );
            }
        }
    }

    println!("\n命中率汇总（严格命中 / 放宽命中 / 仍未命中 / 合计）：");
    for (label, (strict, relaxed, miss, total)) in &summary {
        println!("  {label:<9} 严格 {strict:>3} | 放宽 {relaxed:>3} | 未命中 {miss:>3} | 合计 {total:>3}");
    }

    // 声明的协议下**不允许出现任何放宽命中**（严格趟必须自足），也不允许出现未命中率异常！
    let (declared_strict, declared_relaxed, declared_miss, declared_total) =
        summary.get("declared").copied().unwrap_or_default();
    assert_eq!(declared_relaxed, 0, "样本自己声明的协议下不应出现放宽命中（严格趟必须自足）");
    assert!(declared_strict > declared_total / 2, "declared 协议命中率异常低: {declared_strict}/{declared_total}");
    println!("\ndeclared: 严格命中 {declared_strict}/{declared_total}，未命中 {declared_miss}");
}

/// 修复点本身：阿里云 WAF JSON 走 MQTT（模板只声明 webhook/http-pull/beats/… ）必须命中。
#[test]
fn mqtt_delivered_alicloud_waf_json_now_matches() {
    let Some(sample) = all_samples().into_iter().find(|s| s.key == "aliyun-waf-sls-json") else {
        unreachable!("样本 aliyun-waf-sls-json 必须存在");
    };
    let mut full = ParserRegistry::with_builtins();
    full.load_dir(&repo_root().join("parsers")).expect("加载 parsers/ 失败");

    let (outcome, mode) = full.match_raw_with_mode(&sample.line, IngestProtocol::Mqtt, None, None);
    assert!(outcome.matched, "经 MQTT 投递的阿里云 WAF JSON 必须命中: {:?}", outcome.error);
    assert_eq!(mode, Some(MatchMode::ProtocolRelaxed), "未声明 mqtt → 必须如实标注为放宽命中");
    assert_eq!(full.stats().matched_relaxed, 1);
    assert_eq!(full.stats().unmatched, 0);
    println!(
        "aliyun-waf-sls-json via mqtt -> {} (mode={})",
        outcome.parser_key.as_deref().unwrap_or("<未命中>"),
        mode.map_or("-", |m| m.as_str())
    );
}

/// **放宽会不会误匹配？** 把 MQTT 下每一类命中按"与样本自身模板的关系"分类并打印：
///
/// * `strict`：走严格趟（模板自己声明了 mqtt）；
/// * `relaxed-own`：放宽命中**样本自己的模板**（理想结果）；
/// * `relaxed-same-vendor`：放宽命中**同厂商**的另一模板（可接受：同厂商字段口径互有交叠）；
/// * `relaxed-cross-vendor`：放宽命中**别的厂商**的模板（**真正的误匹配候选**，逐条打印供人工核对）。
///
/// 断言：每一条放宽命中都必须能被该模板重新解析通过（即 `required_fields` 闸门确实生效，
/// 不是"放宽就接受缺字段的载荷"）。跨厂商条数不设硬编码上限——它是**测量值**，随模板库演进，
/// 打印出来供人工复核（下方注释给出本次实测基线）。
#[test]
fn mqtt_relaxed_hits_are_classified_by_template_relationship() {
    let samples = all_samples();
    let mut full = ParserRegistry::with_builtins();
    full.load_dir(&repo_root().join("parsers")).expect("加载 parsers/ 失败");
    let vendors: BTreeMap<String, String> =
        full.all().iter().map(|p| (p.definition.key.clone(), p.definition.vendor.clone())).collect();

    let (mut strict, mut own, mut same_vendor, mut cross_vendor, mut miss) = (0_usize, 0, 0, 0, 0);
    for sample in &samples {
        let (outcome, mode) = full.match_raw_with_mode(&sample.line, IngestProtocol::Mqtt, None, None);
        let Some(key) = outcome.parser_key.clone() else {
            miss += 1;
            continue;
        };
        if mode != Some(MatchMode::ProtocolRelaxed) {
            strict += 1;
            continue;
        }
        // 放宽命中的模板必须能重新解析该载荷（`required_fields` 闸门生效的独立复核）
        let Some(parser) = full.find_key(&key) else {
            unreachable!("命中模板 {key} 不在注册表里");
        };
        let reparse = agf_ingest::engine::parse_with(&parser.definition, &sample.line);
        assert!(reparse.matched, "放宽命中 {key} 却无法重新解析 {}: {:?}", sample.key, reparse.error);

        let sample_vendor = vendors.get(&sample.key).cloned().unwrap_or_default();
        let hit_vendor = vendors.get(&key).cloned().unwrap_or_default();
        if key == sample.key {
            own += 1;
        } else if !sample_vendor.is_empty() && sample_vendor == hit_vendor {
            same_vendor += 1;
        } else {
            cross_vendor += 1;
            println!("  [跨厂商放宽命中] {:<42} (厂商 {}) -> {} (厂商 {})", sample.key, sample_vendor, key, hit_vendor);
        }
    }
    println!(
        "\nMQTT 投放（完整模板库 {} 条样本）：严格命中 {strict} | 放宽-自身模板 {own} | 放宽-同厂商 {same_vendor} | \
         放宽-跨厂商 {cross_vendor} | 未命中 {miss}",
        samples.len()
    );
    assert_eq!(strict + own + same_vendor + cross_vendor + miss, samples.len());
    assert!(own > 0, "放宽趟至少要能把样本交回它自己的模板");
}

/// 真实 OTLP 载荷：`otlp` 协议走严格趟（内置模板已声明 `otlp`），
/// 其它协议（如 jdbc）走放宽趟——两条路都必须落到同一个 OTLP 模板。
#[test]
fn otlp_payload_matches_strictly_on_otlp_and_relaxed_on_other_protocols() {
    let sample = otlp_sample();
    let mut full = ParserRegistry::with_builtins();
    full.load_dir(&repo_root().join("parsers")).expect("加载 parsers/ 失败");

    let (strict, strict_mode) = full.match_raw_with_mode(&sample.line, IngestProtocol::Otlp, None, None);
    assert!(strict.matched, "OTLP 载荷必须命中: {:?}", strict.error);
    assert_eq!(strict.parser_key.as_deref(), Some("otlp-json-log"));
    assert_eq!(strict_mode, Some(MatchMode::Protocol), "otlp 是模板声明过的协议 → 严格趟");

    let (relaxed, relaxed_mode) = full.match_raw_with_mode(&sample.line, IngestProtocol::Jdbc, None, None);
    assert!(relaxed.matched, "同一 OTLP 载荷经 jdbc 投递也必须命中: {:?}", relaxed.error);
    assert_eq!(relaxed.parser_key.as_deref(), Some("otlp-json-log"));
    assert_eq!(relaxed_mode, Some(MatchMode::ProtocolRelaxed));
    assert_eq!(relaxed.fields, strict.fields, "放宽只改'谁来解析'，不改'解析出什么'");
}
