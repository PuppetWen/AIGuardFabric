//! 协议白名单放宽的**命中率实测探针**（诊断测试，只读，不改任何源码）。
//!
//! 目的：把"经新协议（MQTT / OTLP / 对象存储 / JDBC / Kafka / SNMP Trap）进来的载荷
//! 命中不了模板"这件事变成可复现的**前后数字**。
//!
//! 口径：
//!   * `declared`：样本自己在 `parsers/*/samples.json` 里声明的协议（原有语义，应当命中）；
//!   * `mqtt`：把同一条载荷经 **MQTT** 投递（新协议，修复前应当全部未命中）；
//!   * `otlp`：把同一条载荷经 **OTLP** 投递；
//!   * 两个注册表：`builtin`（仅内置模板，调度器 log-pull 视角）与
//!     `full`（内置 + `parsers/` 模板库，`apps/ingest` 视角）。
//!
//! 跑法：`cargo test -p agf-ingest --test match_rate_probe -- --nocapture`
// 本文件只打印矩阵并做**结构性**断言（不锁定具体命中数），命中数变化时人工比对输出。

#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used, clippy::print_stdout)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use agf_core::enums::IngestProtocol;
use agf_ingest::registry::ParserRegistry;

/// 仓库根（`crates/agf-ingest/tests/` 向上三级）。
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

/// 一条样本。
#[derive(Debug, Clone)]
struct Sample {
    /// 模板 key。
    key: String,
    /// 声明的协议文本。
    protocol: String,
    /// 载荷原文（取首个非空行）。
    line: String,
}

/// `parsers/*/samples.json` 全部样本（按 key 升序）。
fn all_samples() -> Vec<Sample> {
    let parsers = repo_root().join("parsers");
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(&parsers)
        .expect("读取 parsers/ 失败")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_dir())
        .collect();
    dirs.sort();
    let fixtures = repo_root().join("tests").join("fixtures").join("logs");
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
            if line.is_empty() {
                continue;
            }
            out.push(Sample { key: key.clone(), protocol, line });
        }
    }
    out.sort_by(|a, b| a.key.cmp(&b.key));
    out
}

/// 协议文本 → 枚举。
fn protocol_of(name: &str) -> IngestProtocol {
    IngestProtocol::all().into_iter().find(|p| p.as_str() == name).unwrap_or(IngestProtocol::File)
}

/// 真实 OTLP 载荷：由接收器自己的 `to_payload()` 生成（不凭想象编字段）。
fn otlp_payload() -> String {
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
    String::from_utf8_lossy(&record.to_payload()).to_string()
}

/// 打印一个注册表的命中矩阵，返回 `(载荷标签, 协议) -> (命中 key, 命中趟次)`。
fn matrix(
    label: &str,
    registry: &mut ParserRegistry,
    samples: &[Sample],
) -> BTreeMap<(String, String), (Option<String>, Option<String>)> {
    let mut out = BTreeMap::new();
    for sample in samples {
        for proto in ["declared", "mqtt", "otlp"] {
            let protocol = match proto {
                "declared" => protocol_of(&sample.protocol),
                "mqtt" => IngestProtocol::Mqtt,
                _ => IngestProtocol::Otlp,
            };
            let (outcome, mode) = registry.match_raw_with_mode(&sample.line, protocol, None, None);
            let hit = if outcome.matched { outcome.parser_key.clone() } else { None };
            println!(
                "[{label}] {:<42} via {:<9} -> {:<22} mode={}",
                sample.key,
                proto,
                hit.as_deref().unwrap_or("<未命中>"),
                mode.map_or("-", |m| m.as_str())
            );
            out.insert((sample.key.clone(), proto.to_string()), (hit, mode.map(|m| m.as_str().to_string())));
        }
    }
    let total = samples.len();
    for proto in ["declared", "mqtt", "otlp"] {
        let rows: Vec<&(Option<String>, Option<String>)> =
            out.iter().filter(|((_, p), _)| p == proto).map(|(_, v)| v).collect();
        let hits = rows.iter().filter(|(k, _)| k.is_some()).count();
        let relaxed = rows.iter().filter(|(_, m)| m.as_deref() == Some("protocol-relaxed")).count();
        let own = out.iter().filter(|((k, p), (v, _))| p == proto && v.as_deref() == Some(k.as_str())).count();
        println!(
            "[{label}] 协议 {proto}: 命中 {hits}/{total}（其中放宽命中 {relaxed}、命中**自身模板** {own}、仍未命中 {}）",
            total - hits
        );
    }
    out
}

#[test]
fn protocol_match_rate_matrix() {
    let mut samples = all_samples();
    samples.push(Sample { key: "otlp-json-log".to_string(), protocol: "otlp".to_string(), line: otlp_payload() });
    println!("\n样本总数 {}（含 1 条真实 OTLP 载荷）\n", samples.len());

    let mut builtin = ParserRegistry::with_builtins();
    let builtin_matrix = matrix("builtin", &mut builtin, &samples);

    let mut full = ParserRegistry::with_builtins();
    let loaded = full.load_dir(&repo_root().join("parsers")).expect("加载 parsers/ 失败");
    println!("\n[full] 内置 {} + YAML {loaded}\n", ParserRegistry::with_builtins().all().len());
    let full_matrix = matrix("full", &mut full, &samples);

    // 结构性断言：矩阵非空、声明的协议名下多数样本应命中（回归护栏，不锁具体数字）
    assert!(!builtin_matrix.is_empty() && !full_matrix.is_empty());
    let declared_hits = full_matrix.iter().filter(|((_, p), v)| p == "declared" && v.0.is_some()).count();
    assert!(declared_hits > samples.len() / 2, "declared 协议命中率异常低: {declared_hits}/{}", samples.len());
    println!("\n[汇总] full/declared 命中 {declared_hits}/{}", samples.len());
}

/// OTLP 载荷的**字段级证据**：命中后 `event.severity` / `host.name` / `service.name` /
/// `trace.id` / `attributes` 到底落在哪里（打印真实取值，供人工核对，不靠"跑通就算"）。
#[test]
fn otlp_payload_field_level_evidence() {
    use agf_core::ids::{Id, TenantId};
    use agf_core::time::Timestamp;
    use agf_ingest::normalize::{self, SourceMeta};

    let payload = otlp_payload();
    let mut reg = ParserRegistry::with_builtins();
    let (outcome, mode) = reg.match_raw_with_mode(&payload, IngestProtocol::Otlp, None, None);
    assert!(outcome.matched, "OTLP 载荷必须命中内置 OTLP 模板: {:?}", outcome.error);
    assert_eq!(outcome.parser_key.as_deref(), Some("otlp-json-log"));
    assert_eq!(mode, Some(agf_ingest::registry::MatchMode::Protocol));

    let meta = SourceMeta {
        tenant_id: TenantId::default_tenant(),
        source_id: Id::new(),
        source_name: "otlp-probe".to_string(),
        vendor: "OpenTelemetry".to_string(),
        product: "OTLP Logs".to_string(),
        protocol: IngestProtocol::Otlp,
        tags: vec![],
        ingested_at: Timestamp::now(),
    };
    let event = normalize::normalize(&outcome, &meta, &payload, "otlp-probe");
    println!("OTLP 载荷 -> parser={:?} mode={}", outcome.parser_key, mode.map_or("-", |m| m.as_str()));
    for path in ["event.time", "event.severity", "log.level", "host.name", "service.name", "trace.id", "trace.span_id"]
    {
        println!("  outcome.fields[{path}] = {:?}", outcome.get_str(path));
    }
    println!("  event.severity   = {}", event.severity.as_str());
    println!("  event.host.name  = {:?}", event.host.name);
    println!("  event.time       = {}", event.time.to_rfc3339());
    println!("  event.message    = {}", event.message);
    for key in ["service.name", "trace.id", "trace.span_id", "otel.attributes"] {
        println!("  event.extra[{key}] = {:?}", event.extra.get(key));
    }
    // 字段级断言（与模板单测同口径，这里再锁一次端到端结果）
    assert_eq!(event.severity, agf_core::enums::Severity::High, "severity_text=ERROR → high");
    assert_eq!(event.host.name.as_deref(), Some("agf-sim-host"));
    assert_eq!(outcome.get_str("log.level"), Some("ERROR"));
    assert_eq!(
        event.extra.get("otel.attributes").and_then(|v| v.get("http.status_code")).and_then(|v| v.as_str()),
        Some("500")
    );
}
