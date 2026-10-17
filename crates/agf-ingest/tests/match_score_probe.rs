//! 样本打分（注册表第 4 步）**修复前后对比**的实测探针（诊断测试，只读，不改任何源码）。
//!
//! 背景：`sample_match_score` 曾用**映射后**的字段名（`ParseOutcome::fields`/`extra`）
//! 校验 `def.required_fields`，而 `parse_with` 用**映射前**的扁平字段名 ⇒ 模板里写
//! 源字段名（`rule_id`/`src`/`serial`…）的模板在映射后查不到这些键，得分被腰斩成
//! `base * 0.5`（上限 0.495）⇒ 永远低于 [`MATCH_THRESHOLD`]（0.5），第 4 步对它们
//! **恒不命中**。
//!
//! 三个口径：
//!   * `sample_score_probe`：逐样本打印"自身模板"的**修复后实测得分**
//!     （`sample_match_score`）与**修复前口径复算得分**（`legacy_score`，逐字复刻旧公式）
//!     ——前者来自被测代码，后者只用公开 API 复刻旧公式，因此本探针**可在修复后**
//!     同时给出"修复前后"；
//!   * `match_mode_histogram`：全量样本按 `declared` / `mqtt` / `otlp` / `vendor-mismatch`
//!     四种投递方式统计命中**趟次直方图**（`sample-score` 即第 4 步）；
//!   * `legacy_step4_would_hit`：按**修复前公式**复算"第 4 步会不会命中"，
//!     与修复后实测直方图并排对比。
//!
//! 跑法：`cargo test -p agf-ingest --test match_score_probe -- --nocapture`
//! 本文件只打印矩阵并做**结构性**断言（不锁定具体命中数），数字变化时人工比对输出。

#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used, clippy::print_stdout)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use agf_core::enums::IngestProtocol;
use agf_core::parser::{ParseOutcome, ParserDefinition};
use agf_ingest::engine::{MATCH_THRESHOLD, sample_match_score};
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

/// 全量注册表（内置 + `parsers/` 模板库），返回（注册表，加载到的 YAML 模板数）。
fn full_registry() -> (ParserRegistry, usize) {
    let mut reg = ParserRegistry::with_builtins();
    let loaded = reg.load_dir(&repo_root().join("parsers")).expect("加载 parsers/ 失败");
    (reg, loaded)
}

/// **修复前口径**的得分公式（逐字复刻旧实现，只用公开 API 复算，便于在修复后并排对比）。
///
/// 旧公式：`n = fields.len() + extra.len()`（**映射后**），必需字段也在**映射后**的表里查，
/// 不齐则 `base * 0.5`。
#[allow(clippy::cast_precision_loss)]
fn legacy_score(def: &ParserDefinition, outcome: &ParseOutcome) -> f32 {
    if !outcome.matched {
        return 0.0;
    }
    let n = outcome.fields.len() + outcome.extra.len();
    if n == 0 {
        return 0.0;
    }
    let base = n as f32 / (n as f32 + 2.0);
    let has = |f: &String| outcome.fields.contains_key(f) || outcome.extra.contains_key(f);
    if def.required_fields.iter().all(has) { base.min(0.99) } else { base * 0.5 }
}

/// **按修复前公式复算**"第 4 步会不会命中"（顺序与 `ParserRegistry` 一致：遍历全部条目，
/// 取最高分且 ≥ 阈值者，命中后仍须 `parse_with` 判为匹配——这里只复算打分与选择）。
#[allow(clippy::cast_precision_loss)]
fn legacy_step4_would_hit(reg: &ParserRegistry, raw: &str) -> Option<(String, f32)> {
    let mut best: Option<(f32, String)> = None;
    for parser in reg.all() {
        if !parser.enabled {
            continue;
        }
        let def = &parser.definition;
        let outcome = agf_ingest::engine::parse_with(def, raw);
        let score = legacy_score(def, &outcome);
        if score >= MATCH_THRESHOLD && best.as_ref().is_none_or(|(best_score, _)| score > *best_score) {
            best = Some((score, def.key.clone()));
        }
    }
    best.map(|(score, key)| (key, score))
}

/// 逐样本打印"自身模板"的修复后实测得分与修复前口径复算得分，并分组统计达标数。
#[test]
fn sample_score_probe() {
    let samples = all_samples();
    let (reg, loaded) = full_registry();
    println!(
        "\n=== 自身模板得分（阈值 MATCH_THRESHOLD = {MATCH_THRESHOLD}）：内置 {} + YAML {loaded} ===\n",
        ParserRegistry::with_builtins().all().len()
    );
    let mut new_pass = 0_usize;
    let mut old_pass = 0_usize;
    for sample in &samples {
        let Some(parser) = reg.find_key(&sample.key) else {
            println!("[score] {:<40} <模板不存在>", sample.key);
            continue;
        };
        let def = &parser.definition;
        let outcome = agf_ingest::engine::parse_with(def, &sample.line);
        let score_new = sample_match_score(def, &sample.line);
        let score_old = legacy_score(def, &outcome);
        let new_ok = score_new >= MATCH_THRESHOLD;
        let old_ok = score_old >= MATCH_THRESHOLD;
        if new_ok {
            new_pass += 1;
        }
        if old_ok {
            old_pass += 1;
        }
        println!(
            "[score] {:<40} new={score_new:.4} {} old={score_old:.4} {} matched={} required={:?}",
            sample.key,
            if new_ok { "PASS" } else { "FAIL" },
            if old_ok { "PASS" } else { "FAIL" },
            outcome.matched,
            def.required_fields
        );
    }
    println!(
        "\n[score-summary] 自身模板达标（≥ {}）：修复后实测 {new_pass}/{}，修复前口径复算 {old_pass}/{}\n",
        MATCH_THRESHOLD,
        samples.len(),
        samples.len()
    );
    assert!(!samples.is_empty());
}

/// 全量样本 × 4 种投递方式 → 命中**趟次直方图**（第 4 步 = `sample-score`）。
///
/// `vendor-mismatch`：带上一个**不匹配任何模板**的厂商提示——严格趟与放宽趟都被
/// `vendor_accepts` 挡掉，只有第 4 步（样本打分不看厂商）可能命中，
/// 这是"第 4 步修好之后到底多救回多少"的受控场景。
fn histogram(label: &str, reg: &mut ParserRegistry, samples: &[Sample]) {
    for proto in ["declared", "mqtt", "otlp", "vendor-mismatch"] {
        let mut modes: BTreeMap<String, usize> = BTreeMap::new();
        let mut own = 0_usize;
        let mut legacy_would = 0_usize;
        for sample in samples {
            let (protocol, vendor) = match proto {
                "declared" => (protocol_of(&sample.protocol), None),
                "mqtt" => (IngestProtocol::Mqtt, None),
                "otlp" => (IngestProtocol::Otlp, None),
                _ => (protocol_of(&sample.protocol), Some("__no_such_vendor__")),
            };
            let (outcome, mode) = reg.match_raw_with_mode(&sample.line, protocol, vendor, None);
            let bucket = mode.map_or_else(|| "unmatched".to_string(), |m| m.as_str().to_string());
            // 严格趟/放宽趟/显式指定的行为不依赖打分（修复不改它们），因此"修复前会不会走到
            // 第 4 步"就等于"现在这三趟没命中"；对这些样本再按旧公式复算第 4 步结果。
            let reached_step4 = !matches!(bucket.as_str(), "explicit" | "protocol" | "protocol-relaxed");
            if reached_step4 && legacy_step4_would_hit(reg, &sample.line).is_some() {
                legacy_would += 1;
            }
            *modes.entry(bucket).or_insert(0) += 1;
            if outcome.matched && outcome.parser_key.as_deref() == Some(sample.key.as_str()) {
                own += 1;
            }
        }
        println!(
            "[{label}] {proto:<15} 趟次直方图 {modes:?} 命中自身模板 {own}/{}；走到第 4 步的样本中**修复前公式**会命中的 {legacy_would} 条",
            samples.len()
        );
    }
}

#[test]
fn match_mode_histogram() {
    let samples = all_samples();
    println!("\n=== 命中趟次直方图（样本总数 {}）===\n", samples.len());

    let mut builtin = ParserRegistry::with_builtins();
    histogram("builtin", &mut builtin, &samples);

    let (mut full, loaded) = full_registry();
    println!("\n[full] 内置 {} + YAML {loaded}", ParserRegistry::with_builtins().all().len());
    histogram("full", &mut full, &samples);

    assert!(!samples.is_empty());
}

/// **逐条 `matched_by` 的原始输出**：三种投递方式各走一条真实样本，
/// 打印 `IngestOutcome` 的 JSON（`matched_by` 就在里面）与 `/stats` 的 `pipeline.matched_by` 分项，
/// 证明逐条趟次与逐趟聚合都能读出来。
#[tokio::test]
async fn ingest_outcome_matched_by_evidence() {
    use agf_core::ids::{Id, TenantId};
    use agf_core::source::{CollectionMode, LogSource, SourceConnection};
    use agf_core::time::Timestamp;
    use agf_ingest::pipeline::{InMemorySink, IngestConfig, IngestPipeline};

    let fixture = repo_root().join("tests").join("fixtures").join("logs").join("aliyun-waf-1.log");
    let text = std::fs::read_to_string(&fixture).expect("读取 aliyun-waf-1.log 失败");
    let line = text
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#'))
        .expect("样本必须有数据行")
        .to_string();

    let source = |vendor: &str| {
        let now = Timestamp::now();
        LogSource {
            id: Id::new(),
            tenant_id: TenantId::default_tenant(),
            name: "probe".to_string(),
            protocol: IngestProtocol::Webhook,
            vendor: vendor.to_string(),
            product: String::new(),
            enabled: true,
            parser_id: None,
            connection: SourceConnection::default(),
            mode: CollectionMode::Push,
            poll_interval_secs: None,
            require_mtls: false,
            allowed_cidrs: vec![],
            max_message_bytes: 1 << 20,
            max_eps: 0,
            tags: vec![],
            health: agf_core::enums::HealthState::Healthy,
            last_event_at: None,
            total_events: 0,
            last_error: None,
            created_at: now,
            updated_at: now,
        }
    };

    let sink = std::sync::Arc::new(InMemorySink::new());
    let pipeline = IngestPipeline::new(
        ParserRegistry::with_builtins(),
        std::sync::Arc::clone(&sink) as std::sync::Arc<dyn agf_ingest::pipeline::Sink>,
        std::sync::Arc::new(agf_ingest::bus::NoopEventBus),
        IngestConfig { emit_to_bus: false, dedup_window_secs: 0, ..IngestConfig::default() },
    );

    // ① 严格趟：日志源厂商 = 阿里云（模板声明过的协议 + 厂商）
    let a = pipeline.ingest_raw(&source("阿里云"), IngestProtocol::Webhook, line.as_bytes(), "webhook").await;
    let a = a.expect("严格趟接入失败");
    println!("[matched_by] 严格趟      IngestOutcome = {}", serde_json::to_string(&a).unwrap_or_default());

    // ② 放宽趟：同一载荷经 MQTT（内置模板未声明 mqtt）
    let b = pipeline.ingest_raw(&source("阿里云"), IngestProtocol::Mqtt, line.as_bytes(), "mqtt").await;
    let b = b.expect("放宽趟接入失败");
    println!("[matched_by] 放宽趟      IngestOutcome = {}", serde_json::to_string(&b).unwrap_or_default());

    // ③ 样本打分：厂商提示与模板不符 ⇒ 严格趟/放宽趟都被挡，第 4 步接住
    let c = pipeline.ingest_raw(&source("Suricata"), IngestProtocol::Webhook, line.as_bytes(), "webhook").await;
    let c = c.expect("样本打分趟接入失败");
    println!("[matched_by] 样本打分趟  IngestOutcome = {}", serde_json::to_string(&c).unwrap_or_default());

    println!("[matched_by] /stats pipeline = {}", serde_json::to_string(&pipeline.stats()).unwrap_or_default());
    // `/metrics` 的文本渲染读取的就是 `MetricsRegistry::prometheus()`（同一段代码），
    // 这里把新指标族原样打印：`apps/ingest` 的 `/metrics` 只是把它拼在四族接收器指标之后。
    let prometheus = agf_ingest::metrics::MetricsRegistry::new().prometheus();
    println!("[matched_by] /metrics 片段（agf_ingest_matched_by_total）:");
    for line in prometheus.lines().filter(|l| l.contains("matched_by_total")) {
        println!("  {line}");
    }
    assert_eq!(a.matched_by.as_deref(), Some("protocol"));
    assert_eq!(b.matched_by.as_deref(), Some("protocol-relaxed"));
    assert_eq!(c.matched_by.as_deref(), Some("sample-score"));
    let stats = pipeline.stats();
    assert_eq!(stats.matched_by.get("protocol"), Some(&1));
    assert_eq!(stats.matched_by.get("protocol-relaxed"), Some(&1));
    assert_eq!(stats.matched_by.get("sample-score"), Some(&1));
    assert_eq!(stats.matched, 3);
}

/// 载荷是否为 JSON 文档（复刻注册表第 4 步/放宽趟共用的**格式自证**闸门）。
fn is_json_document(raw: &str) -> bool {
    let trimmed = raw.trim_start();
    (trimmed.starts_with('{') || trimmed.starts_with('[')) && serde_json::from_str::<serde_json::Value>(trimmed).is_ok()
}

/// **修复后**的第 4 步会选中哪个模板（含格式自证闸门；`None` = 第 4 步接不住）。
///
/// 与 `ParserRegistry::match_raw_with_mode` 的第 4 步同口径：跳过 CSV 模板对 JSON 载荷的
/// 打分（否则 CSV 会把 JSON 按逗号切开凑出必需字段），取最高分且 ≥ 阈值者。
/// 注：打分 > 0 ⟺ `parse_with` 判为命中，因此这里不必再跑一次解析。
fn sample_score_would_hit(reg: &ParserRegistry, raw: &str) -> Option<String> {
    use agf_core::parser::ParserEngine;
    let mut best: Option<(f32, String)> = None;
    for parser in reg.all() {
        if !parser.enabled {
            continue;
        }
        let def = &parser.definition;
        if def.engine == ParserEngine::Csv && is_json_document(raw) {
            continue;
        }
        let score = sample_match_score(def, raw);
        if score >= MATCH_THRESHOLD && best.as_ref().is_none_or(|(best_score, _)| score > *best_score) {
            best = Some((score, def.key.clone()));
        }
    }
    best.map(|(_, key)| key)
}

/// **第 4 步修好后，上一轮新增的"放宽趟"还有多少价值**——用数字回答，不靠印象。
#[test]
fn relaxed_pass_necessity_probe() {
    use agf_ingest::registry::MatchMode;

    let samples = all_samples();
    let (mut reg, loaded) = full_registry();
    println!(
        "\n=== 放宽趟必要性（全量注册表：内置 {} + YAML {loaded}）===\n",
        ParserRegistry::with_builtins().all().len()
    );
    for (label, protocol) in [("mqtt", IngestProtocol::Mqtt), ("otlp", IngestProtocol::Otlp)] {
        let mut relaxed = 0_usize;
        let mut same = 0_usize;
        let mut other = 0_usize;
        let mut none = 0_usize;
        for sample in &samples {
            let (outcome, mode) = reg.match_raw_with_mode(&sample.line, protocol, None, None);
            if mode != Some(MatchMode::ProtocolRelaxed) {
                continue;
            }
            relaxed += 1;
            match sample_score_would_hit(&reg, &sample.line) {
                Some(key) if Some(key.as_str()) == outcome.parser_key.as_deref() => same += 1,
                Some(_) => other += 1,
                None => none += 1,
            }
        }
        println!(
            "[必要性] 经 {label} 投递：放宽趟命中 {relaxed}/{}；**去掉放宽趟**后第 4 步（已修复）能接住 {} 条（选同一模板 {same}、选到别的模板 {other}），**接不住 {none} 条**",
            samples.len(),
            same + other
        );
    }
    assert!(!samples.is_empty());
}

/// **真实装配口径**的前后对比：`apps/ingest` 的 webhook 日志源是
/// `vendor="generic"` + `protocol=webhook`（见 `apps/ingest/src/main.rs::ingest_source`），
/// 与阿里云模板的厂商提示不符 ⇒ 严格趟/放宽趟都被挡，只剩第 4 步。
///
/// 这条用例把"修复前该载荷根本接不住、修复后接住并标注 `sample-score`"变成可复现数字。
#[test]
fn app_wiring_scenario_before_after() {
    use agf_ingest::registry::MatchMode;

    let (mut reg, _loaded) = full_registry();
    let fixture = repo_root().join("tests").join("fixtures").join("logs").join("aliyun-waf-1.log");
    let text = std::fs::read_to_string(&fixture).expect("读取 aliyun-waf-1.log 失败");
    let line = text
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#'))
        .expect("样本必须有数据行")
        .to_string();

    let (outcome, mode) = reg.match_raw_with_mode(&line, IngestProtocol::Webhook, Some("generic"), None);
    let legacy = legacy_step4_would_hit(&reg, &line);
    println!(
        "[app] vendor=generic protocol=webhook -> parser={:?} mode={:?}；修复前公式预测第 4 步 = {legacy:?}",
        outcome.parser_key, mode
    );
    // 修复后：厂商提示挡不住第 4 步，正确模板被接住并如实标注趟次
    assert_eq!(mode, Some(MatchMode::SampleScore));
    assert_eq!(outcome.matched_by.as_deref(), Some("sample-score"));
    assert_eq!(outcome.parser_key.as_deref(), Some("aliyun-waf-webhook"));
    // 修复前：同一条载荷在严格趟/放宽趟同样零命中（这两趟不依赖打分），而第 4 步的
    // **旧公式**最高分也够不到阈值（该模板 required_fields 写源字段名 `rule_id`，
    // 旧公式按映射后字段名查不到 ⇒ 得分腰斩）；因此修复前这条载荷**未命中**。
    assert!(legacy.is_none(), "修复前旧公式应当接不住（< 阈值）: {legacy:?}");
}
