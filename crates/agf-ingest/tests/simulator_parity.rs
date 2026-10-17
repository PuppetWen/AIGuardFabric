//! 模拟器 ↔ 解析注册表 一致性核对（**只读诊断测试**，不改动任何源码）。
//!
//! ## 为什么需要这个测试
//!
//! `tools/simulators/log_source.py` 把 `tests/fixtures/logs/**` 的真实日志喂给
//! `agf-scheduler` 的 `log-pull` 任务，实测某条真实日志在 `log-pull` 里 `parsed=0`，
//! 但同一条载荷投给 `agf-ingest` 的 webhook 却 `accepted=1`。
//!
//! 两者的差别不在数据、而在**注册表**：
//!
//! | 调用方 | 注册表 | 模板数 | 传给 `match_raw` 的协议 |
//! |---|---|---|---|
//! | `agf-scheduler::tasks::run_log_pull` | `ParserRegistry::with_builtins()` | 仅内置 18 | `IngestProtocol::HttpPull` |
//! | `apps/ingest` | `with_builtins()` + `load_dir(parsers/)` | 18 + 117 | 按投递通道（webhook / syslog） |
//!
//! 而 `match_raw` 会做 `def.protocols.contains(&protocol)` 过滤
//! （`crates/agf-ingest/src/registry.rs:306`）：只有显式声明支持 `http-pull` 的模板
//! 才会参与 log-pull 的匹配。本测试把这一过滤后的**实测矩阵**固定成断言。
//!
//! 断言的是**当前实测行为**（不是理想行为）：未命中的记录在 `KNOWN_GAPS` 里并注明原因。
//! 任何一侧发生变化（例如调度器改为加载 `parsers/` 目录），测试会失败并提示更新登记。

// 这是**只读诊断测试**：它把"注册表 × 样本"的命中矩阵打印出来（跑法见 README 第 8 节），
// 因此显式放行 print_stdout（工作区默认 warn，`-D warnings` 下会变成硬错误）。
#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used, clippy::print_stdout)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use agf_core::enums::IngestProtocol;
use agf_ingest::registry::ParserRegistry;

/// 仓库根目录（`crates/agf-ingest/tests/` 向上三级）。
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

/// `parsers/` 模板库目录。
fn parsers_dir() -> PathBuf {
    repo_root().join("parsers")
}

/// `tests/fixtures/logs/` 样本目录。
fn fixtures_dir() -> PathBuf {
    repo_root().join("tests").join("fixtures").join("logs")
}

/// 一条 `samples.json` 样本。
#[derive(Debug, Clone)]
struct Sample {
    /// 厂商目录名。
    vendor: String,
    /// 模板 key。
    key: String,
    /// 声明的接入协议文本。
    protocol: String,
    /// 载荷原文（多行时取首个非空行）。
    line: String,
}

/// 读取全部厂商 `samples.json`。
fn all_samples() -> Vec<Sample> {
    let parsers = parsers_dir();
    let mut out = Vec::new();
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(&parsers)
        .expect("读取 parsers/ 失败")
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|path| path.is_dir())
        .collect();
    dirs.sort();
    for dir in dirs {
        let samples_path = dir.join("samples.json");
        if !samples_path.is_file() {
            continue;
        }
        let text = std::fs::read_to_string(&samples_path).expect("读取 samples.json 失败");
        let value: serde_json::Value = serde_json::from_str(&text).expect("samples.json 非法 JSON");
        let vendor = dir.file_name().and_then(|n| n.to_str()).unwrap_or_default().to_string();
        let Some(entries) = value.get("samples").and_then(|v| v.as_object()) else { continue };
        for (key, entry) in entries {
            let protocol = entry.get("protocol").and_then(|v| v.as_str()).unwrap_or_default().to_string();
            let raw = if let Some(fixture) = entry.get("fixture").and_then(|v| v.as_str()) {
                std::fs::read_to_string(fixtures_dir().join(fixture)).expect("读取 fixture 失败")
            } else {
                entry.get("line").and_then(|v| v.as_str()).unwrap_or_default().to_string()
            };
            let line = raw.lines().find(|l| !l.trim().is_empty()).unwrap_or_default().trim().to_string();
            out.push(Sample { vendor: vendor.clone(), key: key.clone(), protocol, line });
        }
    }
    out.sort_by(|a, b| a.key.cmp(&b.key));
    out
}

/// 按协议筛样本。
fn samples_with_protocol(protocol: &str) -> Vec<Sample> {
    all_samples().into_iter().filter(|s| s.protocol.eq_ignore_ascii_case(protocol)).collect()
}

/// 已知缺口：`log-pull`（仅内置模板 + `HttpPull` 协议过滤）解不出来的真实样本 —— 附原因。
///
/// 这些条目**不是**测试遗漏，而是把已确认的不一致显式登记下来，等修复时同步更新。
fn known_gaps() -> BTreeMap<&'static str, &'static str> {
    BTreeMap::from([
        (
            "crowdstrike-falcon-edr-telemetry-json",
            "该样本协议声明为 http-pull，但内置模板里只有 crowdstrike-falcon-webhook 声明支持 \
             HttpPull，且其 pattern 期望 DetectionSummaryEvent 检测事件的字段；本样本是 EDR 遥测\
             （telemetry）形状，字段对不上。真正能解析它的是 parsers/crowdstrike/\
             crowdstrike-falcon-edr-telemetry-json.yaml，而 agf-scheduler 的 log-pull 只加载内置模板\
             （ParserRegistry::with_builtins()），不加载 parsers/ 目录。",
        ),
        (
            "huawei-waf-access-json",
            "该样本协议声明为 http-pull（华为云 WAF 访问日志），内置模板 huawei-waf-webhook 的 \
             pattern/required_fields 面向**攻击拦截日志**（rule_id 等），访问日志没有这些字段。\
             同样地，能解析它的 YAML 模板未被 log-pull 加载。",
        ),
    ])
}

/// `parsers/*/samples.json` 里的 `http-pull` 样本清单（防止测试静默变成空跑）。
#[test]
fn http_pull_samples_are_present() {
    let samples = samples_with_protocol("http-pull");
    assert!(!samples.is_empty(), "parsers/*/samples.json 里应当有声明 http-pull 协议的样本（log-pull 的验证前提）");
    let keys: Vec<&str> = samples.iter().map(|s| s.key.as_str()).collect();
    println!("http-pull 样本 {} 条: {keys:?}", samples.len());
}

/// 内置注册表（log-pull 实际使用的那个）对 `http-pull` 样本的命中矩阵 + 缺口登记。
#[test]
fn builtin_registry_http_pull_matrix_is_as_documented() {
    let mut registry = ParserRegistry::with_builtins();
    let samples = samples_with_protocol("http-pull");
    let gaps = known_gaps();

    let mut outcomes: BTreeMap<String, Option<String>> = BTreeMap::new();
    for sample in &samples {
        assert!(!sample.line.is_empty(), "样本 {} 无有效载荷行", sample.key);
        let outcome = registry.match_raw(&sample.line, IngestProtocol::HttpPull, None, None);
        let matched = if outcome.matched { outcome.parser_key.clone() } else { None };
        println!("{:<40} protocol={:<10} -> {}", sample.key, sample.protocol, matched.as_deref().unwrap_or("<未命中>"));
        outcomes.insert(sample.key.clone(), matched);
    }

    // 1) 声明的缺口必须确实是缺口（若哪天修好了，这里会失败并提醒删除登记）
    for key in gaps.keys() {
        let matched = outcomes.get(*key).unwrap_or_else(|| panic!("缺口登记 {key} 不在 http-pull 样本清单里"));
        assert!(
            matched.is_none(),
            "缺口登记 {key} 现在已能被内置模板 {} 解析：请把它从 known_gaps() 移除并更新文档",
            matched.clone().unwrap_or_default()
        );
    }

    // 2) 除已登记缺口外，其余 http-pull 样本必须命中
    for (key, matched) in &outcomes {
        if gaps.contains_key(key.as_str()) {
            continue;
        }
        assert!(matched.is_some(), "http-pull 样本 {key} 未被任何内置模板解析，且未登记为已知缺口");
    }

    // 3) 内置模板里**声明**支持 HttpPull 的模板清单（log-pull 的候选集）
    let builtin_http_pull: Vec<String> = ParserRegistry::with_builtins()
        .all()
        .iter()
        .filter(|p| p.definition.protocols.contains(&IngestProtocol::HttpPull))
        .map(|p| p.definition.key.clone())
        .collect();
    println!("\n内置模板中声明支持 HttpPull 的 {} 个: {builtin_http_pull:?}", builtin_http_pull.len());
    assert!(!builtin_http_pull.is_empty(), "内置模板里必须有声明支持 HttpPull 的模板，否则 log-pull 永远 parsed=0");

    println!(
        "\n命中 {} / 合计 {}；已登记缺口 {} 条",
        outcomes.values().filter(|m| m.is_some()).count(),
        outcomes.len(),
        gaps.len()
    );
}

/// 完整模板库（ingest 视角）能解析这些 `http-pull` 样本，证明缺口来自调度器未加载 YAML。
#[test]
fn full_registry_parses_http_pull_samples_that_builtins_miss() {
    let mut registry = ParserRegistry::with_builtins();
    let loaded = registry.load_dir(&parsers_dir()).expect("加载 parsers/ 目录失败");
    assert!(loaded > 0, "parsers/ 目录应当加载到 YAML 模板");

    for sample in samples_with_protocol("http-pull") {
        let outcome = registry.match_raw(&sample.line, IngestProtocol::HttpPull, None, None);
        println!(
            "{:<40} matched={} parser={:?}",
            sample.key,
            outcome.matched,
            outcome.parser_key.as_deref().unwrap_or("<未命中>")
        );
        assert!(
            outcome.matched,
            "完整模板库（内置 + parsers/）必须能解析 http-pull 样本 {}，否则是模板库本身的缺口: {:?}",
            sample.key, outcome.error
        );
    }
}

/// 华为云 HSS 的 `webhook` 样本：内置模板与 YAML 模板的**字段口径不一致**（同样是真实缺口）。
///
/// 内置 `huawei-hss-alert` 期望 `malware_name` 且 `required_fields=["malware"]`（恶意文件告警），
/// 而 `parsers/huawei/samples.json#huawei-hss-alert-json` 与
/// `tests/fixtures/logs/parsers/huawei-hss-alert-1.log` 是**异常进程**告警
/// （`process_name`/`process_path`/`cmd_line`）。这条不一致在 `log_source.py --route /mixed`
/// 的逐行定位里表现为"第 5 行 parsed=0"。
#[test]
fn huawei_hss_sample_is_missed_by_builtin_but_hit_by_yaml_template() {
    let samples = all_samples();
    let sample =
        samples.iter().find(|s| s.key == "huawei-hss-alert-json").expect("样本 huawei-hss-alert-json 必须存在");

    // 内置注册表：webhook 协议下也解不出来（字段名不匹配）
    let mut builtins = ParserRegistry::with_builtins();
    let builtin_outcome = builtins.match_raw(&sample.line, IngestProtocol::Webhook, None, None);
    println!(
        "内置注册表: matched={} parser={:?}",
        builtin_outcome.matched,
        builtin_outcome.parser_key.as_deref().unwrap_or("<未命中>")
    );
    assert!(
        !builtin_outcome.matched,
        "内置 huawei-hss-alert 现在能解析异常进程样本了：请更新 known_gaps 与 README（这其实是好事）"
    );

    // 完整模板库：由 YAML 模板命中
    let mut full = ParserRegistry::with_builtins();
    full.load_dir(&parsers_dir()).expect("加载 parsers/ 目录失败");
    let full_outcome = full.match_raw(&sample.line, IngestProtocol::Webhook, None, None);
    println!(
        "完整注册表: matched={} parser={:?}",
        full_outcome.matched,
        full_outcome.parser_key.as_deref().unwrap_or("<未命中>")
    );
    assert!(full_outcome.matched, "完整模板库必须能解析该样本: {:?}", full_outcome.error);
    assert_eq!(
        full_outcome.parser_key.as_deref(),
        Some("huawei-hss-alert-json"),
        "该样本应由 YAML 模板 huawei-hss-alert-json 命中（内置模板字段口径不同）"
    );
    assert_eq!(sample.vendor, "huawei");
}
