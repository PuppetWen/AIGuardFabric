//! 规则库回归（CI 卡点）：`<项目根>/rules/` 的 YAML 规则必须全部可加载、
//! 正负样本全绿、键唯一、五大安全域各 ≥10 条。
//!
//! 这是验收标准「提示词注入、凭证泄露、RAG 投毒各 ≥10 条规则，正负样本测试全绿」
//! 的可执行形式——**规则库坏了这里就会红**，不依赖人工检查。
//!
//! 说明：规则库是**与代码解耦**的 YAML（§4.2），因此本测试只依赖
//! `crates/agf-scan` 的公开 API，不复制任何规则内容。

// 集成测试即测试代码：workspace lints 对生产代码 `deny(clippy::panic/unwrap_used)`，
// 这里按项目惯例在测试目标中放行（断言失败就该 panic）。
#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use agf_core::enums::RiskDomain;
use agf_scan::loader::{RulePackLoader, RulesDir};
use agf_scan::samples::SampleRegression;

/// 仓库根目录（本 crate 位于 `<root>/crates/agf-scan`）。
fn repo_root() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest.parent().and_then(|p| p.parent()).map_or(manifest.clone(), PathBuf::from)
}

/// 规则库根目录。
fn rules_dir() -> RulesDir {
    RulesDir::new(repo_root().join("rules"))
}

/// 五大安全域（§4.2）及其最少规则数要求。
const REQUIRED_DOMAINS: &[(&str, usize)] =
    &[("prompt-attack", 10), ("credential-leak", 10), ("rag-poison", 10), ("tool-abuse", 10), ("model-data", 10)];

#[test]
fn rules_dir_exists_and_has_yaml_files() {
    let dir = rules_dir();
    assert!(dir.exists(), "规则目录不存在: {}", dir.root.display());
    let mut yaml = 0_usize;
    for (_, path) in dir.domain_dirs() {
        if !path.is_dir() {
            continue;
        }
        let Ok(entries) = std::fs::read_dir(&path) else { continue };
        for entry in entries.flatten() {
            let p = entry.path();
            if p.extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| e.eq_ignore_ascii_case("yaml") || e.eq_ignore_ascii_case("yml"))
            {
                yaml += 1;
            }
        }
    }
    assert!(yaml >= 50, "规则 YAML 文件应 ≥50 个，实际 {yaml}");
}

#[test]
fn rule_pack_loads_cleanly_in_strict_mode() {
    let pack =
        RulePackLoader::strict().load_dir(&rules_dir()).unwrap_or_else(|e| panic!("规则包加载失败（strict）：{e}"));
    assert!(pack.report.invalid.is_empty(), "存在非法规则: {:?}", pack.report.invalid);
    assert!(pack.report.duplicates.is_empty(), "存在重复规则键: {:?}", pack.report.duplicates);
    assert!(pack.report.missing_samples.is_empty(), "存在缺样本规则: {:?}", pack.report.missing_samples);
    assert_eq!(pack.len(), pack.report.loaded, "加载计数与包内规则数不一致");
    assert!(pack.len() >= 50, "规则总数应 ≥50，实际 {}", pack.len());
}

#[test]
fn every_domain_meets_the_minimum_rule_count() {
    let pack = RulePackLoader::strict().load_dir(&rules_dir()).unwrap_or_else(|e| panic!("规则包加载失败：{e}"));
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for rule in &pack.rules {
        *counts.entry(rule.domain.as_str().to_string()).or_insert(0) += 1;
    }
    for (domain, min) in REQUIRED_DOMAINS {
        let actual = counts.get(*domain).copied().unwrap_or(0);
        assert!(actual >= *min, "安全域 {domain} 规则数 {actual} < 要求 {min}；实际分布: {counts:?}");
    }
    // 覆盖五大域之外不应出现"未知域"
    let known: BTreeSet<&str> = RiskDomain::all().iter().map(RiskDomain::as_str).collect();
    for domain in counts.keys() {
        assert!(known.contains(domain.as_str()), "规则使用了未登记的域: {domain}");
    }
}

#[test]
fn rule_keys_are_unique_and_validated() {
    let pack = RulePackLoader::strict().load_dir(&rules_dir()).unwrap_or_else(|e| panic!("规则包加载失败：{e}"));
    let mut seen = BTreeSet::new();
    for rule in &pack.rules {
        assert!(!rule.key.trim().is_empty(), "规则键不能为空");
        assert!(seen.insert(rule.key.clone()), "规则键重复: {}", rule.key);
        rule.validate().unwrap_or_else(|errs| panic!("规则 {} 校验失败: {errs:?}", rule.key));
        assert!(!rule.samples.positive.is_empty(), "规则 {} 缺正样本（§4.2 强制要求）", rule.key);
        assert!(!rule.samples.negative.is_empty(), "规则 {} 缺负样本（§4.2 强制要求）", rule.key);
    }
}

/// 验收标准核心：正负样本回归必须全绿（含内置负样本基线）。
#[test]
fn positive_and_negative_samples_all_pass_strictly() {
    let pack = RulePackLoader::strict().load_dir(&rules_dir()).unwrap_or_else(|e| panic!("规则包加载失败：{e}"));
    let regression = SampleRegression::new();
    let report = regression.run_pack_strict(&pack).unwrap_or_else(|e| panic!("样本回归未通过：{e}"));
    assert_eq!(report.failed, 0, "失败规则: {:?}", report.failing_rules());
    assert!(report.positive_total >= 100, "正样本总量偏少: {}", report.positive_total);
    assert!(report.negative_total >= 100, "负样本总量偏少: {}", report.negative_total);
    assert!((report.positive_rate() - 1.0).abs() < f32::EPSILON, "正样本命中率必须为 100%：{}", report.summary_line());
    assert!((report.negative_rate() - 1.0).abs() < f32::EPSILON, "负样本清零率必须为 100%：{}", report.summary_line());
}

/// 每个域的正负样本也要单独全绿（便于定位是哪一域退化）。
#[test]
fn per_domain_regression_is_green() {
    let pack = RulePackLoader::strict().load_dir(&rules_dir()).unwrap_or_else(|e| panic!("规则包加载失败：{e}"));
    let regression = SampleRegression::new();
    for (domain, min) in REQUIRED_DOMAINS {
        let Ok(parsed) = RiskDomain::parse(domain) else {
            panic!("规则域 {domain} 不是合法的 RiskDomain");
        };
        let indices = pack.indices_of_domain(parsed);
        assert!(indices.len() >= *min, "域 {domain} 规则数 {} < {min}", indices.len());
        for idx in indices {
            let Some(rule) = pack.rules.get(idx) else { continue };
            let outcome = regression.run_rule(rule).unwrap_or_else(|e| panic!("规则 {} 回归执行失败: {e}", rule.key));
            assert!(outcome.passed, "规则 {} 样本未通过: {:?}", rule.key, outcome.failure_notes());
        }
    }
}
