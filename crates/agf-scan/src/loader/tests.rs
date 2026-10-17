//! 由 `loader.rs` 拆分：`def` 等 17 个函数（纯搬移，逻辑不变）。
use super::*;

pub(crate) fn def(key: &str, domain: RiskDomain) -> RuleDefinition {
    RuleDefinition {
        key: key.to_string(),
        name: format!("规则 {key}"),
        description: String::new(),
        domain,
        severity: Severity::High,
        kind: RuleKind::Regex,
        target: RuleTarget::Prompt,
        action: PolicyAction::Deny,
        enabled: true,
        rollout_percent: 100,
        tags: vec![],
        references: vec![],
        detection: Detection::Regex { pattern: format!("(?i){key}-pattern"), case_insensitive: true, min_matches: 1 },
        samples: RuleSamples { positive: vec![format!("{key}-pattern here")], negative: vec!["clean".into()] },
        remediation: "修复".into(),
        author: "test".into(),
        version: 1,
    }
}

pub(crate) fn temp_dir() -> PathBuf {
    let root = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.tmp/scan-tests"));
    let d = root.join(format!("agf-rules-{}", uuid::Uuid::new_v4()));
    let _ = std::fs::create_dir_all(&d);
    d
}

#[test]
pub(crate) fn inline_loading_builds_pack_and_report() {
    let loader = RulePackLoader::lenient();
    let pack = loader.load_inline(vec![
        def("PA-001", RiskDomain::PromptAttack),
        def("CL-001", RiskDomain::CredentialLeak),
        def("PA-002", RiskDomain::PromptAttack),
    ]);
    assert!(pack.is_ok());
    let Ok(pack) = pack else { return };
    assert_eq!(pack.len(), 3);
    assert!(pack.report.is_healthy());
    assert_eq!(pack.report.count_domain(RiskDomain::PromptAttack), 2);
    assert_eq!(pack.report.count_domain(RiskDomain::CredentialLeak), 1);
    assert!(!pack.report.pack_fingerprint.is_empty());
    assert_eq!(pack.report.by_severity.get("high"), Some(&3));
}

#[test]
pub(crate) fn duplicate_keys_are_reported_and_dropped() {
    let loader = RulePackLoader::lenient();
    let pack = loader.load_inline(vec![def("PA-001", RiskDomain::PromptAttack), def("PA-001", RiskDomain::RagPoison)]);
    let Ok(pack) = pack else { return };
    assert_eq!(pack.len(), 1, "重复键只保留第一条");
    assert_eq!(pack.report.duplicates.len(), 1);
    assert!(!pack.report.is_healthy());
}

#[test]
pub(crate) fn strict_mode_rejects_duplicates() {
    assert!(
        RulePackLoader::strict()
            .load_inline(vec![def("PA-001", RiskDomain::PromptAttack), def("PA-001", RiskDomain::PromptAttack)])
            .is_err()
    );
}

#[test]
pub(crate) fn invalid_regex_rule_is_skipped_in_lenient_and_rejected_in_strict() {
    let mut bad = def("BAD", RiskDomain::PromptAttack);
    bad.detection = Detection::Regex { pattern: "(unclosed".into(), case_insensitive: false, min_matches: 1 };
    assert_eq!(RulePackLoader::lenient().load_inline(vec![bad.clone()]).map(|p| p.len()).ok(), Some(0));
    assert!(RulePackLoader::strict().load_inline(vec![bad]).is_err());
}

#[test]
pub(crate) fn missing_samples_flagged() {
    let mut no_samples = def("NS-001", RiskDomain::PromptAttack);
    no_samples.samples = RuleSamples { positive: vec![], negative: vec![] };
    let pack = RulePackLoader::lenient().load_inline(vec![no_samples]);
    let Ok(pack) = pack else { return };
    assert_eq!(pack.report.missing_samples, vec!["NS-001".to_string()]);
    assert!(!pack.report.is_healthy());
    assert!(
        RulePackLoader::strict()
            .load_inline(vec![{
                let mut d = def("NS-002", RiskDomain::PromptAttack);
                d.samples = RuleSamples::default();
                d
            }])
            .is_err()
    );
}

#[test]
pub(crate) fn degraded_semantic_rules_are_reported() {
    let mut sem = def("SEM-001", RiskDomain::PromptAttack);
    sem.detection = Detection::Semantic {
        intent: "系统提示词泄露".into(),
        fallback_keywords: vec!["system prompt".into()],
        threshold: 0.7,
    };
    let pack = RulePackLoader::lenient().load_inline(vec![sem]);
    let Ok(pack) = pack else { return };
    assert_eq!(pack.report.degraded_semantic, vec!["SEM-001".to_string()]);
}

#[test]
pub(crate) fn load_dir_reads_yaml_recursively_and_maps_domain() {
    let dir = temp_dir();
    let pa = dir.join("prompt-attack");
    let cl = dir.join("credential-leak");
    assert!(std::fs::create_dir_all(&pa).is_ok() && std::fs::create_dir_all(&cl).is_ok());
    let yaml = |d: &RuleDefinition| serde_yaml::to_string(d).unwrap_or_default();
    assert!(std::fs::write(pa.join("pa-001.yaml"), yaml(&def("PA-001", RiskDomain::PromptAttack))).is_ok());
    assert!(std::fs::write(cl.join("cl-001.yml"), yaml(&def("CL-001", RiskDomain::CredentialLeak))).is_ok());
    // 非 YAML 文件应被忽略
    assert!(std::fs::write(pa.join("notes.txt"), "not a rule").is_ok());

    let loader = RulePackLoader::lenient();
    let pack = loader.load_dir(&RulesDir::new(&dir));
    assert!(pack.is_ok(), "{:?}", pack.as_ref().err().map(ToString::to_string));
    let Ok(pack) = pack else { return };
    assert_eq!(pack.len(), 2);
    assert_eq!(pack.report.files_scanned, 2);
    assert!(pack.report.is_healthy());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
pub(crate) fn load_dir_reports_broken_yaml_without_failing() {
    let dir = temp_dir();
    let pa = dir.join("prompt-attack");
    assert!(std::fs::create_dir_all(&pa).is_ok());
    assert!(std::fs::write(pa.join("broken.yaml"), "key: [unclosed").is_ok());
    assert!(
        std::fs::write(
            pa.join("good.yaml"),
            serde_yaml::to_string(&def("PA-001", RiskDomain::PromptAttack)).unwrap_or_default()
        )
        .is_ok()
    );
    let loader = RulePackLoader::lenient();
    let pack = loader.load_dir(&RulesDir::new(&dir));
    assert!(pack.is_ok());
    let Ok(pack) = pack else { return };
    assert_eq!(pack.len(), 1, "坏文件被跳过，好规则仍生效");
    assert_eq!(pack.report.invalid.len(), 1);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
pub(crate) fn load_dir_missing_directory_errors() {
    let loader = RulePackLoader::lenient();
    let res = loader.load_dir(&RulesDir::new("Z:/definitely/not/here"));
    assert!(matches!(res.err(), Some(DomainError::NotFound { .. })));
}

#[test]
pub(crate) fn pack_fingerprint_changes_when_rule_changes() {
    let loader = RulePackLoader::lenient();
    let a = loader.load_inline(vec![def("PA-001", RiskDomain::PromptAttack)]).unwrap_or_else(|_| unreachable!());
    let mut changed = def("PA-001", RiskDomain::PromptAttack);
    changed.detection = Detection::Keyword { any: vec!["different".into()] };
    let b = loader.load_inline(vec![changed]).unwrap_or_else(|_| unreachable!());
    assert_ne!(a.report.pack_fingerprint, b.report.pack_fingerprint);
    let c = loader.load_inline(vec![def("PA-001", RiskDomain::PromptAttack)]).unwrap_or_else(|_| unreachable!());
    assert_eq!(a.report.pack_fingerprint, c.report.pack_fingerprint, "内容相同指纹必须稳定");
}

#[test]
pub(crate) fn domain_index_and_gray_applicability() {
    let loader = RulePackLoader::lenient();
    let mut canary = def("PA-CANARY", RiskDomain::PromptAttack);
    canary.rollout_percent = 50;
    let pack = loader
        .load_inline(vec![def("PA-001", RiskDomain::PromptAttack), canary, def("CL-001", RiskDomain::CredentialLeak)])
        .unwrap_or_else(|_| unreachable!());
    assert_eq!(pack.indices_of_domain(RiskDomain::PromptAttack).len(), 2);
    assert_eq!(pack.indices_of_domain(RiskDomain::RagPoison).len(), 0);

    // 灰度：某些资产不适用 PA-CANARY。
    // 使用**确定性 id**（由字符串派生）而非随机 UUID，避免 50% 灰度下测试偶发失败；
    // 样本量取 400 以保证两个桶都必然出现。
    let ids: Vec<agf_core::ids::Id> =
        (0..400).map(|i| agf_core::ids::deterministic_id("agf-test-asset", &i.to_string())).collect();
    let counts: Vec<usize> = ids.iter().map(|id| pack.applicable_to_asset(id).len()).collect();

    // 全量规则 2 条（PA-001 / CL-001）；灰度规则命中时为 3 条、未命中时为 2 条
    assert!(counts.contains(&3), "应有资产命中灰度规则（占比 50%）");
    assert!(counts.contains(&2), "应有资产未命中灰度规则（占比 50%）");
    #[allow(clippy::cast_precision_loss)]
    let hit_ratio = counts.iter().filter(|c| **c == 3).count() as f32 / counts.len() as f32;
    assert!((0.35..=0.65).contains(&hit_ratio), "灰度占比应接近 50%，实际 {hit_ratio}");
}

#[test]
pub(crate) fn iter_compiled_pairs_rules_with_matchers() {
    let loader = RulePackLoader::lenient();
    let pack = loader.load_inline(vec![def("PA-001", RiskDomain::PromptAttack)]).unwrap_or_else(|_| unreachable!());
    let pairs: Vec<_> = pack.iter_compiled().collect();
    assert_eq!(pairs.len(), 1);
    assert!(pairs[0].1.matches("pa-001-pattern").hit);
}

#[test]
#[allow(clippy::unwrap_used)]
pub(crate) fn file_sort_keeps_each_detector_with_its_own_rule() {
    let dir = temp_dir();
    let first = dir.join("a.yaml");
    let second = dir.join("b.yaml");
    std::fs::write(&first, serde_yaml::to_string(&def("Z-LAST", RiskDomain::PromptAttack)).unwrap()).unwrap();
    std::fs::write(&second, serde_yaml::to_string(&def("A-FIRST", RiskDomain::PromptAttack)).unwrap()).unwrap();
    let pack = RulePackLoader::strict().load_files(&[first, second]).unwrap();
    for (rule, detector) in pack.iter_compiled() {
        assert!(detector.matches(&format!("{}-pattern", rule.key)).hit, "wrong matcher for {}", rule.key);
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
pub(crate) fn verify_file_reports_problems() {
    let dir = temp_dir();
    let path = dir.join("bad.yaml");
    let mut bad = def("BAD", RiskDomain::PromptAttack);
    bad.samples = RuleSamples::default();
    assert!(std::fs::write(&path, serde_yaml::to_string(&bad).unwrap_or_default()).is_ok());
    let loader = RulePackLoader::lenient();
    let problems = loader.verify_file(&path);
    assert!(problems.is_ok());
    assert!(!problems.unwrap_or_default().is_empty(), "缺少样本应报告问题");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
pub(crate) fn rules_dir_helpers() {
    let dir = temp_dir();
    let rd = RulesDir::new(&dir);
    assert!(rd.exists());
    assert_eq!(rd.domain_dirs().len(), 5);
    assert!(!RulesDir::new("Z:/nope").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
pub(crate) fn report_to_summary_shape() {
    let loader = RulePackLoader::lenient();
    let pack = loader.load_inline(vec![def("PA-001", RiskDomain::PromptAttack)]).unwrap_or_else(|_| unreachable!());
    let summary = pack.report.to_summary();
    assert_eq!(summary.total, 1);
    assert!(summary.is_healthy());
    assert_eq!(summary.count_domain(RiskDomain::PromptAttack), 1);
}
