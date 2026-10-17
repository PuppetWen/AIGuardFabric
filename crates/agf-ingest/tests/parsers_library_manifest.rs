#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
//! `parsers/` 模板库的**登记一致性**验证：清单/README/样本来源与独立样本文件三者必须互相吻合。
//!
//! 与 `tests/parsers_library.rs` 共用 `tests/common/mod.rs` 的夹具；本文件只放"登记口径"这一类用例。

mod common;

use common::*;

#[test]
fn fixture_backed_samples_are_registered_in_manifest_and_sources() {
    let samples = load_all_samples();
    let manifests = manifest();
    assert_eq!(manifests.version, 1);
    assert!(!manifests.note.trim().is_empty());
    // 既有内置模板段保持不动（本任务只新增 parser_library 段）
    assert!(!manifests.templates.is_empty(), "manifest.json 的 templates 段不应被清空");
    let library = manifests.parser_library.as_ref().expect("manifest.json 缺少 parser_library 段");
    assert!(!library.note.trim().is_empty(), "parser_library 段必须写明样本来源口径");
    let sources = std::fs::read_to_string(fixtures_dir().join("SOURCES.md")).expect("读取 SOURCES.md 失败");
    let mut registry = ParserRegistry::new();
    registry.load_dir(&parsers_dir()).expect("加载 parsers/ 目录失败");

    let mut checked = 0_usize;
    let mut vendors: BTreeSet<String> = BTreeSet::new();
    for (key, entry) in &samples {
        let Some(fixture) = &entry.fixture else { continue };
        let registered = library
            .samples
            .get(key)
            .unwrap_or_else(|| panic!("样本文件 {fixture}（模板 {key}）未登记到 manifest.json 的 parser_library"));
        assert_eq!(&registered.fixture, fixture, "模板 {key} 的样本文件名与 manifest 不一致");
        assert!(fixtures_dir().join(fixture).is_file(), "样本文件不存在: {fixture}");
        assert!(sources.contains(fixture.as_str()), "SOURCES.md 未登记样本 {fixture}");
        // 登记信息必须与模板定义自洽（厂商/产品/协议/等级/类别）
        let parser = registry.find_key(key).unwrap_or_else(|| panic!("注册表中找不到模板 {key}"));
        assert_eq!(
            parser.definition.sample_fixture.trim(),
            format!("tests/fixtures/logs/{fixture}"),
            "模板 {key} 的 YAML sample_fixture 必须与样本登记指向同一文件"
        );
        assert_eq!(registered.vendor, parser.definition.vendor, "模板 {key} 的厂商与 manifest 登记不一致");
        assert_eq!(registered.product, parser.definition.product, "模板 {key} 的产品与 manifest 登记不一致");
        assert!(
            IngestProtocol::all().iter().any(|p| p.as_str() == registered.protocol),
            "模板 {key} 在 manifest 中登记的协议非法: {}",
            registered.protocol
        );
        if let Some(protocol) = &entry.protocol {
            assert_eq!(protocol, &registered.protocol, "模板 {key} 的样本协议与 manifest 登记不一致");
        }
        if registered.synthetic {
            if let Some(public) = manifests.public_samples.get(key) {
                assert_ne!(public["fixture"].as_str(), Some(fixture.as_str()), "重建样本不能冒充原文: {key}");
            }
        } else {
            let public = manifests.public_samples.get(key).expect("原文样本必须有公开来源登记");
            assert_eq!(public["synthetic"], false);
            assert_eq!(public["fixture"].as_str(), Some(fixture.as_str()));
            assert_eq!(public["sourceLine"], 1);
            assert_eq!(public["license"], "Apache-2.0");
            let raw = std::fs::read_to_string(fixtures_dir().join(fixture)).expect("读取原文失败");
            assert_eq!(
                agf_core::secret::content_hash(&raw).to_uppercase(),
                public["fixtureSha256"].as_str().expect("摘录 SHA-256")
            );
        }
        if let Some(severity) = entry.expect.get("event.severity") {
            assert_eq!(&registered.severity, severity, "模板 {key} 的期望等级与 manifest 登记不一致");
        }
        if let Some(category) = entry.expect.get("event.category") {
            assert_eq!(&registered.category, category, "模板 {key} 的期望类别与 manifest 登记不一致");
        }
        vendors.insert(registered.vendor.clone());
        checked += 1;
    }
    assert!(checked >= 5, "有独立样本文件的模板只有 {checked} 个（要求 ≥ 5）");
    assert!(vendors.len() >= 5, "独立样本文件覆盖的厂商只有 {} 个（要求 ≥ 5）: {vendors:?}", vendors.len());
}

#[test]
fn readme_documents_conventions_and_every_template() {
    let path = parsers_dir().join("README.md");
    let readme = std::fs::read_to_string(&path).expect("parsers/README.md 缺失");
    for section in ["命名规范", "字段语义", "新增模板", "样本"] {
        assert!(readme.contains(section), "parsers/README.md 缺少「{section}」章节");
    }
    let mut registry = ParserRegistry::new();
    registry.load_dir(&parsers_dir()).expect("加载 parsers/ 目录失败");
    for parser in registry.all() {
        assert!(readme.contains(&parser.definition.key), "parsers/README.md 未登记模板 {}", parser.definition.key);
    }
    for dir in vendor_dirs() {
        let name = dir.file_name().and_then(|n| n.to_str()).unwrap_or_default();
        assert!(readme.contains(name), "parsers/README.md 未说明厂商目录 {name}");
    }
}

#[test]
fn sample_files_are_not_placeholder_content() {
    let samples = load_all_samples();
    for (key, entry) in &samples {
        let line = match (&entry.fixture, &entry.line) {
            (Some(name), _) => std::fs::read_to_string(fixtures_dir().join(name)).expect("读取样本文件失败"),
            (None, Some(line)) => line.clone(),
            (None, None) => continue,
        };
        let lower = line.to_lowercase();
        for bad in ["lorem ipsum", "foo bar", "test log", "示例日志 1", "placeholder"] {
            assert!(!lower.contains(bad), "模板 {key} 的样本含占位内容 `{bad}`");
        }
        assert!(line.len() > 40, "模板 {key} 的样本过短（{line}），不像真实日志");
    }
}
