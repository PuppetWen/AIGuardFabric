#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
//! `parsers/` 厂商日志解析模板库的**加载**与**真实解析**验证（§4.5 解析）。
//!
//! 本测试文件是模板库的守门人，覆盖四件事：
//!
//! 1. **可加载**：`ParserRegistry::load_dir(parsers/)` 的加载数 ≥ 100、`invalid == 0`、
//!    key 全局唯一、每个厂商子目录都有模板、提示词清单里的厂商/产品一个不少；
//! 2. **真解析**：每个模板都用**正样本**跑一遍 [`agf_ingest::engine::parse_with`]，
//!    并断言关键字段被正确提取（比对 `apply_mapping` 之后的字段值，而不是"不报错"）；
//!    同时过一遍 [`agf_ingest::normalize`]，断言 `event.severity` / `event.category`
//!    归一化结果与样本声明一致；
//! 3. **样本覆盖**：每个模板要么有 1 条能命中的正样本，要么在 `samples.json` 中
//!    显式标记 `untested_reason`（等价于"sample: none"）——不允许"没验证过却宣称可用"；
//! 4. **登记一致**：有独立样本文件的模板必须同时出现在
//!    `tests/fixtures/logs/manifest.json` 的 `parser_library` 段与 `SOURCES.md` 中。
//!
//! 样本来源纪律见 `tests/fixtures/logs/SOURCES.md` 与 `parsers/README.md`：
//! 全部样本为**按厂商公开文档格式重建**的真实感样本（未联网抓取，取值用 RFC 5737/私网示例段）。

mod common;

use common::*;

#[test]
fn parsers_directory_loads_without_invalid_templates() {
    let dir = parsers_dir();
    assert!(dir.is_dir(), "模板库目录不存在: {}", dir.display());
    let mut registry = ParserRegistry::new();
    let loaded = registry.load_dir(&dir).expect("加载 parsers/ 目录失败");
    let invalid = registry.invalid_templates();
    assert!(invalid.is_empty(), "存在加载失败的模板（坏模板必须修掉）: {invalid:?}");
    assert_eq!(registry.stats().invalid, 0);
    assert!(loaded >= MIN_TEMPLATES, "模板总数 {loaded} < {MIN_TEMPLATES}（§4.5 要求 100+）");
    assert_eq!(registry.all().len(), loaded, "存在重复 key（注册表按 key 覆盖，数量会变小）");
    // 提示词清单里的厂商必须都有模板
    let vendors: BTreeSet<&str> = registry.all().iter().map(|p| p.definition.vendor.as_str()).collect();
    for want in REQUIRED_VENDORS {
        assert!(vendors.contains(want), "缺少厂商模板: {want}");
    }
}

#[test]
fn every_vendor_directory_contributes_templates() {
    let mut total = 0_usize;
    for dir in vendor_dirs() {
        let name = dir.file_name().and_then(|n| n.to_str()).unwrap_or_default().to_string();
        assert!(
            REQUIRED_VENDOR_DIRS.contains(&name.as_str()),
            "出现未登记的厂商目录 {name}（新增目录需登记到 REQUIRED_VENDOR_DIRS 与 README）"
        );
        let files = yaml_files(&dir);
        assert!(!files.is_empty(), "厂商目录 {name} 没有任何 YAML 模板");
        total += files.len();
    }
    for want in REQUIRED_VENDOR_DIRS {
        let path = parsers_dir().join(want);
        assert!(path.is_dir(), "缺少厂商目录: {want}");
        assert!(!yaml_files(&path).is_empty(), "厂商目录 {want} 是空的");
    }
    assert!(total >= MIN_TEMPLATES, "YAML 模板文件总数 {total} < {MIN_TEMPLATES}");
}

#[test]
fn every_template_is_covered_by_a_positive_sample_or_explicit_none() {
    let mut registry = ParserRegistry::new();
    registry.load_dir(&parsers_dir()).expect("加载 parsers/ 目录失败");
    let samples = load_all_samples();
    let keys: BTreeSet<String> = registry.all().iter().map(|p| p.definition.key.clone()).collect();
    let missing: Vec<&String> = keys.iter().filter(|k| !samples.contains_key(*k)).collect();
    assert!(missing.is_empty(), "以下模板既无正样本也未标记 untested_reason: {missing:?}");
    let extra: Vec<&String> = samples.keys().filter(|k| !keys.contains(*k)).collect();
    assert!(extra.is_empty(), "样本登记了不存在的模板 key: {extra:?}");
    for (key, entry) in &samples {
        let parser = registry.find_key(key).expect("模板存在");
        match (&entry.line, &entry.fixture, &entry.untested_reason) {
            (None, None, None) => panic!("模板 {key} 的样本条目必须声明 line/fixture 或 untested_reason"),
            (None, None, Some(_)) => {
                assert!(
                    parser.definition.sample_fixture.trim().is_empty(),
                    "模板 {key} 标记为未验证，但声明了 sample_fixture={}",
                    parser.definition.sample_fixture
                );
            }
            _ => {
                // 正样本必须在 YAML 中留下**可追溯指位**：独立样本文件（tests/fixtures/…）
                // 或同厂商样本登记（parsers/<vendor>/samples.json#<key>）。
                let pointer = parser.definition.sample_fixture.trim();
                assert!(!pointer.is_empty(), "模板 {key} 有正样本，但 YAML 未声明 sample_fixture");
                let (path, anchor) = pointer.split_once('#').unwrap_or((pointer, ""));
                if !anchor.is_empty() {
                    assert_eq!(anchor, key, "模板 {key} 的 sample_fixture 锚点与模板 key 不一致");
                }
                let file = repo_root().join(path);
                assert!(file.is_file(), "模板 {key} 的 sample_fixture 指向不存在的文件: {}", file.display());
                assert!(!entry.expect.is_empty(), "模板 {key} 的正样本必须声明 expect 关键字段断言");
            }
        }
    }
}

#[test]
fn every_template_parses_its_positive_sample() {
    let mut registry = ParserRegistry::new();
    registry.load_dir(&parsers_dir()).expect("加载 parsers/ 目录失败");
    let samples = load_all_samples();
    let mut verified = 0_usize;
    let mut untested: Vec<&str> = Vec::new();
    for (key, entry) in &samples {
        if entry.line.is_none() && entry.fixture.is_none() {
            untested.push(key.as_str());
            continue;
        }
        let (raw, event) = parse_and_normalize(&registry, key, entry);
        assert!(!event.message.is_empty(), "模板 {key} 归一化后 message 为空（样本：{raw}）");
        // 原始载荷保真：raw_hash 必须等于样本行的内容哈希
        assert_eq!(event.raw_hash, agf_core::secret::content_hash(&raw));
        verified += 1;
    }
    assert!(verified >= MIN_TEMPLATES, "经过正样本验证的模板只有 {verified} 个（< {MIN_TEMPLATES}）");
    assert!(untested.is_empty(), "以下模板未验证（需补正样本或显式 untested_reason）: {untested:?}");
}
