//! `parsers_library` 系列集成测试的共享夹具：仓库路径定位、模板/样本/清单装载与样本解析助手。
//!
//! 本模块被 `tests/parsers_library.rs` 与 `tests/parsers_library_manifest.rs` 共同 `mod common;` 引入。

#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
#![allow(dead_code)]

pub(crate) use std::collections::{BTreeMap, BTreeSet};
pub(crate) use std::path::{Path, PathBuf};

pub(crate) use agf_core::enums::IngestProtocol;
pub(crate) use agf_core::ids::{Id, TenantId};
pub(crate) use agf_core::time::Timestamp;
pub(crate) use agf_ingest::engine;
pub(crate) use agf_ingest::normalize::{self, SourceMeta};
pub(crate) use agf_ingest::registry::ParserRegistry;
pub(crate) use serde::Deserialize;

/// 模板库最小模板数（§4.5：内置 100+ 模板）。
pub(crate) const MIN_TEMPLATES: usize = 100;

/// 必须存在的厂商子目录（提示词 §4.4/§4.5 清单的目录化）。
pub(crate) const REQUIRED_VENDOR_DIRS: &[&str] = &[
    "qingteng",
    "aliyun",
    "huawei",
    "tencent",
    "sangfor",
    "qianxin",
    "nsfocus",
    "topsec",
    "venustech",
    "fortinet",
    "paloalto",
    "crowdstrike",
    "wazuh",
    "suricata",
    "zeek",
    "snort",
    "modsecurity",
    "webserver",
    "aws",
    "azure",
    "gcp",
    "k8s",
    "os",
    "generic",
    "ai",
];

/// 必须出现的 `vendor` 字段取值（厂商维度覆盖，与目录名解耦）。
pub(crate) const REQUIRED_VENDORS: &[&str] = &[
    "青藤云",
    "阿里云",
    "华为云",
    "腾讯云",
    "深信服",
    "奇安信",
    "绿盟",
    "天融信",
    "启明星辰",
    "Fortinet",
    "Palo Alto",
    "CrowdStrike",
    "Wazuh",
    "Suricata",
    "Zeek",
    "Snort",
    "ModSecurity",
    "Nginx",
    "Apache",
    "AWS",
    "Microsoft Azure",
    "Google Cloud",
    "Kubernetes",
    "Docker",
    "Linux",
    "Microsoft Windows",
    "OpenAI",
    "Anthropic",
];

/// 仓库根目录（`crates/agf-ingest/tests/` 向上三级）。
pub(crate) fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

/// `parsers/` 模板库根目录。
pub(crate) fn parsers_dir() -> PathBuf {
    repo_root().join("parsers")
}

/// `tests/fixtures/logs/` 样本目录。
pub(crate) fn fixtures_dir() -> PathBuf {
    repo_root().join("tests").join("fixtures").join("logs")
}

/// 厂商子目录（升序，保证测试输出稳定）。
pub(crate) fn vendor_dirs() -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(parsers_dir())
        .expect("读取 parsers/ 目录失败（模板库必须存在）")
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|path| path.is_dir())
        .collect();
    dirs.sort();
    dirs
}

/// 目录下的 YAML 模板文件（升序）。
pub(crate) fn yaml_files(dir: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
        .expect("读取厂商目录失败")
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|path| {
            path.is_file()
                && path
                    .extension()
                    .and_then(|ext| ext.to_str())
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("yaml") || ext.eq_ignore_ascii_case("yml"))
        })
        .collect();
    files.sort();
    files
}

/// 单个厂商目录的样本登记文件 `parsers/<vendor>/samples.json`。
#[derive(Debug, Deserialize)]
pub(crate) struct SampleFile {
    /// 版本（当前固定 1）。
    pub(crate) version: u32,
    /// 说明（必须非空，写明样本来源口径）。
    pub(crate) note: String,
    /// 模板 key → 样本条目。
    pub(crate) samples: BTreeMap<String, SampleEntry>,
}

/// 模板正样本条目：`fixture` 与 `line` **二选一**。
#[derive(Debug, Deserialize)]
pub(crate) struct SampleEntry {
    /// 行内样本（未经 syslog 封装的整行原文）。
    #[serde(default)]
    pub(crate) line: Option<String>,
    /// 指向 `tests/fixtures/logs/` 下的样本文件（取首个数据行）。
    #[serde(default)]
    pub(crate) fixture: Option<String>,
    /// 接入协议（可选，缺省 file）。
    #[serde(default)]
    pub(crate) protocol: Option<String>,
    /// 期望字段（`apply_mapping` 之后的字段名 → 期望字符串值）。
    #[serde(default)]
    pub(crate) expect: BTreeMap<String, String>,
    /// 期望的**归一化后**事件类别（模板不显式给类别、依赖消息关键字推断时使用）。
    #[serde(default)]
    pub(crate) category_after_normalize: Option<String>,
    /// 无正样本时的**显式**标记（等价 `sample: none`，必须写明原因）。
    #[serde(default)]
    pub(crate) untested_reason: Option<String>,
}

/// 读取全部厂商的 `samples.json`（key 不允许重复，重复即模板 key 跨目录冲突）。
pub(crate) fn load_all_samples() -> BTreeMap<String, SampleEntry> {
    let mut out: BTreeMap<String, SampleEntry> = BTreeMap::new();
    for dir in vendor_dirs() {
        let path = dir.join("samples.json");
        assert!(path.is_file(), "厂商目录缺少 samples.json: {}", dir.display());
        let text = std::fs::read_to_string(&path).expect("读取 samples.json 失败");
        let file: SampleFile =
            serde_json::from_str(&text).unwrap_or_else(|e| panic!("samples.json 非法（{}）: {e}", path.display()));
        assert_eq!(file.version, 1, "{} 的样本版本应为 1", path.display());
        assert!(!file.note.trim().is_empty(), "{} 的 note 不能为空（须写明样本来源口径）", path.display());
        for (key, entry) in file.samples {
            let prev = out.insert(key.clone(), entry);
            assert!(prev.is_none(), "样本 key 重复: {key}（模板 key 必须全局唯一）");
        }
    }
    out
}

/// 接入协议文本 → 枚举（未知取值回落 `file`，与接入侧默认一致）。
pub(crate) fn protocol_of(name: Option<&str>) -> IngestProtocol {
    let wanted = name.unwrap_or("file");
    IngestProtocol::all().into_iter().find(|p| p.as_str() == wanted).unwrap_or(IngestProtocol::File)
}

/// 取样本原文：`fixture` 读样本文件首个数据行，`line` 直接用行内样本。
///
/// 两者**同时声明**时以样本文件为准，并断言行内样本与文件逐字一致
/// （防止"登记内容"与"落盘样本"漂移）。
pub(crate) fn raw_sample_line(key: &str, entry: &SampleEntry) -> String {
    match (&entry.fixture, &entry.line) {
        (Some(name), declared) => {
            let path = fixtures_dir().join(name);
            assert!(path.is_file(), "模板 {key} 的样本文件不存在: {}", path.display());
            let text = std::fs::read_to_string(&path).expect("读取样本文件失败");
            let line = text
                .lines()
                .map(str::trim)
                .find(|line| !line.is_empty() && !line.starts_with('#'))
                .unwrap_or_default()
                .to_string();
            assert!(!line.is_empty(), "样本 {name} 无数据行（模板 {key}）");
            if let Some(declared) = declared {
                assert_eq!(declared, &line, "模板 {key} 的行内样本与样本文件 {name} 不一致");
            }
            line
        }
        (None, Some(line)) => line.clone(),
        (None, None) => panic!("模板 {key} 既无 fixture 也无 line（应由 untested_reason 标记，调用方需先过滤）"),
    }
}

/// 用注册表里的模板定义跑一次解析 + 归一化。
pub(crate) fn parse_and_normalize(
    registry: &ParserRegistry,
    key: &str,
    entry: &SampleEntry,
) -> (String, agf_core::event::Event) {
    let parser = registry.find_key(key).unwrap_or_else(|| panic!("注册表中找不到模板 {key}"));
    let raw = raw_sample_line(key, entry);
    let outcome = engine::parse_with(&parser.definition, &raw);
    assert!(outcome.matched, "模板 {key} 未能解析其正样本: {:?}", outcome.error);
    assert_eq!(outcome.parser_key.as_deref(), Some(key), "解析结果里的 parser_key 必须等于模板 key");
    assert!(outcome.derived_errors.is_empty(), "模板 {key} 存在派生字段错误: {:?}", outcome.derived_errors);
    for (path, want) in &entry.expect {
        let got = outcome.fields.get(path).and_then(engine::value_to_text);
        assert_eq!(got.as_deref(), Some(want.as_str()), "模板 {key} 的字段 {path} 提取结果不符（样本：{raw}）");
    }

    let def = &parser.definition;
    let meta = SourceMeta {
        tenant_id: TenantId::default_tenant(),
        source_id: Id::new(),
        source_name: format!("parsers-library-{key}"),
        vendor: def.vendor.clone(),
        product: def.product.clone(),
        protocol: protocol_of(entry.protocol.as_deref()),
        tags: vec!["parsers-library".to_string()],
        ingested_at: Timestamp::now(),
    };
    let event = normalize::normalize(&outcome, &meta, &raw, "parsers-library");
    assert_eq!(event.parser_name.as_deref(), Some(key));
    if let Some(severity) = entry.expect.get("event.severity") {
        assert_eq!(event.severity.as_str(), severity, "模板 {key} 归一化后的严重等级不符");
    }
    if let Some(category) = entry.expect.get("event.category") {
        assert_eq!(event.category.as_str(), category, "模板 {key} 归一化后的事件类别不符");
    }
    if let Some(category) = &entry.category_after_normalize {
        assert_eq!(
            event.category.as_str(),
            category,
            "模板 {key} 归一化后的事件类别不符（该模板不给 event.category，依赖消息推断：{})",
            event.message
        );
    }
    (raw, event)
}

/// manifest.json 中的 `parser_library` 段。
#[derive(Debug, Deserialize)]
pub(crate) struct ParserLibrarySection {
    /// 说明。
    #[serde(default)]
    pub(crate) note: String,
    /// 模板 key → 样本登记。
    pub(crate) samples: BTreeMap<String, LibraryFixtureEntry>,
}

/// `parser_library` 的样本登记条目（字段与既有 `templates` 段保持一致）。
#[derive(Debug, Deserialize)]
pub(crate) struct LibraryFixtureEntry {
    /// 样本文件（`tests/fixtures/logs/` 下的文件名）。
    pub(crate) fixture: String,
    /// 厂商。
    pub(crate) vendor: String,
    /// 产品。
    pub(crate) product: String,
    /// 接入协议文本。
    pub(crate) protocol: String,
    /// 是否合成样本。
    pub(crate) synthetic: bool,
    /// 期望严重等级。
    #[serde(default)]
    pub(crate) severity: String,
    /// 期望事件类别。
    #[serde(default)]
    pub(crate) category: String,
}

/// 既有清单（只取本测试关心的字段；`templates` 段保持原样不动）。
#[derive(Debug, Deserialize)]
pub(crate) struct FixtureManifest {
    /// 版本。
    pub(crate) version: u32,
    /// 说明。
    #[serde(default)]
    pub(crate) note: String,
    /// 内置模板登记（本测试不修改、只校验其存在）。
    pub(crate) templates: BTreeMap<String, serde_json::Value>,
    /// 模板库新增样本登记段。
    #[serde(default)]
    pub(crate) parser_library: Option<ParserLibrarySection>,
    /// Public original captures, including additional samples for existing templates.
    #[serde(default)]
    pub(crate) public_samples: BTreeMap<String, serde_json::Value>,
}

/// 读取 `tests/fixtures/logs/manifest.json`。
pub(crate) fn manifest() -> FixtureManifest {
    let path = fixtures_dir().join("manifest.json");
    let text = std::fs::read_to_string(&path).expect("读取 manifest.json 失败");
    serde_json::from_str(&text).expect("manifest.json 非法")
}
