//! 清单（manifest）：气隙离线包与备份包的 sha256 事实来源。
//!
//! ## 为什么清单是"生成 + 校验"共用的一份实现
//!
//! 只要生成与校验各写一遍遍历逻辑，就必然出现"生成时算 A 目录、校验时算 B 目录"
//! 的漂移，最终表现为"包是对的但校验报错"。因此这里：
//!
//! - [`ManifestEntry::from_file`]：单个文件的路径/字节数/sha256；
//! - [`Manifest::build`]：一批文件 → 清单（相对路径用 `/` 分隔，跨平台稳定）；
//! - [`Manifest::verify`]：清单 + 目标目录 → 差异列表（缺失/多出/字节数/哈希）。
//!
//! 校验**同时检查"多出的文件"**：只查缺失会让"包里混入了不该有的东西"静默通过。

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

/// 清单条目。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestEntry {
    /// 相对包根目录的路径（统一 `/` 分隔）。
    pub path: String,
    /// 字节数。
    pub bytes: u64,
    /// sha256（小写 hex）。
    pub sha256: String,
}

impl ManifestEntry {
    /// 由文件生成条目（`root` 为包根，用于取相对路径）。
    ///
    /// # Errors
    /// 文件不可读，或不在 `root` 之下（路径穿越/软链逃逸）。
    pub fn from_file(root: &Path, file: &Path) -> anyhow::Result<Self> {
        let bytes = std::fs::read(file)?;
        let relative = normalize_relative(root, file)?;
        Ok(Self { path: relative, bytes: bytes.len() as u64, sha256: sha256_hex(&bytes) })
    }
}

/// 清单。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    /// 清单格式版本（变更字段语义时递增）。
    pub manifest_version: u32,
    /// 生成者（如 `agfctl airgap bundle`）。
    pub generator: String,
    /// 平台/工具版本。
    pub version: String,
    /// 生成时间（RFC 3339，UTC）。
    pub generated_at: String,
    /// 来源目录是否存在（用于如实说明"某目录缺失，未纳入"）。
    #[serde(default)]
    pub sources: Vec<SourceState>,
    /// 文件条目（按路径排序）。
    pub files: Vec<ManifestEntry>,
}

/// 来源目录状态。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceState {
    /// 来源标识（如 `rules`）。
    pub name: String,
    /// 相对项目根的路径。
    pub path: String,
    /// 目录是否存在。
    pub present: bool,
    /// 纳入的文件数。
    pub files: usize,
}

/// 清单格式版本。
pub const MANIFEST_VERSION: u32 = 1;

impl Manifest {
    /// 由文件列表构建清单（路径会被归一化为 `/` 分隔并排序）。
    ///
    /// # Errors
    /// 任一文件不可读或不在 `root` 之下。
    pub fn build(
        root: &Path,
        files: &[PathBuf],
        sources: Vec<SourceState>,
        generator: impl Into<String>,
        version: impl Into<String>,
        generated_at: String,
    ) -> anyhow::Result<Self> {
        let mut entries = Vec::with_capacity(files.len());
        for f in files {
            entries.push(ManifestEntry::from_file(root, f)?);
        }
        entries.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(Self {
            manifest_version: MANIFEST_VERSION,
            generator: generator.into(),
            version: version.into(),
            generated_at,
            sources,
            files: entries,
        })
    }

    /// 条目数。
    #[must_use]
    pub fn len(&self) -> usize {
        self.files.len()
    }

    /// 是否为空。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }

    /// 条目总字节数。
    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        self.files.iter().map(|e| e.bytes).sum()
    }

    /// 条目路径集合。
    #[must_use]
    pub fn paths(&self) -> BTreeSet<&str> {
        self.files.iter().map(|e| e.path.as_str()).collect()
    }

    /// 序列化为 JSON 文本（末尾带换行，便于 diff 与追加）。
    ///
    /// # Errors
    /// 序列化失败。
    pub fn to_json(&self) -> anyhow::Result<String> {
        Ok(format!("{}\n", serde_json::to_string_pretty(self)?))
    }

    /// 从 JSON 文本解析。
    ///
    /// # Errors
    /// JSON 非法。
    pub fn from_json(text: &str) -> anyhow::Result<Self> {
        Ok(serde_json::from_str(text)?)
    }

    /// 读取清单文件。
    ///
    /// # Errors
    /// 文件不可读或 JSON 非法。
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        Self::from_json(&std::fs::read_to_string(path)?)
    }

    /// 写入清单文件。
    ///
    /// # Errors
    /// 写文件失败。
    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        std::fs::write(path, self.to_json()?)?;
        Ok(())
    }

    /// 按清单校验目录内容。
    ///
    /// `extra` 中列出的文件不参与"多出文件"检查（如清单文件自身）。
    ///
    /// # Errors
    /// 遍历目录失败。
    pub fn verify(&self, root: &Path, ignore: &[&str]) -> anyhow::Result<VerificationReport> {
        let mut issues = Vec::new();
        let mut checked = 0_usize;
        for entry in &self.files {
            let path = root.join(entry.path.replace('/', std::path::MAIN_SEPARATOR_STR));
            if !path.is_file() {
                issues.push(format!("缺失文件: {}", entry.path));
                continue;
            }
            let bytes = std::fs::read(&path)?;
            if bytes.len() as u64 != entry.bytes {
                issues.push(format!("字节数不一致: {}（清单 {}，实际 {}）", entry.path, entry.bytes, bytes.len()));
            }
            let actual = sha256_hex(&bytes);
            if actual != entry.sha256 {
                issues.push(format!("sha256 不一致: {}（清单 {}，实际 {actual}）", entry.path, entry.sha256));
            }
            checked += 1;
        }

        let listed: BTreeSet<&str> = self.files.iter().map(|e| e.path.as_str()).collect();
        for file in collect_files(root)? {
            let rel = normalize_relative(root, &file)?;
            if listed.contains(rel.as_str()) || ignore.iter().any(|i| i.replace('\\', "/") == rel) {
                continue;
            }
            issues.push(format!("清单外文件: {rel}"));
        }

        Ok(VerificationReport { checked, expected: self.files.len(), issues })
    }
}

/// 校验报告。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationReport {
    /// 实际核对的条目数。
    pub checked: usize,
    /// 清单声明的条目数。
    pub expected: usize,
    /// 问题列表（空 = 通过）。
    pub issues: Vec<String>,
}

impl VerificationReport {
    /// 是否通过。
    #[must_use]
    pub fn is_ok(&self) -> bool {
        self.issues.is_empty()
    }

    /// 结论行。
    #[must_use]
    pub fn summary_line(&self) -> String {
        if self.is_ok() {
            format!("清单校验通过：{} 个文件全部一致", self.checked)
        } else {
            format!("清单校验失败：核对 {} 个文件，发现 {} 个问题", self.checked, self.issues.len())
        }
    }
}

/// 递归收集目录下的全部普通文件（不跟随软链，按路径排序，结果稳定）。
///
/// # Errors
/// 遍历过程中出现的 I/O 错误。
pub fn collect_files(root: &Path) -> anyhow::Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    if !root.exists() {
        return Ok(out);
    }
    for entry in WalkDir::new(root).follow_links(false).sort_by_file_name() {
        let entry = entry?;
        if entry.file_type().is_symlink() {
            continue;
        }
        if entry.file_type().is_file() {
            out.push(entry.path().to_path_buf());
        }
    }
    out.sort();
    Ok(out)
}

/// 归一化相对路径（统一 `/` 分隔）。
///
/// # Errors
/// `file` 不在 `root` 之下时返回错误。
pub fn normalize_relative(root: &Path, file: &Path) -> anyhow::Result<String> {
    let rel = file
        .strip_prefix(root)
        .map_err(|_| anyhow::anyhow!("文件 {} 不在根目录 {} 之下，拒绝纳入清单", file.display(), root.display()))?;
    let text = rel.to_string_lossy().replace('\\', "/");
    if text.is_empty() || text.starts_with("../") || text.contains("/../") {
        return Err(anyhow::anyhow!("路径越界，拒绝纳入清单: {text}"));
    }
    Ok(text)
}

/// 计算 sha256（小写 hex）。
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

/// 计算文件的 sha256（小写 hex）。
///
/// # Errors
/// 文件不可读。
pub fn sha256_file(path: &Path) -> anyhow::Result<String> {
    Ok(sha256_hex(&std::fs::read(path)?))
}

/// 当前 UTC 时间的 RFC 3339 文本。
#[must_use]
pub fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("agf-manifest-{tag}-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("创建临时目录");
        dir
    }

    fn write(dir: &Path, rel: &str, content: &str) -> PathBuf {
        let path = dir.join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("创建父目录");
        }
        std::fs::write(&path, content).expect("写测试文件");
        path
    }

    fn sample_manifest(dir: &Path, files: &[PathBuf]) -> Manifest {
        Manifest::build(dir, files, vec![], "agfctl airgap bundle", "0.1.0", "2026-01-01T00:00:00Z".to_string())
            .expect("构建清单")
    }

    #[test]
    fn sha256_matches_known_vector() {
        // NIST 空串与 "abc" 的 SHA-256 向量（独立于本地实现的自校验）
        assert_eq!(sha256_hex(b""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert_eq!(sha256_hex(b"abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    #[test]
    fn build_and_verify_roundtrip_is_clean() {
        let dir = temp_dir("ok");
        let files =
            vec![write(&dir, "rules/prompt-attack/pa-001.yaml", "key: PA-001"), write(&dir, "manifest.json", "{}")];
        let manifest = sample_manifest(&dir, &files);
        assert_eq!(manifest.len(), 2);
        assert_eq!(manifest.files[0].path, "manifest.json");
        assert_eq!(manifest.files[1].path, "rules/prompt-attack/pa-001.yaml", "条目按路径排序");
        let report = manifest.verify(&dir, &["manifest.json"]).expect("校验");
        assert!(report.is_ok(), "{:?}", report.issues);
        assert_eq!(report.checked, 2);
        assert!(report.summary_line().contains("全部一致"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_detects_content_tampering() {
        let dir = temp_dir("tamper");
        let target = write(&dir, "rules/a.yaml", "original");
        let manifest = sample_manifest(&dir, std::slice::from_ref(&target));
        std::fs::write(&target, "tampered!").expect("改写");
        let report = manifest.verify(&dir, &[]).expect("校验");
        assert!(!report.is_ok());
        assert!(report.issues.iter().any(|i| i.contains("sha256 不一致")), "{:?}", report.issues);
        assert!(report.issues.iter().any(|i| i.contains("字节数不一致")), "{:?}", report.issues);
        assert!(report.summary_line().contains("校验失败"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_detects_missing_file() {
        let dir = temp_dir("missing");
        let a = write(&dir, "rules/a.yaml", "a");
        let b = write(&dir, "redteam/cases/b.yaml", "b");
        let manifest = sample_manifest(&dir, &[a, b]);
        std::fs::remove_file(dir.join("rules/a.yaml")).expect("删除");
        let report = manifest.verify(&dir, &[]).expect("校验");
        assert!(!report.is_ok());
        assert!(report.issues.iter().any(|i| i.contains("缺失文件: rules/a.yaml")), "{:?}", report.issues);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_detects_extra_file_not_in_manifest() {
        let dir = temp_dir("extra");
        let a = write(&dir, "rules/a.yaml", "a");
        let manifest = sample_manifest(&dir, &[a]);
        write(&dir, "rules/injected.yaml", "unexpected");
        let report = manifest.verify(&dir, &[]).expect("校验");
        assert!(!report.is_ok(), "清单外文件必须被发现");
        assert!(report.issues.iter().any(|i| i.contains("清单外文件: rules/injected.yaml")), "{:?}", report.issues);
        // ignore 名单可豁免（manifest.json 自身）
        let report2 = manifest.verify(&dir, &["rules/injected.yaml"]).expect("校验");
        assert!(report2.is_ok(), "{:?}", report2.issues);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn json_roundtrip_preserves_semantics() {
        let dir = temp_dir("json");
        let files = vec![write(&dir, "deploy/sql/migrations/0001_init.sql", "SELECT 1;")];
        let sources =
            vec![SourceState { name: "rules".to_string(), path: "rules".to_string(), present: true, files: 1 }];
        let manifest = Manifest::build(
            &dir,
            &files,
            sources.clone(),
            "agfctl airgap bundle",
            "0.1.0",
            "2026-01-01T00:00:00Z".to_string(),
        )
        .expect("构建");
        let text = manifest.to_json().expect("序列化");
        assert!(text.ends_with('\n'));
        let parsed = Manifest::from_json(&text).expect("解析");
        assert_eq!(parsed, manifest);
        assert_eq!(parsed.manifest_version, MANIFEST_VERSION);
        assert_eq!(parsed.sources, sources);
        assert_eq!(parsed.total_bytes(), 9);
        assert_eq!(parsed.paths().len(), 1);
        assert!(!parsed.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn save_and_load_work_on_disk() {
        let dir = temp_dir("save");
        let f = write(&dir, "parsers/README.md", "hello");
        let manifest = sample_manifest(&dir, &[f]);
        let path = dir.join("manifest.json");
        manifest.save(&path).expect("保存");
        let loaded = Manifest::load(&path).expect("载入");
        assert_eq!(loaded, manifest);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn normalize_relative_rejects_escape_and_normalizes_separators() {
        let root = Path::new("D:/proj");
        let inside = normalize_relative(root, Path::new("D:/proj/rules/a.yaml")).expect("归一化");
        assert_eq!(inside, "rules/a.yaml");
        assert!(normalize_relative(root, Path::new("D:/other/a.yaml")).is_err(), "跨根路径必须被拒绝");
    }

    #[test]
    fn collect_files_is_sorted_and_skips_nested_dirs() {
        let dir = temp_dir("collect");
        write(&dir, "b/x.yaml", "b");
        write(&dir, "a/y.yaml", "a");
        write(&dir, "a/z.txt", "z");
        let files = collect_files(&dir).expect("收集");
        let rels: Vec<String> = files.iter().map(|f| normalize_relative(&dir, f).unwrap_or_default()).collect();
        assert_eq!(rels, vec!["a/y.yaml".to_string(), "a/z.txt".to_string(), "b/x.yaml".to_string()]);
        assert!(collect_files(&dir.join("nope")).expect("不存在目录应返回空").is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn from_file_rejects_path_outside_root() {
        let dir = temp_dir("outside");
        let outside = write(&dir, "../agf-outside.yaml", "x");
        let root = dir.join("inner");
        std::fs::create_dir_all(&root).expect("建目录");
        assert!(ManifestEntry::from_file(&root, &outside).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
