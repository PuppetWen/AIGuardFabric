//! 样本夹具定位与 `manifest.json` 装载（`tests/fixtures/logs`）。

use super::*;

/// 样本目录（相对仓库根）。
pub const FIXTURE_DIR_REL: &str = "tests/fixtures/logs";

/// 样本清单文件名。
pub const MANIFEST_FILE: &str = "manifest.json";

/// 仓库内样本目录的绝对路径（以编译期 `CARGO_MANIFEST_DIR` 为基准）。
#[must_use]
pub fn repo_fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..").join(FIXTURE_DIR_REL)
}

/// 样本清单条目。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixtureEntry {
    /// 样本文件名。
    pub fixture: String,
    /// 厂商。
    pub vendor: String,
    /// 产品。
    pub product: String,
    /// 接入协议（文本形式）。
    pub protocol: String,
    /// 是否为合成样本（无法核实公开来源时为 `true`）。
    #[serde(default)]
    pub synthetic: bool,
    /// 期望严重等级。
    pub severity: String,
    /// 期望事件类别。
    pub category: String,
    /// 期望主机名（空 = 该格式不含主机字段）。
    #[serde(default)]
    pub host: String,
    /// 期望命中的 IP（空 = 该格式不含 IP 字段）。
    #[serde(default)]
    pub ip: String,
}

/// 样本清单。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixtureManifest {
    /// 清单版本。
    pub version: u32,
    /// 说明。
    #[serde(default)]
    pub note: String,
    /// 模板 key → 条目。
    pub templates: BTreeMap<String, FixtureEntry>,
}

/// 读取样本清单。
///
/// # Errors
/// 文件缺失或 JSON 非法。
pub fn load_manifest(dir: &Path) -> DomainResult<FixtureManifest> {
    let path = dir.join(MANIFEST_FILE);
    let text = std::fs::read_to_string(&path)
        .map_err(|e| DomainError::NotFound { entity: "fixture-manifest", id: format!("{}: {e}", path.display()) })?;
    serde_json::from_str(&text).map_err(|e| DomainError::Parse(format!("manifest.json 非法: {e}")))
}

/// 取样本文件中的第一条数据行（跳过空行与 `#` 注释行，兼容 Zeek 头部）。
#[must_use]
pub fn first_data_line(text: &str) -> &str {
    text.lines().map(str::trim_end).find(|line| !line.trim().is_empty() && !line.starts_with('#')).unwrap_or("")
}
