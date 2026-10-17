//! 由 `queue.rs` 拆分：`tmp_path` 函数（纯搬移，逻辑不变）。
use super::*;

/// `.tmp` 伴生路径。
#[must_use]
pub fn tmp_path(path: &Path) -> PathBuf {
    let mut name =
        path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| "queue.jsonl".to_string());
    name.push_str(".tmp");
    path.with_file_name(name)
}
