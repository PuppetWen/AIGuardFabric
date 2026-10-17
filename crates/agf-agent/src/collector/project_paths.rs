//! 显式工作区仅扫描固定配置文件；不递归读取任意仓库内容。

use std::path::PathBuf;

/// 最多八个绝对项目根目录下的 MCP 配置候选路径。
pub(super) fn candidate_paths(roots: &[PathBuf]) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    for root in roots.iter().filter(|root| root.is_absolute()).take(8) {
        for relative in [".mcp.json", "mcp.json", ".claude/settings.json", ".vscode/mcp.json"] {
            paths.push(root.join(relative));
        }
    }
    paths.sort();
    paths.dedup();
    paths
}
