//! 由 `backup.rs` 拆分：`verify_backup_package` 函数（纯搬移，逻辑不变）。
use super::*;

/// 校验备份包清单（JSON 优先，回退 PowerShell 文本格式）。
///
/// # Errors
/// 清单不一致（退出码 1）。缺清单时**只提示不失败**（与 restore.ps1 行为一致）。
pub fn verify_backup_package(layout: &BackupLayout, output: Output) -> Result<(), AppError> {
    if layout.manifest_json.is_file() {
        let manifest: BackupManifest = serde_json::from_str(&std::fs::read_to_string(&layout.manifest_json)?)?;
        let mut issues = Vec::new();
        for entry in &manifest.files {
            let path = layout.dir.join(entry.path.replace('/', std::path::MAIN_SEPARATOR_STR));
            if !path.is_file() {
                issues.push(format!("缺失文件: {}", entry.path));
                continue;
            }
            let actual = crate::manifest::sha256_file(&path)?;
            if actual != entry.sha256 {
                issues.push(format!("sha256 不一致: {}", entry.path));
            }
        }
        if issues.is_empty() {
            output.line(&format!("备份包校验通过（manifest.json，{} 个文件）", manifest.files.len()));
            return Ok(());
        }
        return Err(AppError::Exit(Exit::failed(format!("备份包校验失败：{}", issues.join("；")))));
    }

    if layout.manifest_txt.is_file() {
        let text = std::fs::read_to_string(&layout.manifest_txt)?;
        let entries = parse_manifest_txt(&text);
        let mut issues = Vec::new();
        for entry in &entries {
            let path = layout.dir.join(entry.path.replace('/', std::path::MAIN_SEPARATOR_STR));
            if !path.is_file() {
                issues.push(format!("缺失文件: {}", entry.path));
                continue;
            }
            if crate::manifest::sha256_file(&path)? != entry.sha256 {
                issues.push(format!("sha256 不一致: {}", entry.path));
            }
        }
        if issues.is_empty() {
            output.line(&format!("备份包校验通过（MANIFEST.txt，{} 个文件）", entries.len()));
            return Ok(());
        }
        return Err(AppError::Exit(Exit::failed(format!("备份包校验失败：{}", issues.join("；")))));
    }

    output.error(&format!("说明：{} 内没有 {MANIFEST_JSON}/{MANIFEST_TXT}，跳过 sha256 校验", layout.dir.display()));
    Ok(())
}
