//! 数据目录打包/解包（备份包里的 `data-files.zip`）。
//!
//! 用 `zip` crate 而不是调用系统 `Compress-Archive`/`Expand-Archive`：
//! 1. 备份包要被还原脚本与 `agfctl restore --with-data` 两侧共用，格式必须一致；
//! 2. 外部命令在不同 Windows/PowerShell 版本上路径处理有差异，进程内实现更可控。
//!
//! 解包时会**拒绝**绝对路径与包含 `..` 的条目（Zip Slip 防护）。

use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use crate::manifest::{collect_files, normalize_relative};

/// 打包若干目录（目录不存在则跳过）。
///
/// 返回 `(条目数, 字节数)`。
///
/// # Errors
/// 创建压缩包或读写文件失败。
pub fn zip_dirs(root: &Path, dirs: &[PathBuf], dest: &Path) -> anyhow::Result<(usize, u64)> {
    let file = File::create(dest)?;
    let mut zip = zip::ZipWriter::new(file);
    let options: zip::write::FileOptions<'_, ()> =
        zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Deflated);
    let mut entries = 0_usize;
    let mut bytes = 0_u64;
    for dir in dirs {
        if !dir.is_dir() {
            continue;
        }
        for file in collect_files(dir)? {
            let rel = normalize_relative(root, &file)?;
            zip.start_file(rel.clone(), options)?;
            let mut fh = File::open(&file)?;
            let copied = std::io::copy(&mut fh, &mut zip)?;
            entries += 1;
            bytes += copied;
        }
    }
    zip.finish()?.sync_all()?;
    Ok((entries, bytes))
}

/// 解包到目标目录（覆盖同名文件）。
///
/// 返回解包的文件数。
///
/// # Errors
/// 打开压缩包失败、条目路径非法（Zip Slip）或写入失败。
pub fn unzip_into(archive: &Path, dest: &Path) -> anyhow::Result<usize> {
    let file = File::open(archive)?;
    let mut zip = zip::ZipArchive::new(file)?;
    let mut count = 0_usize;
    for i in 0..zip.len() {
        let mut entry = zip.by_index(i)?;
        let name = entry.name().to_string();
        if name.contains("..") || name.starts_with('/') || name.contains(':') {
            anyhow::bail!("压缩包含非法条目路径，拒绝解包: {name}");
        }
        let out_path = dest.join(name.replace('/', std::path::MAIN_SEPARATOR_STR));
        if entry.is_dir() {
            std::fs::create_dir_all(&out_path)?;
            continue;
        }
        if let Some(parent) = out_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut out = File::create(&out_path)?;
        let mut buf = Vec::new();
        entry.read_to_end(&mut buf)?;
        out.write_all(&buf)?;
        out.sync_all()?;
        count += 1;
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("agf-archive-{tag}-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("建目录");
        dir
    }

    #[test]
    fn zip_then_unzip_roundtrip() {
        let root = temp_dir("roundtrip");
        let seed = root.join("data/seed");
        std::fs::create_dir_all(&seed).expect("建目录");
        std::fs::write(seed.join("bootstrap-admin.txt"), "secret").expect("写文件");
        std::fs::write(seed.join("other.txt"), "x").expect("写文件");

        let dest = root.join("out.zip");
        let (entries, bytes) = zip_dirs(&root, std::slice::from_ref(&seed), &dest).expect("打包");
        assert_eq!(entries, 2);
        assert!(bytes >= 7);
        assert!(dest.is_file());

        let back = root.join("restore");
        let count = unzip_into(&dest, &back).expect("解包");
        assert_eq!(count, 2);
        let restored = back.join("data/seed/bootstrap-admin.txt");
        assert!(restored.is_file(), "解包后路径应保持相对结构: {}", restored.display());
        assert_eq!(std::fs::read_to_string(restored).unwrap_or_default(), "secret");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn missing_dirs_are_skipped_without_error() {
        let root = temp_dir("missing");
        let dest = root.join("empty.zip");
        let (entries, bytes) = zip_dirs(&root, &[root.join("nope")], &dest).expect("打包");
        assert_eq!(entries, 0);
        assert_eq!(bytes, 0);
        assert!(dest.is_file(), "即使没有内容也应产出合法（空）压缩包");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn unzip_rejects_path_traversal_entries() {
        let root = temp_dir("zipslip");
        let dest = root.join("evil.zip");
        let file = File::create(&dest).expect("建包");
        let mut zip = zip::ZipWriter::new(file);
        let options: zip::write::FileOptions<'_, ()> = zip::write::FileOptions::default();
        zip.start_file("../escaped.txt", options).expect("写入条目");
        zip.write_all(b"pwned").expect("写内容");
        zip.finish().expect("完成");

        let out = root.join("out");
        let res = unzip_into(&dest, &out);
        assert!(res.is_err(), "含 .. 的条目必须被拒绝");
        assert!(!root.join("escaped.txt").exists(), "不得在目标目录之外落文件");
        let _ = std::fs::remove_dir_all(&root);
    }
}
