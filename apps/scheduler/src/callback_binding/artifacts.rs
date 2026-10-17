//! Report only stable content digests from explicitly configured executor output directories.
use super::types::{Artifact, Outcome};
use crate::TaskOutcome;
use agf_core::error::{DomainError, DomainResult};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use tokio::io::AsyncReadExt;

fn rejected() -> DomainError {
    DomainError::PreconditionFailed("执行制品不能形成可信本地摘要；原执行不得重跑".into())
}
fn absolute(path: &Path) -> DomainResult<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_owned())
    } else {
        std::env::current_dir().map(|root| root.join(path)).map_err(|_| rejected())
    }
}
pub(crate) fn plain(path: &Path) -> DomainResult<()> {
    for component in path.ancestors() {
        let metadata = std::fs::symlink_metadata(component).map_err(|_| rejected())?;
        if metadata.file_type().is_symlink() {
            return Err(rejected());
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if metadata.file_attributes() & 0x400 != 0 {
                return Err(rejected());
            }
        }
    }
    Ok(())
}
pub(crate) async fn summarize(result: &TaskOutcome, roots: &[PathBuf]) -> DomainResult<Outcome> {
    if result.artifacts.len() > 64 || (result.skipped && !result.artifacts.is_empty()) {
        return Err(rejected());
    }
    let mut artifacts = Vec::new();
    for original in &result.artifacts {
        let path = absolute(Path::new(original))?;
        plain(&path)?;
        let resolved = std::fs::canonicalize(&path).map_err(|_| rejected())?;
        let owned = roots.iter().any(|root| {
            absolute(root).is_ok_and(|root| {
                plain(&root).is_ok() && std::fs::canonicalize(root).is_ok_and(|root| resolved.starts_with(root))
            })
        });
        if !owned {
            return Err(rejected());
        }
        plain(&resolved)?;
        let mut file = tokio::fs::File::open(&resolved).await.map_err(|_| rejected())?;
        let before = file.metadata().await.map_err(|_| rejected())?;
        if !before.is_file() {
            return Err(rejected());
        }
        let mut hash = Sha256::new();
        let mut bytes = 0_u64;
        let mut buffer = vec![0_u8; 64 * 1024];
        loop {
            let count = file.read(&mut buffer).await.map_err(|_| rejected())?;
            if count == 0 {
                break;
            }
            bytes = bytes.checked_add(count as u64).ok_or_else(rejected)?;
            hash.update(&buffer[..count]);
        }
        let after = file.metadata().await.map_err(|_| rejected())?;
        if before.len() != bytes || after.len() != bytes || before.modified().ok() != after.modified().ok() {
            return Err(rejected());
        }
        artifacts.push(Artifact { sha256: format!("{:x}", hash.finalize()), bytes });
    }
    Ok(Outcome { ok: result.ok, skipped: result.skipped, degraded: result.degraded, artifacts })
}
