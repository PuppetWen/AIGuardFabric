//! 持久化事务事实；恢复时比对实际文件字节，不重新下载发布。
use super::paths::{InstallRoot, deny, io, plain, sync_parent};
use agf_core::error::DomainResult;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};
use uuid::Uuid;
pub(crate) const MAX_FILE: u64 = 1024 * 1024 * 1024;
pub(crate) const HEALTH_MS: u64 = 60_000;
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Phase {
    Prepared,
    Replacing,
    AwaitingHealth,
    Confirmed,
    RollbackPending,
    RolledBack,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Journal {
    pub transaction: Uuid,
    pub target_name: String,
    pub original_sha256: String,
    pub candidate_sha256: String,
    pub candidate_size: u64,
    pub manifest_sha256: String,
    pub key_id: String,
    pub target_version: String,
    pub phase: Phase,
    pub nonce: Uuid,
    pub health_deadline_ms: u64,
    pub failure: Option<String>,
}
pub(crate) fn now_ms() -> DomainResult<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| deny("System clock is before the epoch"))?
        .as_millis()
        .try_into()
        .map_err(|_| deny("System clock exceeds journal range"))
}
pub(crate) fn hash_file(path: &Path) -> DomainResult<(String, u64)> {
    plain(path)?;
    let metadata = fs::metadata(path).map_err(io)?;
    if !metadata.is_file() || metadata.len() > MAX_FILE {
        return Err(deny("Update file exceeds budget or is not regular"));
    }
    let mut file = fs::File::open(path).map_err(io)?;
    let mut hash = Sha256::new();
    let mut count = 0_u64;
    let mut buffer = vec![0_u8; 32768];
    loop {
        let length = file.read(&mut buffer).map_err(io)?;
        if length == 0 {
            break;
        }
        count += length as u64;
        if count > MAX_FILE {
            return Err(deny("Update file grew beyond budget"));
        }
        hash.update(&buffer[..length]);
    }
    Ok((hex::encode(hash.finalize()), count))
}
pub(crate) fn tx_dir(root: &InstallRoot, transaction: Uuid) -> DomainResult<PathBuf> {
    if transaction.is_nil() {
        return Err(deny("Missing update transaction"));
    }
    let path = root.root.join(".agf-updates").join(transaction.to_string());
    plain(&path)?;
    Ok(path)
}
pub(crate) fn write_json<T: Serialize>(path: &Path, value: &T) -> DomainResult<()> {
    plain(path)?;
    let bytes = serde_json::to_vec(value)?;
    if bytes.len() > 65536 {
        return Err(deny("Update journal exceeds budget"));
    }
    let temporary = path.with_extension(format!("pending-{}", Uuid::new_v4()));
    plain(&temporary)?;
    let mut file = OpenOptions::new().write(true).create_new(true).open(&temporary).map_err(io)?;
    file.write_all(&bytes).map_err(io)?;
    file.sync_all().map_err(io)?;
    drop(file);
    fs::rename(&temporary, path).map_err(io)?;
    sync_parent(path)
}
pub(crate) fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> DomainResult<T> {
    plain(path)?;
    let file = fs::File::open(path).map_err(io)?;
    if !file.metadata().map_err(io)?.is_file() {
        return Err(deny("Journal is not a regular file"));
    }
    let mut bytes = Vec::new();
    file.take(65537).read_to_end(&mut bytes).map_err(io)?;
    if bytes.len() > 65536 {
        return Err(deny("Update journal exceeds budget"));
    }
    Ok(serde_json::from_slice(&bytes)?)
}
pub(crate) fn load(root: &InstallRoot, transaction: Uuid) -> DomainResult<Journal> {
    let fact: Journal = read_json(&tx_dir(root, transaction)?.join("journal.json"))?;
    if fact.transaction != transaction
        || root.target.file_name().and_then(|s| s.to_str()) != Some(&fact.target_name)
        || fact.nonce.is_nil()
        || fact.candidate_size == 0
        || fact.candidate_size > MAX_FILE
        || [&fact.original_sha256, &fact.candidate_sha256, &fact.manifest_sha256]
            .iter()
            .any(|hash| hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        return Err(deny("Update journal identity, target or hashes are invalid"));
    }
    Ok(fact)
}
pub(crate) fn save(root: &InstallRoot, fact: &Journal) -> DomainResult<()> {
    write_json(&tx_dir(root, fact.transaction)?.join("journal.json"), fact)
}
