//! 有界单写者日志；进程退出后保留待确认记录，供精确重放。
use agf_core::{
    audit::{AuditChainKind, AuditLog, SignedAuditAnchor, verify_agent_segment},
    ids::Id,
};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

const OWNER: &str = "AIGuardFabric persistent MCP audit journal v1\n";
const LIMIT: u64 = 64 * 1024;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct State {
    pub chain: Id,
    pub ack: Option<SignedAuditAnchor>,
    pub pending: Vec<AuditLog>,
}
pub(super) struct Journal {
    root: PathBuf,
    path: PathBuf,
    _lock: File,
    pub state: State,
}
impl Journal {
    pub(super) fn open(data_dir: &Path, namespace: &str) -> anyhow::Result<Self> {
        check_existing(data_dir)?;
        fs::create_dir_all(data_dir)?;
        check_existing(data_dir)?;
        let base = fs::canonicalize(data_dir)?;
        let root = base.join("mcp-audit-journals-v1");
        let created = match fs::create_dir(&root) {
            Ok(()) => true,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => false,
            Err(error) => return Err(error.into()),
        };
        if created {
            protect(&root)?;
            let mut owner = File::create_new(root.join(".owner"))?;
            owner.write_all(OWNER.as_bytes())?;
            owner.sync_all()?;
        }
        check_existing(&root)?;
        anyhow::ensure!(
            fs::canonicalize(&root)?.parent() == Some(base.as_path())
                && read(&root.join(".owner"), 256)?.as_deref() == Some(OWNER.as_bytes()),
            "Audit journal owner mismatch"
        );
        anyhow::ensure!(agf_core::audit::valid_hash(namespace), "Invalid audit namespace");
        let lock_path = root.join(format!("{namespace}.lock"));
        check_existing(&lock_path)?;
        let lock = OpenOptions::new().create(true).truncate(false).read(true).write(true).open(&lock_path)?;
        protect(&lock_path)?;
        lock.try_lock().map_err(|_| anyhow::anyhow!("Another MCP proxy owns this audit journal"))?;
        let path = root.join(format!("{namespace}.json"));
        let bytes = read(&path, LIMIT)?;
        let fresh = bytes.is_none();
        let state = bytes.map_or_else(
            || Ok(State { chain: Id::new(), ack: None, pending: Vec::new() }),
            |value| serde_json::from_slice(&value),
        )?;
        validate(&state)?;
        let journal = Self { root, path, _lock: lock, state };
        if fresh {
            journal.save()?;
        }
        Ok(journal)
    }
    pub(super) fn save(&self) -> anyhow::Result<()> {
        validate(&self.state)?;
        let bytes = serde_json::to_vec(&self.state)?;
        anyhow::ensure!(u64::try_from(bytes.len())? <= LIMIT, "Audit journal exceeds limit");
        check_existing(&self.root)?;
        check_existing(&self.path)?;
        let temporary = self.root.join(format!(".pending-{}", Id::new()));
        let result = (|| {
            let mut file = File::create_new(&temporary)?;
            protect(&temporary)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            drop(file);
            fs::rename(&temporary, &self.path)?;
            #[cfg(unix)]
            File::open(&self.root)?.sync_all()?;
            Ok::<(), anyhow::Error>(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }
}
fn validate(state: &State) -> anyhow::Result<()> {
    anyhow::ensure!(!state.chain.is_nil() && state.pending.len() <= 1, "Invalid local audit state");
    if let Some(ack) = &state.ack {
        let agent = ack.agent_id.ok_or_else(|| anyhow::anyhow!("Local audit witness is not Agent-bound"))?;
        ack.validate_identity(ack.anchor.tenant_id, AuditChainKind::AgentRuntime, Some(agent))?;
        anyhow::ensure!(
            ack.chain_id == state.chain && agf_core::audit::valid_hash(&ack.anchor.signature),
            "Local audit identity or signature is invalid"
        );
        verify_agent_segment(
            &state.pending,
            ack.anchor.tenant_id,
            agent,
            ack.anchor.up_to_sequence,
            &ack.anchor.tail_hash,
        )?;
    } else {
        anyhow::ensure!(state.pending.is_empty(), "An unbootstrapped journal contains decisions");
    }
    Ok(())
}
fn read(path: &Path, max: u64) -> anyhow::Result<Option<Vec<u8>>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(value) => value,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    check_existing(path)?;
    anyhow::ensure!(metadata.is_file() && metadata.len() <= max, "Invalid audit journal file");
    let mut bytes = Vec::new();
    File::open(path)?.take(max + 1).read_to_end(&mut bytes)?;
    anyhow::ensure!(u64::try_from(bytes.len())? <= max, "Audit journal exceeds limit");
    Ok(Some(bytes))
}
fn check_existing(path: &Path) -> anyhow::Result<()> {
    let mut current = PathBuf::new();
    for component in std::path::absolute(path)?.components() {
        anyhow::ensure!(
            !matches!(component, std::path::Component::ParentDir),
            "Audit path contains a parent traversal"
        );
        current.push(component);
        // Windows canonicalize 会生成 verbatim 路径；裸前缀 \\?\D: 是卷设备，
        // 不是可查询元数据的目录。先累积前缀，等 RootDir 后核验真实根目录；
        // 根目录及每个后续组件仍必须通过原有 symlink/reparse 和 I/O 检查。
        if matches!(component, std::path::Component::Prefix(_)) {
            continue;
        }
        let metadata = match fs::symlink_metadata(&current) {
            Ok(value) => value,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        anyhow::ensure!(!metadata.file_type().is_symlink(), "Audit path is a symlink");
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            anyhow::ensure!(metadata.file_attributes() & 0x400 == 0, "Audit path is a reparse point");
        }
    }
    Ok(())
}
fn protect(path: &Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(if path.is_dir() { 0o700 } else { 0o600 }))?;
    }
    // Windows 使用操作员管理的 ACL；仍核验现有路径归属和重解析点。
    #[cfg(not(unix))]
    check_existing(path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn canonical_directory_keeps_owner_lock_and_atomic_journal_reopen() {
        let directory = tempfile::tempdir().unwrap();
        let canonical = fs::canonicalize(directory.path()).unwrap();
        check_existing(&canonical).unwrap();
        let namespace = "a".repeat(64);
        let journal = Journal::open(&canonical, &namespace).unwrap();
        let chain = journal.state.chain;
        assert!(Journal::open(&canonical, &namespace).is_err());
        journal.save().unwrap();
        journal.save().unwrap();
        let path = journal.path.clone();
        drop(journal);
        let reopened = Journal::open(&canonical, &namespace).unwrap();
        assert_eq!(reopened.state.chain, chain);
        assert_eq!(reopened.path, path);
        assert_eq!(fs::read(reopened.root.join(".owner")).unwrap(), OWNER.as_bytes());
    }

    #[test]
    fn canonical_directory_still_rejects_foreign_owner_oversized_or_non_file_state() {
        let directory = tempfile::tempdir().unwrap();
        let canonical = fs::canonicalize(directory.path()).unwrap();
        let namespace = "b".repeat(64);
        let journal = Journal::open(&canonical, &namespace).unwrap();
        let root = journal.root.clone();
        let path = journal.path.clone();
        drop(journal);
        fs::write(root.join(".owner"), b"foreign owner").unwrap();
        assert!(Journal::open(&canonical, &namespace).is_err());
        fs::write(root.join(".owner"), OWNER.as_bytes()).unwrap();
        let oversized = File::create(&path).unwrap();
        oversized.set_len(LIMIT + 1).unwrap();
        oversized.sync_all().unwrap();
        drop(oversized);
        assert!(Journal::open(&canonical, &namespace).is_err());
        fs::write(&path, b"malformed journal").unwrap();
        assert!(Journal::open(&canonical, &namespace).is_err());
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        assert!(Journal::open(&canonical, &namespace).is_err());
    }
}
