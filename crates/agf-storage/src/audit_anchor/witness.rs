//! 持久见证保存在 PostgreSQL 之外，并与编译及测试证据目录分离。
use agf_core::{
    audit::SignedAuditAnchor,
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
};

const OWNER: &str = "AIGuardFabric durable audit witnesses v1\n";
const MAX_BYTES: u64 = 16 * 1024;

/// 在配置的数据目录下使用独占系统文件锁及有界持久见证。
/// 解锁后保留锁文件；删除会造成不同 inode 上的文件锁竞态。
#[derive(Debug)]
pub struct AuditWitness {
    root: PathBuf,
    path: PathBuf,
    _lock: File,
}
impl AuditWitness {
    /// 打开可信持久目录，并取得该审计链的非阻塞独占锁。
    ///
    /// # Errors
    /// 目录归属不明、包含链接或重解析点、不可用，或锁已被其他进程持有。
    pub fn acquire(data_dir: &Path, tenant: TenantId, agent: Option<Id>) -> DomainResult<Self> {
        check_components(data_dir)?;
        let base = fs::canonicalize(data_dir)?;
        let root = base.join("audit-witnesses-v1");
        let created = match fs::create_dir(&root) {
            Ok(()) => true,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => false,
            Err(error) => return Err(error.into()),
        };
        if created {
            protect(&root)?;
            let mut marker = File::create_new(root.join(".owner"))?;
            marker.write_all(OWNER.as_bytes())?;
            marker.sync_all()?;
        }
        check_components(&root)?;
        if fs::canonicalize(&root)?.parent() != Some(base.as_path())
            || read_bounded(&root.join(".owner"), 256)?.as_deref() != Some(OWNER.as_bytes())
        {
            return Err(invalid());
        }
        let stem = agent.map_or_else(|| format!("{tenant}-management"), |id| format!("{tenant}-agent-{id}"));
        let lock_path = root.join(format!("{stem}.lock"));
        check_optional(&lock_path)?;
        let lock = OpenOptions::new().create(true).truncate(false).read(true).write(true).open(&lock_path)?;
        protect(&lock_path)?;
        lock.try_lock().map_err(|_| DomainError::Conflict("Audit witness is locked by another process".into()))?;
        let path = root.join(format!("{stem}.json"));
        check_optional(&path)?;
        Ok(Self { root, path, _lock: lock })
    }

    /// 读取最近已提交的见证；不存在时明确表示尚需首个检查点。
    ///
    /// # Errors
    /// 见证为链接、超过大小限制，或格式错误。
    pub fn read(&self) -> DomainResult<Option<SignedAuditAnchor>> {
        read_bounded(&self.path, MAX_BYTES)?.map(|bytes| serde_json::from_slice(&bytes).map_err(Into::into)).transpose()
    }

    /// 仅在数据库事务成功提交后推进见证。
    /// 调用方必须在该事务内验证旧见证属于已签名历史的祖先。
    ///
    /// # Errors
    /// 原子替换、文件同步或边界校验失败。
    pub fn advance(&self, envelope: &SignedAuditAnchor) -> DomainResult<()> {
        let bytes = serde_json::to_vec(envelope)?;
        if bytes.len() > usize::try_from(MAX_BYTES).map_err(|_| invalid())? {
            return Err(invalid());
        }
        check_components(&self.root)?;
        check_optional(&self.path)?;
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
            Ok::<(), DomainError>(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }
}

fn read_bounded(path: &Path, max: u64) -> DomainResult<Option<Vec<u8>>> {
    match fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    }
    check_components(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.len() > max {
        return Err(invalid());
    }
    let mut bytes = Vec::new();
    File::open(path)?.take(max + 1).read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).map_err(|_| invalid())? > max {
        return Err(invalid());
    }
    Ok(Some(bytes))
}
fn check_optional(path: &Path) -> DomainResult<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => check_components(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}
fn check_components(path: &Path) -> DomainResult<()> {
    let absolute = std::path::absolute(path)?;
    let mut current = PathBuf::new();
    for component in absolute.components() {
        if matches!(component, Component::ParentDir) {
            return Err(invalid());
        }
        current.push(component);
        // Windows canonicalize 的裸 verbatim 前缀是卷设备，不能查询目录元数据。
        // 先累积前缀，RootDir 与全部后续组件仍执行原有链接、重解析点及 I/O 检查。
        if matches!(component, Component::Prefix(_)) {
            continue;
        }
        let metadata = fs::symlink_metadata(&current)?;
        if metadata.file_type().is_symlink() {
            return Err(invalid());
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if metadata.file_attributes() & 0x400 != 0 {
                return Err(invalid());
            }
        }
    }
    Ok(())
}
fn protect(path: &Path) -> DomainResult<()> {
    // 建立权限或继承受控 ACL 前，再次拒绝链接与重解析路径。
    check_components(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = if path.is_dir() { 0o700 } else { 0o600 };
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    // Windows 继承运维方控制的 AGF_DATA_DIR ACL；不调用 shell 或修改 ACL。
    Ok(())
}
fn invalid() -> DomainError {
    DomainError::Crypto("Audit witness ownership or integrity is invalid".into())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn canonical_data_directory_preserves_exclusive_witness_reopen() {
        let owner = format!("audit-witness-canonical-{}", Id::new());
        let root = PathBuf::from("target/test-data").join(&owner);
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join(".owned-test"), owner.as_bytes()).unwrap();
        let canonical = fs::canonicalize(&root).unwrap();
        check_components(&canonical).unwrap();
        let tenant = TenantId::new();
        let witness = AuditWitness::acquire(&canonical, tenant, None).unwrap();
        assert!(witness.read().unwrap().is_none());
        assert!(AuditWitness::acquire(&canonical, tenant, None).is_err());
        drop(witness);
        let reopened = AuditWitness::acquire(&canonical, tenant, None).unwrap();
        assert!(reopened.read().unwrap().is_none());
        assert_eq!(fs::read(reopened.root.join(".owner")).unwrap(), OWNER.as_bytes());
        drop(reopened);
        assert_eq!(fs::read(root.join(".owned-test")).unwrap(), owner.as_bytes());
        assert!(!fs::symlink_metadata(&root).unwrap().file_type().is_symlink());
        assert_eq!(fs::canonicalize(&root).unwrap(), canonical);
        fs::remove_dir_all(root).unwrap();
    }
}
