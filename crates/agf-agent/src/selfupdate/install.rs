//! 在操作员控制的单个目录内执行原子替换及保守的崩溃恢复。
use super::{
    journal::{self, Journal, Phase},
    paths::{InstallRoot, deny, io, plain, sync_parent},
    trust::VerifiedUpdate,
};
use agf_core::error::DomainResult;
use serde::Serialize;
use std::{
    fs::{self, File},
    path::Path,
};
use uuid::Uuid;
/// 持久化结果，不输出私有健康随机数与完整下载地址。
#[derive(Debug, Clone, Serialize)]
pub struct UpdateReceipt {
    /// 用于崩溃恢复的稳定更新事务标识。
    pub transaction: Uuid,
    /// 当前更新阶段，包含 prepared、awaiting_health、confirmed 及回滚状态。
    pub status: String,
    /// 已认证的目标版本。
    pub target_version: String,
    /// 下载程序的摘要。
    pub candidate_sha256: String,
    /// 保存在事务目录内的旧程序摘要。
    pub previous_sha256: String,
    /// 不含凭据或响应正文的失败分类。
    pub failure: Option<String>,
}
pub(crate) fn receipt(fact: &Journal) -> UpdateReceipt {
    UpdateReceipt {
        transaction: fact.transaction,
        status: match fact.phase {
            Phase::Prepared => "prepared",
            Phase::Replacing => "replacing",
            Phase::AwaitingHealth => "awaiting_health",
            Phase::Confirmed => "confirmed",
            Phase::RollbackPending => "rollback_pending",
            Phase::RolledBack => "rolled_back",
        }
        .into(),
        target_version: fact.target_version.clone(),
        candidate_sha256: fact.candidate_sha256.clone(),
        previous_sha256: fact.original_sha256.clone(),
        failure: fact.failure.clone(),
    }
}
/// 持有安装根目录独占更新锁的已认证暂存事务。
pub struct StagedUpdate {
    pub(crate) root: InstallRoot,
    pub(crate) fact: Journal,
    pub(crate) _lock: File,
}
impl std::fmt::Debug for StagedUpdate {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("StagedUpdate").field("receipt", &receipt(&self.fact)).finish_non_exhaustive()
    }
}
impl StagedUpdate {
    /// 读取当前持久化回执，不执行程序或应用更新。
    #[must_use]
    pub fn receipt(&self) -> UpdateReceipt {
        receipt(&self.fact)
    }
    pub(crate) fn begin(root: InstallRoot, update: &VerifiedUpdate) -> DomainResult<Self> {
        let lock = root.lock()?;
        root.idle()?;
        let parent = root.root.join(".agf-updates");
        plain(&parent)?;
        fs::create_dir_all(&parent).map_err(io)?;
        if fs::read_dir(&parent).map_err(io)?.take(17).count() >= 16 {
            return Err(deny("Update receipt capacity reached; archive reviewed old transactions first"));
        }
        for entry in fs::read_dir(&parent).map_err(io)? {
            let entry = entry.map_err(io)?;
            let transaction = entry
                .file_name()
                .to_str()
                .and_then(|name| Uuid::parse_str(name).ok())
                .ok_or_else(|| deny("Unknown update history entry; explicit review required"))?;
            let previous = journal::load(&root, transaction)?;
            if matches!(previous.phase, Phase::Replacing | Phase::AwaitingHealth | Phase::RollbackPending) {
                return Err(deny("Recover the original pending transaction before starting a new update"));
            }
        }
        let transaction = Uuid::new_v4();
        let dir = journal::tx_dir(&root, transaction)?;
        fs::create_dir(&dir).map_err(io)?;
        let original_sha256 = journal::hash_file(&root.target)?.0;
        let fact = Journal {
            transaction,
            target_name: root
                .target
                .file_name()
                .and_then(|s| s.to_str())
                .ok_or_else(|| deny("Executable filename must be UTF-8"))?
                .into(),
            original_sha256,
            candidate_sha256: update.plan.sha256.to_ascii_lowercase(),
            candidate_size: update.plan.size,
            manifest_sha256: update.manifest_sha256.clone(),
            key_id: update.key_id.clone(),
            target_version: update.plan.target.clone(),
            phase: Phase::Prepared,
            nonce: Uuid::new_v4(),
            health_deadline_ms: 0,
            failure: None,
        };
        // 下载失败时仅留下受预算约束的暂存事务，不修改安装目标。
        journal::save(&root, &fact)?;
        Ok(Self { root, fact, _lock: lock })
    }
    pub(crate) fn candidate(&self) -> DomainResult<std::path::PathBuf> {
        Ok(journal::tx_dir(&self.root, self.fact.transaction)?.join("candidate"))
    }
    pub(crate) fn prepared(&self) -> DomainResult<()> {
        if journal::hash_file(&self.root.target)?.0 != self.fact.original_sha256
            || journal::hash_file(&self.candidate()?)? != (self.fact.candidate_sha256.clone(), self.fact.candidate_size)
        {
            return Err(deny("Installed/candidate bytes changed after the authenticated plan"));
        }
        let previous = journal::tx_dir(&self.root, self.fact.transaction)?.join("previous");
        copy_new(&self.root.target, &previous)?;
        if journal::hash_file(&previous)?.0 != self.fact.original_sha256 {
            return Err(deny("Previous executable backup failed verification"));
        }
        fs::set_permissions(self.candidate()?, fs::metadata(&self.root.target).map_err(io)?.permissions())
            .map_err(io)?;
        Ok(())
    }
    pub(crate) fn replace(&mut self, health_ms: u64) -> DomainResult<()> {
        self.root.idle()?;
        if journal::hash_file(&self.root.target)?.0 != self.fact.original_sha256 {
            return Err(deny("Installed executable changed before apply"));
        }
        if journal::hash_file(&self.candidate()?)? != (self.fact.candidate_sha256.clone(), self.fact.candidate_size) {
            return Err(deny("Staged executable changed before apply"));
        }
        self.fact.phase = Phase::Replacing;
        self.fact.health_deadline_ms =
            journal::now_ms()?.checked_add(health_ms).ok_or_else(|| deny("Health deadline overflow"))?;
        journal::save(&self.root, &self.fact)?;
        plain(&self.root.target)?;
        fs::rename(self.candidate()?, &self.root.target).map_err(io)?;
        sync_parent(&self.root.target)?;
        self.fact.phase = Phase::AwaitingHealth;
        journal::save(&self.root, &self.fact)
    }
    pub(crate) fn rollback(&mut self) -> DomainResult<()> {
        self.fact.phase = Phase::RollbackPending;
        journal::save(&self.root, &self.fact)?;
        self.root.idle()?;
        let dir = journal::tx_dir(&self.root, self.fact.transaction)?;
        let previous = dir.join("previous");
        if journal::hash_file(&previous)?.0 != self.fact.original_sha256 {
            return Err(deny("Rollback backup hash mismatch; no executable replaced"));
        }
        let current = journal::hash_file(&self.root.target)?.0;
        if current != self.fact.original_sha256 && current != self.fact.candidate_sha256 {
            return Err(deny("Target changed outside this transaction; rollback refuses to overwrite"));
        }
        if current != self.fact.original_sha256 {
            let restore = dir.join(format!("restore-{}", Uuid::new_v4()));
            copy_new(&previous, &restore)?;
            fs::rename(&restore, &self.root.target).map_err(io)?;
            sync_parent(&self.root.target)?;
        }
        self.fact.phase = Phase::RolledBack;
        journal::save(&self.root, &self.fact)
    }
}
fn copy_new(source: &Path, destination: &Path) -> DomainResult<()> {
    use std::io::{Read, Write};
    plain(source)?;
    plain(destination)?;
    let input = File::open(source).map_err(io)?;
    let mut output = fs::OpenOptions::new().write(true).create_new(true).open(destination).map_err(io)?;
    let copied = std::io::copy(&mut input.take(journal::MAX_FILE + 1), &mut output).map_err(io)?;
    if copied > journal::MAX_FILE {
        return Err(deny("Executable backup exceeds budget"));
    }
    output.flush().map_err(io)?;
    output.sync_all().map_err(io)?;
    fs::set_permissions(destination, fs::metadata(source).map_err(io)?.permissions()).map_err(io)?;
    sync_parent(destination)
}
/// 恢复已有事务，不重复下载、安装派发或云端操作。
///
/// # Errors
/// 拒绝摘要损坏、链接、目标被外部修改及回滚目标被占用。
pub fn recover_update(root: InstallRoot, transaction: Uuid) -> DomainResult<UpdateReceipt> {
    let lock = root.lock()?;
    let fact = journal::load(&root, transaction)?;
    let mut staged = StagedUpdate { root, fact, _lock: lock };
    let actual = journal::hash_file(&staged.root.target)?.0;
    if staged.fact.phase == Phase::Confirmed {
        if actual != staged.fact.candidate_sha256 {
            return Err(deny("Confirmed executable changed"));
        }
        return Ok(receipt(&staged.fact));
    }
    if staged.fact.phase == Phase::RolledBack {
        if actual != staged.fact.original_sha256 {
            return Err(deny("Rolled-back executable changed"));
        }
        return Ok(receipt(&staged.fact));
    }
    if actual == staged.fact.original_sha256 && matches!(staged.fact.phase, Phase::Prepared | Phase::Replacing) {
        staged.fact.phase = Phase::Prepared;
        journal::save(&staged.root, &staged.fact)?;
        return Ok(receipt(&staged.fact));
    }
    if actual != staged.fact.candidate_sha256 && staged.fact.phase != Phase::RollbackPending {
        return Err(deny("Recovery cannot attribute the installed executable"));
    }
    if staged.fact.phase == Phase::Replacing {
        staged.fact.phase = Phase::AwaitingHealth;
        journal::save(&staged.root, &staged.fact)?;
    }
    if staged.fact.phase == Phase::RollbackPending {
        staged.rollback()?;
    } else if super::health::valid(&staged.root, &staged.fact)? {
        staged.fact.phase = Phase::Confirmed;
        journal::save(&staged.root, &staged.fact)?;
    } else if journal::now_ms()? >= staged.fact.health_deadline_ms {
        staged.rollback()?;
    }
    Ok(receipt(&staged.fact))
}
