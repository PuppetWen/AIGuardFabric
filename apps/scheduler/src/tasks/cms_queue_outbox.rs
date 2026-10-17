//! Immutable, hashed files: no provider call precedes a durable payload and send marker.
use super::{Id, Path, PathBuf, TenantId};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
};

const MAX_FILE: u64 = 64 * 1024;
const MAX_BYTES: u64 = 16 * 1024 * 1024;
const MAX_RUNS: usize = 1024;
pub(super) fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
pub(super) fn fingerprint(value: &Value) -> anyhow::Result<String> {
    Ok(hash(&serde_json::to_vec(value)?))
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    tenant: TenantId,
    run: Id,
    sha256: String,
    value: Value,
}
pub(super) struct Outbox {
    root: PathBuf,
    tenant: TenantId,
    _lock: File,
}
pub(super) struct Run {
    path: PathBuf,
    tenant: TenantId,
    pub(super) id: Id,
}

fn plain(path: &Path) -> anyhow::Result<()> {
    crate::callback_binding::artifacts::plain(path)
        .map_err(|_| anyhow::anyhow!("CMS outbox 拒绝符号链接或 reparse 路径"))
}
fn directory(parent: &Path, name: &str) -> anyhow::Result<PathBuf> {
    plain(parent)?;
    let path = parent.join(name);
    match std::fs::create_dir(&path) {
        Ok(()) => (),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(e) => return Err(e.into()),
    }
    plain(&path)?;
    anyhow::ensure!(
        path.is_dir() && std::fs::canonicalize(&path)?.parent() == Some(std::fs::canonicalize(parent)?.as_path()),
        "CMS outbox 目录越界"
    );
    Ok(path)
}
impl Outbox {
    pub(super) fn open(output: &Path, tenant: TenantId) -> anyhow::Result<Self> {
        anyhow::ensure!(!tenant.as_uuid().is_nil(), "CMS outbox 租户无效");
        let output = if output.is_absolute() { output.to_owned() } else { std::env::current_dir()?.join(output) };
        plain(&output)?;
        let root = directory(&directory(&output, "cms-outbox")?, &tenant.to_string())?;
        let lock_path = root.join("owner.lock");
        if lock_path.exists() {
            plain(&lock_path)?;
        }
        let lock = OpenOptions::new().read(true).write(true).create(true).truncate(false).open(&lock_path)?;
        plain(&lock_path)?;
        lock.try_lock().map_err(|_| anyhow::anyhow!("CMS outbox 正由另一执行持有；不并发写入"))?;
        let outbox = Self { root, tenant, _lock: lock };
        Self::budget(&outbox.root, 0)?;
        Ok(outbox)
    }
    fn budget(root: &Path, reserve: u64) -> anyhow::Result<()> {
        let mut count = 0_usize;
        let mut bytes = 0_u64;
        for entry in std::fs::read_dir(root)?.take(MAX_RUNS + 2) {
            let entry = entry?;
            plain(&entry.path())?;
            if entry.file_name() == "owner.lock" {
                continue;
            }
            anyhow::ensure!(entry.file_type()?.is_dir(), "CMS outbox 出现未知文件");
            count += 1;
            anyhow::ensure!(count <= MAX_RUNS, "CMS outbox 达到 1024 个周期；原始 payload 不自动删除");
            let mut files = 0;
            for file in std::fs::read_dir(entry.path())?.take(10) {
                let file = file?;
                plain(&file.path())?;
                let metadata = file.metadata()?;
                files += 1;
                anyhow::ensure!(
                    metadata.is_file() && metadata.len() <= MAX_FILE && files <= 8,
                    "CMS outbox 文件预算超限"
                );
                bytes = bytes.checked_add(metadata.len()).ok_or_else(|| anyhow::anyhow!("CMS outbox 大小溢出"))?;
            }
        }
        anyhow::ensure!(
            bytes.checked_add(reserve).is_some_and(|total| total <= MAX_BYTES),
            "CMS outbox 达到 16 MiB；先审查归档，禁止丢弃原 payload"
        );
        Ok(())
    }
    pub(super) fn run(&self, id: Id) -> anyhow::Result<Run> {
        anyhow::ensure!(!id.is_nil(), "CMS 周期编号无效");
        if !self.root.join(id.to_string()).try_exists()? {
            anyhow::ensure!(
                std::fs::read_dir(&self.root)?.take(MAX_RUNS + 1).count() <= MAX_RUNS,
                "CMS outbox 达到 1024 个周期，禁止丢弃原身份"
            );
        }
        Ok(Run { path: directory(&self.root, &id.to_string())?, tenant: self.tenant, id })
    }
    pub(super) fn pending(&self, current: Id) -> anyhow::Result<Vec<Run>> {
        let mut ids = Vec::new();
        for entry in std::fs::read_dir(&self.root)? {
            let entry = entry?;
            if entry.file_name() == "owner.lock" {
                continue;
            }
            let id: Id = entry.file_name().to_str().ok_or_else(|| anyhow::anyhow!("CMS 周期目录名无效"))?.parse()?;
            if id != current {
                ids.push(id);
            }
        }
        ids.sort_by_key(ToString::to_string);
        let mut runs = Vec::new();
        for id in ids {
            let run = self.run(id)?;
            if run.read("accepted")?.is_none() {
                runs.push(run);
            }
            if runs.len() == 16 {
                break;
            }
        }
        Ok(runs)
    }
}
impl Run {
    fn path(&self, name: &str) -> anyhow::Result<PathBuf> {
        anyhow::ensure!(
            ["payload", "enqueue", "send", "send-started", "accepted"].contains(&name),
            "CMS outbox 阶段无效"
        );
        plain(&self.path)?;
        Ok(self.path.join(format!("{name}.json")))
    }
    fn decode(&self, path: &Path) -> anyhow::Result<Value> {
        plain(path)?;
        let file = File::open(path)?;
        anyhow::ensure!(file.metadata()?.is_file() && file.metadata()?.len() <= MAX_FILE, "CMS outbox 文件超过预算");
        let mut bytes = Vec::new();
        file.take(MAX_FILE + 1).read_to_end(&mut bytes)?;
        anyhow::ensure!(bytes.len() as u64 <= MAX_FILE, "CMS outbox 文件读取越界");
        let envelope: Envelope = serde_json::from_slice(&bytes)?;
        anyhow::ensure!(envelope.tenant == self.tenant, "CMS outbox 租户不匹配");
        anyhow::ensure!(envelope.run == self.id, "CMS outbox 周期不匹配");
        anyhow::ensure!(envelope.sha256 == fingerprint(&envelope.value)?, "CMS outbox payload 哈希不匹配");
        Ok(envelope.value)
    }
    pub(super) fn read(&self, name: &str) -> anyhow::Result<Option<Value>> {
        let path = self.path(name)?;
        let pending = path.with_extension("pending");
        if !path.try_exists()? && pending.try_exists()? {
            self.decode(&pending)?;
            std::fs::rename(&pending, &path)?;
        }
        if !path.try_exists()? {
            return Ok(None);
        }
        self.decode(&path).map(Some)
    }
    pub(super) fn save(&self, name: &str, value: &Value) -> anyhow::Result<()> {
        if let Some(old) = self.read(name)? {
            anyhow::ensure!(old == *value, "CMS 原始 payload/wire 已存在，拒绝篡改");
            return Ok(());
        }
        let path = self.path(name)?;
        let pending = path.with_extension("pending");
        let bytes = serde_json::to_vec(&Envelope {
            tenant: self.tenant,
            run: self.id,
            sha256: fingerprint(value)?,
            value: value.clone(),
        })?;
        anyhow::ensure!(bytes.len() as u64 <= MAX_FILE, "CMS outbox payload 超过 64 KiB");
        Outbox::budget(
            self.path.parent().ok_or_else(|| anyhow::anyhow!("CMS outbox 根目录缺失"))?,
            bytes.len() as u64,
        )?;
        let mut file = OpenOptions::new().write(true).create_new(true).open(&pending)?;
        plain(&pending)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        self.decode(&pending)?;
        std::fs::rename(&pending, &path)?;
        #[cfg(unix)]
        File::open(&self.path)?.sync_all()?;
        Ok(())
    }
    pub(super) fn artifact(&self) -> String {
        self.path.join("payload.json").display().to_string()
    }
}
