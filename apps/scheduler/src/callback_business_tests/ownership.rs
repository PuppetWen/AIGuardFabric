//! Only this run's plain, create-new case directory may be removed.
use agf_core::ids::Id;
use std::path::{Path, PathBuf};
use std::{
    io::Write as _,
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

pub(super) struct Scratch {
    pub(super) root: PathBuf,
    marker: String,
    tenant: Mutex<Option<agf_core::ids::TenantId>>,
    cleaned: AtomicBool,
}
pub(super) fn plain(path: &Path) -> anyhow::Result<()> {
    for ancestor in path.ancestors() {
        let metadata = std::fs::symlink_metadata(ancestor)?;
        anyhow::ensure!(!metadata.file_type().is_symlink(), "fixture path contains a link");
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            anyhow::ensure!(metadata.file_attributes() & 0x400 == 0, "fixture path contains a reparse point");
        }
    }
    Ok(())
}
impl Scratch {
    pub(super) fn new(run: &str, database: &str) -> anyhow::Result<Self> {
        let base = PathBuf::from(std::env::var("AGF_SCHEDULER_CALLBACK_BUSINESS_TEST_DIR")?);
        anyhow::ensure!(base.is_absolute(), "fixed task validation root must be absolute");
        plain(&base)?;
        let base = std::fs::canonicalize(base)?;
        anyhow::ensure!(
            base.file_name().is_some_and(|name| name == "scheduler-callback-business-validation"),
            "wrong validation directory"
        );
        let run_root = base.join(run);
        if !run_root.exists() {
            std::fs::create_dir(&run_root)?;
            std::fs::write(run_root.join(".owner"), format!("scheduler-callback-business:{run}:{database}"))?;
        }
        plain(&run_root)?;
        anyhow::ensure!(
            std::fs::read_to_string(run_root.join(".owner"))?
                == format!("scheduler-callback-business:{run}:{database}"),
            "foreign run directory"
        );
        let root = run_root.join(Id::new().to_string());
        std::fs::create_dir(&root)?;
        let marker = format!(
            "scheduler-callback-business:{run}:{database}:{}",
            root.file_name().and_then(|name| name.to_str()).ok_or_else(|| anyhow::anyhow!("case name invalid"))?
        );
        std::fs::write(root.join(".owner"), &marker)?;
        for name in ["rules", "cases", "reports", "archive", "objects", "data"] {
            std::fs::create_dir(root.join(name))?;
        }
        Ok(Self { root, marker, tenant: Mutex::new(None), cleaned: AtomicBool::new(false) })
    }
    pub(super) fn path(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }
    pub(super) fn bind(&self, tenant: agf_core::ids::TenantId) -> anyhow::Result<()> {
        anyhow::ensure!(!tenant.as_uuid().is_nil(), "owned tenant cannot be nil");
        let mut current = self.tenant.lock().map_err(|_| anyhow::anyhow!("owner marker poisoned"))?;
        anyhow::ensure!(current.is_none(), "fixture root already bound");
        let path = self.root.join(".tenant");
        let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(path)?;
        write!(file, "{}:tenant:{tenant}", self.marker)?;
        file.sync_all()?;
        *current = Some(tenant);
        Ok(())
    }
    pub(super) fn clean(&self) -> anyhow::Result<()> {
        plain(&self.root)?;
        anyhow::ensure!(std::fs::read_to_string(self.root.join(".owner"))? == self.marker, "case owner changed");
        let current_tenant = *self.tenant.lock().map_err(|_| anyhow::anyhow!("owner marker poisoned"))?;
        if let Some(tenant) = current_tenant {
            anyhow::ensure!(
                std::fs::read_to_string(self.root.join(".tenant"))? == format!("{}:tenant:{tenant}", self.marker),
                "tenant marker changed"
            );
        }
        check_tree(&self.root)?;
        std::fs::remove_dir_all(&self.root)?;
        self.cleaned.store(true, Ordering::SeqCst);
        Ok(())
    }
}
fn check_tree(path: &Path) -> anyhow::Result<()> {
    plain(path)?;
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        plain(&entry.path())?;
        if entry.file_type()?.is_dir() {
            check_tree(&entry.path())?;
        }
    }
    Ok(())
}
impl Drop for Scratch {
    fn drop(&mut self) {
        if !self.cleaned.load(Ordering::SeqCst) {
            // Failure paths can still have cancelling business futures. The task runner owns final cleanup
            // after the native process exits; do not race those futures with recursive deletion here.
            tracing::warn!("callback fixture did not finish; preserve its owner-marked files for runner cleanup");
        }
    }
}
