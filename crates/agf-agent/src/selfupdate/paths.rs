//! 约束安装根目录，逐层拒绝现有祖先中的符号链接与重解析点。
use agf_core::error::{DomainError, DomainResult};
use std::{
    fs::{self, File, OpenOptions},
    path::{Component, Path, PathBuf},
};
pub(crate) fn io(error: std::io::Error) -> DomainError {
    DomainError::from(error)
}
pub(crate) fn deny(message: &str) -> DomainError {
    DomainError::PreconditionFailed(message.into())
}
pub(crate) fn plain(path: &Path) -> DomainResult<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        if matches!(component, Component::Prefix(_)) {
            current.push(component.as_os_str());
            continue;
        }
        if matches!(component, Component::ParentDir | Component::CurDir) {
            return Err(deny("Non-normal update path"));
        }
        current.push(component.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(metadata) => {
                #[cfg(windows)]
                let reparse = {
                    use std::os::windows::fs::MetadataExt;
                    metadata.file_attributes() & 0x400 != 0
                };
                #[cfg(not(windows))]
                let reparse = false;
                if metadata.file_type().is_symlink() || reparse {
                    return Err(deny("Update path contains a link/reparse point"));
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(error) => return Err(io(error)),
        }
    }
    Ok(())
}
/// 操作员明确控制的安装目录及单个固定程序文件名。
#[derive(Debug, Clone)]
pub struct InstallRoot {
    pub(crate) root: PathBuf,
    pub(crate) target: PathBuf,
}
impl InstallRoot {
    /// 解析现有安装目录，拒绝将更新助手自身的运行映像作为安装目标。
    ///
    /// # Errors
    /// 拒绝链接、缺失或非普通目标文件、相对根目录及路径穿越。
    pub fn new(root: &Path, name: &str) -> DomainResult<Self> {
        if !root.is_absolute()
            || name.is_empty()
            || Path::new(name).components().count() != 1
            || !matches!(Path::new(name).components().next(), Some(Component::Normal(_)))
        {
            return Err(deny("Explicit absolute install root and one executable filename required"));
        }
        plain(root)?;
        let root = fs::canonicalize(root).map_err(io)?;
        let target = root.join(name);
        plain(&target)?;
        if !fs::metadata(&target).map_err(io)?.is_file() {
            return Err(deny("Installed target must be a regular file"));
        }
        if std::env::current_exe().ok().and_then(|p| fs::canonicalize(p).ok()).as_ref() == Some(&target) {
            return Err(deny("Run an external updater helper; never replace its own running image"));
        }
        Ok(Self { root, target })
    }
    pub(crate) fn lock(&self) -> DomainResult<File> {
        plain(&self.root)?;
        let path = self.root.join(".agf-update.lock");
        plain(&path)?;
        let file = OpenOptions::new().read(true).write(true).create(true).truncate(false).open(path).map_err(io)?;
        file.try_lock().map_err(|_| deny("Another updater owns this installation root"))?;
        Ok(file)
    }
    pub(crate) fn idle(&self) -> DomainResult<()> {
        plain(&self.target)?;
        let system = sysinfo::System::new_all();
        if system
            .processes()
            .values()
            .filter_map(sysinfo::Process::exe)
            .filter_map(|p| fs::canonicalize(p).ok())
            .any(|p| p == self.target)
        {
            return Err(deny("Installed target is running; stop it through its own service manager before apply"));
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            let _probe = OpenOptions::new().read(true).write(true).share_mode(0).open(&self.target).map_err(io)?;
        }
        Ok(())
    }
}
pub(crate) fn sync_parent(path: &Path) -> DomainResult<()> {
    let parent = path.parent().ok_or_else(|| deny("Missing parent"))?;
    #[cfg(unix)]
    File::open(parent).map_err(io)?.sync_all().map_err(io)?;
    // Windows 的 std 接口没有目录 fsync；只保证调用者已同步文件内容。
    #[cfg(not(unix))]
    let _ = parent;
    Ok(())
}
