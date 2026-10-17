//! 显式受管启动：先验证已打开的文件，再获取已审计的放行决定，最后启动同一字节。
use super::client::{ProcessClient, denied};
use agf_core::{
    error::{DomainError, DomainResult},
    ids::Id,
    process_hook::{ProcessMode, ProcessRequest, ProcessSource},
    time::Timestamp,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek},
    path::{Component, Path, PathBuf},
    process::{Child, Command, Stdio},
};

struct Executable {
    file: File,
    path: PathBuf,
    sha256: String,
}
fn plain(path: &Path) -> DomainResult<()> {
    let mut current = PathBuf::new();
    for part in path.components() {
        if matches!(part, Component::Prefix(_)) {
            current.push(part.as_os_str());
            continue;
        }
        if matches!(part, Component::ParentDir | Component::CurDir) {
            return Err(denied("Executable path traversal rejected"));
        }
        current.push(part.as_os_str());
        let metadata = fs::symlink_metadata(&current)?;
        #[cfg(windows)]
        let reparse = {
            use std::os::windows::fs::MetadataExt;
            metadata.file_attributes() & 0x400 != 0
        };
        #[cfg(not(windows))]
        let reparse = false;
        if metadata.file_type().is_symlink() || reparse {
            return Err(denied("Executable path link/reparse rejected"));
        }
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
                return Err(denied(
                    "Linux managed executable and ancestors must be root owned and not group/world writable",
                ));
            }
        }
    }
    Ok(())
}
impl Executable {
    fn open(path: &Path) -> DomainResult<Self> {
        if !path.is_absolute() {
            return Err(denied("Managed executable must be an explicit absolute path"));
        }
        #[cfg(windows)]
        {
            use std::path::Prefix;
            if !matches!(path.components().next(),Some(Component::Prefix(prefix)) if matches!(prefix.kind(),Prefix::Disk(_)|Prefix::VerbatimDisk(_)))
            {
                return Err(denied("Managed executable must be a local disk file; UNC/device paths are unsupported"));
            }
        }
        plain(path)?;
        let path = fs::canonicalize(path)?;
        plain(&path)?;
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            options.share_mode(1);
        }
        let mut file = options.open(&path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.len() > 1024 * 1024 * 1024 {
            return Err(denied("Executable size/type rejected"));
        }
        #[cfg(windows)]
        {
            if path.extension().and_then(|s| s.to_str()).is_none_or(|s| !s.eq_ignore_ascii_case("exe")) {
                return Err(denied("Windows managed launch supports explicit PE .exe files only"));
            }
            let mut header = [0_u8; 64];
            file.read_exact(&mut header)?;
            let pe = u32::from_le_bytes(header[60..64].try_into().map_err(|_| denied("Invalid PE header"))?);
            if &header[..2] != b"MZ" || !(64..=1024 * 1024).contains(&pe) || u64::from(pe) + 4 > metadata.len() {
                return Err(denied("Invalid bounded Windows PE image"));
            }
            file.seek(std::io::SeekFrom::Start(u64::from(pe)))?;
            let mut signature = [0_u8; 4];
            file.read_exact(&mut signature)?;
            file.rewind()?;
            if signature != *b"PE\0\0" {
                return Err(denied("Windows executable has no PE signature"));
            }
        }
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::MetadataExt;
            let mut magic = [0_u8; 4];
            file.read_exact(&mut magic)?;
            file.rewind()?;
            if magic != *b"\x7fELF"
                || metadata.uid() != 0
                || metadata.mode() & 0o111 == 0
                || metadata.mode() & 0o022 != 0
            {
                return Err(denied("Linux managed launch supports only root-owned non-writable executable ELF files"));
            }
        }
        #[cfg(not(any(windows, target_os = "linux")))]
        {
            return Err(denied("Managed process launch is unsupported on this OS"));
        }
        let sha256 = hash(&mut file)?;
        Ok(Self { file, path, sha256 })
    }
    fn recheck(&mut self) -> DomainResult<()> {
        plain(&self.path)?;
        self.file.rewind()?;
        if hash(&mut self.file)? != self.sha256 {
            return Err(denied("Opened executable changed during process policy decision"));
        }
        Ok(())
    }
    fn command(&self) -> Command {
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd;
            Command::new(format!("/proc/self/fd/{}", self.file.as_raw_fd()))
        }
        #[cfg(not(target_os = "linux"))]
        {
            Command::new(&self.path)
        }
    }
}
fn hash(file: &mut File) -> DomainResult<String> {
    let mut hash = Sha256::new();
    let mut count = 0_u64;
    let mut buffer = vec![0_u8; 32768];
    loop {
        let size = file.read(&mut buffer)?;
        if size == 0 {
            break;
        }
        count += size as u64;
        if count > 1024 * 1024 * 1024 {
            return Err(denied("Executable grew beyond budget"));
        }
        hash.update(&buffer[..size]);
    }
    Ok(hex::encode(hash.finalize()))
}
fn sanitized_environment(command: &mut Command) {
    command.env_clear();
    for name in ["SystemRoot", "WINDIR", "TEMP", "TMP", "PATH", "HOME", "LANG", "LC_ALL", "TZ"] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
}
/// 拥有的受管子进程；调用者可等待/取消这个 Child，不能凭任意 PID 控制其它进程。
pub struct ManagedChild {
    child: Child,
    admission: agf_core::process_hook::ProcessReceipt,
}
impl std::fmt::Debug for ManagedChild {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ManagedChild").field("admission", &self.admission).finish_non_exhaustive()
    }
}
impl ManagedChild {
    /// 原始已提交判定，不宣称任意宿主进程都被拦截。
    pub fn admission(&self) -> &agf_core::process_hook::ProcessReceipt {
        &self.admission
    }
    /// 只等待本次启动得到的 Child 句柄。
    pub fn wait(&mut self) -> DomainResult<std::process::ExitStatus> {
        self.child.wait().map_err(DomainError::from)
    }
    /// 只停止本次启动得到的 Child 句柄。
    pub fn cancel(&mut self) -> DomainResult<()> {
        if self.child.try_wait()?.is_none() {
            self.child.kill()?;
            self.child.wait()?;
        }
        Ok(())
    }
}
/// 严格受管入口；拒绝/超时/未知动作/回执审计失败均在创建子进程前返回。
/// Linux 以已打开 FD 执行 ELF，保留调用者 UID/GID；不提升权限，不防御同 UID 恶意管理员。
pub async fn run_managed(
    client: &ProcessClient,
    agent: Id,
    path: &Path,
    arguments: &[String],
) -> DomainResult<ManagedChild> {
    let mut executable = Executable::open(path)?;
    let name = executable.path.to_str().ok_or_else(|| denied("Managed executable must have a UTF8 name"))?;
    let request = ProcessRequest {
        request_id: Id::new(),
        agent_id: agent,
        mode: ProcessMode::Launch,
        source: ProcessSource::ManagedLauncher,
        executable_b64: STANDARD.encode(name.as_bytes()),
        arguments: arguments.to_vec(),
        executable_sha256: Some(executable.sha256.clone()),
        pid: None,
        uid: None,
        monotonic_ns: None,
        truncated: false,
        lost: 0,
    };
    request.validate()?;
    let admission = client.check(&request).await?;
    if !admission.launch_allowed {
        return Err(denied("Process launch denied or requires an unsupported action"));
    }
    executable.recheck()?;
    if Timestamp::now().unix_millis() >= admission.expires_at_ms {
        return Err(denied("Original process admission expired before spawn"));
    }
    let mut command = executable.command();
    command
        .args(arguments)
        .stdin(Stdio::null())
        .current_dir(executable.path.parent().ok_or_else(|| denied("Executable has no parent"))?);
    sanitized_environment(&mut command);
    let child = command.spawn()?;
    // Windows 的只读共享锁保持到 spawn 完成；Linux 内核已通过原 FD 打开同一 ELF。
    drop(executable);
    Ok(ManagedChild { child, admission })
}
