//! 固定 Linux eBPF 进程观察探针；只观察 exec 已发生的事实，不冒充执行前阻断。
//! 内核对象仅通过本对象持有的文件描述符存活；不写全局 bpffs、trace 配置或其它进程。
use std::io;

mod record;
pub use record::{ExecEvent, ProbeSample};

#[cfg(all(target_os = "linux", target_endian = "little", any(target_arch = "x86_64", target_arch = "aarch64")))]
mod linux;
#[cfg(all(target_os = "linux", target_endian = "little", any(target_arch = "x86_64", target_arch = "aarch64")))]
mod program;
#[cfg(all(target_os = "linux", target_endian = "little", any(target_arch = "x86_64", target_arch = "aarch64")))]
pub use linux::ProcessProbe;

#[cfg(not(all(target_os = "linux", target_endian = "little", any(target_arch = "x86_64", target_arch = "aarch64"))))]
#[derive(Debug)]
pub struct ProcessProbe;

#[cfg(not(all(target_os = "linux", target_endian = "little", any(target_arch = "x86_64", target_arch = "aarch64"))))]
impl ProcessProbe {
    /// 当前平台明确不支持此 Linux 内核探针。
    pub fn open(_tracefs: &std::path::Path) -> io::Result<Self> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "eBPF exec probe requires little-endian Linux x86_64/aarch64"))
    }
    /// 不产生虚构事件。
    pub fn try_next(&mut self) -> io::Result<Option<ProbeSample>> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "eBPF exec probe is unavailable"))
    }
}

#[cfg(any(
    test,
    all(target_os = "linux", target_endian = "little", any(target_arch = "x86_64", target_arch = "aarch64"))
))]
pub(crate) fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
