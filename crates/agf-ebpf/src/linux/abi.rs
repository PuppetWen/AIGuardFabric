//! Linux 64-bit UAPI。unsafe 仅用于固定 eBPF/perf ABI，所有用户指针有同步调用期所有权。
use crate::{invalid, program::Insn};
use std::{
    ffi::{c_int, c_long, c_ulong, c_void},
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};

#[cfg(target_arch = "x86_64")]
const SYS_BPF: c_long = 321;
#[cfg(target_arch = "x86_64")]
const SYS_PERF: c_long = 298;
#[cfg(target_arch = "aarch64")]
const SYS_BPF: c_long = 280;
#[cfg(target_arch = "aarch64")]
const SYS_PERF: c_long = 241;

unsafe extern "C" {
    fn syscall(number: c_long, ...) -> c_long;
    fn ioctl(fd: c_int, request: c_ulong, ...) -> c_int;
    pub(super) fn mmap(
        address: *mut c_void,
        length: usize,
        protection: c_int,
        flags: c_int,
        fd: c_int,
        offset: i64,
    ) -> *mut c_void;
    pub(super) fn munmap(address: *mut c_void, length: usize) -> c_int;
    pub(super) fn sysconf(name: c_int) -> c_long;
}

#[repr(C)]
#[derive(Default)]
struct MapCreate {
    kind: u32,
    key: u32,
    value: u32,
    entries: u32,
    flags: u32,
    inner: u32,
    numa: u32,
    name: [u8; 16],
    ifindex: u32,
}
#[repr(C)]
#[derive(Default)]
struct MapElement {
    fd: u32,
    pad: u32,
    key: u64,
    value: u64,
    flags: u64,
}
#[repr(C)]
#[derive(Default)]
struct ProgLoad {
    kind: u32,
    count: u32,
    instructions: u64,
    license: u64,
    log_level: u32,
    log_size: u32,
    log: u64,
    kernel: u32,
    flags: u32,
    name: [u8; 16],
    ifindex: u32,
    expected_attach: u32,
}

fn bpf<T>(command: c_int, attr: &T) -> io::Result<c_long> {
    // SAFETY: T 是上列 repr(C) 初始化 UAPI 结构，指针只供此同步内核调用读取。
    let result = unsafe { syscall(SYS_BPF, command, std::ptr::from_ref(attr), std::mem::size_of::<T>()) };
    if result < 0 { Err(io::Error::last_os_error()) } else { Ok(result) }
}
fn descriptor(value: c_long) -> io::Result<OwnedFd> {
    let raw = i32::try_from(value).map_err(|_| invalid("kernel descriptor exceeds signed fd range"))?;
    if raw < 0 {
        return Err(invalid("negative kernel descriptor"));
    }
    // SAFETY: 成功的 bpf/perf 调用返回新描述符，这里只转移一次所有权。
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}
pub(super) fn events_map(entries: u32) -> io::Result<OwnedFd> {
    descriptor(bpf(0, &MapCreate { kind: 27, entries, ..MapCreate::default() })?)
}
pub(super) fn losses_map() -> io::Result<OwnedFd> {
    descriptor(bpf(0, &MapCreate { kind: 2, key: 4, value: 8, entries: 1, ..MapCreate::default() })?)
}
pub(super) fn losses(map: &OwnedFd) -> io::Result<u64> {
    let key = 0_u32;
    let mut value = 0_u64;
    let attr = MapElement {
        fd: u32::try_from(map.as_raw_fd()).map_err(|_| invalid("map fd"))?,
        key: std::ptr::from_ref(&key) as u64,
        value: std::ptr::from_mut(&mut value) as u64,
        ..MapElement::default()
    };
    bpf(1, &attr)?;
    Ok(value)
}
pub(super) fn program(code: &[Insn]) -> io::Result<OwnedFd> {
    let mut log = vec![0_u8; 64 * 1024];
    let mut name = [0_u8; 16];
    name[..13].copy_from_slice(b"agf_exec_seen");
    let attr = ProgLoad {
        kind: 5,
        count: u32::try_from(code.len()).map_err(|_| invalid("BPF instruction count"))?,
        instructions: code.as_ptr() as u64,
        license: c"GPL".as_ptr() as u64,
        log_level: 1,
        log_size: u32::try_from(log.len()).map_err(|_| invalid("verifier log size"))?,
        log: log.as_mut_ptr() as u64,
        name,
        ..ProgLoad::default()
    };
    match bpf(5, &attr) {
        Ok(value) => descriptor(value),
        Err(error) => {
            let end = log.iter().position(|byte| *byte == 0).unwrap_or(log.len()).min(4096);
            Err(io::Error::new(
                error.kind(),
                format!("eBPF verifier/load failed: {error}; {}", String::from_utf8_lossy(&log[..end])),
            ))
        }
    }
}
pub(super) fn attach(tracepoint: u32, cpu: i32, program: &OwnedFd) -> io::Result<OwnedFd> {
    // PERF_ATTR_SIZE_VER0=64；八字节对齐且完全初始化，不传递尚未使用的新字段。
    let mut attr = [0_u64; 8];
    attr[0] = 2_u64 | (64_u64 << 32);
    attr[1] = u64::from(tracepoint);
    attr[2] = 1;
    attr[5] = 1; // 先保持 disabled，附着后才启用，不继承其它进程或全局会话。
    // SAFETY: 对齐的 64 字节属性在同步调用期间存活；pid=-1/cpu>=0 只观察该 tracepoint。
    let value = unsafe { syscall(SYS_PERF, attr.as_ptr(), -1_i32, cpu, -1_i32, 8_u64) };
    if value < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = descriptor(value)?;
    // SAFETY: perf 描述符和固定程序均由本对象拥有，内核保留附着引用。
    if unsafe { ioctl(fd.as_raw_fd(), 0x4004_2408_u64, program.as_raw_fd()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: 只启用本次新建的描述符；任意失败路径都会通过 drop 关闭并解除附着。
    if unsafe { ioctl(fd.as_raw_fd(), 0x2400_u64, 0_u64) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn uapi_structures_have_kernel_offsets_and_no_uninitialized_tail() {
        assert_eq!(std::mem::size_of::<MapCreate>(), 48);
        assert_eq!(std::mem::size_of::<MapElement>(), 32);
        assert_eq!(std::mem::size_of::<ProgLoad>(), 72);
        assert_eq!(std::mem::offset_of!(ProgLoad, instructions), 8);
        assert_eq!(std::mem::offset_of!(ProgLoad, log), 32);
        assert_eq!(std::mem::offset_of!(ProgLoad, name), 48);
    }
}
