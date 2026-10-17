#[cfg(any(
    test,
    all(target_os = "linux", target_endian = "little", any(target_arch = "x86_64", target_arch = "aarch64"))
))]
use crate::invalid;
#[cfg(any(
    test,
    all(target_os = "linux", target_endian = "little", any(target_arch = "x86_64", target_arch = "aarch64"))
))]
use std::io;

/// 内核实际可得的 exec 事实；文件名可能截断，不包含 argv，也不是阻断回执。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecEvent {
    pub monotonic_ns: u64,
    pub pid: u32,
    pub uid: u32,
    pub filename: Vec<u8>,
    pub truncated: bool,
}

/// 丢失必须显式暴露，不能将不完整的观察窗口称为全面监控。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeSample {
    Exec(ExecEvent),
    Lost { count: u64 },
}

#[cfg(any(
    test,
    all(target_os = "linux", target_endian = "little", any(target_arch = "x86_64", target_arch = "aarch64"))
))]
pub(crate) const RECORD_SIZE: usize = 280;

#[cfg(any(
    test,
    all(target_os = "linux", target_endian = "little", any(target_arch = "x86_64", target_arch = "aarch64"))
))]
pub(crate) fn decode(bytes: &[u8]) -> io::Result<ExecEvent> {
    if bytes.len() != RECORD_SIZE {
        return Err(invalid("eBPF exec record length differs"));
    }
    let monotonic_ns = u64::from_le_bytes(bytes[0..8].try_into().map_err(|_| invalid("timestamp"))?);
    let pid = u32::from_le_bytes(bytes[8..12].try_into().map_err(|_| invalid("pid"))?);
    let uid = u32::from_le_bytes(bytes[12..16].try_into().map_err(|_| invalid("uid"))?);
    let length = i32::from_le_bytes(bytes[16..20].try_into().map_err(|_| invalid("path length"))?);
    let length = usize::try_from(length).map_err(|_| invalid("negative kernel path length"))?;
    if pid == 0 || !(2..=256).contains(&length) || bytes[20..24] != [0; 4] || bytes[24 + length - 1] != 0 {
        return Err(invalid("eBPF exec record fields are invalid"));
    }
    let filename = bytes[24..24 + length - 1].to_vec();
    if filename.contains(&0) {
        return Err(invalid("embedded NUL in kernel filename"));
    }
    Ok(ExecEvent { monotonic_ns, pid, uid, filename, truncated: length == 256 })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    fn sample(path: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0; RECORD_SIZE];
        bytes[0..8].copy_from_slice(&12_u64.to_le_bytes());
        bytes[8..12].copy_from_slice(&7_u32.to_le_bytes());
        bytes[12..16].copy_from_slice(&42_u32.to_le_bytes());
        bytes[16..20].copy_from_slice(&i32::try_from(path.len() + 1).unwrap().to_le_bytes());
        bytes[24..24 + path.len()].copy_from_slice(path);
        bytes
    }
    #[test]
    fn real_wire_bytes_keep_non_utf8_and_control_filename_without_frame_injection() {
        let event = decode(&sample(b"/tmp/a\n\xff\"b")).unwrap();
        assert_eq!(event.filename, b"/tmp/a\n\xff\"b");
        assert_eq!((event.pid, event.uid, event.monotonic_ns), (7, 42, 12));
        assert!(!event.truncated);
    }
    #[test]
    fn truncation_and_corruption_are_explicit() {
        assert!(decode(&sample(&[b'a'; 255])).unwrap().truncated);
        for length in [-1_i32, 0, 1, 257, i32::MAX] {
            let mut bytes = sample(b"/bin/x");
            bytes[16..20].copy_from_slice(&length.to_le_bytes());
            assert!(decode(&bytes).is_err());
        }
        let mut bytes = sample(b"/bin/x");
        bytes[26] = 0;
        assert!(decode(&bytes).is_err());
        let mut bytes = sample(b"/bin/x");
        bytes[30] = 1;
        assert!(decode(&bytes).is_err());
        let mut bytes = sample(b"/bin/x");
        bytes[20] = 1;
        assert!(decode(&bytes).is_err());
        assert!(decode(&bytes[..279]).is_err());
    }
}
