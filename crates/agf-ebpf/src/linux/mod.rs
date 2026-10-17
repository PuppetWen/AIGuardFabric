use crate::{ProbeSample, invalid, program::exec_program};
use std::{
    fs, io,
    os::fd::{AsRawFd, OwnedFd},
    path::Path,
};
mod abi;
mod ring;

/// 真正持有已附着的固定进程 tracepoint 程序；没有权限或内核不兼容时明确失败。
#[derive(Debug)]
pub struct ProcessProbe {
    ring: ring::Ring,
    losses: OwnedFd,
    previous_losses: u64,
    drain_before_loss: bool,
    online_snapshot: Vec<i32>,
    next_topology_check: std::time::Instant,
    _program: OwnedFd,
    _attachments: Vec<OwnedFd>,
}
fn small_text(path: &Path) -> io::Result<String> {
    use std::io::Read;
    let mut bytes = Vec::new();
    fs::File::open(path)?.take(65537).read_to_end(&mut bytes)?;
    if bytes.len() > 65536 {
        return Err(invalid("kernel probe metadata exceeds limit"));
    }
    String::from_utf8(bytes).map_err(|_| invalid("kernel metadata is not UTF8"))
}
fn tracepoint_id(root: &Path) -> io::Result<u32> {
    if !root.is_absolute() {
        return Err(invalid("explicit absolute read-only tracefs root required"));
    }
    let base = root.join("events/sched/sched_process_exec");
    let format = small_text(&base.join("format"))?;
    // 固定程序使用 data_loc offset=8；内核布局不同则拒绝，不猜读任意 ctx 字段。
    let valid = format.lines().any(|line| {
        let fields = line.split(';').map(str::trim).collect::<Vec<_>>();
        fields.contains(&"field:__data_loc char[] filename")
            && fields.contains(&"offset:8")
            && fields.contains(&"size:4")
    });
    if !valid {
        return Err(invalid("sched_process_exec filename layout differs"));
    }
    small_text(&base.join("id"))?
        .trim()
        .parse::<u32>()
        .ok()
        .filter(|id| *id > 0)
        .ok_or_else(|| invalid("tracepoint id invalid"))
}
fn cpus(raw: &str) -> io::Result<Vec<i32>> {
    let mut values = std::collections::BTreeSet::new();
    for range in raw.trim().split(',') {
        let parts = range.split('-').collect::<Vec<_>>();
        let first = parts.first().and_then(|v| v.parse::<i32>().ok()).ok_or_else(|| invalid("CPU range invalid"))?;
        let last = match parts.as_slice() {
            [_] => first,
            [_, value] => value.parse::<i32>().map_err(|_| invalid("CPU end invalid"))?,
            _ => return Err(invalid("CPU range shape invalid")),
        };
        if first < 0 || first > last || last >= 4096 {
            return Err(invalid("CPU index outside probe budget"));
        }
        for cpu in first..=last {
            if !values.insert(cpu) {
                return Err(invalid("duplicate online CPU"));
            }
        }
    }
    if values.is_empty() {
        return Err(invalid("no online CPU"));
    }
    Ok(values.into_iter().collect())
}
impl ProcessProbe {
    /// 读取 tracefs 元数据并附着全部在线 CPU；不修改全局 trace 或安装任何工具。
    /// 首个失败会销毁本轮已创建的所有 FD/映射，不声称部分探针已经就绪。
    pub fn open(tracefs: &Path) -> io::Result<Self> {
        let id = tracepoint_id(tracefs)?;
        let cpus = cpus(&small_text(Path::new("/sys/devices/system/cpu/online"))?)?;
        let events = abi::events_map(u32::try_from(ring::CAPACITY).map_err(|_| invalid("ring capacity"))?)?;
        let losses = abi::losses_map()?;
        let program = abi::program(&exec_program(events.as_raw_fd(), losses.as_raw_fd())?)?;
        let ring = ring::Ring::new(events)?;
        let attachments = cpus.iter().map(|cpu| abi::attach(id, *cpu, &program)).collect::<io::Result<Vec<_>>>()?;
        Ok(Self {
            ring,
            losses,
            previous_losses: 0,
            drain_before_loss: false,
            online_snapshot: cpus,
            next_topology_check: std::time::Instant::now(),
            _program: program,
            _attachments: attachments,
        })
    }
    /// 非阻塞读取；返回真实丢失计数或完整事实，调用者负责受控轮询/停止及健康上报。
    pub fn try_next(&mut self) -> io::Result<Option<ProbeSample>> {
        if std::time::Instant::now() >= self.next_topology_check {
            topology_unchanged(&self.online_snapshot, &small_text(Path::new("/sys/devices/system/cpu/online"))?)?;
            self.next_topology_check = std::time::Instant::now() + std::time::Duration::from_secs(1);
        }
        next_sample(
            &mut self.previous_losses,
            &mut self.drain_before_loss,
            || self.ring.next(),
            || abi::losses(&self.losses),
        )
    }
}
fn topology_unchanged(expected: &[i32], raw: &str) -> io::Result<()> {
    if cpus(raw)? != expected {
        return Err(invalid("online CPU topology changed; probe degraded, explicit controlled reopen required"));
    }
    Ok(())
}
fn next_sample<F, L>(previous: &mut u64, drain: &mut bool, mut take: F, mut total: L) -> io::Result<Option<ProbeSample>>
where
    F: FnMut() -> io::Result<Option<crate::ExecEvent>>,
    L: FnMut() -> io::Result<u64>,
{
    // 每次报告 loss 后优先消费一条记录，持续丢失不能饿死已提交事件。
    if *drain {
        *drain = false;
        if let Some(event) = take()? {
            return Ok(Some(ProbeSample::Exec(event)));
        }
    }
    let losses = total()?;
    let delta = losses.wrapping_sub(*previous);
    *previous = losses;
    if delta != 0 {
        *drain = true;
        return Ok(Some(ProbeSample::Lost { count: delta }));
    }
    take().map(|event| event.map(ProbeSample::Exec))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    #[test]
    fn cpu_range_parser_rejects_injections_duplicates_and_excessive_work() {
        assert_eq!(cpus("0-2,4,7-8\n").unwrap(), vec![0, 1, 2, 4, 7, 8]);
        for bad in ["", "-1", "0-1,1", "2-1", "4096", "1-999999999", "1-2-3", "0;touch /tmp/x"] {
            assert!(cpus(bad).is_err());
        }
    }
    #[test]
    fn no_privileged_attachment_is_attempted_for_relative_root() {
        assert_eq!(ProcessProbe::open(Path::new("relative")).unwrap_err().kind(), io::ErrorKind::InvalidData);
    }
    #[test]
    fn changed_online_cpu_snapshot_requires_explicit_reopen_instead_of_silent_partial_coverage() {
        assert!(topology_unchanged(&[0, 1], "0-1\n").is_ok());
        assert!(topology_unchanged(&[0, 1], "0,2").is_err());
        assert!(topology_unchanged(&[0, 1], "0").is_err());
    }
    #[test]
    fn continuous_loss_does_not_starve_committed_exec_records() {
        let mut previous = 0;
        let mut drain = false;
        let mut counter = 0;
        let mut consumed = 0;
        for index in 0..6 {
            let sample = next_sample(
                &mut previous,
                &mut drain,
                || {
                    consumed += 1;
                    Ok(Some(crate::ExecEvent {
                        monotonic_ns: 1,
                        pid: 7,
                        uid: 0,
                        filename: b"/owned".to_vec(),
                        truncated: false,
                    }))
                },
                || {
                    counter += 1;
                    Ok(counter)
                },
            )
            .unwrap();
            assert!(matches!(
                (index % 2, sample),
                (0, Some(ProbeSample::Lost { count: 1 })) | (1, Some(ProbeSample::Exec(_)))
            ));
        }
        assert_eq!(consumed, 3);
    }
}
