//! 进程观察与受管执行。观察器不阻断已发生的宿主进程；只有显式受管入口先判定后启动。
mod client;
mod launcher;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod tls_tests;
#[cfg(windows)]
mod windows;
use agf_core::{
    error::DomainResult,
    ids::Id,
    process_hook::{ProcessMode, ProcessRequest, ProcessSource},
};
use base64::{Engine, engine::general_purpose::STANDARD};
pub use client::ProcessClient;
pub use launcher::{ManagedChild, run_managed};
use std::{path::Path, time::Duration};

/// 有限生命周期的显式观察；默认采集循环不调用此函数。
pub async fn observe(
    client: &ProcessClient,
    agent: Id,
    tracefs: &Path,
    duration: Duration,
    limit: u32,
) -> DomainResult<u32> {
    if agent.is_nil() || duration.is_zero() || duration > Duration::from_hours(1) || !(1..=10000).contains(&limit) {
        return Err(client::denied("Process observation budget rejected"));
    }
    #[cfg(target_os = "linux")]
    {
        linux::observe(client, agent, tracefs, duration, limit).await
    }
    #[cfg(windows)]
    {
        let _ = tracefs;
        windows::observe(client, agent, duration, limit).await
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        let _ = (client, tracefs);
        Err(client::denied("Process observation is unsupported on this OS"))
    }
}
fn event(
    agent: Id,
    source: ProcessSource,
    filename: &[u8],
    pid: Option<u32>,
    uid: Option<u32>,
    monotonic_ns: Option<u64>,
    truncated: bool,
    lost: u64,
) -> ProcessRequest {
    ProcessRequest {
        request_id: Id::new(),
        agent_id: agent,
        mode: if lost > 0 { ProcessMode::Loss } else { ProcessMode::Observe },
        source,
        executable_b64: STANDARD.encode(filename),
        arguments: Vec::new(),
        executable_sha256: None,
        pid,
        uid,
        monotonic_ns,
        truncated,
        lost,
    }
}
