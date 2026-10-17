//! 固定内核探针适配；权限不足或 CPU 热插拔明确降级，绝不输出虚构全覆盖健康。
use super::*;
use agf_core::process_hook::ProcessSource;
use agf_ebpf::{ProbeSample, ProcessProbe};
pub(super) async fn observe(
    client: &ProcessClient,
    agent: Id,
    tracefs: &Path,
    duration: Duration,
    limit: u32,
) -> DomainResult<u32> {
    let mut probe = ProcessProbe::open(tracefs)?;
    let until = tokio::time::Instant::now() + duration;
    let mut count = 0;
    loop {
        if count >= limit || tokio::time::Instant::now() >= until {
            return Ok(count);
        }
        if let Some(sample) = probe.try_next()? {
            let body = match sample {
                ProbeSample::Exec(value) => event(
                    agent,
                    ProcessSource::LinuxSchedExec,
                    &value.filename,
                    Some(value.pid),
                    Some(value.uid),
                    Some(value.monotonic_ns),
                    value.truncated,
                    0,
                ),
                ProbeSample::Lost { count } => {
                    event(agent, ProcessSource::LinuxSchedExec, &[], None, None, None, false, count)
                }
            };
            // 服务端写入失败立即停止并释放本对象 FD，不能把漏报窗口称为完整监测。
            let receipt = client.check(&body).await?;
            if receipt.launch_allowed {
                return Err(client::denied("Observation response must never authorize launch"));
            }
            count += 1;
        } else {
            tokio::select! {()=tokio::time::sleep(Duration::from_millis(50))=>{},result=tokio::signal::ctrl_c()=>{result?;return Ok(count);}}
        }
    }
}
