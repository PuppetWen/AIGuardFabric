//! 默认不激活内核；观察和执行都必须由本地操作者显式选择。
use agf_agent::{
    ClientConfig,
    process_hook::{ProcessClient, observe, run_managed},
};
use agf_core::ids::Id;
use clap::Args;
use std::{path::PathBuf, time::Duration};
#[derive(Debug, Args)]
pub(super) struct Common {
    /// 已验证 HTTPS 平台原点；凭据仅从 AGF_AGENT_TOKEN 读取。
    #[arg(long)]
    server: String,
    /// 必须与 API Key 在平台的 Agent 绑定一致。
    #[arg(long)]
    agent_id: Id,
}
impl Common {
    fn client(&self) -> anyhow::Result<ProcessClient> {
        let config = ClientConfig::from_env();
        let token =
            config.token.ok_or_else(|| anyhow::anyhow!("Process commands require AGF_AGENT_TOKEN bound API Key"))?;
        Ok(ProcessClient::new(&self.server, token, &config.tls)?)
    }
}
#[derive(Debug, Args)]
pub(super) struct ObserveArgs {
    #[command(flatten)]
    common: Common,
    /// Linux 只读 tracefs；Windows 不使用该路径。
    #[arg(long, default_value = "/sys/kernel/tracing")]
    tracefs: PathBuf,
    /// 观察期限 1..3600 秒。
    #[arg(long, default_value_t = 300)]
    seconds: u64,
    /// 最大上报事件数 1..10000。
    #[arg(long, default_value_t = 1000)]
    limit: u32,
}
#[derive(Debug, Args)]
pub(super) struct RunArgs {
    #[command(flatten)]
    common: Common,
    /// 显式绝对可执行文件路径；不通过 shell。
    #[arg(long)]
    executable: PathBuf,
    /// 原始参数数组，在 -- 后传入。
    #[arg(last = true)]
    arguments: Vec<String>,
}
pub(super) async fn observe_command(args: ObserveArgs) -> anyhow::Result<()> {
    let count = observe(
        &args.common.client()?,
        args.common.agent_id,
        &args.tracefs,
        Duration::from_secs(args.seconds),
        args.limit,
    )
    .await?;
    println!("{{\"observed_records\":{count},\"enforced\":false,\"host_preexecution_blocking\":false}}");
    Ok(())
}
pub(super) async fn run_command(args: RunArgs) -> anyhow::Result<()> {
    let mut child =
        run_managed(&args.common.client()?, args.common.agent_id, &args.executable, &args.arguments).await?;
    println!("{}", serde_json::to_string(child.admission())?);
    let status = child.wait()?;
    if !status.success() {
        anyhow::bail!("Owned managed process exited unsuccessfully");
    }
    Ok(())
}
