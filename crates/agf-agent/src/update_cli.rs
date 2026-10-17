//! 本机操作员显式执行的更新命令；默认采集循环不会自动触发。
use agf_agent::{
    ReleaseManifest, platform,
    selfupdate::{self, DownloadPolicy, InstallRoot, TrustedReleaseKey},
};
use clap::Args;
use std::{
    io::Read,
    path::{Path, PathBuf},
};
use uuid::Uuid;
#[derive(Debug, Args)]
pub(super) struct ApplyArgs {
    /// 已签名的发布清单文件，最多 64 KiB。
    #[arg(long)]
    manifest: PathBuf,
    /// 由操作员独立配置的可信公钥 JSON，不能来自发布清单。
    #[arg(long)]
    trusted_key: PathBuf,
    /// 操作员控制的现有安装目录；更新助手必须从目标程序之外运行。
    #[arg(long)]
    install_root: PathBuf,
    /// 安装目录内的单个目标文件名，Windows 需包含 .exe。
    #[arg(long)]
    target_name: String,
    /// 由操作员资产清单提供的已安装版本号。
    #[arg(long)]
    current: String,
    /// 用于灰度分组的稳定注册 Agent 身份。
    #[arg(long)]
    agent_id: String,
    /// 明确允许的 HTTPS 来源，例如 https://releases.example.com。
    #[arg(long = "origin", required = true)]
    origins: Vec<String>,
    /// 企业证书颁发机构的 PEM 文件。
    #[arg(long)]
    ca: Option<PathBuf>,
    /// 程序下载大小上限，默认 256 MiB，最高 1 GiB。
    #[arg(long, default_value_t = 268435456)]
    max_bytes: u64,
    /// 放在 -- 之后的新 Agent 参数；只支持 run 子命令，省略时默认 run。
    #[arg(last = true)]
    arguments: Vec<String>,
}
#[derive(Debug, Args)]
pub(super) struct RecoverArgs {
    #[arg(long)]
    install_root: PathBuf,
    #[arg(long)]
    target_name: String,
    /// 原始事务标识；恢复过程不会重新下载或派发安装。
    #[arg(long)]
    transaction: Uuid,
}
fn bounded_json<T: serde::de::DeserializeOwned>(path: &Path, maximum: u64) -> anyhow::Result<T> {
    let file = std::fs::File::open(path)?;
    if !file.metadata()?.is_file() {
        anyhow::bail!("Update input must be a regular file");
    }
    let mut bytes = Vec::new();
    file.take(maximum + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum {
        anyhow::bail!("Update input exceeds budget");
    }
    Ok(serde_json::from_slice(&bytes)?)
}
pub(super) async fn apply(args: ApplyArgs) -> anyhow::Result<()> {
    let manifest: ReleaseManifest = bounded_json(&args.manifest, 65536)?;
    let key: TrustedReleaseKey = bounded_json(&args.trusted_key, 4096)?;
    let policy = DownloadPolicy { allowed_origins: args.origins, enterprise_ca: args.ca, max_bytes: args.max_bytes };
    let verified = selfupdate::verify_release(
        &manifest,
        &key,
        policy,
        &args.agent_id,
        &args.current,
        platform::current(),
        platform::current_arch(),
    )?;
    let Some(verified) = verified else {
        println!("{{\"status\":\"not_selected_or_not_newer\",\"installed\":false}}");
        return Ok(());
    };
    let root = InstallRoot::new(&args.install_root, &args.target_name)?;
    let arguments = if args.arguments.is_empty() { vec!["run".into()] } else { args.arguments };
    let receipt = selfupdate::download_and_apply(&verified, root, &arguments).await?;
    println!("{}", serde_json::to_string_pretty(&receipt)?);
    if receipt.status != "confirmed" {
        anyhow::bail!("Update did not become healthy; use the original transaction receipt");
    }
    Ok(())
}
pub(super) fn recover(args: RecoverArgs) -> anyhow::Result<()> {
    let receipt =
        selfupdate::recover_update(InstallRoot::new(&args.install_root, &args.target_name)?, args.transaction)?;
    println!("{}", serde_json::to_string_pretty(&receipt)?);
    if receipt.status == "rollback_pending" || receipt.status == "awaiting_health" {
        anyhow::bail!("Original transaction is still pending; no new install was dispatched");
    }
    Ok(())
}
